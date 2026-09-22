#include "DumpFacts.h"

#include <algorithm>
#include <utility>

namespace ksword::evidence {
namespace {

// ---------------------------------------------------------------------------
// Format constants. Hardcoded in the implementation; not read from parsed files and not exposed to tests. Tests must write
// offsets according to the public layout of DUMP_HEADER64 themselves; otherwise, incorrect offsets cannot be detected (Q-01).
// ---------------------------------------------------------------------------
constexpr std::uint32_t kSignatureMdmp = 0x504D444DU;   // 'MDMP'
constexpr std::uint32_t kSignaturePage = 0x45474150U;   // 'PAGE'
constexpr std::uint32_t kValidDump64 = 0x34365544U;     // 'DU64'
constexpr std::uint32_t kValidDump32 = 0x504D5544U;     // 'DUMP'

// The dump writer only populates fields it cares about; the rest remain 'PAGE' filled. Reading a fill value
// means 'this cell was never written' and must never be treated as a real value — a trap highlighted by C-03.
constexpr std::uint32_t kPageFillDword = 0x45474150U;
constexpr std::uint64_t kPageFillQword = 0x4547415045474150ULL;

constexpr std::size_t kMinidumpHeaderBytes = 0x20U;
constexpr std::size_t kKernelHeader64Bytes = 0x2000U;
constexpr std::size_t kKernelHeader32Bytes = 0x1000U;
constexpr std::size_t kSignatureBytes = 8U;

// DUMP_HEADER64 field offsets.
constexpr std::size_t kOffMajorVersion = 0x08U;
constexpr std::size_t kOffMinorVersion = 0x0CU;
constexpr std::size_t kOffDirectoryTableBase = 0x10U;
constexpr std::size_t kOffMachineImageType = 0x30U;
constexpr std::size_t kOffNumberProcessors = 0x34U;
constexpr std::size_t kOffBugCheckCode = 0x38U;
constexpr std::size_t kOffBugCheckParameters = 0x40U;
constexpr std::size_t kOffDumpType = 0xF98U;
constexpr std::size_t kOffSystemTime = 0xFA8U;
constexpr std::size_t kOffSystemUpTime = 0x1030U;
constexpr std::size_t kOffWriterStatus = 0x1048U;

// PE machine type.
constexpr std::uint32_t kMachineX86 = 0x014CU;
constexpr std::uint32_t kMachineX64 = 0x8664U;
constexpr std::uint32_t kMachineArm = 0x01C4U;
constexpr std::uint32_t kMachineArm64 = 0xAA64U;

constexpr const char* kRecognitionDomain = "KSWORD_DUMPRECOGNITION";

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
constexpr bool isAsciiUpper(unsigned char byte) noexcept { return byte >= 'A' && byte <= 'Z'; }
constexpr bool isAsciiLower(unsigned char byte) noexcept { return byte >= 'a' && byte <= 'z'; }
constexpr bool isAsciiDigit(unsigned char byte) noexcept { return byte >= '0' && byte <= '9'; }

constexpr bool isAsciiAlpha(unsigned char byte) noexcept {
    return isAsciiUpper(byte) || isAsciiLower(byte);
}

constexpr bool isAsciiAlnum(unsigned char byte) noexcept {
    return isAsciiAlpha(byte) || isAsciiDigit(byte);
}

constexpr char asciiLowerChar(char value) noexcept {
    const auto kByte = static_cast<unsigned char>(value);
    return isAsciiUpper(kByte) ? static_cast<char>(kByte - 'A' + 'a') : value;
}

// Only fold ASCII case. Non-ASCII bytes are preserved as-is: without a locale, guessing other character
// sets is inappropriate, as incorrect folding would merge two distinct module names into one.
std::string asciiLower(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (const char kValue : text) {
        result.push_back(asciiLowerChar(kValue));
    }
    return result;
}

// The following two comparison functions allocate no memory and are provided specifically for noexcept predicates: the predicate
// must not allow allocations that could throw bad_alloc, otherwise noexcept would convert a memory shortage into std::terminate.
bool asciiEqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t index = 0; index < a.size(); ++index) {
        if (asciiLowerChar(a[index]) != asciiLowerChar(b[index])) {
            return false;
        }
    }
    return true;
}

// Note: needle must already be a lowercase literal.
bool containsIgnoreCase(std::string_view haystack, std::string_view loweredNeedle) noexcept {
    if (loweredNeedle.empty() || haystack.size() < loweredNeedle.size()) {
        return false;
    }
    const std::size_t kLast = haystack.size() - loweredNeedle.size();
    for (std::size_t start = 0; start <= kLast; ++start) {
        std::size_t offset = 0;
        while (offset < loweredNeedle.size() &&
               asciiLowerChar(haystack[start + offset]) == loweredNeedle[offset]) {
            ++offset;
        }
        if (offset == loweredNeedle.size()) {
            return true;
        }
    }
    return false;
}

// Control characters: C0 range and DEL.
constexpr bool isControlByte(unsigned char byte) noexcept {
    return byte < 0x20U || byte == 0x7FU;
}

// Allowed layout control characters in the report.
constexpr bool isLayoutControlByte(unsigned char byte) noexcept {
    return byte == '\t' || byte == '\n' || byte == '\r';
}

std::string_view baseNameOf(std::string_view path) noexcept {
    std::size_t begin = 0;
    for (std::size_t index = 0; index < path.size(); ++index) {
        if (path[index] == '\\' || path[index] == '/') {
            begin = index + 1;
        }
    }
    return path.substr(begin);
}

} // namespace

// ---------------------------------------------------------------------------
// Byte read
// ---------------------------------------------------------------------------
bool readLittleEndianU32(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint32_t& out) noexcept {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        return false;
    }
    out = static_cast<std::uint32_t>(bytes[offset]) |
          (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
          (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
          (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    return true;
}

bool readLittleEndianU64(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint64_t& out) noexcept {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    if (!readLittleEndianU32(bytes, offset, low) ||
        !readLittleEndianU32(bytes, offset + 4U, high)) {
        return false;
    }
    out = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
    return true;
}

// ---------------------------------------------------------------------------
// C-02 File identification
// ---------------------------------------------------------------------------
const char* dumpKindName(DumpKind kind) noexcept {
    switch (kind) {
    case DumpKind::kNotADump: return "NotADump";
    case DumpKind::kUnsupported: return "Unsupported";
    case DumpKind::kUserMinidump: return "UserMinidump";
    case DumpKind::kKernelSmall: return "KernelSmall";
    case DumpKind::kKernelMemory: return "KernelMemory";
    }
    return "NotADump";
}

bool dumpKindCarriesKernelFacts(DumpKind kind) noexcept {
    return kind == DumpKind::kKernelSmall || kind == DumpKind::kKernelMemory;
}

const char* signatureFamilyName(SignatureFamily family) noexcept {
    switch (family) {
    case SignatureFamily::kNone: return "None";
    case SignatureFamily::kMdmp: return "Mdmp";
    case SignatureFamily::kKernelPage64: return "KernelPage64";
    case SignatureFamily::kKernelPage32: return "KernelPage32";
    }
    return "None";
}

const char* recognitionReasonName(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::kRecognized: return "Recognized";
    case RecognitionReason::kEmptyFile: return "EmptyFile";
    case RecognitionReason::kTooSmallForSignature: return "TooSmallForSignature";
    case RecognitionReason::kTruncatedHeader: return "TruncatedHeader";
    case RecognitionReason::kUnknownSignature: return "UnknownSignature";
    case RecognitionReason::kUnsupportedKernelBitness: return "UnsupportedKernelBitness";
    case RecognitionReason::kUnsupportedArchitecture: return "UnsupportedArchitecture";
    case RecognitionReason::kUnsupportedDumpType: return "UnsupportedDumpType";
    }
    return "UnknownSignature";
}

const char* targetArchitectureName(TargetArchitecture architecture) noexcept {
    switch (architecture) {
    case TargetArchitecture::kUnknown: return "Unknown";
    case TargetArchitecture::kX86: return "X86";
    case TargetArchitecture::kX64: return "X64";
    case TargetArchitecture::kArm: return "Arm";
    case TargetArchitecture::kArm64: return "Arm64";
    case TargetArchitecture::kOther: return "Other";
    }
    return "Unknown";
}

namespace {

TargetArchitecture architectureFromMachineType(std::uint32_t machineType) noexcept {
    switch (machineType) {
    case kMachineX86: return TargetArchitecture::kX86;
    case kMachineX64: return TargetArchitecture::kX64;
    case kMachineArm: return TargetArchitecture::kArm;
    case kMachineArm64: return TargetArchitecture::kArm64;
    default: break;
    }
    // 'PAGE' fill is not a machine type; it means 'not set'. Do not map it to 'Other' to fake a valid value.
    if (machineType == kPageFillDword || machineType == 0U) {
        return TargetArchitecture::kUnknown;
    }
    return TargetArchitecture::kOther;
}

const char* recognitionMessageKey(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::kRecognized: return "dump.recognize.ok";
    case RecognitionReason::kEmptyFile: return "dump.recognize.empty_file";
    case RecognitionReason::kTooSmallForSignature: return "dump.recognize.too_small";
    case RecognitionReason::kTruncatedHeader: return "dump.recognize.truncated_header";
    case RecognitionReason::kUnknownSignature: return "dump.recognize.unknown_signature";
    case RecognitionReason::kUnsupportedKernelBitness: return "dump.recognize.kernel32_unsupported";
    case RecognitionReason::kUnsupportedArchitecture: return "dump.recognize.arch_unsupported";
    case RecognitionReason::kUnsupportedDumpType: return "dump.recognize.dumptype_unsupported";
    }
    return "dump.recognize.unknown_signature";
}

CollectionStatus recognitionStatus(RecognitionReason reason) noexcept {
    switch (reason) {
    case RecognitionReason::kRecognized:
        return CollectionStatus::kSuccess;
    case RecognitionReason::kTruncatedHeader:
        // Signature header read but format tail unread — this is partial collection, not 'unsupported format'.
        return CollectionStatus::kPartial;
    case RecognitionReason::kUnsupportedKernelBitness:
    case RecognitionReason::kUnsupportedArchitecture:
    case RecognitionReason::kUnsupportedDumpType:
        return CollectionStatus::kUnsupported;
    case RecognitionReason::kEmptyFile:
    case RecognitionReason::kTooSmallForSignature:
    case RecognitionReason::kUnknownSignature:
        return CollectionStatus::kError;
    }
    return CollectionStatus::kError;
}

void finishRecognition(DumpRecognition& recognition, RecognitionReason reason) {
    recognition.reason = reason;
    const CollectionStatus kStatus = recognitionStatus(reason);
    if (kStatus == CollectionStatus::kSuccess) {
        recognition.outcome = CollectionOutcome::success();
        recognition.outcome.message = recognitionMessageKey(reason);
        return;
    }
    recognition.outcome = CollectionOutcome::failure(kStatus,
                                                     kRecognitionDomain,
                                                     static_cast<std::uint64_t>(reason),
                                                     recognitionMessageKey(reason));
}

} // namespace

// Intentionally not noexcept: finishRecognition must construct a CollectionOutcome containing a 22-byte domain
// string on every failure path, which inevitably triggers heap allocation (MSVC's SSO limit is 15 bytes).
// See the declaration of this function in DumpFacts.h.
DumpRecognition recognizeDump(std::span<const std::uint8_t> headBytes,
                              const OptionalU64& totalFileSize) {
    DumpRecognition recognition;
    recognition.bytesProvided = OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));
    recognition.fileSize = totalFileSize.present
                               ? totalFileSize
                               : OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));

    const std::uint64_t kDeclaredSize = recognition.fileSize.value;

    if (kDeclaredSize == 0U) {
        finishRecognition(recognition, RecognitionReason::kEmptyFile);
        return recognition;
    }

    std::uint32_t signature = 0;
    std::uint32_t validDump = 0;
    if (kDeclaredSize < kSignatureBytes || headBytes.size() < kSignatureBytes ||
        !readLittleEndianU32(headBytes, 0U, signature) ||
        !readLittleEndianU32(headBytes, 4U, validDump)) {
        // The file itself is too short, or the window provided by the caller is too short. The distinction is
        // exposed via the bytesProvided and fileSize fields rather than being obscured in a single reason.
        finishRecognition(recognition, RecognitionReason::kTooSmallForSignature);
        return recognition;
    }

    recognition.rawSignature = OptionalU64::of(signature);
    recognition.rawValidDump = OptionalU64::of(validDump);

    // The criterion for user-mode minidumps is a single one: the signature must be 'MDMP'. This is a hard line —
    // once matched, all subsequent kernel branches are ignored, and it can never be recognized as a kernel dump.
    if (signature == kSignatureMdmp) {
        recognition.family = SignatureFamily::kMdmp;
        recognition.headerBytesRequired =
            OptionalU64::of(static_cast<std::uint64_t>(kMinidumpHeaderBytes));
        if (kDeclaredSize < kMinidumpHeaderBytes || headBytes.size() < kMinidumpHeaderBytes) {
            recognition.kind = DumpKind::kUnsupported;
            finishRecognition(recognition, RecognitionReason::kTruncatedHeader);
            return recognition;
        }
        recognition.parseAttempted = true;
        recognition.kind = DumpKind::kUserMinidump;
        // The target architecture for user-mode minidumps resides in SystemInfoStream, not the header.
        // This function only inspects the header, so the architecture is Unknown—no guessing and no extension-based inference.
        recognition.architecture = TargetArchitecture::kUnknown;
        finishRecognition(recognition, RecognitionReason::kRecognized);
        return recognition;
    }

    if (signature != kSignaturePage) {
        finishRecognition(recognition, RecognitionReason::kUnknownSignature);
        return recognition;
    }

    if (validDump == kValidDump32) {
        recognition.family = SignatureFamily::kKernelPage32;
        recognition.headerBytesRequired =
            OptionalU64::of(static_cast<std::uint64_t>(kKernelHeader32Bytes));
        recognition.kind = DumpKind::kUnsupported;
        // This round supports only x64 kernel dumps. Explicitly reject; do not forcibly read 32-bit files using 64-bit layout.
        finishRecognition(recognition, RecognitionReason::kUnsupportedKernelBitness);
        return recognition;
    }

    if (validDump != kValidDump64) {
        finishRecognition(recognition, RecognitionReason::kUnknownSignature);
        return recognition;
    }

    recognition.family = SignatureFamily::kKernelPage64;
    recognition.headerBytesRequired =
        OptionalU64::of(static_cast<std::uint64_t>(kKernelHeader64Bytes));

    // Try to read the machine type even if the header is truncated (it's at offset 0x30, far before 0x2000),
    // so the UI can at least say "it's a truncated x64 kernel dump", though the kind remains inconclusive.
    std::uint32_t machineType = 0;
    if (readLittleEndianU32(headBytes, kOffMachineImageType, machineType)) {
        recognition.parseAttempted = true;
        recognition.rawMachineType = OptionalU64::of(machineType);
        recognition.architecture = architectureFromMachineType(machineType);
    }

    if (kDeclaredSize < kKernelHeader64Bytes || headBytes.size() < kKernelHeader64Bytes) {
        recognition.kind = DumpKind::kUnsupported;
        finishRecognition(recognition, RecognitionReason::kTruncatedHeader);
        return recognition;
    }

    if (recognition.architecture != TargetArchitecture::kX64) {
        recognition.kind = DumpKind::kUnsupported;
        finishRecognition(recognition, RecognitionReason::kUnsupportedArchitecture);
        return recognition;
    }

    std::uint32_t dumpType = 0;
    if (!readLittleEndianU32(headBytes, kOffDumpType, dumpType)) {
        recognition.kind = DumpKind::kUnsupported;
        finishRecognition(recognition, RecognitionReason::kTruncatedHeader);
        return recognition;
    }
    recognition.rawDumpType = OptionalU64::of(dumpType);
    recognition.parseAttempted = true;

    switch (dumpType) {
    case 3U:  // Dump header only
    case 4U:  // Triage / small memory dump.
        // Neither guarantees IRP/lock/process/pool data. Both have the same C-07 upper bound and therefore map to KernelSmall.
        // The original DumpType is losslessly preserved in rawDumpType; check that specific field when the report needs to distinguish them.
        recognition.kind = DumpKind::kKernelSmall;
        break;
    case 1U:  // Full memory
    case 2U:  // Kernel memory
    case 5U:  // Active memory (bitmap full).
    case 6U:  // Active kernel memory (bitmap kernel)
    case 7U:  // Automatic memory
        recognition.kind = DumpKind::kKernelMemory;
        break;
    default:
        recognition.kind = DumpKind::kUnsupported;
        finishRecognition(recognition, RecognitionReason::kUnsupportedDumpType);
        return recognition;
    }

    finishRecognition(recognition, RecognitionReason::kRecognized);
    return recognition;
}

bool recognitionIsDamagedRatherThanUnsupported(const DumpRecognition& recognition) noexcept {
    switch (recognition.reason) {
    case RecognitionReason::kEmptyFile:
    case RecognitionReason::kTooSmallForSignature:
    case RecognitionReason::kTruncatedHeader:
        return true;
    case RecognitionReason::kRecognized:
    case RecognitionReason::kUnknownSignature:
    case RecognitionReason::kUnsupportedKernelBitness:
    case RecognitionReason::kUnsupportedArchitecture:
    case RecognitionReason::kUnsupportedDumpType:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// C-03 Crash facts
// ---------------------------------------------------------------------------
const char* dumpFieldAvailabilityName(DumpFieldAvailability availability) noexcept {
    switch (availability) {
    case DumpFieldAvailability::kNotParsed: return "NotParsed";
    case DumpFieldAvailability::kNotRecorded: return "NotRecorded";
    case DumpFieldAvailability::kPresent: return "Present";
    }
    return "NotParsed";
}

DumpField DumpField::present(std::uint64_t v) noexcept {
    DumpField field;
    field.availability = DumpFieldAvailability::kPresent;
    field.value = OptionalU64::of(v);
    return field;
}

DumpField DumpField::notRecorded() noexcept {
    DumpField field;
    field.availability = DumpFieldAvailability::kNotRecorded;
    return field;
}

DumpField DumpField::notParsed() noexcept {
    return DumpField{};
}

bool DumpField::consistent() const noexcept {
    return (availability == DumpFieldAvailability::kPresent) == value.present;
}

namespace {

// zeroIsUnrecorded is explicitly provided per field with no default; whether "0" counts as a truthy
// value is a field-specific semantic, and unified handling would inevitably misclassify half the cases.
DumpField classifyU32Field(std::span<const std::uint8_t> bytes,
                           std::size_t offset,
                           bool zeroIsUnrecorded) {
    std::uint32_t raw = 0;
    if (!readLittleEndianU32(bytes, offset, raw)) {
        return DumpField::notParsed();
    }
    if (raw == kPageFillDword) {
        return DumpField::notRecorded();
    }
    if (zeroIsUnrecorded && raw == 0U) {
        return DumpField::notRecorded();
    }
    return DumpField::present(raw);
}

DumpField classifyU64Field(std::span<const std::uint8_t> bytes,
                           std::size_t offset,
                           bool zeroIsUnrecorded) {
    std::uint64_t raw = 0;
    if (!readLittleEndianU64(bytes, offset, raw)) {
        return DumpField::notParsed();
    }
    if (raw == kPageFillQword) {
        return DumpField::notRecorded();
    }
    if (zeroIsUnrecorded && raw == 0U) {
        return DumpField::notRecorded();
    }
    return DumpField::present(raw);
}

// Unified traversal point for all fields. New fields must be added here simultaneously, otherwise the count will silently miss items.
std::array<const DumpField*, 12> allFields(const BugCheckFacts& facts) noexcept {
    return {&facts.code,
            &facts.parameters[0],
            &facts.parameters[1],
            &facts.parameters[2],
            &facts.parameters[3],
            &facts.targetOsMajor,
            &facts.targetOsBuild,
            &facts.processorCount,
            &facts.crashTimeUtc100ns,
            &facts.uptime100ns,
            &facts.writerStatus,
            &facts.directoryTableBase};
}

std::size_t countFields(const BugCheckFacts& facts, DumpFieldAvailability wanted) noexcept {
    std::size_t count = 0;
    for (const DumpField* field : allFields(facts)) {
        if (field->availability == wanted) {
            ++count;
        }
    }
    return count;
}

void setAllFields(BugCheckFacts& facts, const DumpField& value) {
    facts.code = value;
    for (DumpField& parameter : facts.parameters) {
        parameter = value;
    }
    facts.targetOsMajor = value;
    facts.targetOsBuild = value;
    facts.processorCount = value;
    facts.crashTimeUtc100ns = value;
    facts.uptime100ns = value;
    facts.writerStatus = value;
    facts.directoryTableBase = value;
}

} // namespace

std::size_t BugCheckFacts::fieldCount() const noexcept { return allFields(*this).size(); }

std::size_t BugCheckFacts::presentFieldCount() const noexcept {
    return countFields(*this, DumpFieldAvailability::kPresent);
}

std::size_t BugCheckFacts::notRecordedFieldCount() const noexcept {
    return countFields(*this, DumpFieldAvailability::kNotRecorded);
}

std::size_t BugCheckFacts::notParsedFieldCount() const noexcept {
    return countFields(*this, DumpFieldAvailability::kNotParsed);
}

bool BugCheckFacts::hasAnyFact() const noexcept { return presentFieldCount() > 0U; }

BugCheckFacts extractBugCheckFacts(const DumpRecognition& recognition,
                                   std::span<const std::uint8_t> headBytes) {
    BugCheckFacts facts;
    facts.dumpKind = recognition.kind;
    facts.bytesProvided = OptionalU64::of(static_cast<std::uint64_t>(headBytes.size()));
    facts.fileSizeDeclared = recognition.fileSize;
    facts.windowShorterThanFile =
        recognition.fileSize.present &&
        static_cast<std::uint64_t>(headBytes.size()) < recognition.fileSize.value;

    switch (recognition.kind) {
    case DumpKind::kNotADump:
        // Parsing was never executed. All fields are set to NotParsed — meaning 'unknown if present', not 'absent'.
        setAllFields(facts, DumpField::notParsed());
        facts.outcome = CollectionOutcome::notCollected();
        facts.outcome.message = "dump.facts.not_a_dump";
        return facts;
    case DumpKind::kUnsupported:
        setAllFields(facts, DumpField::notParsed());
        facts.outcome = CollectionOutcome::failure(CollectionStatus::kUnsupported,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.unsupported_format");
        return facts;
    case DumpKind::kUserMinidump:
        // The user-mode minidump format does not contain a bugcheck field. This is 'NotRecorded'
        // (known to be absent), which is distinct from 'NotParsed' (unknown presence).
        setAllFields(facts, DumpField::notRecorded());
        facts.outcome = CollectionOutcome::failure(CollectionStatus::kUnsupported,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.user_minidump_has_no_bugcheck");
        return facts;
    case DumpKind::kKernelSmall:
    case DumpKind::kKernelMemory:
        break;
    }

    // Note: Stop code 0 does not exist in Windows; reading 0 indicates this field was not filled by the writer.
    // Handle it as missing rather than reporting a fake 0x0—this is the inverse of the trap highlighted in C-03.
    facts.code = classifyU32Field(headBytes, kOffBugCheckCode, true);
    // Stop code parameter 0 is a completely valid value (many stop codes use only the first one or two
    // parameters). Therefore, zeroIsUnrecorded=false: if the value is truly 0, report it as Present(0).
    for (std::size_t index = 0; index < facts.parameters.size(); ++index) {
        facts.parameters[index] =
            classifyU64Field(headBytes, kOffBugCheckParameters + index * 8U, false);
    }
    facts.targetOsMajor = classifyU32Field(headBytes, kOffMajorVersion, true);
    facts.targetOsBuild = classifyU32Field(headBytes, kOffMinorVersion, true);
    facts.processorCount = classifyU32Field(headBytes, kOffNumberProcessors, true);
    // FILETIME 0 corresponds to 1601, not the actual crash time; uptime 0 similarly indicates the field is unset.
    facts.crashTimeUtc100ns = classifyU64Field(headBytes, kOffSystemTime, true);
    facts.uptime100ns = classifyU64Field(headBytes, kOffSystemUpTime, true);
    // A writer status of 0 indicates "write normal"; this is a meaningful value and must never be treated as missing.
    facts.writerStatus = classifyU32Field(headBytes, kOffWriterStatus, false);
    facts.directoryTableBase = classifyU64Field(headBytes, kOffDirectoryTableBase, true);

    const std::size_t kNotParsed = facts.notParsedFieldCount();
    if (facts.presentFieldCount() == 0U && kNotParsed == facts.fieldCount()) {
        facts.outcome = CollectionOutcome::failure(CollectionStatus::kError,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.nothing_readable");
    } else if (kNotParsed > 0U) {
        facts.outcome = CollectionOutcome::failure(CollectionStatus::kPartial,
                                                   kRecognitionDomain,
                                                   static_cast<std::uint64_t>(recognition.reason),
                                                   "dump.facts.window_or_file_truncated");
    } else {
        facts.outcome = CollectionOutcome::success();
        facts.outcome.message = "dump.facts.ok";
    }
    return facts;
}

// ---------------------------------------------------------------------------
// C-04 Symbol exact match
// ---------------------------------------------------------------------------
const char* symbolMatchName(SymbolMatch match) noexcept {
    switch (match) {
    case SymbolMatch::kNotAttempted: return "NotAttempted";
    case SymbolMatch::kAbsent: return "Absent";
    case SymbolMatch::kWrongVersion: return "WrongVersion";
    case SymbolMatch::kMatched: return "Matched";
    }
    return "NotAttempted";
}

const char* symbolCacheSourceName(SymbolCacheSource source) noexcept {
    switch (source) {
    case SymbolCacheSource::kUnknown: return "Unknown";
    case SymbolCacheSource::kNotLoaded: return "NotLoaded";
    case SymbolCacheSource::kLocalDirectory: return "LocalDirectory";
    case SymbolCacheSource::kLocalCache: return "LocalCache";
    case SymbolCacheSource::kSymbolServer: return "SymbolServer";
    case SymbolCacheSource::kDumpEmbedded: return "DumpEmbedded";
    }
    return "Unknown";
}

const char* symbolLoadAttemptName(SymbolLoadAttempt attempt) noexcept {
    switch (attempt) {
    case SymbolLoadAttempt::kNotAttempted: return "NotAttempted";
    case SymbolLoadAttempt::kFileNotFound: return "FileNotFound";
    case SymbolLoadAttempt::kLoadFailed: return "LoadFailed";
    case SymbolLoadAttempt::kFileLoaded: return "FileLoaded";
    }
    return "NotAttempted";
}

bool samePdbIdentity(const PdbIdentity& a, const PdbIdentity& b) noexcept {
    // If either side lacks an identifier, identity cannot be proven. Two empty identifiers do not count as 'identical'—that
    // 'default-to-safe' approach would incorrectly assign function names to modules without CodeView records.
    if (!a.present || !b.present) {
        return false;
    }
    return a.age == b.age && a.guid == b.guid;
}

SymbolMatch deriveSymbolMatch(SymbolLoadAttempt attempt,
                              const PdbIdentity& wanted,
                              const PdbIdentity& loaded) noexcept {
    switch (attempt) {
    case SymbolLoadAttempt::kNotAttempted:
        return SymbolMatch::kNotAttempted;
    case SymbolLoadAttempt::kFileNotFound:
    case SymbolLoadAttempt::kLoadFailed:
        // Both fall to Absent (SymbolMatch only has the four values specified), but the distinction is determined by
        // ModuleSymbolState::attempt and outcome are retained; the report can describe them separately.
        return SymbolMatch::kAbsent;
    case SymbolLoadAttempt::kFileLoaded:
        break;
    }
    if (samePdbIdentity(wanted, loaded)) {
        return SymbolMatch::kMatched;
    }
    // Loaded but version mismatch, or unable to prove version consistency (either side lacks GUID/Age).
    // Both cases yield the exact same answer regarding 'whether a function name/line number can be reported': no.
    return SymbolMatch::kWrongVersion;
}

bool mayReportFunctionName(const ModuleSymbolState& state) noexcept {
    return state.match == SymbolMatch::kMatched;
}

bool mayReportSourceLine(const ModuleSymbolState& state) noexcept {
    return state.match == SymbolMatch::kMatched;
}

const char* symbolAttributionName(SymbolAttribution attribution) noexcept {
    switch (attribution) {
    case SymbolAttribution::kModuleOnly: return "ModuleOnly";
    case SymbolAttribution::kModulePlusOffset: return "ModulePlusOffset";
    case SymbolAttribution::kFunctionPlusOffset: return "FunctionPlusOffset";
    case SymbolAttribution::kFunctionAndSourceLine: return "FunctionAndSourceLine";
    }
    return "ModuleOnly";
}

SymbolAttribution allowedAttribution(const ModuleSymbolState& state,
                                     bool moduleBaseKnown) noexcept {
    if (state.match == SymbolMatch::kMatched) {
        return SymbolAttribution::kFunctionAndSourceLine;
    }
    // Erroneous version / No signature / Never tested: At most 'Module + Offset'. Without a base address, even the offset cannot be calculated.
    return moduleBaseKnown ? SymbolAttribution::kModulePlusOffset : SymbolAttribution::kModuleOnly;
}

const char* symbolServerDecisionName(SymbolServerDecision decision) noexcept {
    switch (decision) {
    case SymbolServerDecision::kAllow: return "Allow";
    case SymbolServerDecision::kRejectNotEnabled: return "RejectNotEnabled";
    case SymbolServerDecision::kRejectNotCancellable: return "RejectNotCancellable";
    case SymbolServerDecision::kRejectNoTimeBudget: return "RejectNoTimeBudget";
    }
    return "RejectNotEnabled";
}

SymbolServerDecision decideSymbolServerFetch(const SymbolServerPolicy& policy) noexcept {
    if (!policy.userEnabled) {
        return SymbolServerDecision::kRejectNotEnabled;
    }
    if (!policy.cancellable) {
        return SymbolServerDecision::kRejectNotCancellable;
    }
    // 'Finite time' must be a true time budget: limiting bytes or pages is
    // insufficient, as a symbol server stuck in connect() consumes no bytes.
    if (!policy.budget.maxDurationNanos.present || policy.budget.maxDurationNanos.value == 0U) {
        return SymbolServerDecision::kRejectNoTimeBudget;
    }
    return SymbolServerDecision::kAllow;
}

// ---------------------------------------------------------------------------
// C-05 Stack and modules
// ---------------------------------------------------------------------------
const char* unwindStateName(UnwindState state) noexcept {
    switch (state) {
    case UnwindState::kTruncatedNoData: return "TruncatedNoData";
    case UnwindState::kTruncatedCorrupt: return "TruncatedCorrupt";
    case UnwindState::kGuessed: return "Guessed";
    case UnwindState::kUnwound: return "Unwound";
    }
    return "TruncatedNoData";
}

bool unwindStateIsTerminal(UnwindState state) noexcept {
    return state == UnwindState::kTruncatedNoData || state == UnwindState::kTruncatedCorrupt;
}

bool unwindStateIsTrustworthy(UnwindState state) noexcept {
    return state == UnwindState::kUnwound;
}

std::size_t StackTrace::unwoundCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (frame.unwindState == UnwindState::kUnwound) {
            ++count;
        }
    }
    return count;
}

std::size_t StackTrace::guessedCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (frame.unwindState == UnwindState::kGuessed) {
            ++count;
        }
    }
    return count;
}

std::size_t StackTrace::truncatedCount() const noexcept {
    std::size_t count = 0;
    for (const StackFrame& frame : frames) {
        if (unwindStateIsTerminal(frame.unwindState)) {
            ++count;
        }
    }
    return count;
}

const char* stackValidationName(StackValidation validation) noexcept {
    switch (validation) {
    case StackValidation::kOk: return "Ok";
    case StackValidation::kFramesAfterTruncation: return "FramesAfterTruncation";
    case StackValidation::kFunctionNameWithoutMatchedSymbols:
        return "FunctionNameWithoutMatchedSymbols";
    case StackValidation::kSourceLineWithoutMatchedSymbols:
        return "SourceLineWithoutMatchedSymbols";
    case StackValidation::kCandidatesWithoutMatchedSymbols:
        return "CandidatesWithoutMatchedSymbols";
    case StackValidation::kAmbiguityCollapsed: return "AmbiguityCollapsed";
    case StackValidation::kIncompleteArgumentsClaimedComplete:
        return "IncompleteArgumentsClaimedComplete";
    }
    return "Ok";
}

StackValidation validateStackTrace(const StackTrace& trace) noexcept {
    bool truncationSeen = false;
    for (const StackFrame& frame : trace.frames) {
        // Boundary check first: Any frame appearing after truncation means the guessed frame was appended to the unwind result.
        if (truncationSeen) {
            return StackValidation::kFramesAfterTruncation;
        }
        // Function offset and function name are treated equally: if the function cannot be resolved, the concept of 'offset within function' does not exist.
        if ((!frame.functionName.empty() || frame.functionOffset.present) &&
            frame.symbolMatch != SymbolMatch::kMatched) {
            return StackValidation::kFunctionNameWithoutMatchedSymbols;
        }
        if ((!frame.sourceFile.empty() || frame.sourceLine.present) &&
            frame.symbolMatch != SymbolMatch::kMatched) {
            return StackValidation::kSourceLineWithoutMatchedSymbols;
        }
        // Candidate function names are also rendered in the UI, just pluralized. Names resolved from a mismatched PDB
        // do not become valid information by appending "Candidate" — the C-04 red line applies equally to plural forms.
        if (!frame.candidateFunctions.empty() && frame.symbolMatch != SymbolMatch::kMatched) {
            return StackValidation::kCandidatesWithoutMatchedSymbols;
        }
        if (frame.attributionAmbiguous && frame.candidateFunctions.size() < 2U) {
            // Marked as ambiguous but only one candidate remains = collapsing the ambiguity into a definite answer.
            return StackValidation::kAmbiguityCollapsed;
        }
        if (frame.argsComplete) {
            for (const OptionalU64& argument : frame.availableArgs) {
                if (!argument.present) {
                    return StackValidation::kIncompleteArgumentsClaimedComplete;
                }
            }
        }
        if (unwindStateIsTerminal(frame.unwindState)) {
            truncationSeen = true;
        }
    }
    return StackValidation::kOk;
}

// ---------------------------------------------------------------------------
// C-06 Suspicious module explanation
// ---------------------------------------------------------------------------
const char* moduleEvidenceKindName(ModuleEvidenceKind kind) noexcept {
    switch (kind) {
    case ModuleEvidenceKind::kOnStack: return "OnStack";
    case ModuleEvidenceKind::kFaultingIpModule: return "FaultingIpModule";
    case ModuleEvidenceKind::kVerifierReported: return "VerifierReported";
    }
    return "OnStack";
}

std::size_t ModuleEvidenceGroup::evidenceCount() const noexcept {
    return onStack.size() + faultingIp.size() + verifier.size();
}

bool isWellKnownSystemModuleName(std::string_view moduleName) noexcept {
    // The list is hardcoded in the implementation, not read from the dump. A hit only reduces 'clue' eligibility, not the verdict.
    static constexpr std::string_view kNames[] = {
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe",
        "hal.dll",      "halmacpi.dll", "halacpi.dll",  "ntdll.dll",
        "win32k.sys",   "win32kbase.sys", "win32kfull.sys", "ci.dll",
        "kernel32.dll", "kernelbase.dll",
    };
    const std::string_view kBase = baseNameOf(moduleName);
    for (const std::string_view kCandidate : kNames) {
        if (asciiEqualsIgnoreCase(kBase, kCandidate)) {
            return true;
        }
    }
    return false;
}

const char* investigationLeadName(InvestigationLead lead) noexcept {
    switch (lead) {
    case InvestigationLead::kUndetermined: return "Undetermined";
    case InvestigationLead::kSystemModuleOnly: return "SystemModuleOnly";
    case InvestigationLead::kStackPresenceOnly: return "StackPresenceOnly";
    case InvestigationLead::kFaultingIpAttributed: return "FaultingIpAttributed";
    case InvestigationLead::kVerifierNamed: return "VerifierNamed";
    }
    return "Undetermined";
}

namespace {

// Prerequisite for Faulting IP evidence. Normally, the faulting IP comes from the trap
// frame/context record, making ipFromContextRecord true regardless of unwind quality; conversely,
// if this evidence is read from an unwind frame, that frame must have actually been unwound.
// The frame has been marked as TruncatedCorrupt (self-contradictory data), yet a third-party driver is still implicated based on
// this. Drawing conclusions from data you don't trust violates C-06, which requires stating "Unable to determine" in such cases.
bool faultingIpEvidenceIsFounded(const ModuleEvidenceItem& item) noexcept {
    return item.ipFromContextRecord || unwindStateIsTrustworthy(item.frameUnwindState);
}

} // namespace

InvestigationLead classifyLead(const ModuleEvidenceGroup& group) noexcept {
    // No group key = no identity for this group. groupModuleEvidence produces such a group for an
    // empty module name, but stating that 'a module with no name is a searchable clue' is meaningless.
    if (group.moduleKey.empty()) {
        return InvestigationLead::kUndetermined;
    }
    // The verifier is the only evidence "named by the system itself"; its strength differs from the other two categories, so check it first.
    if (!group.verifier.empty()) {
        return InvestigationLead::kVerifierNamed;
    }
    if (!group.faultingIp.empty()) {
        // A fault IP within ntoskrnl/hal is typical of delayed memory corruption, not the root cause.
        if (group.isWellKnownSystemModule) {
            return InvestigationLead::kSystemModuleOnly;
        }
        for (const ModuleEvidenceItem& item : group.faultingIp) {
            if (faultingIpEvidenceIsFounded(item)) {
                return InvestigationLead::kFaultingIpAttributed;
            }
        }
        // Fault IP evidence is insufficient on its own: do not upgrade it, but do not discard this group either. Continue
        // evaluating based on stack evidence; treat it as a weak lead if it is weak, or indeterminate if it is indeterminate.
    }
    if (!group.onStack.empty()) {
        if (group.isWellKnownSystemModule) {
            return InvestigationLead::kSystemModuleOnly;
        }
        // Modules appearing only in stack-scan-guessed frames do not constitute a lead: Guessed is not an
        // unwind result, and residual return addresses on the stack may originate from calls long ago.
        for (const ModuleEvidenceItem& item : group.onStack) {
            if (unwindStateIsTrustworthy(item.frameUnwindState)) {
                return InvestigationLead::kStackPresenceOnly;
            }
        }
        return InvestigationLead::kUndetermined;
    }
    return InvestigationLead::kUndetermined;
}

std::vector<ModuleEvidenceGroup> groupModuleEvidence(std::vector<ModuleEvidenceItem> items) {
    // O(n log n): Compute keys once, sort indices by keys, then merge in a final pass.
    // No pairwise comparisons — the previous real-world test in another module caught an O(n^2) case taking 13/15 seconds.
    std::vector<std::pair<std::string, std::size_t>> keyed;
    keyed.reserve(items.size());
    for (std::size_t index = 0; index < items.size(); ++index) {
        keyed.emplace_back(asciiLower(items[index].moduleName), index);
    }
    std::stable_sort(keyed.begin(), keyed.end(),
                     [](const std::pair<std::string, std::size_t>& a,
                        const std::pair<std::string, std::size_t>& b) {
                         return a.first < b.first;
                     });

    std::vector<ModuleEvidenceGroup> groups;
    for (std::size_t position = 0; position < keyed.size(); ++position) {
        const std::string& key = keyed[position].first;
        if (groups.empty() || groups.back().moduleKey != key) {
            ModuleEvidenceGroup group;
            group.moduleKey = key;
            // Display names use the original casing from their first occurrence; no normalization is applied.
            group.moduleName = items[keyed[position].second].moduleName;
            group.isWellKnownSystemModule = isWellKnownSystemModuleName(group.moduleName);
            groups.push_back(std::move(group));
        }
        ModuleEvidenceItem& item = items[keyed[position].second];
        ModuleEvidenceGroup& target = groups.back();
        switch (item.kind) {
        case ModuleEvidenceKind::kOnStack:
            target.onStack.push_back(std::move(item));
            break;
        case ModuleEvidenceKind::kFaultingIpModule:
            target.faultingIp.push_back(std::move(item));
            break;
        case ModuleEvidenceKind::kVerifierReported:
            target.verifier.push_back(std::move(item));
            break;
        }
    }
    return groups;
}

SuspectReport buildSuspectReport(std::vector<ModuleEvidenceGroup> groups,
                                 const CollectionOutcome& stackOutcome) {
    SuspectReport report;
    report.leads.reserve(groups.size());

    // No observation means no conclusion. Even if the caller injects a group, it is uniformly downgraded
    // to Undetermined: 'failing to gather data to derive a conclusion' is a definitive red line.
    const bool kHaveObservation = statusCarriesObservation(stackOutcome.status);
    for (ModuleEvidenceGroup& group : groups) {
        SuspectLead lead;
        lead.lead = kHaveObservation ? classifyLead(group) : InvestigationLead::kUndetermined;
        lead.group = std::move(group);
        report.leads.push_back(std::move(lead));
    }

    if (!kHaveObservation) {
        report.conclusion = AnalysisConclusion::kNoEvidence;
        report.limitationKeys.emplace_back("dump.suspect.no_stack_observation");
        return report;
    }

    bool anyActionable = false;
    bool anySystemOnly = false;
    bool anyStackOnly = false;
    for (const SuspectLead& lead : report.leads) {
        switch (lead.lead) {
        case InvestigationLead::kVerifierNamed:
        case InvestigationLead::kFaultingIpAttributed:
            anyActionable = true;
            break;
        case InvestigationLead::kSystemModuleOnly:
            anySystemOnly = true;
            break;
        case InvestigationLead::kStackPresenceOnly:
            anyStackOnly = true;
            break;
        case InvestigationLead::kUndetermined:
            break;
        }
    }

    // This function never returns NoDifferenceObserved: a dump is only generated when a crash has occurred;
    // 'No Difference Observed' is meaningless here and would be misinterpreted as 'the machine is fine'.
    report.conclusion = anyActionable ? AnalysisConclusion::kDifferenceObserved
                                      : AnalysisConclusion::kIndeterminate;

    if (report.leads.empty()) {
        report.limitationKeys.emplace_back("dump.suspect.no_module_evidence");
    }
    if (!anyActionable) {
        report.limitationKeys.emplace_back("dump.suspect.insufficient_evidence");
    }
    if (anySystemOnly) {
        report.limitationKeys.emplace_back("dump.suspect.system_module_only");
    }
    if (anyStackOnly) {
        report.limitationKeys.emplace_back("dump.suspect.stack_presence_only");
    }
    if (stackOutcome.status == CollectionStatus::kPartial) {
        report.limitationKeys.emplace_back("dump.suspect.stack_partial");
    }
    return report;
}

// ---------------------------------------------------------------------------
// C-07 Missing memory boundary
// ---------------------------------------------------------------------------
const char* contentCategoryName(ContentCategory category) noexcept {
    switch (category) {
    case ContentCategory::kIrpObjects: return "IrpObjects";
    case ContentCategory::kLockObjects: return "LockObjects";
    case ContentCategory::kFullProcessSpace: return "FullProcessSpace";
    case ContentCategory::kPoolMemory: return "PoolMemory";
    case ContentCategory::kKernelModuleList: return "KernelModuleList";
    case ContentCategory::kThreadStacks: return "ThreadStacks";
    case ContentCategory::kPhysicalMemory: return "PhysicalMemory";
    }
    return "IrpObjects";
}

const char* contentPresenceName(ContentPresence presence) noexcept {
    switch (presence) {
    case ContentPresence::kUnknown: return "Unknown";
    case ContentPresence::kNotIncluded: return "NotIncluded";
    case ContentPresence::kNotParsable: return "NotParsable";
    case ContentPresence::kIncluded: return "Included";
    }
    return "Unknown";
}

ContentPresence DumpContentAvailability::presenceOf(ContentCategory category) const noexcept {
    const auto kIndex = static_cast<std::size_t>(category);
    if (kIndex >= presence.size()) {
        return ContentPresence::kUnknown;
    }
    return presence[kIndex];
}

void DumpContentAvailability::set(ContentCategory category, ContentPresence value) noexcept {
    const auto kIndex = static_cast<std::size_t>(category);
    if (kIndex < presence.size()) {
        presence[kIndex] = value;
    }
}

DumpContentAvailability deriveAvailabilityFromKind(DumpKind kind) noexcept {
    DumpContentAvailability availability;  // Start with all Unknown.
    switch (kind) {
    case DumpKind::kKernelSmall:
        // The small dump format does not include these four categories, so it is certain that the dump does not contain them.
        availability.set(ContentCategory::kIrpObjects, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kLockObjects, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kFullProcessSpace, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kPoolMemory, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kPhysicalMemory, ContentPresence::kNotIncluded);
        // The module table and crash thread stack may be in the triage block, but if DumpType=3 (header only), they are absent.
        // Cannot infer from the type, so leave as Unknown and confirm via actual parsing—never pre-write Included.
        break;
    case DumpKind::kKernelMemory:
        // Full, kernel, and active memory dumps differ significantly (DumpType 1/2/5/6/7 have been merged into this class);
        // one cannot deduce any 'definitely included' item solely from the kind. All Unknown is the only honest answer.
        break;
    case DumpKind::kUserMinidump:
        // Kernel objects are not present in user-mode dumps.
        availability.set(ContentCategory::kIrpObjects, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kLockObjects, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kPoolMemory, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kKernelModuleList, ContentPresence::kNotIncluded);
        availability.set(ContentCategory::kPhysicalMemory, ContentPresence::kNotIncluded);
        // Full process space depends on MiniDumpWithFullMemory; thread stack depends on the write option — Unknown.
        break;
    case DumpKind::kNotADump:
    case DumpKind::kUnsupported:
        // Unknown. Never claim "not present" just because parsing failed.
        break;
    }
    return availability;
}

const char* contentQueryResultName(ContentQueryResult result) noexcept {
    switch (result) {
    case ContentQueryResult::kAvailable: return "Available";
    case ContentQueryResult::kNotIncludedInDump: return "NotIncludedInDump";
    case ContentQueryResult::kNotParsableHere: return "NotParsableHere";
    case ContentQueryResult::kUnknownAvailability: return "UnknownAvailability";
    }
    return "UnknownAvailability";
}

ContentQueryResult queryContent(const DumpContentAvailability& availability,
                               ContentCategory category) noexcept {
    switch (availability.presenceOf(category)) {
    case ContentPresence::kIncluded: return ContentQueryResult::kAvailable;
    case ContentPresence::kNotIncluded: return ContentQueryResult::kNotIncludedInDump;
    case ContentPresence::kNotParsable: return ContentQueryResult::kNotParsableHere;
    case ContentPresence::kUnknown: return ContentQueryResult::kUnknownAvailability;
    }
    return ContentQueryResult::kUnknownAvailability;
}

bool supplementDisclosed(const ExternalSupplement& supplement) noexcept {
    if (!supplement.used) {
        return true;  // No external data used, nothing to declare.
    }
    return !supplement.disclosureKey.empty() && !supplement.source.collectorId.empty() &&
           supplement.source.origin == SourceOrigin::kExternalFile;
}

// ---------------------------------------------------------------------------
// C-08: Timeout, cancellation, and isolation.
// ---------------------------------------------------------------------------
const char* helperStateName(HelperState state) noexcept {
    switch (state) {
    case HelperState::kNotStarted: return "NotStarted";
    case HelperState::kStarting: return "Starting";
    case HelperState::kReady: return "Ready";
    case HelperState::kBusy: return "Busy";
    case HelperState::kStalled: return "Stalled";
    case HelperState::kDisconnected: return "Disconnected";
    case HelperState::kCancelling: return "Cancelling";
    case HelperState::kExited: return "Exited";
    case HelperState::kFailed: return "Failed";
    }
    return "NotStarted";
}

bool helperStateIsTerminal(HelperState state) noexcept {
    return state == HelperState::kExited || state == HelperState::kFailed;
}

bool helperStateSettled(HelperState state) noexcept {
    // Use a whitelist-style check rather than '!= these values': when adding a new state to HelperState in
    // the future, the default must fall into the 'unsettled' category, not incorrectly become 'settled'.
    switch (state) {
    case HelperState::kReady:
    case HelperState::kExited:
        return true;
    case HelperState::kNotStarted:
    case HelperState::kStarting:
    case HelperState::kBusy:
    case HelperState::kStalled:
    case HelperState::kDisconnected:
    case HelperState::kCancelling:
    case HelperState::kFailed:
        return false;
    }
    return false;
}

namespace {

// Note: When the helper is unsettled, the report must specify which type of 'unsettled' state it is.
const char* helperUnsettledKey(HelperState state) noexcept {
    switch (state) {
    case HelperState::kNotStarted: return "dump.helper.not_started";
    case HelperState::kStarting:
    case HelperState::kBusy: return "dump.helper.still_running";
    case HelperState::kCancelling: return "dump.helper.cancelling";
    case HelperState::kStalled: return "dump.helper.stalled";
    case HelperState::kDisconnected: return "dump.helper.disconnected";
    case HelperState::kFailed: return "dump.helper.failed";
    case HelperState::kReady:
    case HelperState::kExited: break;
    }
    return "dump.helper.not_settled";
}

} // namespace

const char* terminateDecisionName(TerminateDecision decision) noexcept {
    switch (decision) {
    case TerminateDecision::kAllow: return "Allow";
    case TerminateDecision::kRejectNotOwned: return "RejectNotOwned";
    case TerminateDecision::kRejectOwnerMismatch: return "RejectOwnerMismatch";
    case TerminateDecision::kRejectNoHelperIdentity: return "RejectNoHelperIdentity";
    }
    return "RejectNotOwned";
}

TerminateDecision decideHelperTermination(const HelperOwnership& helper,
                                          std::string_view requestingModuleId) noexcept {
    // Fixed order: first check if 'started by this module', then verify owner, finally check for a specific target.
    if (!helper.startedByThisModule) {
        return TerminateDecision::kRejectNotOwned;
    }
    if (helper.ownerModuleId.empty() || requestingModuleId.empty() ||
        helper.ownerModuleId != requestingModuleId) {
        return TerminateDecision::kRejectOwnerMismatch;
    }
    if (helper.helperId.empty()) {
        // Killing by PID without an instance ID — PIDs are reused and may terminate someone else's debugger.
        return TerminateDecision::kRejectNoHelperIdentity;
    }
    return TerminateDecision::kAllow;
}

InterruptedResult buildInterruptedResult(BudgetStop stop,
                                         HelperState helperState,
                                         const ScanBudget& budget,
                                         CoverageAccount coverage,
                                         bool haveAnyResult) {
    InterruptedResult result;
    result.stop = stop;
    result.helperState = helperState;
    result.coverage = std::move(coverage);
    applyStopToCoverage(stop, budget, result.coverage);
    result.outcome = outcomeForStop(stop);
    result.partialResultsRetained = haveAnyResult;

    if (stop != BudgetStop::kContinue) {
        result.interruptionKeys.emplace_back(std::string("dump.interrupt.") +
                                             budgetStopName(stop));
    }

    switch (helperState) {
    case HelperState::kStalled:
        result.outcome.status = CollectionStatus::kTimeout;
        result.outcome.message = "dump.helper.stalled";
        result.interruptionKeys.emplace_back("dump.helper.stalled");
        break;
    case HelperState::kDisconnected:
        result.outcome.status = CollectionStatus::kError;
        result.outcome.message = "dump.helper.disconnected";
        result.interruptionKeys.emplace_back("dump.helper.disconnected");
        break;
    case HelperState::kFailed:
        result.outcome.status = CollectionStatus::kError;
        result.outcome.message = "dump.helper.failed";
        result.interruptionKeys.emplace_back("dump.helper.failed");
        break;
    case HelperState::kCancelling:
        // Still finalizing; do not falsely report 'cleaned'.
        result.interruptionKeys.emplace_back("dump.helper.cancelling");
        break;
    case HelperState::kNotStarted:
        // Never started: The 0 results in this round do not mean "there
        // is truly nothing here," but rather "no one ever checked."
        result.interruptionKeys.emplace_back("dump.helper.not_started");
        break;
    case HelperState::kStarting:
    case HelperState::kBusy:
        // Still running: the current result set is inherently incomplete.
        result.interruptionKeys.emplace_back("dump.helper.still_running");
        break;
    case HelperState::kReady:
    case HelperState::kExited:
        break;
    }

    if (!haveAnyResult) {
        // A 'nothing collected' interruption must never report Partial: statusCarriesObservation
        // allows it through, enabling downstream components to derive a positive conclusion.
        switch (stop) {
        case BudgetStop::kContinue:
            // Not interrupted and truly empty — this is a "correct empty set"; keep Success.
            break;
        case BudgetStop::kCancelled:
            if (result.outcome.status == CollectionStatus::kPartial) {
                result.outcome.status = CollectionStatus::kNotCollected;
                result.outcome.message = "dump.interrupt.cancelled_before_any_result";
            }
            break;
        case BudgetStop::kTimeExhausted:
            if (result.outcome.status == CollectionStatus::kPartial) {
                result.outcome.status = CollectionStatus::kTimeout;
                result.outcome.message = "dump.interrupt.timeout_before_any_result";
            }
            break;
        case BudgetStop::kBytesExhausted:
        case BudgetStop::kPagesExhausted:
        case BudgetStop::kItemsExhausted:
            if (result.outcome.status == CollectionStatus::kPartial) {
                result.outcome.status = CollectionStatus::kError;
                result.outcome.message = "dump.interrupt.budget_before_any_result";
            }
            break;
        }
        if (stop != BudgetStop::kContinue) {
            result.interruptionKeys.emplace_back("dump.interrupt.no_partial_results");
        }
    }

    // helperState represents a second dimension independent of stop. stop==Continue only indicates that the budget was not
    // exhausted; it provides no information on whether the helper actually ran. Reporting Success in any of the NotStarted,
    // Starting, Busy, or Cancelling states allows downstream statusCarriesObservation to pass, causing deriveConclusion to
    // output "No differences found"—a transition from "never collected" to "normal," violating the C-08 red line.
    // Only downgrade, never upgrade: more severe conclusions already set to Timeout/Error/NotCollected remain unchanged.
    if (!helperStateSettled(helperState)) {
        if (result.outcome.status == CollectionStatus::kSuccess) {
            result.outcome.status = haveAnyResult ? CollectionStatus::kPartial
                                                  : CollectionStatus::kNotCollected;
            result.outcome.message = helperUnsettledKey(helperState);
        } else if (result.outcome.status == CollectionStatus::kPartial && !haveAnyResult) {
            result.outcome.status = CollectionStatus::kNotCollected;
            result.outcome.message = helperUnsettledKey(helperState);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// C-09: Untrusted paths and output.
// ---------------------------------------------------------------------------
std::string escapeForReport(std::string_view untrusted) {
    std::string out;
    out.reserve(untrusted.size() + untrusted.size() / 4U + 8U);
    for (const char kRaw : untrusted) {
        const auto kByte = static_cast<unsigned char>(kRaw);
        if (isControlByte(kByte)) {
            // Newlines, tabs, or NUL characters in module names, paths, or symbol names are inherently anomalous inputs:
            // Always replace with the decimal numeric reference for U+FFFD (pure ASCII output, preserving report structure).
            out += "&#65533;";
            continue;
        }
        switch (kByte) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default:
            // Bytes >= 0x80 are passed through transparently without breaking UTF-8 sequences.
            out.push_back(kRaw);
            break;
        }
    }
    return out;
}

std::string sanitizeForPlainTextField(std::string_view untrusted) {
    std::string out;
    out.reserve(untrusted.size());
    for (const char kRaw : untrusted) {
        const auto kByte = static_cast<unsigned char>(kRaw);
        // Plain-text reports use tabs for columns and newlines for rows, so control characters within fields can disrupt the
        // structure seen by reviewers. This is not an injection, but it is equally misleading; replace all such characters with '?'.
        out.push_back(isControlByte(kByte) ? '?' : kRaw);
    }
    return out;
}

namespace {

// The whitelist requires **full commands**, not prefixes, and excludes any appendable parameters.
constexpr std::string_view kAllowedCommands[] = {
    ".bugcheck",
    "lm",
    "k",
    "vertarget",
    ".time",
};

constexpr std::size_t kMaxCommandBytes = 64U;
constexpr std::size_t kMaxPathBytes = 32767U;

bool isShellMetacharacter(unsigned char byte) noexcept {
    switch (byte) {
    case ';': case '|': case '&': case '<': case '>': case '$': case '`':
    case '"': case '\'': case '\\': case '(': case ')': case '{': case '}':
    case '[': case ']': case '!': case '*': case '?': case '^': case '%':
        return true;
    default:
        return false;
    }
}

} // namespace

std::span<const std::string_view> allowedAnalysisCommands() noexcept {
    return std::span<const std::string_view>(kAllowedCommands,
                                             sizeof(kAllowedCommands) / sizeof(kAllowedCommands[0]));
}

bool isSafeAnalysisCommand(std::string_view command) noexcept {
    for (const std::string_view kAllowed : kAllowedCommands) {
        if (command == kAllowed) {
            return true;
        }
    }
    return false;
}

const char* commandRejectionName(CommandRejection rejection) noexcept {
    switch (rejection) {
    case CommandRejection::kAccepted: return "Accepted";
    case CommandRejection::kEmpty: return "Empty";
    case CommandRejection::kTooLong: return "TooLong";
    case CommandRejection::kContainsControlCharacter: return "ContainsControlCharacter";
    case CommandRejection::kContainsShellMetacharacter: return "ContainsShellMetacharacter";
    case CommandRejection::kNotInWhitelist: return "NotInWhitelist";
    }
    return "NotInWhitelist";
}

CommandRejection classifyCommandRequest(std::string_view request) noexcept {
    if (request.empty()) {
        return CommandRejection::kEmpty;
    }
    if (request.size() > kMaxCommandBytes) {
        return CommandRejection::kTooLong;
    }
    for (const char kRaw : request) {
        if (isControlByte(static_cast<unsigned char>(kRaw))) {
            return CommandRejection::kContainsControlCharacter;
        }
    }
    for (const char kRaw : request) {
        if (isShellMetacharacter(static_cast<unsigned char>(kRaw))) {
            return CommandRejection::kContainsShellMetacharacter;
        }
    }
    if (!isSafeAnalysisCommand(request)) {
        return CommandRejection::kNotInWhitelist;
    }
    return CommandRejection::kAccepted;
}

const char* pathRiskName(PathRisk risk) noexcept {
    switch (risk) {
    case PathRisk::kOk: return "Ok";
    case PathRisk::kEmpty: return "Empty";
    case PathRisk::kTooLong: return "TooLong";
    case PathRisk::kControlCharacter: return "ControlCharacter";
    case PathRisk::kWildCard: return "WildCard";
    case PathRisk::kParentTraversal: return "ParentTraversal";
    case PathRisk::kAlternateDataStream: return "AlternateDataStream";
    case PathRisk::kDeviceName: return "DeviceName";
    case PathRisk::kTrailingDotOrSpace: return "TrailingDotOrSpace";
    case PathRisk::kUncOrRemote: return "UncOrRemote";
    }
    return "Empty";
}

namespace {

bool isReservedDeviceBase(std::string_view segment) noexcept {
    static constexpr std::string_view kDevices[] = {
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    };
    // Device name determination considers only the part before the first '.': "nul.dmp" is treated as belonging to the NUL device.
    const std::size_t kDot = segment.find('.');
    const std::string_view kBase =
        kDot == std::string_view::npos ? segment : segment.substr(0, kDot);
    for (const std::string_view kDevice : kDevices) {
        if (asciiEqualsIgnoreCase(kBase, kDevice)) {
            return true;
        }
    }
    return false;
}

constexpr bool isPathSeparator(char value) noexcept { return value == '\\' || value == '/'; }

// The three Win32 "\\x\" prefix semantics are completely different and cannot be handled uniformly:
//   \\.\ DOS device namespace (\\.\PhysicalDrive0, \\.\pipe\x). Not a file; reject directly.
//            CreateFile treats //./ and \\.\ equivalently, so both separators are recognized.
//   \\?\ is the long path prefix. It is the only way to open dump files exceeding MAX_PATH. This prefix must be
//            stripped before evaluation; otherwise, the '?' inside will be incorrectly treated as a wildcard during scanning.
//            This prefix is only valid in the backslash form (its purpose is to disable path normalization). "//?/" is not
//            this prefix—in that path, the '?' should be treated as a wildcard, and the failure direction is safe.
//   Long-path UNC format \\?\UNC\: after stripping the prefix, it remains a remote path.
struct PathPrefixInfo final {
    std::size_t skip = 0;
    bool deviceNamespace = false;
    bool uncFromPrefix = false;
};

PathPrefixInfo classifyPathPrefix(std::string_view path) noexcept {
    PathPrefixInfo info;
    if (path.size() >= 4U && isPathSeparator(path[0]) && isPathSeparator(path[1]) &&
        path[2] == '.' && isPathSeparator(path[3])) {
        info.deviceNamespace = true;
        return info;
    }
    if (path.size() >= 4U && path[0] == '\\' && path[1] == '\\' && path[2] == '?' &&
        path[3] == '\\') {
        info.skip = 4U;
        const std::string_view kRest = path.substr(4U);
        // \\?\GLOBALROOT\Device\HarddiskVolume1\... wraps back to the device namespace; reject it as well.
        if (kRest.size() >= 10U && asciiEqualsIgnoreCase(kRest.substr(0U, 10U), "globalroot") &&
            (kRest.size() == 10U || isPathSeparator(kRest[10U]))) {
            info.deviceNamespace = true;
            return info;
        }
        if (kRest.size() >= 4U && asciiEqualsIgnoreCase(kRest.substr(0U, 3U), "unc") &&
            isPathSeparator(kRest[3U])) {
            info.skip = 8U;
            info.uncFromPrefix = true;
        }
    }
    return info;
}

// Windows strips trailing '.' and ' ' from each path segment when opening a file. Keeping them means the
// "determined string" and the "actually opened file" are not the same, rendering the determination meaningless. '.'
// and '..' are part of path syntax and are not in this category ('..' is handled separately by ParentTraversal).
bool segmentHasTrailingDotOrSpace(std::string_view segment) noexcept {
    if (segment.empty() || segment == "." || segment == "..") {
        return false;
    }
    const char kLast = segment.back();
    return kLast == '.' || kLast == ' ';
}

} // namespace

PathRisk classifyDumpPath(std::string_view path) noexcept {
    // Validation order is fixed; both reporting and testing depend on it.
    if (path.empty()) {
        return PathRisk::kEmpty;
    }
    if (path.size() > kMaxPathBytes) {
        return PathRisk::kTooLong;
    }
    for (const char kRaw : path) {
        if (isControlByte(static_cast<unsigned char>(kRaw))) {
            return PathRisk::kControlCharacter;
        }
    }

    // Strip the prefix first. Device namespaces are blocked here: they are neither remote paths nor files. Previously,
    // they would proceed to the end and be treated as UncOrRemote. The UI would ask the wrong question ('Is this a remote
    // path, confirm?'), and after user confirmation, it would actually pass raw disks or named pipes to the parser.
    const PathPrefixInfo kPrefix = classifyPathPrefix(path);
    if (kPrefix.deviceNamespace) {
        return PathRisk::kDeviceName;
    }
    const std::string_view kBody = path.substr(kPrefix.skip);
    if (kBody.empty()) {
        // Only a prefix exists with nothing following: there is nothing to open.
        return PathRisk::kEmpty;
    }

    for (const char kRaw : kBody) {
        if (kRaw == '*' || kRaw == '?') {
            return PathRisk::kWildCard;
        }
    }

    // Segmented scan: ".." segments, '.'/' ' at segment ends, and device name segments. Both types of delimiters are recognized.
    std::size_t segmentBegin = 0;
    bool sawDeviceSegment = false;
    for (std::size_t index = 0; index <= kBody.size(); ++index) {
        const bool kAtEnd = index == kBody.size();
        if (!kAtEnd && !isPathSeparator(kBody[index])) {
            continue;
        }
        const std::string_view kSegment = kBody.substr(segmentBegin, index - segmentBegin);
        if (kSegment == "..") {
            return PathRisk::kParentTraversal;
        }
        if (segmentHasTrailingDotOrSpace(kSegment)) {
            return PathRisk::kTrailingDotOrSpace;
        }
        if (!kSegment.empty() && isReservedDeviceBase(kSegment)) {
            sawDeviceSegment = true;
        }
        segmentBegin = index + 1;
    }

    // Colon: Only drive letters in the "X:" format are valid; all others are treated as alternate data streams.
    for (std::size_t index = 0; index < kBody.size(); ++index) {
        if (kBody[index] != ':') {
            continue;
        }
        const bool kDriveColon =
            index == 1U && isAsciiAlpha(static_cast<unsigned char>(kBody[0]));
        if (!kDriveColon) {
            return PathRisk::kAlternateDataStream;
        }
    }

    if (sawDeviceSegment) {
        return PathRisk::kDeviceName;
    }

    const bool kUnc = kPrefix.uncFromPrefix ||
                     (kBody.size() >= 2U && ((kBody[0] == '\\' && kBody[1] == '\\') ||
                                            (kBody[0] == '/' && kBody[1] == '/')));
    if (kUnc) {
        return PathRisk::kUncOrRemote;
    }
    return PathRisk::kOk;
}

bool pathAcceptableForOpen(PathRisk risk) noexcept {
    return risk == PathRisk::kOk || risk == PathRisk::kUncOrRemote;
}

bool pathNeedsExplicitConfirmation(PathRisk risk) noexcept {
    return risk == PathRisk::kUncOrRemote;
}

const char* reportOutputRiskName(ReportOutputRisk risk) noexcept {
    switch (risk) {
    case ReportOutputRisk::kOk: return "Ok";
    case ReportOutputRisk::kRawControlCharacter: return "RawControlCharacter";
    case ReportOutputRisk::kExternalLink: return "ExternalLink";
    case ReportOutputRisk::kExternalResourceTag: return "ExternalResourceTag";
    case ReportOutputRisk::kDebuggerMarkupLink: return "DebuggerMarkupLink";
    case ReportOutputRisk::kScriptOrEventHandler: return "ScriptOrEventHandler";
    }
    return "Ok";
}

namespace {

int riskSeverity(ReportOutputRisk risk) noexcept {
    switch (risk) {
    case ReportOutputRisk::kOk: return 0;
    case ReportOutputRisk::kExternalLink: return 1;
    case ReportOutputRisk::kExternalResourceTag: return 2;
    case ReportOutputRisk::kDebuggerMarkupLink: return 3;
    case ReportOutputRisk::kScriptOrEventHandler: return 4;
    case ReportOutputRisk::kRawControlCharacter: return 5;
    }
    return 0;
}

// Event handler attributes: Format like " onclick=" or " onerror =". Case-insensitive comparison without creating temporary strings.
bool hasEventHandlerAttribute(std::string_view attributes) noexcept {
    for (std::size_t index = 0; index + 2U < attributes.size(); ++index) {
        const char kPrevious = index == 0U ? ' ' : attributes[index - 1U];
        const bool kBoundary = kPrevious == ' ' || kPrevious == '\t' || kPrevious == '\n' ||
                              kPrevious == '\r' || kPrevious == '/';
        if (!kBoundary || asciiLowerChar(attributes[index]) != 'o' ||
            asciiLowerChar(attributes[index + 1U]) != 'n') {
            continue;
        }
        std::size_t cursor = index + 2U;
        std::size_t letters = 0;
        while (cursor < attributes.size() &&
               isAsciiAlpha(static_cast<unsigned char>(attributes[cursor]))) {
            ++cursor;
            ++letters;
        }
        while (cursor < attributes.size() && attributes[cursor] == ' ') {
            ++cursor;
        }
        if (letters > 0U && cursor < attributes.size() && attributes[cursor] == '=') {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Character reference folding. Browsers resolve character references before parsing attribute values as URLs,
// so `&#106;avascript:` becomes `javascript:` to them; comparing it is no different than comparing the literal.
//
// Do not extract a new string here: this predicate runs on a noexcept path, where a single allocation could turn an out-of-memory condition
// into std::terminate (see the section at the file's start). Instead, decode and compare character-by-character on demand for zero allocation.
//
// Only unescape the attribute region, never the entire fragment: unescaping `&lt;` back to '<'
// would reassemble a **already-escaped** safe text into a tag, which is the real false positive.
// ---------------------------------------------------------------------------
constexpr char kNonAsciiSentinel = '\x01';  // The needle in the criterion consists entirely of printable ASCII, so it won't collide.

struct NamedEntity final {
    std::string_view name;
    char value;
};

constexpr NamedEntity kNamedEntities[] = {
    {"lt", '<'},     {"gt", '>'},     {"amp", '&'},    {"quot", '"'},   {"apos", '\''},
    {"colon", ':'},  {"sol", '/'},    {"period", '.'}, {"commat", '@'}, {"lpar", '('},
    {"rpar", ')'},   {"tab", '\t'},   {"newline", '\n'}, {"nbsp", ' '},
};

struct DecodedByte final {
    char value = '\0';
    std::size_t consumed = 1U;
};

// Decodes a character from text[pos]. If it hits a character reference, decode it; otherwise, return this single byte as-is.
// Semicolons are optional: browsers are equally tolerant of numeric references in attribute values; this side prefers to accept one more variant.
DecodedByte decodeEntityAt(std::string_view text, std::size_t pos) noexcept {
    DecodedByte decoded;
    decoded.value = text[pos];
    if (text[pos] != '&' || pos + 1U >= text.size()) {
        return decoded;
    }
    std::size_t cursor = pos + 1U;
    if (text[cursor] == '#') {
        ++cursor;
        std::uint32_t base = 10U;
        if (cursor < text.size() && (text[cursor] == 'x' || text[cursor] == 'X')) {
            base = 16U;
            ++cursor;
        }
        std::uint32_t code = 0;
        std::size_t digits = 0;
        while (cursor < text.size() && digits < 8U) {
            const auto kByte = static_cast<unsigned char>(text[cursor]);
            std::uint32_t digit = 0;
            if (isAsciiDigit(kByte)) {
                digit = static_cast<std::uint32_t>(kByte - '0');
            } else if (base == 16U && kByte >= 'a' && kByte <= 'f') {
                digit = static_cast<std::uint32_t>(kByte - 'a') + 10U;
            } else if (base == 16U && kByte >= 'A' && kByte <= 'F') {
                digit = static_cast<std::uint32_t>(kByte - 'A') + 10U;
            } else {
                break;
            }
            code = code * base + digit;
            ++cursor;
            ++digits;
        }
        if (digits == 0U) {
            return decoded;  // No digits after "&#": these are just three ordinary bytes.
        }
        if (cursor < text.size() && text[cursor] == ';') {
            ++cursor;
        }
        decoded.value = code <= 0x7FU ? static_cast<char>(code) : kNonAsciiSentinel;
        decoded.consumed = cursor - pos;
        return decoded;
    }

    std::size_t nameEnd = cursor;
    while (nameEnd < text.size() && (nameEnd - cursor) < 12U &&
           isAsciiAlpha(static_cast<unsigned char>(text[nameEnd]))) {
        ++nameEnd;
    }
    const std::string_view kName = text.substr(cursor, nameEnd - cursor);
    if (kName.empty()) {
        return decoded;
    }
    for (const NamedEntity& entity : kNamedEntities) {
        if (!asciiEqualsIgnoreCase(kName, entity.name)) {
            continue;
        }
        std::size_t end = nameEnd;
        if (end < text.size() && text[end] == ';') {
            ++end;
        }
        decoded.value = entity.value;
        decoded.consumed = end - pos;
        return decoded;
    }
    return decoded;
}

// Search for loweredNeedle in the "folded" text. The needle must already be a lowercase literal.
bool containsFoldedIgnoreCase(std::string_view text, std::string_view loweredNeedle) noexcept {
    if (loweredNeedle.empty() || text.empty()) {
        return false;
    }
    for (std::size_t start = 0; start < text.size(); ++start) {
        std::size_t cursor = start;
        std::size_t matched = 0;
        while (matched < loweredNeedle.size() && cursor < text.size()) {
            const DecodedByte kDecoded = decodeEntityAt(text, cursor);
            if (asciiLowerChar(kDecoded.value) != loweredNeedle[matched]) {
                break;
            }
            cursor += kDecoded.consumed;
            ++matched;
        }
        if (matched == loweredNeedle.size()) {
            return true;
        }
    }
    return false;
}

bool mentionsAnyOf(std::string_view attributes,
                   std::span<const std::string_view> loweredNames) noexcept {
    for (const std::string_view kName : loweredNames) {
        if (containsIgnoreCase(attributes, kName)) {
            return true;
        }
    }
    return false;
}

bool containsAnyFolded(std::string_view attributes,
                       std::span<const std::string_view> loweredNeedles) noexcept {
    for (const std::string_view kNeedle : loweredNeedles) {
        if (containsFoldedIgnoreCase(attributes, kNeedle)) {
            return true;
        }
    }
    return false;
}

// References to external resources. url( and @import are two CSS syntaxes for fetching resources
// — they trigger requests when appearing in style attributes or <style> tags, just like http://.
constexpr std::string_view kExternalTargetNeedles[] = {
    "http://", "https://", "ftp://", "file:", "//", "url(", "@import",
};

// Dangerous protocols: execute scripts with a single click (or even without clicking). Include data: as well—the reports
// generated by this module will never legitimately produce data: URIs, and data:text/html is an executable document in a browser.
constexpr std::string_view kDangerousSchemeNeedles[] = {
    "javascript:", "vbscript:", "data:",
};

// Attributes that automatically trigger requests upon opening the report, without requiring user clicks. 'style' is included:
// <div style="background:url(https://evil/beacon.png)"> represents a silent external connection.
constexpr std::string_view kAutoFetchAttributes[] = {
    "src", "srcset", "background", "poster", "data", "style", "lowsrc",
};

// Attributes that require a user click or form submission to navigate away.
constexpr std::string_view kLinkAttributes[] = {
    "href", "action", "formaction", "cite", "content", "ping",
};

bool attributesAutoFetchExternal(std::string_view attributes) noexcept {
    return mentionsAnyOf(attributes, kAutoFetchAttributes) &&
           containsAnyFolded(attributes, kExternalTargetNeedles);
}

bool attributesReferenceExternal(std::string_view attributes) noexcept {
    return mentionsAnyOf(attributes, kLinkAttributes) &&
           containsAnyFolded(attributes, kExternalTargetNeedles);
}

bool attributesUseDangerousScheme(std::string_view attributes) noexcept {
    // This rule has no attribute name threshold: dangerous protocols appearing anywhere in the attribute section must not be written to the report.
    return containsAnyFolded(attributes, kDangerousSchemeNeedles);
}

bool isExternalResourceTagName(std::string_view name) noexcept {
    static constexpr std::string_view kTags[] = {
        "img", "iframe", "object", "embed", "video", "audio", "source", "link", "base", "meta",
        // @import / url() in <style> and <img src> are both automatic external connections; the former
        // is embedded in tag content and invisible in the attribute section, so handle by tag name.
        "style",
    };
    for (const std::string_view kTag : kTags) {
        if (asciiEqualsIgnoreCase(name, kTag)) {
            return true;
        }
    }
    return false;
}

} // namespace

ReportOutputRisk classifyReportFragment(std::string_view fragment) noexcept {
    // Check control characters first and return immediately: this indicates an external text stream never passed through the escape exit.
    for (const char kRaw : fragment) {
        const auto kByte = static_cast<unsigned char>(kRaw);
        if (isControlByte(kByte) && !isLayoutControlByte(kByte)) {
            return ReportOutputRisk::kRawControlCharacter;
        }
    }

    ReportOutputRisk worst = ReportOutputRisk::kOk;
    const auto kConsider = [&worst](ReportOutputRisk candidate) noexcept {
        if (riskSeverity(candidate) > riskSeverity(worst)) {
            worst = candidate;
        }
    };

    // Single pass: each time a '<' is encountered, extract the tag name and attribute
    // region to check, then jump to after the '>'. Total cost O(n), no backtracking.
    std::size_t index = 0;
    while (index < fragment.size()) {
        if (fragment[index] != '<') {
            ++index;
            continue;
        }
        std::size_t cursor = index + 1U;
        if (cursor < fragment.size() && fragment[cursor] == '/') {
            ++cursor;
        }
        const std::size_t kNameBegin = cursor;
        while (cursor < fragment.size() &&
               isAsciiAlnum(static_cast<unsigned char>(fragment[cursor]))) {
            ++cursor;
        }
        const std::string_view kName = fragment.substr(kNameBegin, cursor - kNameBegin);
        const std::size_t kClose = fragment.find('>', cursor);
        const std::size_t kAttributesEnd = kClose == std::string_view::npos ? fragment.size() : kClose;
        const std::string_view kAttributes = fragment.substr(cursor, kAttributesEnd - cursor);

        if (asciiEqualsIgnoreCase(kName, "script") ||
            attributesUseDangerousScheme(kAttributes) ||
            hasEventHandlerAttribute(kAttributes)) {
            kConsider(ReportOutputRisk::kScriptOrEventHandler);
        }
        // DML: Debugger Markup Language <exec cmd="..."> / <link cmd="...">.
        // This allows report readers to feed any command back to the debugger with a single click, which is more dangerous than external links.
        if (asciiEqualsIgnoreCase(kName, "exec") ||
            ((asciiEqualsIgnoreCase(kName, "link") || asciiEqualsIgnoreCase(kName, "a")) &&
             containsIgnoreCase(kAttributes, "cmd="))) {
            kConsider(ReportOutputRisk::kDebuggerMarkupLink);
        }
        if (isExternalResourceTagName(kName) || attributesAutoFetchExternal(kAttributes)) {
            // A harmless tag name does not imply a harmless fragment: <table background="//evil/x.png"> is as dangerous as <div
            // style="background:url(https://evil/x.png)">, both triggering external connections immediately upon rendering.
            kConsider(ReportOutputRisk::kExternalResourceTag);
        }
        if (attributesReferenceExternal(kAttributes)) {
            kConsider(ReportOutputRisk::kExternalLink);
        }

        index = kClose == std::string_view::npos ? fragment.size() : kClose + 1U;
    }
    return worst;
}

// ---------------------------------------------------------------------------
// C-10 Report provenance
// ---------------------------------------------------------------------------
const char* provenanceGapName(ProvenanceGap gap) noexcept {
    switch (gap) {
    case ProvenanceGap::kMissingEngineIdentity: return "MissingEngineIdentity";
    case ProvenanceGap::kMissingEngineVersion: return "MissingEngineVersion";
    case ProvenanceGap::kMissingInputPath: return "MissingInputPath";
    case ProvenanceGap::kMissingInputSize: return "MissingInputSize";
    case ProvenanceGap::kMissingInputHash: return "MissingInputHash";
    case ProvenanceGap::kMissingAnalysisWindow: return "MissingAnalysisWindow";
    case ProvenanceGap::kMissingSymbolStates: return "MissingSymbolStates";
    case ProvenanceGap::kUnstatedAnalysisScope: return "UnstatedAnalysisScope";
    case ProvenanceGap::kWrongSourceOrigin: return "WrongSourceOrigin";
    case ProvenanceGap::kUndisclosedExternalSupplement:
        return "UndisclosedExternalSupplement";
    }
    return "MissingEngineIdentity";
}

namespace {

bool looksLikeSha256Hex(std::string_view text) noexcept {
    if (text.size() != 64U) {
        return false;
    }
    for (const char kRaw : text) {
        const auto kByte = static_cast<unsigned char>(kRaw);
        const bool kHex = isAsciiDigit(kByte) || (kByte >= 'a' && kByte <= 'f') ||
                         (kByte >= 'A' && kByte <= 'F');
        if (!kHex) {
            return false;
        }
    }
    return true;
}

bool scopeStated(const CoverageAccount& scope) noexcept {
    if (scope.totalKnown.present) {
        return true;
    }
    if (scope.requestedBegin.present && scope.requestedEnd.present) {
        return true;
    }
    return scope.succeeded > 0U || scope.failed > 0U || scope.skipped > 0U ||
           scope.truncated > 0U;
}

std::string optionalFieldValue(const OptionalU64& value, U64Format format) {
    if (!value.present) {
        return std::string(kUnknownValueKey);
    }
    return formatU64(value.value, format);
}

} // namespace

std::vector<ProvenanceGap> auditProvenance(const DumpReportProvenance& provenance) {
    std::vector<ProvenanceGap> gaps;
    if (provenance.engine.engineId.empty()) {
        gaps.push_back(ProvenanceGap::kMissingEngineIdentity);
    }
    if (provenance.engine.engineVersion.empty()) {
        gaps.push_back(ProvenanceGap::kMissingEngineVersion);
    }
    if (provenance.input.filePath.empty()) {
        gaps.push_back(ProvenanceGap::kMissingInputPath);
    }
    if (!provenance.input.fileSize.present) {
        gaps.push_back(ProvenanceGap::kMissingInputSize);
    }
    if (!provenance.input.hashComputed || !looksLikeSha256Hex(provenance.input.sha256Hex)) {
        gaps.push_back(ProvenanceGap::kMissingInputHash);
    }
    if (!provenance.window.startUtc100ns.present || !provenance.window.endUtc100ns.present) {
        gaps.push_back(ProvenanceGap::kMissingAnalysisWindow);
    }
    if (provenance.symbolStates.empty()) {
        // A report without symbol states cannot be re-verified: readers cannot distinguish between 'function name is trusted' and 'just a guess'.
        gaps.push_back(ProvenanceGap::kMissingSymbolStates);
    }
    if (!scopeStated(provenance.analysisScope)) {
        gaps.push_back(ProvenanceGap::kUnstatedAnalysisScope);
    }
    if (provenance.source.origin != SourceOrigin::kOfflineSample) {
        gaps.push_back(ProvenanceGap::kWrongSourceOrigin);
    }
    if (!supplementDisclosed(provenance.supplement)) {
        gaps.push_back(ProvenanceGap::kUndisclosedExternalSupplement);
    }
    return gaps;
}

bool provenanceReviewable(const DumpReportProvenance& provenance) {
    return auditProvenance(provenance).empty();
}

std::vector<ReportField> buildProvenanceFields(const DumpReportProvenance& provenance) {
    std::vector<ReportField> fields;
    fields.reserve(18U);

    const auto kPush = [&fields](std::string key, std::string rawValue) {
        // Single exit point: all values are uniformly escaped here, so callers receive values ready for direct inclusion in HTML.
        fields.push_back(ReportField{std::move(key), escapeForReport(rawValue)});
    };
    const auto kPushText = [&kPush](std::string key, const std::string& text) {
        kPush(std::move(key), text.empty() ? std::string(kUnknownValueKey) : text);
    };

    kPushText("dump.report.engine_id", provenance.engine.engineId);
    kPushText("dump.report.engine_version", provenance.engine.engineVersion);
    kPush("dump.report.engine_available",
         provenance.engine.engineAvailable ? std::string("true") : std::string("false"));

    kPushText("dump.report.input_path", provenance.input.filePath);
    kPush("dump.report.input_size",
         optionalFieldValue(provenance.input.fileSize, U64Format::kDecimal));
    kPush("dump.report.input_sha256",
         provenance.input.hashComputed && !provenance.input.sha256Hex.empty()
             ? provenance.input.sha256Hex
             : std::string(kUnknownValueKey));
    kPush("dump.report.input_last_modified",
         optionalFieldValue(provenance.input.lastModifiedUtc100ns, U64Format::kDecimal));

    kPushText("dump.report.source_collector", provenance.source.collectorId);
    kPush("dump.report.source_origin", sourceOriginName(provenance.source.origin));

    kPush("dump.report.analysis_window_start",
         optionalFieldValue(provenance.window.startUtc100ns, U64Format::kDecimal));
    kPush("dump.report.analysis_window_end",
         optionalFieldValue(provenance.window.endUtc100ns, U64Format::kDecimal));
    kPush("dump.report.analysis_scope_remaining", provenance.analysisScope.describeRemaining());

    std::uint64_t matched = 0;
    std::uint64_t wrongVersion = 0;
    std::uint64_t absent = 0;
    std::uint64_t notAttempted = 0;
    for (const ModuleSymbolState& state : provenance.symbolStates) {
        switch (state.match) {
        case SymbolMatch::kMatched: ++matched; break;
        case SymbolMatch::kWrongVersion: ++wrongVersion; break;
        case SymbolMatch::kAbsent: ++absent; break;
        case SymbolMatch::kNotAttempted: ++notAttempted; break;
        }
    }
    kPush("dump.report.symbol_module_count",
         formatU64(static_cast<std::uint64_t>(provenance.symbolStates.size()), U64Format::kDecimal));
    kPush("dump.report.symbol_matched_count", formatU64(matched, U64Format::kDecimal));
    kPush("dump.report.symbol_wrong_version_count", formatU64(wrongVersion, U64Format::kDecimal));
    kPush("dump.report.symbol_absent_count", formatU64(absent, U64Format::kDecimal));
    kPush("dump.report.symbol_not_attempted_count", formatU64(notAttempted, U64Format::kDecimal));

    kPush("dump.report.external_supplement",
         provenance.supplement.used
             ? (provenance.supplement.disclosureKey.empty()
                    ? std::string(kUnknownValueKey)
                    : provenance.supplement.disclosureKey)
             : std::string("none"));
    return fields;
}

} // namespace ksword::evidence
