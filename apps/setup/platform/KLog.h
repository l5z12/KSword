#ifndef KSWORD_WIN_API_CORE_KLOG_HEAD_FILE
#define KSWORD_WIN_API_CORE_KLOG_HEAD_FILE

#include <cstddef>
#include <ctime>
#include <ios>
#include <mutex>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include <guiddef.h>

// KLogLevel describes the severity attached to every archived and displayed log.
// The values are ordered from lowest diagnostic severity to process-ending severity.
enum class KLogLevel {
    kDebug,
    kInfo,
    kWarn,
    kError,
    kFatal
};

// KLogEvent represents a business event that can group several log lines.
// Input: none. Processing: construction creates a GUID. Return: objects expose the GUID.
class KLogEvent {
public:
    // The constructor generates one GUID immediately so the event can be streamed later.
    KLogEvent();

    // guid is public and immutable after construction so Track(guid) callers get a stable key.
    const GUID kGuid;
};

// kEvent is the immutable-style archive record produced when LogStream receives eol.
// It stores content plus source location metadata for later UI display, export, or tracking.
struct KEvent {
    GUID guid{};
    KLogLevel level{};
    std::string content;
    std::string fileLocation;
    std::string functionName;
    std::time_t timestamp{};
};

// KEventEntry owns the process-wide log archive and protects it with a mutex.
// Inputs are kEvent records and GUIDs. Processing copies snapshots under lock.
// Return values are status booleans, event vectors, or the current revision counter.
class KEventEntry {
public:
    // add appends one event record and increments Revision; it returns no value.
    void add(KEvent eventItem);

    // clear removes all archived records and increments Revision; it returns no value.
    void clear();

    // Save writes a tab-separated snapshot to outputPath and returns true on success.
    bool save(std::string outputPath);

    // Track returns all records whose GUID equals targetGuid.
    std::vector<KEvent> track(GUID targetGuid);

    // Snapshot returns a complete copy of the current archive.
    std::vector<KEvent> snapshot() const;

    // Revision returns the archive version, incremented by add and clear.
    std::size_t revision() const;

private:
    // m_mutex serializes access to m_events and m_revision for multi-threaded logging.
    mutable std::mutex mutex_;

    // m_events stores all emitted records until clear is called.
    std::vector<KEvent> events_;

    // m_revision lets readers cheaply detect archive changes.
    std::size_t revision_ = 0;
};

// LogEndToken is created by the eol macro and carries call-site metadata.
// LogStream consumes it as the explicit end-of-log marker.
struct LogEndToken {
    const char* filePath = "";
    int lineNumber = 0;
    const char* functionName = "";
    const char* functionSignature = "";
};

// LogStream is a thread-aware stream facade for dbg/info/warn/err/fatal.
// Inputs are streamable values, KLogEvent objects, manipulators, and eol.
// Processing buffers per thread and severity until eol commits the record.
class LogStream {
public:
    using OStreamManipulator = std::ostream& (*)(std::ostream&);
    using IOSManipulator = std::ios& (*)(std::ios&);
    using IOSBaseManipulator = std::ios_base& (*)(std::ios_base&);

    // The constructor binds this stream instance to a fixed severity level.
    explicit LogStream(KLogLevel level);

    // operator<<(KLogEvent) binds the following buffered text to logEvent.guid.
    LogStream& operator<<(const KLogEvent& logEvent);

    // This overload supports std::endl and also flushes for legacy callers.
    LogStream& operator<<(OStreamManipulator manipulator);

    // This overload supports manipulators such as std::boolalpha; it returns this stream.
    LogStream& operator<<(IOSManipulator manipulator);

    // This overload supports manipulators such as std::hex; it returns this stream.
    LogStream& operator<<(IOSBaseManipulator manipulator);

    // operator<<(LogEndToken) commits the current buffered line and returns this stream.
    LogStream& operator<<(const LogEndToken& logEndToken);

    // The template accepts any type that std::ostringstream can format.
    // It appends into the current thread-local buffer and returns this stream.
    template <typename TValue>
    LogStream& operator<<(const TValue& value) {
        PendingLogState& pendingState = getPendingState();
        pendingState.messageBuffer << value;
        return *this;
    }

private:
    // PendingLogState is isolated by thread and by LogStream instance.
    struct PendingLogState {
        bool hasEvent = false;
        GUID currentGuid{};
        std::ostringstream messageBuffer;
    };

    // getPendingState returns the state for the current thread and this stream object.
    PendingLogState& getPendingState();

    // flushPendingState builds kEvent, prints to console, archives, then clears the buffer.
    void flushPendingState(const LogEndToken& logEndToken);

    // m_level is the immutable severity attached to every record emitted by this stream.
    const KLogLevel kMLevel;
};

// Compatibility aliases keep older KLogLevel/KLogStream references source-compatible.
using KLogLevel = KLogLevel;
using KLogStream = LogStream;

// KswordARKEventEntry is the global archive consumed by UI and business logic.
extern KEventEntry kswordArkEventEntry;

// Global streams provide the intended syntax: info << "message" << eol.
extern LogStream dbg;
extern LogStream info;
extern LogStream warn;
extern LogStream err;
extern LogStream fatal;

// guidToString converts a GUID to canonical text and returns that string.
std::string guidToString(const GUID& guidValue);

// isSameGuid compares two GUID structures and returns true when all bytes match.
bool isSameGuid(const GUID& leftGuid, const GUID& rightGuid);

// logLevelToString converts a severity enum to DEBUG/INFO/WARN/ERROR/FATAL text.
std::string logLevelToString(KLogLevel logLevel);

// formatTimeToString converts a time_t value into "YYYY-MM-DD HH:MM:SS" text.
std::string formatTimeToString(std::time_t timeValue);

#if defined(_MSC_VER)
#define KSWORDARK_FUNCTION_SIGNATURE __FUNCSIG__
#elif defined(__GNUC__) || defined(__clang__)
#define KSWORDARK_FUNCTION_SIGNATURE __PRETTY_FUNCTION__
#else
#define KSWORDARK_FUNCTION_SIGNATURE __func__
#endif

// eol captures the current call site and tells LogStream to commit the buffered record.
#define eol LogEndToken{__FILE__, __LINE__, __FUNCTION__, KSWORDARK_FUNCTION_SIGNATURE}

#endif
