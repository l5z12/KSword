#include "KLog.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <utility>

// CoCreateGuid is provided by Ole32.lib. The vcxproj also lists this dependency
// so command-line and IDE builds both resolve the symbol.
#pragma comment(lib, "Ole32.lib")

namespace {

// The default text color is restored after every colored prefix write.
constexpr WORD kDefaultConsoleColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

// consoleMutex serializes complete log-line printing, including color changes.
std::mutex& consoleMutex() {
    static std::mutex mutex;
    return mutex;
}

// createGuid asks Windows for a GUID and returns an all-zero GUID only on failure.
GUID createGuid() {
    GUID guidValue{};
    if (::CoCreateGuid(&guidValue) != S_OK) {
        return GUID{};
    }
    return guidValue;
}

// levelBadge returns the compact severity marker displayed before each line.
const char* levelBadge(KLogLevel level) {
    switch (level) {
    case KLogLevel::kDebug:
        return "[   ]";
    case KLogLevel::kInfo:
        return "[ + ]";
    case KLogLevel::kWarn:
        return "[ ! ]";
    case KLogLevel::kError:
        return "[ x ]";
    case KLogLevel::kFatal:
        return "[!!!]";
    default:
        return "[ ? ]";
    }
}

// prefixColor maps each severity to a Windows console attribute.
WORD prefixColor(KLogLevel level) {
    switch (level) {
    case KLogLevel::kDebug:
        return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case KLogLevel::kInfo:
        return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case KLogLevel::kWarn:
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case KLogLevel::kError:
        return FOREGROUND_RED | FOREGROUND_INTENSITY;
    case KLogLevel::kFatal:
        return BACKGROUND_RED | BACKGROUND_INTENSITY | kDefaultConsoleColor;
    default:
        return kDefaultConsoleColor;
    }
}

// shouldPrintLocation limits file and line output to Error/Fatal console records.
bool shouldPrintLocation(KLogLevel level) {
    return level == KLogLevel::kError || level == KLogLevel::kFatal;
}

// outputStreamForLevel routes Error/Fatal to stderr and other levels to stdout.
std::ostream& outputStreamForLevel(KLogLevel level) {
    return shouldPrintLocation(level) ? std::cerr : std::cout;
}

// consoleHandleForLevel picks the matching Windows console handle for the stream.
DWORD consoleHandleForLevel(KLogLevel level) {
    return shouldPrintLocation(level) ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE;
}

// buildLocationString combines file and line into the archived "file:line" form.
std::string buildLocationString(const char* filePath, int lineNumber) {
    const std::string kSafePath = (filePath == nullptr) ? "" : std::string(filePath);
    return kSafePath + ":" + std::to_string(lineNumber);
}

// resolveFunctionName prefers a compiler function signature and falls back to a name.
std::string resolveFunctionName(const char* functionName, const char* functionSignature) {
    const std::string kSignature = (functionSignature == nullptr) ? "" : std::string(functionSignature);
    if (!kSignature.empty()) {
        return kSignature;
    }
    return (functionName == nullptr) ? "" : std::string(functionName);
}

// fileNameOnly shortens console location text while archive data keeps full paths.
std::string fileNameOnly(const std::string& filePath) {
    const std::size_t kSlashPosition = filePath.find_last_of("\\/");
    if (kSlashPosition == std::string::npos) {
        return filePath;
    }
    return filePath.substr(kSlashPosition + 1);
}

// sanitizeTsvField replaces separators so Save keeps a stable tab-separated shape.
std::string sanitizeTsvField(std::string fieldValue) {
    std::replace(fieldValue.begin(), fieldValue.end(), '\t', ' ');
    std::replace(fieldValue.begin(), fieldValue.end(), '\r', ' ');
    std::replace(fieldValue.begin(), fieldValue.end(), '\n', ' ');
    return fieldValue;
}

} // namespace

// The process-wide event archive instance.
KEventEntry kswordArkEventEntry;

// The five public stream objects exposed through KLog.h and ksword.h.
LogStream dbg(KLogLevel::kDebug);
LogStream info(KLogLevel::kInfo);
LogStream warn(KLogLevel::kWarn);
LogStream err(KLogLevel::kError);
LogStream fatal(KLogLevel::kFatal);

// KLogEvent construction creates a GUID immediately for later stream binding.
KLogEvent::KLogEvent()
    : kGuid(createGuid()) {
}

// guidToString formats a GUID as 8-4-4-4-12 uppercase hexadecimal text.
std::string guidToString(const GUID& guidValue) {
    char guidBuffer[64] = {};
    std::snprintf(
        guidBuffer,
        sizeof(guidBuffer),
        "%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X",
        static_cast<unsigned long>(guidValue.Data1),
        static_cast<unsigned short>(guidValue.Data2),
        static_cast<unsigned short>(guidValue.Data3),
        static_cast<unsigned int>(guidValue.Data4[0]),
        static_cast<unsigned int>(guidValue.Data4[1]),
        static_cast<unsigned int>(guidValue.Data4[2]),
        static_cast<unsigned int>(guidValue.Data4[3]),
        static_cast<unsigned int>(guidValue.Data4[4]),
        static_cast<unsigned int>(guidValue.Data4[5]),
        static_cast<unsigned int>(guidValue.Data4[6]),
        static_cast<unsigned int>(guidValue.Data4[7]));
    return guidBuffer;
}

// isSameGuid compares GUID memory because GUID is a plain Win32 value type.
bool isSameGuid(const GUID& leftGuid, const GUID& rightGuid) {
    return std::memcmp(&leftGuid, &rightGuid, sizeof(GUID)) == 0;
}

// logLevelToString returns a stable uppercase label for exports and diagnostics.
std::string logLevelToString(KLogLevel logLevel) {
    switch (logLevel) {
    case KLogLevel::kDebug:
        return "DEBUG";
    case KLogLevel::kInfo:
        return "INFO";
    case KLogLevel::kWarn:
        return "WARN";
    case KLogLevel::kError:
        return "ERROR";
    case KLogLevel::kFatal:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

// formatTimeToString converts time_t to local time using MSVC's thread-safe helper.
std::string formatTimeToString(std::time_t timeValue) {
    std::tm localTime{};
    if (::localtime_s(&localTime, &timeValue) != 0) {
        return "1970-01-01 00:00:00";
    }

    std::ostringstream formattedTime;
    formattedTime << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return formattedTime.str();
}

// add appends an item under lock and increments the change counter.
void KEventEntry::add(KEvent eventItem) {
    std::lock_guard<std::mutex> lockGuard(mutex_);
    events_.emplace_back(std::move(eventItem));
    ++revision_;
}

// clear removes every archived event under lock and increments the change counter.
void KEventEntry::clear() {
    std::lock_guard<std::mutex> lockGuard(mutex_);
    events_.clear();
    ++revision_;
}

// Save copies a snapshot first, then writes it to disk without holding the mutex.
bool KEventEntry::save(std::string outputPath) {
    std::vector<KEvent> eventsSnapshot;
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        eventsSnapshot = events_;
    }

    std::ofstream outputFile(outputPath, std::ios::out | std::ios::trunc);
    if (!outputFile.is_open()) {
        return false;
    }

    for (const KEvent& singleEvent : eventsSnapshot) {
        outputFile
            << logLevelToString(singleEvent.level) << '\t'
            << formatTimeToString(singleEvent.timestamp) << '\t'
            << guidToString(singleEvent.guid) << '\t'
            << sanitizeTsvField(singleEvent.content) << '\t'
            << sanitizeTsvField(singleEvent.fileLocation) << '\t'
            << sanitizeTsvField(singleEvent.functionName) << '\n';
    }

    return outputFile.good();
}

// Track filters archived records by GUID and returns a detached result vector.
std::vector<KEvent> KEventEntry::track(GUID targetGuid) {
    std::vector<KEvent> trackedEvents;
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (const KEvent& singleEvent : events_) {
        if (isSameGuid(singleEvent.guid, targetGuid)) {
            trackedEvents.push_back(singleEvent);
        }
    }
    return trackedEvents;
}

// Snapshot returns a full copy so callers can inspect records without holding locks.
std::vector<KEvent> KEventEntry::snapshot() const {
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return events_;
}

// Revision returns the current archive revision under lock.
std::size_t KEventEntry::revision() const {
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return revision_;
}

// LogStream binds a severity to this public stream instance.
LogStream::LogStream(KLogLevel level)
    : kMLevel(level) {
}

// operator<<(KLogEvent) stores the event GUID for the next eol commit.
LogStream& LogStream::operator<<(const KLogEvent& logEvent) {
    PendingLogState& pendingState = getPendingState();
    pendingState.hasEvent = true;
    pendingState.currentGuid = logEvent.kGuid;
    return *this;
}

// operator<<(OStreamManipulator) supports std::endl and flushes it for compatibility.
LogStream& LogStream::operator<<(OStreamManipulator manipulator) {
    PendingLogState& pendingState = getPendingState();
    manipulator(pendingState.messageBuffer);

    if (manipulator == static_cast<OStreamManipulator>(std::endl<char, std::char_traits<char>>)) {
        LogEndToken compatibilityToken{};
        flushPendingState(compatibilityToken);
    }
    return *this;
}

// operator<<(IOSManipulator) forwards stream state manipulators into the buffer.
LogStream& LogStream::operator<<(IOSManipulator manipulator) {
    PendingLogState& pendingState = getPendingState();
    manipulator(pendingState.messageBuffer);
    return *this;
}

// operator<<(IOSBaseManipulator) forwards base stream manipulators into the buffer.
LogStream& LogStream::operator<<(IOSBaseManipulator manipulator) {
    PendingLogState& pendingState = getPendingState();
    manipulator(pendingState.messageBuffer);
    return *this;
}

// operator<<(LogEndToken) is the planned commit path for all new log statements.
LogStream& LogStream::operator<<(const LogEndToken& logEndToken) {
    flushPendingState(logEndToken);
    return *this;
}

// getPendingState returns this stream's state in a thread-local map keyed by object.
LogStream::PendingLogState& LogStream::getPendingState() {
    thread_local std::unordered_map<const LogStream*, PendingLogState> threadLocalStates;
    return threadLocalStates[this];
}

// flushPendingState creates an archive record, prints a colored line, and clears state.
void LogStream::flushPendingState(const LogEndToken& logEndToken) {
    PendingLogState& pendingState = getPendingState();
    std::string messageText = pendingState.messageBuffer.str();

    if (!messageText.empty() && messageText.back() == '\n') {
        messageText.pop_back();
        if (!messageText.empty() && messageText.back() == '\r') {
            messageText.pop_back();
        }
    }

    const GUID kActiveGuid = pendingState.hasEvent ? pendingState.currentGuid : createGuid();
    const std::time_t kNowTime = std::time(nullptr);
    const std::string kLocationString = buildLocationString(logEndToken.filePath, logEndToken.lineNumber);
    const std::string kFunctionString = resolveFunctionName(logEndToken.functionName, logEndToken.functionSignature);

    KEvent archivedEvent;
    archivedEvent.guid = kActiveGuid;
    archivedEvent.level = kMLevel;
    archivedEvent.content = messageText;
    archivedEvent.fileLocation = kLocationString;
    archivedEvent.functionName = kFunctionString;
    archivedEvent.timestamp = kNowTime;
    kswordArkEventEntry.add(std::move(archivedEvent));

    {
        std::lock_guard<std::mutex> lockGuard(consoleMutex());
        std::ostream& outputStream = outputStreamForLevel(kMLevel);
        HANDLE outputHandle = ::GetStdHandle(consoleHandleForLevel(kMLevel));

        CONSOLE_SCREEN_BUFFER_INFO originalConsoleInfo{};
        const bool kHasConsoleColor =
            outputHandle != nullptr &&
            outputHandle != INVALID_HANDLE_VALUE &&
            ::GetConsoleScreenBufferInfo(outputHandle, &originalConsoleInfo) != 0;

        if (kHasConsoleColor) {
            ::SetConsoleTextAttribute(outputHandle, prefixColor(kMLevel));
        }

        outputStream << levelBadge(kMLevel) << "[" << formatTimeToString(kNowTime) << "] ";

        if (kHasConsoleColor) {
            ::SetConsoleTextAttribute(outputHandle, kDefaultConsoleColor);
        }

        outputStream << messageText;

        if (shouldPrintLocation(kMLevel)) {
            const std::string kFilePath = (logEndToken.filePath == nullptr) ? "" : std::string(logEndToken.filePath);
            outputStream
                << " (File:" << fileNameOnly(kFilePath)
                << ", Line " << logEndToken.lineNumber;

            if (!kFunctionString.empty()) {
                outputStream << ", " << kFunctionString;
            }

            outputStream << ")";
        }

        outputStream << std::endl;

        if (kHasConsoleColor) {
            ::SetConsoleTextAttribute(outputHandle, originalConsoleInfo.wAttributes);
        }
    }

    pendingState.hasEvent = false;
    pendingState.currentGuid = GUID{};
    pendingState.messageBuffer.str("");
    pendingState.messageBuffer.clear();
}
