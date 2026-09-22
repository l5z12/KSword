#include "Log.h"

// Windows console coloring and GUID creation are implemented here so the
// public header remains mostly declarative and cheap to include.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>

#include <algorithm>     // std::replace: TSV field sanitization.
#include <cstdio>        // std::snprintf: GUID formatting.
#include <cstring>       // std::memcmp: GUID comparison.
#include <filesystem>    // std::filesystem::path: UTF-8 output path.
#include <fstream>       // std::ofstream: TSV export writer.
#include <iomanip>       // std::put_time: timestamp formatting.
#include <iostream>      // std::cout: console log output.
#include <unordered_map> // std::unordered_map: thread-local stream states.
#include <utility>       // std::move: efficient Event insertion.

#pragma comment(lib, "Ole32.lib")

namespace
{
    // g_consoleOutputMutex serializes console writes across worker threads.
    // Input: locked by Stream::flushPendingState.
    // Processing: protects color changes and line emission as one unit.
    // Return behavior: no direct return value.
    std::mutex gConsoleOutputMutex;

    constexpr WORD kDefaultWhiteColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    // createRandomGuid asks COM for a new GUID and falls back to zero GUID.
    // Input: none.
    // Processing: calls CoCreateGuid; failure is intentionally non-throwing.
    // Return behavior: generated GUID or default GUID{} on failure.
    GUID createRandomGuid()
    {
        GUID newGuid{};
        if (::CoCreateGuid(&newGuid) != S_OK)
        {
            return GUID{};
        }
        return newGuid;
    }

    // getLevelBadge maps a log level to the console badge prefix.
    // Input: level selects the badge.
    // Processing: switch over supported levels.
    // Return behavior: printable badge text.
    std::string getLevelBadge(const ks::log::Level level)
    {
        switch (level)
        {
        case ks::log::Level::kDebug: return "[   ]";
        case ks::log::Level::kInfo:  return "[ + ]";
        case ks::log::Level::kWarn:  return "[ ! ]";
        case ks::log::Level::kError: return "[ x ]";
        case ks::log::Level::kFatal: return "[***]";
        default:                    return "[ ? ]";
        }
    }

    // getPrefixColor maps a level to Win32 console attributes.
    // Input: level selects the color.
    // Processing: switch over supported levels.
    // Return behavior: SetConsoleTextAttribute-compatible WORD.
    WORD getPrefixColor(const ks::log::Level level)
    {
        switch (level)
        {
        case ks::log::Level::kDebug:
            return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case ks::log::Level::kInfo:
            return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case ks::log::Level::kWarn:
            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case ks::log::Level::kError:
            return FOREGROUND_RED | FOREGROUND_INTENSITY;
        case ks::log::Level::kFatal:
            return BACKGROUND_RED | BACKGROUND_INTENSITY | kDefaultWhiteColor;
        default:
            return kDefaultWhiteColor;
        }
    }

    // shouldPrintLocation decides whether console output includes location.
    // Input: level is the archived severity.
    // Processing: only Error and Fatal are considered high-signal enough.
    // Return behavior: true when location should be printed.
    bool shouldPrintLocation(const ks::log::Level level)
    {
        return level == ks::log::Level::kError || level == ks::log::Level::kFatal;
    }

    // extractFileNameOnly shortens a path for console display.
    // Input: fullPath may be a full Windows or POSIX-style path.
    // Processing: searches for the last slash/backslash.
    // Return behavior: file name when found, otherwise original text.
    std::string extractFileNameOnly(const std::string& fullPath)
    {
        const std::size_t kSlashPosition = fullPath.find_last_of("\\/");
        if (kSlashPosition == std::string::npos)
        {
            return fullPath;
        }
        return fullPath.substr(kSlashPosition + 1);
    }

    // sanitizeFieldForTsv keeps each log field inside one TSV cell.
    // Input: fieldValue is copied because replacements are in-place.
    // Processing: tabs and line breaks become spaces.
    // Return behavior: sanitized field text.
    std::string sanitizeFieldForTsv(std::string fieldValue)
    {
        std::replace(fieldValue.begin(), fieldValue.end(), '\t', ' ');
        std::replace(fieldValue.begin(), fieldValue.end(), '\r', ' ');
        std::replace(fieldValue.begin(), fieldValue.end(), '\n', ' ');
        return fieldValue;
    }

    // buildLocationString creates the archived file:line string.
    // Input: filePath may be null; lineNumber is the preprocessor line.
    // Processing: null paths become an empty string.
    // Return behavior: combined location string.
    std::string buildLocationString(const char* const filePath, const int lineNumber)
    {
        const std::string kSafeFilePath = (filePath == nullptr) ? "" : std::string(filePath);
        return kSafeFilePath + ":" + std::to_string(lineNumber);
    }

    // resolveFunctionDescription chooses the best available function text.
    // Input: functionName is short; functionSignature is compiler-specific.
    // Processing: signature wins because it is richer under MSVC.
    // Return behavior: selected function description text.
    std::string resolveFunctionDescription(
        const char* const functionName,
        const char* const functionSignature)
    {
        const std::string kSignatureText =
            (functionSignature == nullptr) ? "" : std::string(functionSignature);
        if (!kSignatureText.empty())
        {
            return kSignatureText;
        }
        return (functionName == nullptr) ? "" : std::string(functionName);
    }
} // namespace

namespace ks::log
{
    TraceEvent::TraceEvent()
        : kGuid(createRandomGuid())
    {
    }

    LogEntry& defaultEntry()
    {
        static LogEntry entry;
        return entry;
    }

    Stream& debugStream()
    {
        static Stream stream(Level::kDebug);
        return stream;
    }

    Stream& infoStream()
    {
        static Stream stream(Level::kInfo);
        return stream;
    }

    Stream& warnStream()
    {
        static Stream stream(Level::kWarn);
        return stream;
    }

    Stream& errorStream()
    {
        static Stream stream(Level::kError);
        return stream;
    }

    Stream& fatalStream()
    {
        static Stream stream(Level::kFatal);
        return stream;
    }

    std::string guidToString(const GUID& guidValue)
    {
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

    bool isSameGuid(const GUID& leftGuid, const GUID& rightGuid)
    {
        return std::memcmp(&leftGuid, &rightGuid, sizeof(GUID)) == 0;
    }

    std::string levelToString(const Level level)
    {
        switch (level)
        {
        case Level::kDebug: return "DEBUG";
        case Level::kInfo:  return "INFO";
        case Level::kWarn:  return "WARN";
        case Level::kError: return "ERROR";
        case Level::kFatal: return "FATAL";
        default:           return "UNKNOWN";
        }
    }

    std::string formatTimeToString(const std::time_t timeValue)
    {
        std::tm localTime{};
        if (::localtime_s(&localTime, &timeValue) != 0)
        {
            return "1970-01-01 00:00:00";
        }

        std::ostringstream formattedTime;
        formattedTime << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
        return formattedTime.str();
    }

    void LogEntry::add(Event eventItem)
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        // recordSequence is allocated within the lock, ensuring each archived log entry has a stable and unique UI key during multi-threaded log writes.
        eventItem.recordSequence = nextRecordSequence_++;
        events_.emplace_back(std::move(eventItem));
        ++revision_;
    }

    void LogEntry::clear()
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        events_.clear();
        ++revision_;
    }

    bool LogEntry::save(std::string outputPath)
    {
        std::vector<Event> eventsSnapshot;
        {
            std::lock_guard<std::mutex> lockGuard(mutex_);
            eventsSnapshot = events_;
        }

        // outputPathUtf8: Converts the UTF-8 byte string to a filesystem::path in the recommended C++20/23 format to avoid u8path deprecation errors.
        const std::u8string kOutputPathUtf8(outputPath.begin(), outputPath.end());
        const std::filesystem::path kOutputFilePath(kOutputPathUtf8);
        std::ofstream outputFile(kOutputFilePath, std::ios::out | std::ios::trunc);
        if (!outputFile.is_open())
        {
            return false;
        }

        for (const Event& singleEvent : eventsSnapshot)
        {
            outputFile
                << levelToString(singleEvent.level) << '\t'
                << formatTimeToString(singleEvent.timestamp) << '\t'
                << ::ks::log::guidToString(singleEvent.guid) << '\t'
                << sanitizeFieldForTsv(singleEvent.content) << '\t'
                << sanitizeFieldForTsv(singleEvent.fileLocation) << '\t'
                << sanitizeFieldForTsv(singleEvent.functionName) << '\n';
        }

        return outputFile.good();
    }

    std::vector<Event> LogEntry::track(const GUID targetGuid)
    {
        std::vector<Event> trackedEvents;
        std::lock_guard<std::mutex> lockGuard(mutex_);
        for (const Event& singleEvent : events_)
        {
            if (::ks::log::isSameGuid(singleEvent.guid, targetGuid))
            {
                trackedEvents.push_back(singleEvent);
            }
        }
        return trackedEvents;
    }

    std::vector<Event> LogEntry::snapshotRecent(
        const std::size_t maxCount,
        const std::uint32_t enabledLevelMask,
        const GUID* const trackedGuid) const
    {
        std::vector<Event> recentEvents;
        if (maxCount == 0 || enabledLevelMask == 0)
        {
            return recentEvents;
        }

        std::lock_guard<std::mutex> lockGuard(mutex_);
        recentEvents.reserve(std::min(maxCount, events_.size()));

        // The UI only needs the 'most recent N' entries, but the internal m_events must retain the full history.
        // Therefore, scan backwards from the tail; copy only upon matching the filter condition; stop immediately upon reaching maxCount.
        // This ensures that when log volume is large, the log Dock refresh does not copy the entire history just to display 200 lines.
        for (auto reverseIterator = events_.rbegin(); reverseIterator != events_.rend(); ++reverseIterator)
        {
            const Event& singleEvent = *reverseIterator;
            const unsigned int kLevelIndex = static_cast<unsigned int>(singleEvent.level);
            if (kLevelIndex >= 32U)
            {
                continue;
            }

            const std::uint32_t kLevelBit = (std::uint32_t{ 1 } << kLevelIndex);
            if ((enabledLevelMask & kLevelBit) == 0)
            {
                continue;
            }

            if (trackedGuid != nullptr && !::ks::log::isSameGuid(singleEvent.guid, *trackedGuid))
            {
                continue;
            }

            recentEvents.push_back(singleEvent);
            if (recentEvents.size() >= maxCount)
            {
                break;
            }
        }

        // Reverse iteration yields 'new to old', but the table displays in normal chronological order 'old to new'.
        std::reverse(recentEvents.begin(), recentEvents.end());
        return recentEvents;
    }

    std::vector<Event> LogEntry::snapshot() const
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        return events_;
    }

    std::size_t LogEntry::revision() const
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        return revision_;
    }

    Stream::Stream(const Level level)
        : kMLevel(level)
    {
    }

    Stream& Stream::operator<<(const TraceEvent& logEvent)
    {
        PendingLogState& pendingState = getPendingState();
        pendingState.hasEvent = true;
        pendingState.currentGuid = logEvent.kGuid;
        return *this;
    }

    Stream& Stream::operator<<(std::ostream& (*streamManipulator)(std::ostream&))
    {
        PendingLogState& pendingState = getPendingState();
        pendingState.messageBuffer << streamManipulator;
        return *this;
    }

    Stream& Stream::operator<<(const EndToken& endToken)
    {
        flushPendingState(endToken);
        return *this;
    }

    Stream::PendingLogState& Stream::getPendingState()
    {
        thread_local std::unordered_map<const Stream*, PendingLogState> threadLocalStates;
        return threadLocalStates[this];
    }

    void Stream::flushPendingState(const EndToken& endToken)
    {
        PendingLogState& pendingState = getPendingState();
        const std::string kMessageText = pendingState.messageBuffer.str();
        const GUID kActiveGuid = pendingState.hasEvent ? pendingState.currentGuid : createRandomGuid();

        const std::time_t kNowTime = std::time(nullptr);
        const std::string kFormattedTime = formatTimeToString(kNowTime);
        const std::string kLocationString = buildLocationString(endToken.filePath, endToken.lineNumber);
        const std::string kFunctionString = resolveFunctionDescription(
            endToken.functionName,
            endToken.functionSignature);

        Event archivedEvent;
        archivedEvent.guid = kActiveGuid;
        archivedEvent.level = kMLevel;
        archivedEvent.content = kMessageText;
        archivedEvent.fileLocation = kLocationString;
        archivedEvent.functionName = kFunctionString;
        archivedEvent.timestamp = kNowTime;
        defaultEntry().add(std::move(archivedEvent));

        {
            std::lock_guard<std::mutex> lockGuard(gConsoleOutputMutex);
            HANDLE outputHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO originalConsoleInfo{};
            const bool kHasConsoleInfo =
                outputHandle != INVALID_HANDLE_VALUE &&
                outputHandle != nullptr &&
                ::GetConsoleScreenBufferInfo(outputHandle, &originalConsoleInfo) != 0;

            const WORD kPrefixColor = getPrefixColor(kMLevel);
            if (kHasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, kPrefixColor);
            }
            std::cout << getLevelBadge(kMLevel) << "[" << kFormattedTime << "]";

            if (kHasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, kDefaultWhiteColor);
            }
            std::cout << kMessageText;

            if (shouldPrintLocation(kMLevel))
            {
                const std::string kShortFileName =
                    extractFileNameOnly(endToken.filePath == nullptr ? "" : endToken.filePath);
                std::cout
                    << "(File:" << kShortFileName
                    << ", Line " << endToken.lineNumber
                    << ", " << kFunctionString
                    << ")";
            }

            std::cout << std::endl;
            if (kHasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, originalConsoleInfo.wAttributes);
            }
        }

        pendingState.hasEvent = false;
        pendingState.currentGuid = GUID{};
        pendingState.messageBuffer.str("");
        pendingState.messageBuffer.clear();
    }
} // namespace ks::log

// Legacy global references bind existing source code to the new ks::log core.
KEventEntry& kswordArkEventEntry = ::ks::log::defaultEntry();
LogStream& dbg = ::ks::log::debugStream();
LogStream& info = ::ks::log::infoStream();
LogStream& warn = ::ks::log::warnStream();
LogStream& err = ::ks::log::errorStream();
LogStream& fatal = ::ks::log::fatalStream();
