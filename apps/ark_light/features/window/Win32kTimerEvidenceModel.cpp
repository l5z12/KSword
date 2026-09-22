#include "Win32kTimerEvidenceModel.h"

#include "../../../../shared/ark_client/ArkDriverTypes.h"

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <sstream>

namespace ksword::features::window {
namespace {

constexpr std::size_t kMaximumSummaryDetailChars = 2048U;
constexpr std::size_t kMaximumDriverDetailChars = 256U;

std::wstring hex32(const std::uint32_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(8) << value;
    return stream.str();
}

std::wstring hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(16) << value;
    return stream.str();
}

std::wstring boundedDisplayText(const std::wstring& value, const std::size_t maximumChars) {
    std::wstring text;
    const std::size_t kCopiedChars = std::min(value.size(), maximumChars);
    text.reserve(kCopiedChars);
    for (std::size_t index = 0U; index < kCopiedChars; ++index) {
        const wchar_t kCharacter = value[index];
        text.push_back(kCharacter == L'\r' || kCharacter == L'\n' || kCharacter == L'\t' ? L' ' : kCharacter);
    }
    if (value.size() > maximumChars && maximumChars >= 3U) {
        text.resize(maximumChars - 3U);
        text += L"...";
    }
    return text;
}

std::wstring boundedPacketText(const wchar_t* value, const std::size_t capacity) {
    if (value == nullptr || capacity == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < capacity && value[length] != L'\0') {
        ++length;
    }
    return boundedDisplayText(std::wstring(value, length), kMaximumDriverDetailChars);
}

std::wstring boundedUtf8Diagnostic(const std::string& value) {
    std::wstring text;
    const std::size_t kCopiedChars = std::min(value.size(), kMaximumDriverDetailChars);
    text.reserve(kCopiedChars);
    for (std::size_t index = 0U; index < kCopiedChars; ++index) {
        const wchar_t kCharacter = static_cast<unsigned char>(value[index]);
        text.push_back(kCharacter == L'\r' || kCharacter == L'\n' || kCharacter == L'\t' ? L' ' : kCharacter);
    }
    if (value.size() > kMaximumDriverDetailChars) {
        text.resize(kMaximumDriverDetailChars - 3U);
        text += L"...";
    }
    return text;
}

std::wstring optionalHex32(const bool present, const std::uint32_t rawValue) {
    return present ? hex32(rawValue) : L"<absent; raw=" + hex32(rawValue) + L">";
}

std::wstring optionalHex64(const bool present, const std::uint64_t rawValue) {
    return present ? hex64(rawValue) : L"<absent; raw=" + hex64(rawValue) + L">";
}

std::wstring optionalDecimal(const bool present, const std::uint32_t rawValue) {
    return present ? std::to_wstring(rawValue) : L"<absent; raw=" + std::to_wstring(rawValue) + L">";
}

const wchar_t* layoutSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
        return L"ValidatedDisassembly";
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS:
        return L"NearestPrevious";
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_UNKNOWN:
    default:
        return L"Unknown";
    }
}

std::wstring snapshotStatusText(const ksword::ark::Win32kTimersResult& result) {
    if (!result.io.ok) {
        return result.unsupported ? L"Unsupported" : L"Unavailable";
    }
    if (result.unsupported || result.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED) {
        return L"Unsupported";
    }
    if (result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND) {
        return L"Win32kMissing";
    }
    return win32kTimerEvidenceStatusText(result.status);
}

std::wstring buildSnapshotDetail(const ksword::ark::Win32kTimersResult& result) {
    std::wostringstream detail;
    detail << L"version=" << hex32(result.version)
           << L"; responseStatus=" << hex32(result.status)
           << L"; flags=" << hex32(result.flags)
           << L"; total=" << result.totalCount
           << L"; returned=" << result.returnedCount
           << L"; parsedRows=" << result.entries.size()
           << L"; entrySize=" << result.entrySize
           << L"; lastStatus=" << hex32(static_cast<std::uint32_t>(result.lastStatus))
           << L"; ioOk=" << (result.io.ok ? L"true" : L"false")
           << L"; win32Error=" << hex32(static_cast<std::uint32_t>(result.io.win32Error))
           << L"; ioNtStatus=" << hex32(static_cast<std::uint32_t>(result.io.ntStatus))
           << L"; unsupported=" << (result.unsupported ? L"true" : L"false")
           << L"; capabilityMask=" << hex64(result.capabilityMask)
           << L"; missingCapabilityMask=" << hex64(result.missingCapabilityMask)
           << L"; gTimerHashTable=" << hex64(result.timerHashTable)
           << L"; layoutSource=" << layoutSourceText(result.layout.source)
           << L" (" << hex32(result.layout.source) << L")"
           << L"; visited=" << result.visitedNodeCount
           << L"; readFailures=" << result.readFailureCount
           << L"; corruptBuckets=" << result.corruptBucketCount
           << L"; duplicates=" << result.duplicateCount
           << L"; win32kbase=" << hex32(result.win32kbaseTimeDateStamp)
           << L"/" << hex32(result.win32kbaseImageSize)
           << L"; win32kfull=" << hex32(result.win32kfullTimeDateStamp)
           << L"/" << hex32(result.win32kfullImageSize);
    const std::wstring kIoMessage = boundedUtf8Diagnostic(result.io.message);
    detail << L"; ioMessage=" << (kIoMessage.empty() ? L"<empty>" : kIoMessage);
    const std::wstring kDriverDetail = boundedDisplayText(result.detail, kMaximumDriverDetailChars);
    detail << L"; driverDetail=" << (kDriverDetail.empty() ? L"<empty>" : kDriverDetail);
    return boundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

std::wstring buildLayoutDetail(const KSWORD_ARK_WIN32K_TIMER_LAYOUT& layout) {
    std::wostringstream detail;
    detail << L"source=" << layoutSourceText(layout.source) << L" (" << hex32(layout.source) << L")"
           << L"; objectSize=" << hex32(layout.objectSize)
           << L"; primaryThreadInfo=" << hex32(layout.primaryThreadInfo)
           << L"; callback=" << hex32(layout.callback)
           << L"; countdown=" << hex32(layout.countdown)
           << L"; tolerance=" << hex32(layout.tolerance)
           << L"; flags=" << hex32(layout.flags)
           << L"; interval=" << hex32(layout.interval)
           << L"; globalListEntry=" << hex32(layout.globalListEntry)
           << L"; window=" << hex32(layout.window)
           << L"; timerId=" << hex32(layout.timerId)
           << L"; alternateThreadInfo=" << hex32(layout.alternateThreadInfo)
           << L"; hashListEntry=" << hex32(layout.hashListEntry)
           << L"; timestamp=" << hex32(layout.timestamp)
           << L"; bucketCount=" << hex32(layout.bucketCount)
           << L"; bucketStride=" << hex32(layout.bucketStride)
           << L"; profileTimeDateStamp=" << hex32(layout.timeDateStamp)
           << L"; profileImageSize=" << hex32(layout.imageSize);
    return boundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

std::wstring buildTimerDetail(const KSWORD_ARK_WIN32K_TIMER_ENTRY& entry) {
    const bool kHasObject = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT) != 0U;
    const bool kHasThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD) != 0U;
    const bool kHasCallback = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_CALLBACK) != 0U;
    const bool kHasInterval = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_INTERVAL) != 0U;
    const bool kHasFlags = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_FLAGS) != 0U;
    const bool kHasWindow = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_WINDOW) != 0U;
    const bool kHasId = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_ID) != 0U;
    const bool kHasAlternateThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_ALTERNATE_THREAD) != 0U;
    const bool kHasHashLink = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_HASH_LINK) != 0U;

    std::wostringstream detail;
    detail << L"fieldFlags=" << hex32(entry.fieldFlags)
           << L"; statusCode=" << hex32(entry.status)
           << L"; processId=" << optionalDecimal(kHasThread, entry.processId)
           << L"; threadId=" << optionalDecimal(kHasThread, entry.threadId)
           << L"; sessionId=" << optionalDecimal(kHasThread, entry.sessionId)
           << L"; flags=" << optionalHex32(kHasFlags, entry.flags)
           << L"; intervalMs=" << optionalDecimal(kHasInterval, entry.intervalMs)
           << L"; countdownMs=" << optionalDecimal(kHasInterval, entry.countdownMs)
           << L"; toleranceMs=" << optionalDecimal(kHasInterval, entry.toleranceMs)
           << L"; lastStatus=" << hex32(static_cast<std::uint32_t>(entry.lastStatus))
           << L"; reserved=" << hex32(entry.reserved)
           << L"; timerObject=" << optionalHex64(kHasObject, entry.timerObject)
           << L"; callbackAddress=" << optionalHex64(kHasCallback, entry.callbackAddress)
           << L"; primaryThreadInfo=" << optionalHex64(kHasThread, entry.primaryThreadInfo)
           << L"; alternateThreadInfo=" << optionalHex64(kHasAlternateThread, entry.alternateThreadInfo)
           << L"; windowObject=" << optionalHex64(kHasWindow, entry.windowObject)
           << L"; timerId=" << optionalHex64(kHasId, entry.timerId)
           << L"; hashLink=" << optionalHex64(kHasHashLink, entry.hashLink);
    const std::wstring kDriverDetail = boundedPacketText(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
    detail << L"; driverDetail=" << (kDriverDetail.empty() ? L"<empty>" : kDriverDetail);
    return boundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

} // namespace

std::wstring win32kTimerEvidenceStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_WIN32K_STATUS_OK: return L"OK";
    case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return L"ProfileMissing";
    case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return L"Win32kMissing";
    case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return L"BufferTruncated";
    case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return L"ReadFailed";
    case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return L"EnumFailed";
    case KSWORD_ARK_WIN32K_STATUS_UNKNOWN: return L"Unknown";
    default: return L"Status(" + hex32(status) + L")";
    }
}

std::vector<Win32kTimerEvidenceRow> buildWin32kTimerEvidenceRows(
    const ksword::ark::Win32kTimersResult& result) {
    std::vector<Win32kTimerEvidenceRow> rows;
    rows.reserve(result.entries.size() + 2U);
    rows.push_back({
        L"Win32k Timer Snapshot",
        L"ArkDriverClient::queryWin32kTimers",
        L"gTimerHashTable / tagTIMER",
        snapshotStatusText(result),
        buildSnapshotDetail(result),
        0U
    });
    const bool kProjectionUnavailable =
        !result.io.ok ||
        result.unsupported ||
        result.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
        result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND ||
        result.status == KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    if (kProjectionUnavailable) {
        return rows;
    }
    rows.push_back({
        L"Win32k Timer Layout",
        L"KSWORD_ARK_WIN32K_TIMER_LAYOUT",
        L"tagTIMER layout / " + std::wstring(layoutSourceText(result.layout.source)),
        result.layout.source == KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY
            ? L"Exact"
            : (result.layout.source == KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS
                ? L"NearestPrevious"
                : L"Unknown"),
        buildLayoutDetail(result.layout),
        0U
    });

    for (std::size_t index = 0U; index < result.entries.size(); ++index) {
        const KSWORD_ARK_WIN32K_TIMER_ENTRY& entry = result.entries[index];
        const bool kHasObject = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT) != 0U;
        const bool kHasThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD) != 0U;
        const std::wstring kTimerObject = kHasObject ? hex64(entry.timerObject) : std::wstring(L"<object absent>");
        rows.push_back({
            L"Win32k Timer",
            L"gTimerHashTable / tagTIMER",
            L"Timer #" + std::to_wstring(index) + L" / " + kTimerObject,
            win32kTimerEvidenceStatusText(entry.status),
            buildTimerDetail(entry),
            kHasThread ? entry.processId : 0U
        });
    }
    return rows;
}

} // namespace Ksword::Features::Window
