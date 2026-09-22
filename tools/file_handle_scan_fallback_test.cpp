// regression harness for the R0 file-handle scan policy and query volume.
//
// The fake DriverClient covers five production bugs:
// 1. A successful R0 enumeration with zero target matches must not fall back to
//    the much slower R3 DuplicateHandle path.
// 2. Once an object type index is known to be non-File, later handles of that
//    type must be skipped without another R0 object-name query. File-like
//    counts must describe all File handles examined, not only target matches.
// 3. A process that exits between the process snapshot and its HandleTable
//    query is normal system churn, not an R0 enumeration failure.
// 4. A handle closed between enumeration and object lookup is likewise normal
//    churn and must not inflate the R0 object-query failure diagnostic.
// 5. A successful partial query for an unnamed File object is unmatchable, but
//    it is not an R0 transport/query failure.
// 6. The batch scanner marks per-process enumeration and per-handle object
//    queries as quiet, so a normal scan cannot flood the driver log with one
//    or two success records for every handle it examines.
// 7. When R0 is unavailable, the scanner records that R0 was attempted before
//    entering the R3 fallback so the UI can wait for R0 start and rescan once.
// 8. A QUIET_LOG enumeration racing a process exit must classify
//    STATUS_INVALID_CID as expected churn; every other status remains visible.

#include "../shared/platform/file/FileHandleTools.h"
#include "../shared/ark_client/ArkDriverClient.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    constexpr int kEmptyScenario = 0;
    constexpr int kTypedHandleScenario = 1;
    constexpr int kDriverUnavailableScenario = 2;
    constexpr std::uint32_t kHandleBase = 0x1000;
    constexpr std::uint32_t kNonFileHandleCount = 900;
    constexpr std::uint32_t kFileHandleCount = 100;
    constexpr std::uint32_t kNonFileTypeIndex = 42;
    constexpr std::uint32_t kFileTypeIndex = 37;
    constexpr long kNtStatusInvalidCid =
        static_cast<long>(static_cast<std::int32_t>(0xC000000BU));
    constexpr wchar_t kTargetPath[] = L"C:\\ksword-regression\\occupied.dat";

    std::atomic_int gScenario = kEmptyScenario;
    std::atomic_bool gKernelEnumerationCompleted = false;
    std::atomic_bool gR3FallbackEntered = false;
    std::atomic_bool gCancelRequested = false;
    std::atomic_uint32_t gObjectQueryCount = 0;
    std::atomic_uint32_t gActiveObjectQueryCount = 0;
    std::atomic_uint32_t gPeakObjectQueryCount = 0;
    std::atomic_bool gEnumQuietFlagObserved = true;
    std::atomic_bool gQueryQuietFlagObserved = true;

    void recordQueryStarted()
    {
        const std::uint32_t kActiveCount =
            gActiveObjectQueryCount.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::uint32_t peakCount = gPeakObjectQueryCount.load(std::memory_order_acquire);
        while (kActiveCount > peakCount &&
               !gPeakObjectQueryCount.compare_exchange_weak(
                   peakCount,
                   kActiveCount,
                   std::memory_order_acq_rel,
                   std::memory_order_acquire))
        {
        }
    }

    void recordQueryFinished()
    {
        gActiveObjectQueryCount.fetch_sub(1, std::memory_order_acq_rel);
    }

    std::size_t diagnosticCount(
        const std::wstring& diagnosticText,
        const std::wstring& label)
    {
        const std::size_t kLabelOffset = diagnosticText.find(label);
        if (kLabelOffset == std::wstring::npos)
        {
            return 0;
        }
        std::size_t offset = kLabelOffset + label.size();
        std::size_t value = 0;
        while (offset < diagnosticText.size() &&
               diagnosticText[offset] >= L'0' && diagnosticText[offset] <= L'9')
        {
            value = (value * 10U) + static_cast<std::size_t>(diagnosticText[offset] - L'0');
            ++offset;
        }
        return value;
    }
}

namespace ksword::ark
{
    ProcessEnumResult DriverClient::enumerateProcesses(unsigned long) const
    {
        ProcessEnumResult result{};
        if (gScenario.load(std::memory_order_acquire) == kDriverUnavailableScenario)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_FILE_NOT_FOUND;
            result.io.message = "CreateFileW(KswordARK) failed, error=2";
            return result;
        }
        result.io.ok = true;
        ProcessEntry entry{};
        entry.processId = ::GetCurrentProcessId();
        result.entries.push_back(entry);
        ProcessEntry exitedEntry{};
        exitedEntry.processId = entry.processId + 100000U;
        result.entries.push_back(exitedEntry);
        result.totalCount = 2;
        result.returnedCount = 2;
        return result;
    }

    HandleEnumResult DriverClient::enumerateProcessHandles(
        const std::uint32_t processId,
        const unsigned long flags) const
    {
        if ((flags & KSWORD_ARK_ENUM_HANDLE_FLAG_QUIET_LOG) == 0UL)
        {
            gEnumQuietFlagObserved.store(false, std::memory_order_release);
        }
        HandleEnumResult result{};
        if (processId != ::GetCurrentProcessId())
        {
            result.io.ok = false;
            result.io.ntStatus = kNtStatusInvalidCid;
            result.processId = processId;
            result.lastStatus = kNtStatusInvalidCid;
            return result;
        }
        result.io.ok = true;
        result.processId = processId;
        if (gScenario.load(std::memory_order_acquire) == kTypedHandleScenario)
        {
            const std::uint32_t kTotalCount = kNonFileHandleCount + kFileHandleCount;
            result.entries.reserve(kTotalCount);
            for (std::uint32_t index = 0; index < kTotalCount; ++index)
            {
                HandleEntry entry{};
                entry.processId = processId;
                entry.handleValue = kHandleBase + index;
                entry.grantedAccess = 0x00120089;
                entry.objectTypeIndex = index < kNonFileHandleCount
                    ? kNonFileTypeIndex
                    : kFileTypeIndex;
                result.entries.push_back(entry);
            }
            result.totalCount = kTotalCount;
            result.returnedCount = kTotalCount;
        }
        gKernelEnumerationCompleted.store(true, std::memory_order_release);
        return result;
    }

    HandleObjectQueryResult DriverClient::queryHandleObject(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const unsigned long flags,
        unsigned long) const
    {
        if ((flags & KSWORD_ARK_QUERY_OBJECT_FLAG_QUIET_LOG) == 0UL)
        {
            gQueryQuietFlagObserved.store(false, std::memory_order_release);
        }
        gObjectQueryCount.fetch_add(1, std::memory_order_acq_rel);
        recordQueryStarted();

        HandleObjectQueryResult result{};
        result.io.ok = true;
        result.processId = processId;
        result.handleValue = handleValue;
        result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_OK;
        result.actualGrantedAccess = 0x00120089;
        const std::uint64_t kFileHandleBase = kHandleBase + kNonFileHandleCount;
        if (handleValue < kFileHandleBase)
        {
            result.objectTypeIndex = kNonFileTypeIndex;
            result.typeName = L"Event";
            result.objectName = L"\\BaseNamedObjects\\ksword-regression-event";
            recordQueryFinished();
            return result;
        }

        // Model the per-File ObQueryNameString/IOCTL latency seen in the live
        // scan. A serial production loop remains deterministic but slow, while
        // bounded parallel queries produce the same result with overlap.
        ::Sleep(3);
        result.objectTypeIndex = kFileTypeIndex;
        result.typeName = L"File";
        if (handleValue == kFileHandleBase + kFileHandleCount - 3U)
        {
            result.io.ok = false;
            recordQueryFinished();
            return result;
        }
        if (handleValue == kFileHandleBase + kFileHandleCount - 2U)
        {
            result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL;
            recordQueryFinished();
            return result;
        }
        if (handleValue == kFileHandleBase + kFileHandleCount - 1U)
        {
            result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED;
            result.objectReferenceStatus = kNtStatusInvalidCid;
            recordQueryFinished();
            return result;
        }
        if (handleValue == kFileHandleBase)
        {
            result.objectName = kTargetPath;
        }
        else
        {
            result.objectName = L"C:\\ksword-regression\\other-" +
                std::to_wstring(handleValue - kFileHandleBase) + L".dat";
        }
        recordQueryFinished();
        return result;
    }
}

namespace ks::process
{
    std::string queryProcessPathByPid(std::uint32_t)
    {
        return {};
    }
}

namespace ks::str
{
    std::wstring utf8ToUtf16(const std::string& text)
    {
        if (text.empty())
        {
            return {};
        }
        const int kLength = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0);
        if (kLength <= 0)
        {
            return {};
        }
        std::wstring result(static_cast<std::size_t>(kLength), L'\0');
        ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            kLength);
        return result;
    }

    std::string utf16ToUtf8(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }
        const int kLength = ::WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (kLength <= 0)
        {
            return {};
        }
        std::string result(static_cast<std::size_t>(kLength), '\0');
        ::WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            kLength,
            nullptr,
            nullptr);
        return result;
    }
}

int wmain()
{
    ks::file::HandleUsageScanOptions emptyOptions{};
    emptyOptions.tryKernelHandleTable = true;
    emptyOptions.progressCallback = [](const std::string& stepText, float)
    {
        if (stepText == "准备抓取系统句柄快照")
        {
            gR3FallbackEntered.store(true, std::memory_order_release);
            gCancelRequested.store(true, std::memory_order_release);
        }
    };
    emptyOptions.cancellationCallback = []()
    {
        return gCancelRequested.load(std::memory_order_acquire);
    };
    (void)ks::file::scanHandleUsageByPaths({ kTargetPath }, emptyOptions);
    if (!gKernelEnumerationCompleted.load(std::memory_order_acquire))
    {
        return 2;
    }
    if (gR3FallbackEntered.load(std::memory_order_acquire))
    {
        return 1;
    }

    gScenario.store(kDriverUnavailableScenario, std::memory_order_release);
    gR3FallbackEntered.store(false, std::memory_order_release);
    gCancelRequested.store(false, std::memory_order_release);
    ks::file::HandleUsageScanOptions unavailableOptions{};
    unavailableOptions.tryKernelHandleTable = true;
    const ks::file::HandleUsageScanResult kUnavailableResult =
        ks::file::scanHandleUsageByPaths({ kTargetPath }, unavailableOptions);
    const bool kHasR3FallbackDiagnostic =
        kUnavailableResult.diagnosticText.find(L"文件句柄来源:R3 DuplicateHandle") != std::wstring::npos;
    if (!kUnavailableResult.kernelHandleTableAttempted ||
        kUnavailableResult.kernelHandleTableUsed ||
        !kUnavailableResult.r3HandleFallbackUsed ||
        !kHasR3FallbackDiagnostic)
    {
        return 12;
    }

    gScenario.store(kTypedHandleScenario, std::memory_order_release);
    gKernelEnumerationCompleted.store(false, std::memory_order_release);
    gR3FallbackEntered.store(false, std::memory_order_release);
    gCancelRequested.store(false, std::memory_order_release);
    gObjectQueryCount.store(0, std::memory_order_release);
    gActiveObjectQueryCount.store(0, std::memory_order_release);
    gPeakObjectQueryCount.store(0, std::memory_order_release);
    gEnumQuietFlagObserved.store(true, std::memory_order_release);
    gQueryQuietFlagObserved.store(true, std::memory_order_release);

    ks::file::HandleUsageScanOptions typedOptions{};
    typedOptions.tryKernelHandleTable = true;
    typedOptions.progressCallback = [](const std::string& stepText, float)
    {
        if (stepText == "准备抓取系统句柄快照")
        {
            gR3FallbackEntered.store(true, std::memory_order_release);
        }
    };
    const ks::file::HandleUsageScanResult kResult =
        ks::file::scanHandleUsageByPaths({ kTargetPath }, typedOptions);
    const std::uint32_t kQueryCount = gObjectQueryCount.load(std::memory_order_acquire);
    const std::uint32_t kPeakQueryCount = gPeakObjectQueryCount.load(std::memory_order_acquire);
    const bool kHasEnumFailureDiagnostic =
        kResult.diagnosticText.find(L"R0枚举失败进程:") != std::wstring::npos;
    const std::size_t kObjectFailureDiagnosticCount =
        diagnosticCount(kResult.diagnosticText, L"R0对象查询失败:");
    const bool kQuietInvalidCid = KSWORD_ARK_ENUM_HANDLE_STATUS_IS_EXPECTED_CHURN(
        KSWORD_ARK_ENUM_HANDLE_FLAG_QUIET_LOG,
        kNtStatusInvalidCid);
    const bool kNonQuietInvalidCid = KSWORD_ARK_ENUM_HANDLE_STATUS_IS_EXPECTED_CHURN(
        0UL,
        kNtStatusInvalidCid);
    const bool kQuietAccessDenied = KSWORD_ARK_ENUM_HANDLE_STATUS_IS_EXPECTED_CHURN(
        KSWORD_ARK_ENUM_HANDLE_FLAG_QUIET_LOG,
        static_cast<long>(0xC0000022UL));

    std::cout << "R3_FALLBACK=" << (gR3FallbackEntered.load() ? 1 : 0) << '\n'
              << "OBJECT_QUERIES=" << kQueryCount << '\n'
              << "PEAK_OBJECT_QUERIES=" << kPeakQueryCount << '\n'
              << "FILE_LIKE_HANDLES=" << kResult.fileLikeHandleCount << '\n'
              << "MATCHED_HANDLES=" << kResult.matchedHandleCount << '\n'
              << "ENUM_CHURN_REPORTED_AS_ERROR=" << (kHasEnumFailureDiagnostic ? 1 : 0) << '\n'
              << "OBJECT_FAILURES=" << kObjectFailureDiagnosticCount << '\n'
              << "ENUM_QUIET_LOG=" << (gEnumQuietFlagObserved.load() ? 1 : 0) << '\n'
              << "QUERY_QUIET_LOG=" << (gQueryQuietFlagObserved.load() ? 1 : 0) << '\n'
              << "R0_ATTEMPT_RECORDED=" << (kUnavailableResult.kernelHandleTableAttempted ? 1 : 0) << '\n'
              << "R3_FALLBACK_RECORDED=" << (kUnavailableResult.r3HandleFallbackUsed ? 1 : 0) << '\n'
              << "QUIET_INVALID_CID=" << (kQuietInvalidCid ? 1 : 0) << '\n'
              << "NONQUIET_INVALID_CID=" << (kNonQuietInvalidCid ? 1 : 0) << '\n'
              << "QUIET_ACCESS_DENIED=" << (kQuietAccessDenied ? 1 : 0) << '\n';

    if (gR3FallbackEntered.load(std::memory_order_acquire))
    {
        return 3;
    }
    if (kQueryCount > kFileHandleCount + 2)
    {
        return 4;
    }
    if (kHasEnumFailureDiagnostic)
    {
        return 8;
    }
    if (kObjectFailureDiagnosticCount != 1U)
    {
        return 9;
    }
    if (kPeakQueryCount < 2)
    {
        return 7;
    }
    if (kResult.fileLikeHandleCount != kFileHandleCount)
    {
        return 5;
    }
    if (kResult.matchedHandleCount != 1)
    {
        return 6;
    }
    if (!gEnumQuietFlagObserved.load(std::memory_order_acquire))
    {
        return 10;
    }
    if (!gQueryQuietFlagObserved.load(std::memory_order_acquire))
    {
        return 11;
    }
    if (!kResult.kernelHandleTableAttempted || !kResult.kernelHandleTableUsed ||
        kResult.r3HandleFallbackUsed)
    {
        return 13;
    }
    if (!kQuietInvalidCid || kNonQuietInvalidCid || kQuietAccessDenied)
    {
        return 14;
    }
    return 0;
}
