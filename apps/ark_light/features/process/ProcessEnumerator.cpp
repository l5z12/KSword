#include "ProcessEnumerator.h"

#include "../../core/NtApi.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <vector>
#include <winternl.h>

namespace ksword::features::process {
namespace {
constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusProcedureNotFound = static_cast<LONG>(0xC000007AUL);

// KsystemProcessInformation mirrors the leading fields of the documented / SDK
// SYSTEM_PROCESS_INFORMATION layout that are stable for process enumeration. The
// project defines it locally so the feature remains independent from SDK-private
// declarations and can parse the raw NtQuerySystemInformation buffer directly.
struct KsystemProcessInformation {
    ULONG nextEntryOffset;
    ULONG numberOfThreads;
    LARGE_INTEGER workingSetPrivateSize;
    ULONG hardFaultCount;
    ULONG numberOfThreadsHighWatermark;
    ULONGLONG cycleTime;
    LARGE_INTEGER createTime;
    LARGE_INTEGER userTime;
    LARGE_INTEGER kernelTime;
    UNICODE_STRING imageName;
    LONG basePriority;
    HANDLE uniqueProcessId;
    HANDLE inheritedFromUniqueProcessId;
    ULONG handleCount;
    ULONG sessionId;
    ULONG_PTR uniqueProcessKey;
    SIZE_T peakVirtualSize;
    SIZE_T virtualSize;
    ULONG pageFaultCount;
    SIZE_T peakWorkingSetSize;
    SIZE_T workingSetSize;
    SIZE_T quotaPeakPagedPoolUsage;
    SIZE_T quotaPagedPoolUsage;
    SIZE_T quotaPeakNonPagedPoolUsage;
    SIZE_T quotaNonPagedPoolUsage;
    SIZE_T pagefileUsage;
    SIZE_T peakPagefileUsage;
    SIZE_T privatePageCount;
    LARGE_INTEGER readOperationCount;
    LARGE_INTEGER writeOperationCount;
    LARGE_INTEGER otherOperationCount;
    LARGE_INTEGER readTransferCount;
    LARGE_INTEGER writeTransferCount;
    LARGE_INTEGER otherTransferCount;
};

std::wstring unicodeStringToWString(const UNICODE_STRING& value) {
    if (value.Buffer == nullptr || value.Length == 0) {
        return {};
    }
    return std::wstring(value.Buffer, value.Buffer + (value.Length / sizeof(wchar_t)));
}

DWORD handleToProcessId(HANDLE value) {
    return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(value));
}

bool isGrowStatus(LONG status) {
    return status == kStatusInfoLengthMismatch ||
           status == kStatusBufferTooSmall ||
           status == kStatusBufferOverflow;
}

std::wstring ntStatusText(LONG status) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"NTSTATUS 0x%08lX", static_cast<unsigned long>(status));
    return buffer;
}

} // namespace

std::wstring queryProcessImagePath(DWORD processId) {
    if (processId == 0) {
        return {};
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return {};
    }

    std::wstring path;
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &size) && size > 0) {
        path.assign(buffer.data(), buffer.data() + size);
    }
    ::CloseHandle(process);
    return path;
}

ProcessEnumerationResult enumerateProcessesByNtQuerySystemInformation() {
    ProcessEnumerationResult result;
    ksword::core::NtApi api;
    if (!api.available()) {
        result.success = false;
        result.ntStatus = kStatusProcedureNotFound;
        result.diagnosticText = L"NtQuerySystemInformation is unavailable.";
        return result;
    }

    ULONG bufferSize = 1u << 20;
    std::vector<std::byte> buffer;
    LONG status = kStatusProcedureNotFound;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returnLength = 0;
        status = api.querySystemInformation(
            ksword::core::SystemInformationClass::kSystemProcessInformation,
            buffer.data(),
            bufferSize,
            &returnLength);
        if (status == kStatusSuccess) {
            break;
        }
        if (!isGrowStatus(status)) {
            result.success = false;
            result.ntStatus = status;
            result.diagnosticText = L"NtQuerySystemInformation failed: " + ntStatusText(status);
            return result;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2u, returnLength + 0x10000u);
    }

    if (status != kStatusSuccess) {
        result.success = false;
        result.ntStatus = status;
        result.diagnosticText = L"NtQuerySystemInformation retry limit reached: " + ntStatusText(status);
        return result;
    }

    std::size_t offset = 0;
    for (;;) {
        if (offset + sizeof(KsystemProcessInformation) > buffer.size()) {
            break;
        }
        const auto* info = reinterpret_cast<const KsystemProcessInformation*>(buffer.data() + offset);

        ProcessSnapshotRow row;
        row.processId = handleToProcessId(info->uniqueProcessId);
        row.parentProcessId = handleToProcessId(info->inheritedFromUniqueProcessId);
        row.handleCount = info->handleCount;
        row.sessionId = info->sessionId;
        row.threadCount = info->numberOfThreads;
        row.basePriority = info->basePriority;
        row.kernelTime100ns = static_cast<ULONGLONG>(info->kernelTime.QuadPart);
        row.userTime100ns = static_cast<ULONGLONG>(info->userTime.QuadPart);
        row.cycleTime = info->cycleTime;
        row.creationTime100ns = info->createTime.QuadPart > 0
            ? static_cast<ULONGLONG>(info->createTime.QuadPart)
            : 0U;
        row.workingSetBytes = info->workingSetSize;
        row.peakWorkingSetBytes = info->peakWorkingSetSize;
        row.privatePageBytes = info->privatePageCount;
        row.virtualSizeBytes = info->virtualSize;
        row.commitBytes = info->pagefileUsage;
        row.pagedPoolBytes = info->quotaPagedPoolUsage;
        row.nonPagedPoolBytes = info->quotaNonPagedPoolUsage;
        row.pageFaultCount = info->pageFaultCount;
        row.ioReadOperations = static_cast<ULONGLONG>(info->readOperationCount.QuadPart);
        row.ioWriteOperations = static_cast<ULONGLONG>(info->writeOperationCount.QuadPart);
        row.ioOtherOperations = static_cast<ULONGLONG>(info->otherOperationCount.QuadPart);
        row.ioReadBytes = static_cast<ULONGLONG>(info->readTransferCount.QuadPart);
        row.ioWriteBytes = static_cast<ULONGLONG>(info->writeTransferCount.QuadPart);
        row.ioOtherBytes = static_cast<ULONGLONG>(info->otherTransferCount.QuadPart);
        row.imageName = unicodeStringToWString(info->imageName);
        if (row.imageName.empty()) {
            row.imageName = row.processId == 0 ? L"System Idle Process" : L"System";
        }
        row.imagePath = queryProcessImagePath(row.processId);
        result.rows.push_back(std::move(row));

        if (info->nextEntryOffset == 0) {
            break;
        }
        offset += info->nextEntryOffset;
    }

    result.success = true;
    result.ntStatus = kStatusSuccess;
    result.diagnosticText = L"OK";
    return result;
}

} // namespace Ksword::Features::Process
