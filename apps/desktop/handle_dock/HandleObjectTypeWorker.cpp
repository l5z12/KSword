#include "HandleObjectTypeWorker.h"

// ============================================================
// HandleObjectTypeWorker.cpp
// Purpose:
// - Implement object type resolution for NtQueryObject(ObjectTypesInformation);
// - Output: Stable typeIndex/typeName mapping for reuse by the handle module.
// - Compatible with differences in system structures (alignment, missing TypeIndex, out-of-bounds name pointers).
// ============================================================

#include <QChar>
#include <QStringList>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <unordered_set>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    // NTSTATUS constants: Unified local definitions to avoid missing environment macros.
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);

    // NtQueryObject information class constants: Avoid scattered magic numbers.
    constexpr ULONG kObjectTypesInformationClass = 3;

    // NtQueryObject function signature.
    using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // NtApi: caches the ntdll handle and the NtQueryObject address.
    struct NtApi final
    {
        HMODULE ntdllModule = nullptr;      // ntdllModule: The handle to the ntdll module.
        NtQueryObjectFn queryObject = nullptr; // queryObject: Address of NtQueryObject.
    };

    // RawObjectTypesHeader: Header returned by ObjectTypesInformation.
    struct RawObjectTypesHeader
    {
        ULONG numberOfTypes = 0; // numberOfTypes: Total number of type records.
    };

    // RawObjectTypeInformation: Original structure for object type information (subset of fields required by this module).
    struct RawObjectTypeInformation
    {
        UNICODE_STRING typeName{};
        ULONG totalNumberOfObjects = 0;
        ULONG totalNumberOfHandles = 0;
        ULONG totalPagedPoolUsage = 0;
        ULONG totalNonPagedPoolUsage = 0;
        ULONG totalNamePoolUsage = 0;
        ULONG totalHandleTableUsage = 0;
        ULONG highWaterNumberOfObjects = 0;
        ULONG highWaterNumberOfHandles = 0;
        ULONG highWaterPagedPoolUsage = 0;
        ULONG highWaterNonPagedPoolUsage = 0;
        ULONG highWaterNamePoolUsage = 0;
        ULONG highWaterHandleTableUsage = 0;
        ULONG invalidAttributes = 0;
        GENERIC_MAPPING genericMapping{};
        ULONG validAccessMask = 0;
        BOOLEAN securityRequired = FALSE;
        BOOLEAN maintainHandleCount = FALSE;
        UCHAR typeIndex = 0;
        CHAR reservedByte = 0;
        ULONG poolType = 0;
        ULONG defaultPagedPoolCharge = 0;
        ULONG defaultNonPagedPoolCharge = 0;
    };

    // loadNtApi：
    // - Purpose: Load ntdll and resolve the NtQueryObject address;
    // - On failure, return false and write the error text.
    bool loadNtApi(NtApi& apiOut, QString& errorTextOut)
    {
        errorTextOut.clear();
        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = QStringLiteral("加载 ntdll.dll 失败。");
            return false;
        }

        apiOut.queryObject = reinterpret_cast<NtQueryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQueryObject"));
        if (apiOut.queryObject == nullptr)
        {
            errorTextOut = QStringLiteral("解析 NtQueryObject 入口失败。");
            return false;
        }
        return true;
    }

    // isNeedGrowBufferStatus：
    // - Purpose: Check if NTSTATUS indicates 'buffer too small, needs expansion'.
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    // ntStatusToText：
    // - Purpose: Convert NTSTATUS to "hexadecimal + text".
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();
        const QString kSuccessText = NT_SUCCESS(statusCode)
            ? QStringLiteral("SUCCESS")
            : QStringLiteral("FAILED");

        wchar_t messageBuffer[256] = {};
        const DWORD kTextLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(statusCode),
            0,
            messageBuffer,
            static_cast<DWORD>(std::size(messageBuffer)),
            nullptr);
        if (kTextLength == 0)
        {
            return QStringLiteral("%1 (%2)").arg(kHexText, kSuccessText);
        }
        return QStringLiteral("%1 (%2) %3")
            .arg(kHexText, kSuccessText, QString::fromWCharArray(messageBuffer).trimmed());
    }

    // alignUp：
    // - Purpose: Align the offset upward to the specified alignment value.
    std::size_t alignUp(const std::size_t value, const std::size_t alignment)
    {
        if (alignment == 0)
        {
            return value;
        }
        const std::size_t kMask = alignment - 1;
        return (value + kMask) & ~kMask;
    }

    // isReadableMemoryRange：
    // - Purpose: Detect if a memory range is readable.
    // - Prevents crashes caused by dereferencing invalid pointers directly.
    bool isReadableMemoryRange(const void* beginAddress, const std::size_t length)
    {
        if (beginAddress == nullptr || length == 0)
        {
            return false;
        }

        std::uintptr_t currentAddress = reinterpret_cast<std::uintptr_t>(beginAddress);
        const std::uintptr_t kEndAddress = currentAddress + length;
        if (kEndAddress < currentAddress)
        {
            return false;
        }

        while (currentAddress < kEndAddress)
        {
            MEMORY_BASIC_INFORMATION memoryInfo{};
            const SIZE_T kQuerySize = ::VirtualQuery(
                reinterpret_cast<LPCVOID>(currentAddress),
                &memoryInfo,
                sizeof(memoryInfo));
            if (kQuerySize != sizeof(memoryInfo))
            {
                return false;
            }
            if (memoryInfo.State != MEM_COMMIT)
            {
                return false;
            }
            const DWORD kProtect = (memoryInfo.Protect & 0xFFU);
            if (kProtect == PAGE_NOACCESS || kProtect == PAGE_GUARD)
            {
                return false;
            }

            const std::uintptr_t kRegionBegin = reinterpret_cast<std::uintptr_t>(memoryInfo.BaseAddress);
            const std::uintptr_t kRegionEnd = kRegionBegin + memoryInfo.RegionSize;
            if (kRegionEnd <= currentAddress)
            {
                return false;
            }
            currentAddress = std::min(kRegionEnd, kEndAddress);
        }
        return true;
    }

    // queryAutoBuffer：
    // - Purpose: Automatically resize and retry Nt queries until success or failure.
    // - Returns true when outputBuffer contains a valid response.
    bool queryAutoBuffer(
        const std::function<NTSTATUS(void*, ULONG, ULONG*)>& queryFunction,
        std::vector<std::uint8_t>& outputBuffer,
        NTSTATUS& statusCodeOut,
        const ULONG initialSize = 4096U)
    {
        statusCodeOut = kStatusUnsuccessful;
        ULONG bufferSize = std::max<ULONG>(initialSize, 256U);

        for (int retryIndex = 0; retryIndex < 8; ++retryIndex)
        {
            outputBuffer.assign(bufferSize, 0);
            ULONG returnLength = 0;
            const NTSTATUS kStatusCode = queryFunction(outputBuffer.data(), bufferSize, &returnLength);
            statusCodeOut = kStatusCode;

            if (NT_SUCCESS(kStatusCode))
            {
                if (returnLength > 0 && returnLength <= outputBuffer.size())
                {
                    outputBuffer.resize(returnLength);
                }
                return true;
            }
            if (!isNeedGrowBufferStatus(kStatusCode))
            {
                return false;
            }
            bufferSize = std::max(bufferSize * 2U, returnLength + 512U);
        }
        return false;
    }
}

bool runHandleObjectTypeSnapshotTask(
    std::vector<HandleObjectTypeEntry>& rowsOut,
    QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    // Log start of collection: used for auditing the object type refresh chain.
    KLogEvent beginEvent;
    info << beginEvent << "[HandleObjectTypeWorker] 开始采集对象类型快照。" << eol;

    NtApi api{};
    if (!loadNtApi(api, errorTextOut))
    {
        KLogEvent loadFailEvent;
        err << loadFailEvent
            << "[HandleObjectTypeWorker] 加载 NtApi 失败: "
            << errorTextOut.toStdString()
            << eol;
        return false;
    }

    std::vector<std::uint8_t> buffer;
    NTSTATUS statusCode = kStatusUnsuccessful;
    const bool kQueryOk = queryAutoBuffer(
        [&api](void* outBuffer, ULONG outLength, ULONG* returnLengthOut) -> NTSTATUS
        {
            return api.queryObject(
                nullptr,
                kObjectTypesInformationClass,
                outBuffer,
                outLength,
                returnLengthOut);
        },
        buffer,
        statusCode,
        64U * 1024U);
    if (!kQueryOk || !NT_SUCCESS(statusCode))
    {
        errorTextOut = QStringLiteral("NtQueryObject(ObjectTypesInformation) 失败: %1")
            .arg(ntStatusToText(api.ntdllModule, statusCode));
        KLogEvent queryFailEvent;
        err << queryFailEvent
            << "[HandleObjectTypeWorker] 查询对象类型失败: "
            << errorTextOut.toStdString()
            << eol;
        return false;
    }
    if (buffer.size() < sizeof(RawObjectTypesHeader))
    {
        errorTextOut = QStringLiteral("对象类型返回缓冲区长度不足。");
        return false;
    }

    std::vector<HandleObjectTypeEntry> snapshotRows;
    const auto* header = reinterpret_cast<const RawObjectTypesHeader*>(buffer.data());
    snapshotRows.reserve(header->numberOfTypes);

    // Structure traversal strategy: align pointers after the header, then read and advance sequentially.
    const std::uintptr_t kBufferBase = reinterpret_cast<std::uintptr_t>(buffer.data());
    const std::uintptr_t kBufferEnd = kBufferBase + buffer.size();
    std::uintptr_t entryAddress = alignUp(
        kBufferBase + sizeof(RawObjectTypesHeader),
        sizeof(void*));

    // usedTypeIndex: Provides a fallback numbering scheme when typeIndex is missing or duplicated.
    std::unordered_set<std::uint32_t> usedTypeIndex;
    usedTypeIndex.reserve(header->numberOfTypes);

    for (ULONG index = 0; index < header->numberOfTypes; ++index)
    {
        if (entryAddress + sizeof(RawObjectTypeInformation) > kBufferEnd)
        {
            break;
        }

        const auto* rawInfo = reinterpret_cast<const RawObjectTypeInformation*>(entryAddress);
        QString typeNameText;

        // Path A: Prioritize reading the Buffer pointer from UNICODE_STRING.
        if (rawInfo->typeName.Buffer != nullptr && rawInfo->typeName.Length > 0)
        {
            const std::size_t kByteLength = static_cast<std::size_t>(rawInfo->typeName.Length);
            const std::uintptr_t kPtrAddress = reinterpret_cast<std::uintptr_t>(rawInfo->typeName.Buffer);
            const bool kInReplyBuffer =
                kPtrAddress >= kBufferBase &&
                kPtrAddress <= kBufferEnd &&
                kByteLength <= (kBufferEnd - kPtrAddress);
            const bool kExternalReadable =
                !kInReplyBuffer &&
                isReadableMemoryRange(rawInfo->typeName.Buffer, kByteLength);
            if (kInReplyBuffer || kExternalReadable)
            {
                typeNameText = QString::fromWCharArray(
                    rawInfo->typeName.Buffer,
                    rawInfo->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }

        // Path B: Fallback to reading the string immediately following the structure (compatible with legacy system layouts).
        if (typeNameText.trimmed().isEmpty() && rawInfo->typeName.Length > 0)
        {
            const std::uintptr_t kInlineNameAddress = entryAddress + sizeof(RawObjectTypeInformation);
            if (kInlineNameAddress + rawInfo->typeName.Length <= kBufferEnd)
            {
                typeNameText = QString::fromWCharArray(
                    reinterpret_cast<const wchar_t*>(kInlineNameAddress),
                    rawInfo->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }
        if (typeNameText.trimmed().isEmpty())
        {
            typeNameText = QStringLiteral("<UnknownType_%1>").arg(index);
        }

        // typeIndex fallback: fill by index when missing or duplicate to ensure mapping stability.
        std::uint32_t resolvedTypeIndex = static_cast<std::uint32_t>(rawInfo->typeIndex);
        if (resolvedTypeIndex == 0 || usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
        {
            resolvedTypeIndex = static_cast<std::uint32_t>(index + 1);
            while (usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
            {
                ++resolvedTypeIndex;
            }
        }
        usedTypeIndex.insert(resolvedTypeIndex);

        HandleObjectTypeEntry row{};
        row.typeIndex = resolvedTypeIndex;
        row.typeNameText = typeNameText;
        row.totalObjectCount = rawInfo->totalNumberOfObjects;
        row.totalHandleCount = rawInfo->totalNumberOfHandles;
        row.validAccessMask = rawInfo->validAccessMask;
        row.securityRequired = rawInfo->securityRequired != FALSE;
        row.maintainHandleCount = rawInfo->maintainHandleCount != FALSE;
        row.poolType = rawInfo->poolType;
        row.defaultPagedPoolCharge = rawInfo->defaultPagedPoolCharge;
        row.defaultNonPagedPoolCharge = rawInfo->defaultNonPagedPoolCharge;
        snapshotRows.push_back(std::move(row));

        // Advance to the next entry: structure + MaximumLength, then align to pointer size.
        const std::size_t kEntrySpan = alignUp(
            sizeof(RawObjectTypeInformation) + static_cast<std::size_t>(rawInfo->typeName.MaximumLength),
            sizeof(void*));
        if (kEntrySpan < sizeof(RawObjectTypeInformation))
        {
            break;
        }
        entryAddress += kEntrySpan;
        if (entryAddress >= kBufferEnd)
        {
            break;
        }
    }

    std::sort(
        snapshotRows.begin(),
        snapshotRows.end(),
        [](const HandleObjectTypeEntry& leftRow, const HandleObjectTypeEntry& rightRow)
        {
            if (leftRow.typeIndex == rightRow.typeIndex)
            {
                return QString::compare(leftRow.typeNameText, rightRow.typeNameText, Qt::CaseInsensitive) < 0;
            }
            return leftRow.typeIndex < rightRow.typeIndex;
        });

    rowsOut = std::move(snapshotRows);
    KLogEvent finishEvent;
    info << finishEvent
        << "[HandleObjectTypeWorker] 对象类型采集完成，条目数="
        << rowsOut.size()
        << eol;
    return true;
}

std::unordered_map<std::uint16_t, std::string> buildTypeNameMapFromObjectTypeRows(
    const std::vector<HandleObjectTypeEntry>& rows)
{
    std::unordered_map<std::uint16_t, std::string> resultMap;
    resultMap.reserve(rows.size());
    for (const HandleObjectTypeEntry& row : rows)
    {
        if (row.typeIndex > static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()))
        {
            continue;
        }
        resultMap[static_cast<std::uint16_t>(row.typeIndex)] = row.typeNameText.toStdString();
    }
    return resultMap;
}
