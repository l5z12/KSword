#include "KernelDockQueryWorker.h"

// ============================================================
// KernelDockQueryWorker.cpp
// Purpose:
// 1) Handle background data collection for KernelDock.
// 2) Separate time-consuming NtQuery logic from UI rendering;
// 3) Ensure the main UI thread is responsible only for display to avoid blocking.
// ============================================================

#include "../Framework.h"

#include <QStringList>

#include <algorithm>  // std::max/std::sort: Buffer expansion and sorting.
#include <array>      // std::array: Fixed buffer for FormatMessage.
#include <cstdint>    // std::uintXX_t: Explicit bit width.
#include <functional> // std::function: Unifies query callback signatures.
#include <unordered_set> // std::unordered_set: Detect TypeIndex conflicts and apply a fallback fix.
#include <vector>     // std::vector: Container for binary data and results.

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
    // NTSTATUS constants: Unified local definitions to prevent compilation errors due to missing macros.
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);

    // NtQueryObject information class constants: Avoid scattered magic numbers.
    constexpr ULONG kObjectNameInformationClass = 1;
    constexpr ULONG kObjectBasicInformationClass = 0;
    constexpr ULONG kObjectTypeInformationClass = 2;
    constexpr ULONG kObjectTypesInformationClass = 3;

    // Nt API function pointer types: Unified signature for Query call entry points.
    using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // NtApi: cache ntdll handle and function addresses to avoid repeated GetProcAddress calls.
    struct NtApi
    {
        HMODULE ntdllModule = nullptr;                      // ntdll module handle.
        NtQueryObjectFn queryObject = nullptr;              // NtQueryObject。
        NtQuerySystemInformationFn querySystem = nullptr;   // NtQuerySystemInformation。
        NtQueryInformationProcessFn queryProcess = nullptr; // NtQueryInformationProcess。
        NtQueryInformationThreadFn queryThread = nullptr;   // NtQueryInformationThread。
        NtQueryInformationTokenFn queryToken = nullptr;     // NtQueryInformationToken。
    };

    // RawObjectTypesHeader: Header returned by ObjectTypesInformation.
    struct RawObjectTypesHeader
    {
        ULONG numberOfTypes = 0; // Total number of type records.
    };

    // RawObjectTypeInformation: Object type record structure.
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
    // - Purpose: Loads ntdll and resolves addresses for common NtQuery* APIs.
    bool loadNtApi(NtApi& api, QString& errorTextOut)
    {
        errorTextOut.clear();
        api.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (api.ntdllModule == nullptr)
        {
            api.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (api.ntdllModule == nullptr)
        {
            errorTextOut = QStringLiteral("加载 ntdll.dll 失败。");
            return false;
        }

        api.queryObject = reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(api.ntdllModule, "NtQueryObject"));
        api.querySystem = reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(api.ntdllModule, "NtQuerySystemInformation"));
        api.queryProcess = reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationProcess"));
        api.queryThread = reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationThread"));
        api.queryToken = reinterpret_cast<NtQueryInformationTokenFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationToken"));

        if (api.queryObject == nullptr
            || api.querySystem == nullptr
            || api.queryProcess == nullptr
            || api.queryThread == nullptr
            || api.queryToken == nullptr)
        {
            errorTextOut = QStringLiteral("解析 NtQuery* 入口失败。");
            return false;
        }
        return true;
    }

    // isNeedGrowBufferStatus：
    // - Purpose: Determine if buffer expansion and retry are needed.
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    // ntStatusToText：
    // - Purpose: Convert status codes to hex + status text for UI display.
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();
        const QString kSuccessText = NT_SUCCESS(statusCode) ? QStringLiteral("SUCCESS") : QStringLiteral("FAILED");

        std::array<wchar_t, 256> buffer{};
        const DWORD kLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(statusCode),
            0,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr);
        if (kLength == 0)
        {
            return QStringLiteral("%1 (%2)").arg(kHexText, kSuccessText);
        }
        return QStringLiteral("%1 (%2) %3")
            .arg(kHexText, kSuccessText, QString::fromWCharArray(buffer.data()).trimmed());
    }

    // bytesPreview：
    // - Purpose: Output a 32-byte hexadecimal preview to avoid excessive UI detail length.
    QString bytesPreview(const std::vector<std::uint8_t>& bytes)
    {
        const std::size_t kPreviewSize = std::min<std::size_t>(bytes.size(), 32);
        if (kPreviewSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        QStringList parts;
        parts.reserve(static_cast<int>(kPreviewSize));
        for (std::size_t index = 0; index < kPreviewSize; ++index)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(static_cast<unsigned>(bytes[index]), 2, 16, QChar('0'))
                .toUpper());
        }
        return parts.join(' ');
    }

    // alignUp：
    // - Purpose: Align variable-length structure pointers upward according to platform alignment.
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
    // - Purpose: Checks if a memory range is readable to avoid access violations caused by blind pointer reads.
    // - Note: ObjectTypesInformation may return pointers outside the buffer on different
    //         systems. Perform a readability check first, then attempt to parse the type name.
    bool isReadableMemoryRange(const void* beginAddress, const std::size_t length)
    {
        // Null address or zero length is immediately deemed unreadable to avoid meaningless VirtualQuery calls.
        if (beginAddress == nullptr || length == 0)
        {
            return false;
        }

        // Use uintptr_t for address calculations to avoid truncation issues caused by 32/64-bit differences.
        std::uintptr_t currentAddress = reinterpret_cast<std::uintptr_t>(beginAddress);
        const std::uintptr_t kEndAddress = currentAddress + length;
        if (kEndAddress < currentAddress)
        {
            return false;
        }

        // Check memory regions segment by segment to ensure the entire range is readable.
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

            // Only committed pages are allowed; regions with NOACCESS or GUARD protection attributes are treated as unreadable.
            if (memoryInfo.State != MEM_COMMIT)
            {
                return false;
            }
            const DWORD kProtect = (memoryInfo.Protect & 0xFFU);
            if (kProtect == PAGE_NOACCESS || kProtect == PAGE_GUARD)
            {
                return false;
            }

            // Jump to the end of the current region and continue checking the next region.
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

    // parseUnicodeStringBuffer：
    // - Purpose: Extract text from the returned buffer according to UNICODE_STRING description.
    QString parseUnicodeStringBuffer(const std::vector<std::uint8_t>& buffer, const UNICODE_STRING& unicodeText)
    {
        if (buffer.empty() || unicodeText.Length == 0)
        {
            return QString();
        }

        const std::uint8_t* begin = buffer.data();
        const std::uint8_t* end = buffer.data() + buffer.size();
        const std::uint8_t* ptr = reinterpret_cast<const std::uint8_t*>(unicodeText.Buffer);
        if (ptr >= begin && (ptr + unicodeText.Length) <= end)
        {
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(ptr), unicodeText.Length / sizeof(wchar_t));
        }

        if (buffer.size() >= sizeof(UNICODE_STRING) + unicodeText.Length)
        {
            const wchar_t* fallbackText = reinterpret_cast<const wchar_t*>(begin + sizeof(UNICODE_STRING));
            return QString::fromWCharArray(fallbackText, unicodeText.Length / sizeof(wchar_t));
        }
        return QString();
    }

    // queryAutoBuffer：
    // - Purpose: Automatically expand the buffer and retry the query, hiding details of insufficient length.
    bool queryAutoBuffer(
        const std::function<NTSTATUS(void*, ULONG, ULONG*)>& queryFunction,
        std::vector<std::uint8_t>& outputBuffer,
        NTSTATUS& statusCodeOut,
        const ULONG initialSize = 4096)
    {
        statusCodeOut = kStatusUnsuccessful;
        ULONG bufferSize = std::max<ULONG>(initialSize, 256);

        for (int retry = 0; retry < 8; ++retry)
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

    // enumerateNtQueryExports：
    // - Purpose: Extract NtQuery*Information names from the ntdll export table.
    QStringList enumerateNtQueryExports(HMODULE ntdllModule)
    {
        QStringList result;
        if (ntdllModule == nullptr)
        {
            return result;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdllModule);
        if (dosHeader == nullptr || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return result;
        }
        const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + dosHeader->e_lfanew);
        if (ntHeader == nullptr || ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return result;
        }

        const IMAGE_DATA_DIRECTORY kExportDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (kExportDir.VirtualAddress == 0 || kExportDir.Size == 0)
        {
            return result;
        }

        const auto* exportInfo = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + kExportDir.VirtualAddress);
        const auto* nameRvaArray = reinterpret_cast<const DWORD*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + exportInfo->AddressOfNames);
        if (exportInfo == nullptr || nameRvaArray == nullptr || exportInfo->NumberOfNames == 0)
        {
            return result;
        }

        for (DWORD index = 0; index < exportInfo->NumberOfNames; ++index)
        {
            const char* name = reinterpret_cast<const char*>(
                reinterpret_cast<const std::uint8_t*>(ntdllModule) + nameRvaArray[index]);
            if (name == nullptr)
            {
                continue;
            }

            const QString kNameText = QString::fromLatin1(name);
            if (kNameText.startsWith(QStringLiteral("NtQuery"), Qt::CaseInsensitive)
                && kNameText.contains(QStringLiteral("Information"), Qt::CaseInsensitive))
            {
                result.push_back(kNameText);
            }
        }

        result.sort(Qt::CaseInsensitive);
        return result;
    }

    // appendResult：
    // - Purpose: Populate a single NtQuery result row with unified field write logic.
    void appendResult(
        std::vector<KernelNtQueryResultEntry>& resultList,
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const NTSTATUS statusCode,
        const QString& statusText,
        const QString& summaryText,
        const QString& detailText)
    {
        KernelNtQueryResultEntry entry;
        entry.categoryText = categoryText;
        entry.functionNameText = functionText;
        entry.queryItemText = itemText;
        entry.statusCode = statusCode;
        entry.statusText = statusText;
        entry.summaryText = summaryText;
        entry.detailText = detailText;
        resultList.push_back(std::move(entry));
    }
}

bool runKernelTypeSnapshotTask(std::vector<KernelObjectTypeEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    KLogEvent beginEvent;
    info << beginEvent << "[KernelDockWorker] 开始采集内核对象类型。" << eol;

    NtApi api;
    if (!loadNtApi(api, errorTextOut))
    {
        KLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 加载 NtApi 失败: " << errorTextOut.toStdString() << eol;
        return false;
    }

    std::vector<std::uint8_t> buffer;
    NTSTATUS statusCode = kStatusUnsuccessful;
    const bool kSuccess = queryAutoBuffer(
        [&api](void* out, ULONG len, ULONG* ret) -> NTSTATUS {
            return api.queryObject(nullptr, kObjectTypesInformationClass, out, len, ret);
        },
        buffer,
        statusCode,
        64 * 1024U);
    if (!kSuccess || !NT_SUCCESS(statusCode))
    {
        errorTextOut = QStringLiteral("NtQueryObject(ObjectTypesInformation)失败: %1")
            .arg(ntStatusToText(api.ntdllModule, statusCode));
        KLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 查询对象类型失败: " << errorTextOut.toStdString() << eol;
        return false;
    }
    if (buffer.size() < sizeof(RawObjectTypesHeader))
    {
        errorTextOut = QStringLiteral("返回数据长度不足。");
        KLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 查询对象类型失败: 返回缓冲区长度不足。" << eol;
        return false;
    }

    std::vector<KernelObjectTypeEntry> resultRows;
    resultRows.reserve(reinterpret_cast<const RawObjectTypesHeader*>(buffer.data())->numberOfTypes);

    // Here, we follow the Ksword5.0 logic to align the header before the pointer. This is key to fixing
    // garbled data or misalignment: on x64, there is typically 4 bytes of padding after NumberOfTypes.
    const std::uintptr_t kBufferBase = reinterpret_cast<std::uintptr_t>(buffer.data());
    const std::uintptr_t kBufferEnd = kBufferBase + buffer.size();
    const auto* header = reinterpret_cast<const RawObjectTypesHeader*>(buffer.data());
    std::uintptr_t entryAddress = alignUp(
        kBufferBase + sizeof(RawObjectTypesHeader),
        sizeof(void*));

    // usedTypeIndex: Handles cases where TypeIndex is invalid or duplicated under old systems or special structures.
    std::unordered_set<std::uint32_t> usedTypeIndex;
    usedTypeIndex.reserve(header->numberOfTypes);

    for (ULONG index = 0; index < header->numberOfTypes; ++index)
    {
        // Boundary check: Stop immediately if remaining space is insufficient for one structure to avoid out-of-bounds access.
        if (entryAddress + sizeof(RawObjectTypeInformation) > kBufferEnd)
        {
            KLogEvent boundaryEvent;
            warn << boundaryEvent
                << "[KernelDockWorker] 解析对象类型提前结束：entryAddress越界，index="
                << static_cast<unsigned long long>(index)
                << eol;
            break;
        }

        const auto* raw = reinterpret_cast<const RawObjectTypeInformation*>(entryAddress);
        QString typeName;

        // First, follow the legacy project logic to prioritize decoding directly from TypeName.Buffer.
        if (raw->typeName.Buffer != nullptr && raw->typeName.Length > 0)
        {
            const std::size_t kNameByteLength = raw->typeName.Length;
            const auto* directBuffer = raw->typeName.Buffer;

            // If the buffer points within the reply buffer, read directly; otherwise, perform a readability probe before reading.
            const std::uintptr_t kDirectAddress = reinterpret_cast<std::uintptr_t>(directBuffer);
            const bool kInReplyBuffer =
                kDirectAddress >= kBufferBase &&
                kDirectAddress <= kBufferEnd &&
                kNameByteLength <= (kBufferEnd - kDirectAddress);
            const bool kExternalReadable = !kInReplyBuffer &&
                isReadableMemoryRange(directBuffer, kNameByteLength);
            if (kInReplyBuffer || kExternalReadable)
            {
                typeName = QString::fromWCharArray(
                    directBuffer,
                    raw->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }

        // Fallback compatibility: If the directBuffer approach fails, attempt parsing as "struct immediately followed by string".
        if (typeName.trimmed().isEmpty() && raw->typeName.Length > 0)
        {
            const std::uintptr_t kInlineNameAddress = entryAddress + sizeof(RawObjectTypeInformation);
            if (kInlineNameAddress + raw->typeName.Length <= kBufferEnd)
            {
                typeName = QString::fromWCharArray(
                    reinterpret_cast<const wchar_t*>(kInlineNameAddress),
                    raw->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }
        if (typeName.trimmed().isEmpty())
        {
            typeName = QStringLiteral("<UnknownType_%1>").arg(index);
        }

        // Read TypeIndex:
        // - New systems generally yield the correct value directly;
        // - If the value is 0 or a conflict occurs, assign a fallback ID based on the enumeration index to ensure 'all types have an ID'.
        std::uint32_t resolvedTypeIndex = static_cast<std::uint32_t>(raw->typeIndex);
        if (resolvedTypeIndex == 0 || usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
        {
            resolvedTypeIndex = static_cast<std::uint32_t>(index + 1);
            while (usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
            {
                ++resolvedTypeIndex;
            }
        }
        usedTypeIndex.insert(resolvedTypeIndex);

        KernelObjectTypeEntry entry;
        entry.typeIndex = resolvedTypeIndex;
        entry.typeNameText = typeName;
        entry.totalObjectCount = raw->totalNumberOfObjects;
        entry.totalHandleCount = raw->totalNumberOfHandles;
        entry.validAccessMask = raw->validAccessMask;
        entry.securityRequired = raw->securityRequired != FALSE;
        entry.maintainHandleCount = raw->maintainHandleCount != FALSE;
        entry.poolType = raw->poolType;
        entry.defaultPagedPoolCharge = raw->defaultPagedPoolCharge;
        entry.defaultNonPagedPoolCharge = raw->defaultNonPagedPoolCharge;
        resultRows.push_back(std::move(entry));

        // Advance by struct size plus TypeName.MaximumLength, and align to the next entry by pointer size.
        const std::size_t kEntrySpan = alignUp(
            sizeof(RawObjectTypeInformation) + static_cast<std::size_t>(raw->typeName.MaximumLength),
            sizeof(void*));
        if (kEntrySpan < sizeof(RawObjectTypeInformation))
        {
            KLogEvent spanEvent;
            warn << spanEvent
                << "[KernelDockWorker] 解析对象类型提前结束：entrySpan异常，index="
                << static_cast<unsigned long long>(index)
                << eol;
            break;
        }

        entryAddress += kEntrySpan;
        if (entryAddress >= kBufferEnd)
        {
            break;
        }
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelObjectTypeEntry& left, const KernelObjectTypeEntry& right) {
        if (left.typeIndex == right.typeIndex)
        {
            return QString::compare(left.typeNameText, right.typeNameText, Qt::CaseInsensitive) < 0;
        }
        return left.typeIndex < right.typeIndex;
    });

    rowsOut = std::move(resultRows);
    KLogEvent finishEvent;
    info << finishEvent << "[KernelDockWorker] 内核对象类型采集完成，数量=" << rowsOut.size() << eol;
    return true;
}

bool runNtQuerySnapshotTask(std::vector<KernelNtQueryResultEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    KLogEvent beginEvent;
    info << beginEvent << "[KernelDockWorker] 开始采集 NtQuery 信息。" << eol;

    NtApi api;
    if (!loadNtApi(api, errorTextOut))
    {
        KLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 加载 NtApi 失败: " << errorTextOut.toStdString() << eol;
        return false;
    }

    const QStringList kExportList = enumerateNtQueryExports(api.ntdllModule);
    for (const QString& exportName : kExportList)
    {
        appendResult(
            rowsOut,
            QStringLiteral("导出"),
            exportName,
            QStringLiteral("导出入口"),
            kStatusSuccess,
            QStringLiteral("已枚举"),
            QStringLiteral("未直接调用"),
            QStringLiteral("该 NtQuery*Information 导出已发现，部分接口需专用参数结构。"));
    }

    auto appendQueryResult = [&rowsOut, &api](
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const NTSTATUS statusCode,
        const std::vector<std::uint8_t>& buffer)
        {
            const QString kStatusText = ntStatusToText(api.ntdllModule, statusCode);
            const QString kSummaryText = NT_SUCCESS(statusCode)
                ? QStringLiteral("返回 %1 字节").arg(buffer.size())
                : QStringLiteral("调用失败");
            const QString kDetailText = NT_SUCCESS(statusCode)
                ? QStringLiteral("十六进制预览: %1").arg(bytesPreview(buffer))
                : kStatusText;
            appendResult(rowsOut, categoryText, functionText, itemText, statusCode, kStatusText, kSummaryText, kDetailText);

            KLogEvent event;
            dbg << event
                << "[KernelDockWorker] 查询完成 category="
                << categoryText.toStdString()
                << ", func="
                << functionText.toStdString()
                << ", item="
                << itemText.toStdString()
                << ", status="
                << kStatusText.toStdString()
                << ", bytes="
                << buffer.size()
                << eol;
        };

    auto callQuery = [&appendQueryResult](
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const std::function<NTSTATUS(void*, ULONG, ULONG*)>& queryFunction,
        const ULONG initialSize = 4096)
        {
            std::vector<std::uint8_t> buffer;
            NTSTATUS statusCode = kStatusUnsuccessful;
            queryAutoBuffer(queryFunction, buffer, statusCode, initialSize);
            appendQueryResult(categoryText, functionText, itemText, statusCode, buffer);
        };

    // System-level NtQuerySystemInformation.
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(0, out, len, ret); }, 2048);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemPerformanceInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(2, out, len, ret); }, 4096);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemTimeOfDayInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(3, out, len, ret); }, 2048);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemProcessInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(5, out, len, ret); }, 64 * 1024U);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemModuleInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(11, out, len, ret); }, 64 * 1024U);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemHandleInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(16, out, len, ret); }, 64 * 1024U);

    // Process-level NtQueryInformationProcess.
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 0, out, len, ret); }, 512);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessHandleCount"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 20, out, len, ret); }, 256);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessImageFileName"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 27, out, len, ret); }, 2048);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessDebugPort"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 7, out, len, ret); }, 64);

    // Thread-level NtQueryInformationThread.
    callQuery(QStringLiteral("线程"), QStringLiteral("NtQueryInformationThread"), QStringLiteral("ThreadBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryThread(::GetCurrentThread(), 0, out, len, ret); }, 512);
    callQuery(QStringLiteral("线程"), QStringLiteral("NtQueryInformationThread"), QStringLiteral("ThreadTimes"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryThread(::GetCurrentThread(), 1, out, len, ret); }, 512);

    // Token-level NtQueryInformationToken.
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenUser"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenUser), out, len, ret); }, 512);
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenIntegrityLevel"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenIntegrityLevel), out, len, ret); }, 512);
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenStatistics"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenStatistics), out, len, ret); }, 512);
        ::CloseHandle(tokenHandle);
    }
    else
    {
        KLogEvent warnEvent;
        warn << warnEvent << "[KernelDockWorker] OpenProcessToken 失败，跳过令牌类查询。" << eol;
        appendResult(
            rowsOut,
            QStringLiteral("令牌"),
            QStringLiteral("OpenProcessToken"),
            QStringLiteral("TOKEN_QUERY"),
            kStatusUnsuccessful,
            QStringLiteral("OpenProcessToken失败"),
            QStringLiteral("跳过令牌查询"),
            QStringLiteral("无法打开当前进程令牌，令牌类 NtQuery 未执行。"));
    }

    // Object-level NtQueryObject.
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectBasicInformationClass, out, len, ret); }, 512);
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectNameInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectNameInformationClass, out, len, ret); }, 2048);
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectTypeInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectTypeInformationClass, out, len, ret); }, 1024);

    KLogEvent finishEvent;
    info << finishEvent
        << "[KernelDockWorker] NtQuery 信息采集完成，结果条目="
        << rowsOut.size()
        << ", 导出函数数="
        << kExportList.size()
        << eol;
    return true;
}
