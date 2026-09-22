// ============================================================
// MinidumpParser.cpp
// Purpose:
// - Implements the dump parsing entry point parseDumpFile: maps the file, checks the signature, and dispatches.
// - Implement the main parsing flow for MDMP user-mode dumps (header, stream directory, and overview
//   assembly); specific stream parsing implementations are located in MinidumpParser.Streams.cpp.
// - Implement shared common helper functions for two files (hex/time formatting,
//   MINIDUMP_STRING reading, stream directory lookup, and context instruction pointer retrieval).
// - All file access goes through DumpFileView boundary checks; malformed samples
//   will only yield diagnostic information without causing out-of-bounds access.
// Structure source:
// - MDMP-related structures must use the official SDK definitions
//   (minidumpapiset.h) to avoid layout errors from manual implementation.
// ============================================================

#include "MinidumpParser.h"

#include "DumpAnalyzer.h"
#include "DumpContextRegisters.h"
#include "KernelDumpParser.h"
#include "MinidumpCodeText.h"
#include "MinidumpParser.Internal.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>

#include <algorithm>

namespace ks::minidump
{
    namespace detail
    {
        QString hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
        }

        QString timeTToText(const std::uint64_t secondsSince1970)
        {
            if (secondsSince1970 == 0)
            {
                return QString();
            }
            return QDateTime::fromSecsSinceEpoch(
                static_cast<qint64>(secondsSince1970))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }

        QString byteCountText(const std::uint64_t bytes)
        {
            // units: unit table from bytes to TB; index is the selected unit index.
            const char* const kUnits[] = { "B", "KB", "MB", "GB", "TB" };
            double scaled = static_cast<double>(bytes);
            int index = 0;
            while (scaled >= 1024.0 && index < 4)
            {
                scaled /= 1024.0;
                ++index;
            }
            if (index == 0)
            {
                return QStringLiteral("%1 B").arg(bytes);
            }
            return QStringLiteral("%1 %2 (%3 字节)")
                .arg(QString::number(scaled, 'f', 1))
                .arg(QString::fromLatin1(kUnits[index]))
                .arg(bytes);
        }

        QString readMinidumpString(const DumpFileView& view, const std::uint64_t rva)
        {
            if (rva == 0)
            {
                return QString();
            }
            // lengthBytes: The string byte count (excluding the terminator); read the length first, then validate the data region.
            ULONG32 lengthBytes = 0;
            if (!view.readStruct(rva, &lengthBytes) || lengthBytes > kMaxStringBytes)
            {
                return QString();
            }
            const unsigned char* const kTextData = view.at(rva + sizeof(ULONG32), lengthBytes);
            if (kTextData == nullptr)
            {
                return QString();
            }
            return QString::fromUtf16(
                reinterpret_cast<const char16_t*>(kTextData),
                static_cast<qsizetype>(lengthBytes / sizeof(char16_t)));
        }

        bool findStream(
            const DumpFileView& view,
            const std::uint64_t directoryRva,
            const std::uint32_t streamCount,
            const std::uint32_t streamType,
            MINIDUMP_LOCATION_DESCRIPTOR* const locationOut)
        {
            for (std::uint32_t index = 0; index < streamCount; ++index)
            {
                // entry: The index-th directory entry; the directory itself requires boundary validation.
                MINIDUMP_DIRECTORY entry{};
                if (!view.readStruct(directoryRva + static_cast<std::uint64_t>(index) * sizeof(MINIDUMP_DIRECTORY), &entry))
                {
                    return false;
                }
                if (entry.StreamType == streamType && entry.Location.Rva != 0)
                {
                    *locationOut = entry.Location;
                    return true;
                }
            }
            return false;
        }

        // Instruction pointer offset is based on the official CONTEXT layout for each architecture:
        // x64 Rip=0xF8，x86 Eip=0xB8，ARM64 Pc=0x108。
        std::uint64_t instructionPointerFromContext(
            const DumpFileView& view,
            const MINIDUMP_LOCATION_DESCRIPTOR& contextLocation,
            const std::uint16_t architecture)
        {
            if (contextLocation.Rva == 0)
            {
                return 0;
            }
            // ipOffset/ipSize: Offset and width of the instruction pointer within the CONTEXT for the target architecture.
            std::uint64_t ipOffset = 0;
            std::uint32_t ipSize = 0;
            switch (architecture)
            {
            case PROCESSOR_ARCHITECTURE_AMD64:
                ipOffset = 0xF8;
                ipSize = 8;
                break;
            case PROCESSOR_ARCHITECTURE_INTEL:
                ipOffset = 0xB8;
                ipSize = 4;
                break;
            case PROCESSOR_ARCHITECTURE_ARM64:
                ipOffset = 0x108;
                ipSize = 8;
                break;
            default:
                return 0;
            }
            if (contextLocation.DataSize < ipOffset + ipSize)
            {
                return 0;
            }
            if (ipSize == 8)
            {
                std::uint64_t value = 0;
                return view.readStruct(contextLocation.Rva + ipOffset, &value) ? value : 0;
            }
            std::uint32_t value32 = 0;
            return view.readStruct(contextLocation.Rva + ipOffset, &value32) ? value32 : 0;
        }
    }

    namespace
    {
        using namespace detail;

        // kMaxFaultingThreadFrames: Maximum number of frames to reconstruct for the crashing thread's call stack.
        constexpr int kMaxFaultingThreadFrames = 64;
        // kMaxOtherThreadFrames: Maximum number of frames to reconstruct per remaining thread.
        constexpr int kMaxOtherThreadFrames = 24;
        // kMaxScannedThreads: Maximum number of threads to scan stacks for, to avoid flooding the output when thread count is high.
        constexpr std::size_t kMaxScannedThreads = 32;

        // parseUserMinidump: Main parsing flow for MDMP user-mode dumps.
        // Accepts view (file view) and result (output); parses and assembles an overview stream by stream.
        // The stream parsing order is not arbitrary: modules must be parsed first because exception addresses, thread
        // instruction pointers, call stacks, and attribution all depend on the module address index; the memory index
        //can only be finalized after all memory sources (memory streams + thread stacks) have been registered.
        void parseUserMinidump(const DumpFileView& view, DumpParseResult& result)
        {
            result.kind = DumpKind::kUserMinidump;
            result.recognized = true;

            MINIDUMP_HEADER header{};
            if (!view.readStruct(0, &header))
            {
                result.errorText = QStringLiteral("文件过小，无法读取 MDMP 头。");
                return;
            }
            // The directory must be fully contained within the file; otherwise, treat it as a truncated, corrupted dump.
            const std::uint64_t kDirectoryBytes =
                static_cast<std::uint64_t>(header.NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY);
            if (!view.contains(header.StreamDirectoryRva, kDirectoryBytes))
            {
                result.errorText = QStringLiteral("流目录越界，转储文件已截断或损坏。");
                return;
            }

            // The overview first provides file-level information: category, version, stream count, write time, and type flags.
            result.overview.push_back({ QStringLiteral("转储类别"),
                QStringLiteral("用户态 MDMP 小型转储") });
            result.overview.push_back({ QStringLiteral("文件大小"),
                byteCountText(result.fileSize) });
            result.overview.push_back({ QStringLiteral("格式版本"),
                QString::number(header.Version & 0xFFFFu) });
            result.overview.push_back({ QStringLiteral("流数量"),
                QString::number(header.NumberOfStreams) });
            result.overview.push_back({ QStringLiteral("写入时间"),
                timeTToText(header.TimeDateStamp) });
            result.overview.push_back({ QStringLiteral("转储类型标志"),
                dumpTypeFlagText(header.Flags) });

            // Stream directory page: list all directory entries (including unknown types).
            // Must enforce the same parsing limit as other lists: NumberOfStreams comes directly from the
            // file. The previous 'contains' check only limits it to fileSize/12, but each StreamEntry
            // carries two QStrings (approx. 72 bytes), potentially expanding to ~6x the file size. Since
            // parsing runs in a thread pool worker without try/catch, a std::bad_alloc will escape and
            // trigger std::terminate, crashing the entire process rather than reporting a parse failure.
            const std::uint64_t kSafeStreamCount =
                std::min<std::uint64_t>(header.NumberOfStreams, kMaxListEntries);
            if (kSafeStreamCount != header.NumberOfStreams)
            {
                result.diagnostics.append(
                    QStringLiteral("流数量 %1 超过解析上限，仅展示前 %2 条。")
                        .arg(header.NumberOfStreams)
                        .arg(kSafeStreamCount));
            }
            result.streams.reserve(static_cast<std::size_t>(kSafeStreamCount));
            for (std::uint64_t index = 0; index < kSafeStreamCount; ++index)
            {
                MINIDUMP_DIRECTORY entry{};
                if (!view.readStruct(
                        header.StreamDirectoryRva +
                            static_cast<std::uint64_t>(index) * sizeof(MINIDUMP_DIRECTORY),
                        &entry))
                {
                    break;
                }
                StreamEntry streamEntry{};
                streamEntry.type = entry.StreamType;
                streamEntry.typeName = streamTypeName(entry.StreamType);
                if (streamEntry.typeName.isEmpty())
                {
                    streamEntry.typeName = QStringLiteral("未知流 (%1)").arg(entry.StreamType);
                }
                streamEntry.rva = entry.Location.Rva;
                streamEntry.size = entry.Location.DataSize;
                streamEntry.note = streamTypeNote(entry.StreamType);
                // List streams whose data regions are out of bounds, but add warnings to identify truncated samples.
                if (entry.Location.DataSize != 0 &&
                    !view.contains(entry.Location.Rva, entry.Location.DataSize))
                {
                    streamEntry.note = QStringLiteral("数据区越界（文件截断） ") + streamEntry.note;
                    result.diagnostics.append(
                        QStringLiteral("流 %1 的数据区越界，相关内容可能缺失。")
                            .arg(streamEntry.typeName));
                }
                result.streams.push_back(std::move(streamEntry));
            }

            // architecture: CPU architecture required for parsing thread and exception contexts.
            std::uint16_t architecture = 0xFFFF;
            MINIDUMP_LOCATION_DESCRIPTOR location{};
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    SystemInfoStream, &location))
            {
                parseSystemInfo(view, location, result, &architecture);
            }
            // contextArch/pointerSize: Used as the step size for subsequent CONTEXT extraction and stack scanning.
            const ContextArch kContextArch = contextArchFromProcessorArchitecture(architecture);
            result.pointerSize = contextPointerSize(kContextArch);
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    MiscInfoStream, &location))
            {
                parseMiscInfo(view, location, result);
            }
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ProcessVmCountersStream, &location))
            {
                parseProcessVmCounters(view, location, result);
            }

            // ---------- Modules are parsed first: subsequent steps must use module addresses for indexing ----------
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ModuleListStream, &location))
            {
                parseModuleList(view, location, result);
            }
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    UnloadedModuleListStream, &location))
            {
                parseUnloadedModuleList(view, location, result);
            }
            // modules: Address-to-module interval index.
            ModuleIndex modules;
            modules.build(result.modules, result.unloadedModules, result.pointerSize);

            // ---------- Memory: Register all sources first, then finalize uniformly at the end. ----------
            // memory: Virtual address index of captured memory; required for validating call instructions during stack scanning.
            DumpMemoryReader memory;
            parseMemoryLists(
                view, header.StreamDirectoryRva, header.NumberOfStreams, result, &memory);

            // faultingThreadId: The crashing thread referenced by the exception stream, used for thread table marking and stack scan priority.
            std::uint32_t faultingThreadId = 0xFFFFFFFFu;
            // faultingContext: the location of the crash thread's CONTEXT, serving as the source for the register snapshot.
            MINIDUMP_LOCATION_DESCRIPTOR faultingContext{};
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ExceptionStream, &location))
            {
                parseExceptionStream(
                    view, location, architecture, modules, result,
                    &faultingThreadId, &faultingContext);
            }

            // Thread: Prefer the standard list; if unavailable, try the extended list; then merge and supplement with additional streams.
            // scanInputs: Stack memory locations for each thread, used later for unified call stack reconstruction.
            std::vector<StackScanInput> scanInputs;
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ThreadListStream, &location))
            {
                parseThreadList(view, location, false, architecture, faultingThreadId,
                    modules, result, &scanInputs, &memory);
            }
            else if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ThreadExListStream, &location))
            {
                parseThreadList(view, location, true, architecture, faultingThreadId,
                    modules, result, &scanInputs, &memory);
            }
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    ThreadInfoListStream, &location))
            {
                parseThreadInfoList(view, location, result);
            }
            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    static_cast<std::uint32_t>(24) /* ThreadNamesStream */, &location))
            {
                parseThreadNames(view, location, result);
            }
            // Memory indices can only be finalized after all thread stacks are registered.
            memory.finalize(view);
            // The memory index parsed during this phase is destroyed after the function returns. Return the validated lightweight mapping with
            // the result to the UI so the viewer can reopen the DMP in read-only mode later without keeping the entire file resident in memory.
            memory.appendCapturedRanges(&result.capturedMemoryRanges);

            // Module ownership of the start address can only be determined after ThreadInfoList is merged.
            for (ThreadEntry& thread : result.threads)
            {
                if (thread.startAddress != 0)
                {
                    thread.startSymbolText = modules.symbolText(thread.startAddress);
                }
            }

            // ---------- Crash-point registers ---------- Registers are provided only when
            // an exception record exists: snapshot dumps without exceptions have no "crash
            // point," and displaying registers from an arbitrary thread would be misleading.
            if (faultingContext.Rva != 0)
            {
                result.registers = readContextRegisters(
                    view,
                    faultingContext.Rva,
                    faultingContext.DataSize,
                    kContextArch,
                    faultingThreadId,
                    modules);
            }

            // ---------- Call stack reconstruction ---------- Place the crashing
            // thread first with more frames; truncate other threads at the limit.
            std::stable_sort(
                scanInputs.begin(),
                scanInputs.end(),
                [faultingThreadId](const StackScanInput& left, const StackScanInput& right)
                {
                    const bool kLeftFaulting = left.threadId == faultingThreadId;
                    const bool kRightFaulting = right.threadId == faultingThreadId;
                    return kLeftFaulting && !kRightFaulting;
                });
            const std::size_t kScanCount =
                std::min<std::size_t>(scanInputs.size(), kMaxScannedThreads);
            for (std::size_t index = 0; index < kScanCount; ++index)
            {
                const StackScanInput& input = scanInputs[index];
                const int kFrameLimit = input.threadId == faultingThreadId
                    ? kMaxFaultingThreadFrames
                    : kMaxOtherThreadFrames;
                const std::vector<StackFrameEntry> kFrames =
                    scanStackFrames(view, input, modules, memory, kFrameLimit);
                result.stackFrames.insert(
                    result.stackFrames.end(), kFrames.begin(), kFrames.end());
            }
            if (scanInputs.size() > kScanCount)
            {
                result.diagnostics.append(
                    QStringLiteral("线程数 %1 较多，只对前 %2 个线程重建了调用栈。")
                        .arg(scanInputs.size())
                        .arg(kScanCount));
            }

            if (findStream(view, header.StreamDirectoryRva, header.NumberOfStreams,
                    HandleDataStream, &location))
            {
                parseHandleData(view, location, result);
            }
            parseComments(view, header.StreamDirectoryRva, header.NumberOfStreams, result);

            // Add summary statistics to the overview so users can gauge scale without clicking into sub-pages.
            result.overview.push_back({ QStringLiteral("线程数"),
                QString::number(result.threads.size()) });
            result.overview.push_back({ QStringLiteral("模块数"),
                QString::number(result.modules.size()) });
            if (result.memoryRegionTotal != 0)
            {
                result.overview.push_back({ QStringLiteral("内存区域数"),
                    QString::number(result.memoryRegionTotal) });
            }
            if (!result.handles.empty())
            {
                result.overview.push_back({ QStringLiteral("句柄数"),
                    QString::number(result.handles.size()) });
            }
            if (memory.rangeCount() != 0)
            {
                result.overview.push_back({ QStringLiteral("已捕获内存块数"),
                    QString::number(memory.rangeCount()) });
            }

            // ---------- Attribution Conclusion ----------
            buildAnalysis(modules, result);
            result.success = true;
        }
    }

    DumpParseResult parseDumpFile(const QString& filePath)
    {
        // result: The sole return value; first records the file path and size, then progressively fills in other details.
        DumpParseResult result{};
        result.filePath = filePath;

        QFile dumpFile(filePath);
        const QFileInfo kFileInfo(filePath);
        if (!kFileInfo.exists() || !kFileInfo.isFile())
        {
            result.errorText = QStringLiteral("文件不存在或不是普通文件。");
            return result;
        }
        if (!dumpFile.open(QIODevice::ReadOnly))
        {
            result.errorText = QStringLiteral("无法打开文件（可能被占用或权限不足）：%1")
                .arg(dumpFile.errorString());
            return result;
        }
        result.fileSize = static_cast<std::uint64_t>(dumpFile.size());
        result.fileLastModifiedUtcMs = kFileInfo.lastModified().toUTC().toMSecsSinceEpoch();
        if (result.fileSize < 8)
        {
            result.errorText = QStringLiteral("文件过小，不可能是有效转储。");
            return result;
        }

        // mapped: Read-only mapping of the entire file; QFile remains open during parsing and the mapping is automatically unmapped before returning.
        uchar* const kMapped = dumpFile.map(0, static_cast<qint64>(result.fileSize));
        if (kMapped == nullptr)
        {
            result.errorText = QStringLiteral("文件映射失败（文件过大或系统资源不足）。");
            return result;
        }
        DumpFileView view{};
        view.data = kMapped;
        view.size = result.fileSize;

        // signature/validDump: Determines the format based on the first 8 bytes.
        std::uint32_t signature = 0;
        std::uint32_t validDump = 0;
        view.readStruct(0, &signature);
        view.readStruct(4, &validDump);
        if (signature == 0x504D444Du) // 'MDMP'
        {
            parseUserMinidump(view, result);
        }
        else if (signature == 0x45474150u && validDump == 0x34365544u) // 'PAGE' + 'DU64'
        {
            parseKernelDump64(view, result);
        }
        else if (signature == 0x45474150u && validDump == 0x504D5544u) // 'PAGE' + 'DUMP'
        {
            parseKernelDump32(view, result);
        }
        else
        {
            result.errorText = QStringLiteral(
                "无法识别的文件签名 %1：既不是 MDMP 用户态转储，也不是 PAGEDUMP/PAGEDU64 内核转储。")
                .arg(detail::hex(signature));
        }
        dumpFile.unmap(kMapped);
        return result;
    }
}
