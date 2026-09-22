// ============================================================
// MinidumpParser.Streams.cpp
// Purpose:
// - Implement parsing of specific streams in MDMP user-mode dumps.
//   System information, miscellaneous information, exception, threads (including supplementary streams),
//   modules, unloaded modules, memory (three sources), handles, comment streams, and dump type flag text;
// - Shares helper functions and parsing limit constants
//   with MinidumpParser.cpp via MinidumpParser.Internal.h;
// - All offset accesses are boundary-checked via DumpFileView, ensuring safe degradation for malformed samples.
// ============================================================

#include "MinidumpParser.Internal.h"

#include "DumpContextRegisters.h"
#include "MinidumpCodeText.h"

#include <QDateTime>

#include <algorithm>

namespace ks::minidump::detail
{
    namespace
    {
        // Local definition for MinidumpThreadNameHeader/Entry in ThreadNamesStream (24).
        // Old SDKs may lack MINIDUMP_THREAD_NAME_LIST; declare using official layout with pack(4).
#pragma pack(push, 4)
        struct MinidumpThreadNameHeader
        {
            ULONG32 numberOfThreadNames; // NumberOfThreadNames: Number of thread name entries.
        };
        struct MinidumpThreadNameEntry
        {
            ULONG32 threadId;        // ThreadId: Thread ID.
            ULONG64 rvaOfThreadName; // RvaOfThreadName: 64-bit RVA of the MINIDUMP_STRING.
        };
#pragma pack(pop)
        static_assert(sizeof(MinidumpThreadNameEntry) == 12, "线程名条目必须是 pack(4) 的 12 字节");

#pragma pack(push, 4)
        // MinidumpProcessVmCounters1: Revision 1 layout for ProcessVmCountersStream (22).
        // Old SDKs may not have MINIDUMP_PROCESS_VM_COUNTERS_1; declare locally with the official pack(4) layout.
        struct MinidumpProcessVmCounters1
        {
            std::uint16_t revision;                  // Revision: Structure version; 1 is the base version.
            std::uint32_t pageFaultCount;            // PageFaultCount: Cumulative page fault count for the process.
            std::uint64_t peakWorkingSetSize;        // PeakWorkingSetSize: Peak working set size.
            std::uint64_t workingSetSize;            // WorkingSetSize: Working set at crash time.
            std::uint64_t quotaPeakPagedPoolUsage;   // QuotaPeakPagedPoolUsage: Peak paged pool usage.
            std::uint64_t quotaPagedPoolUsage;       // QuotaPagedPoolUsage: Current paged pool usage.
            std::uint64_t quotaPeakNonPagedPoolUsage; // QuotaPeakNonPagedPoolUsage: Peak non-paged pool usage.
            std::uint64_t quotaNonPagedPoolUsage;    // QuotaNonPagedPoolUsage: Current non-paged pool usage.
            std::uint64_t pagefileUsage;             // PagefileUsage: Current committed amount.
            std::uint64_t peakPagefileUsage;         // PeakPagefileUsage: Peak committed memory.
            std::uint64_t privateUsage;              // PrivateUsage: private byte count.
        };
        static_assert(sizeof(MinidumpProcessVmCounters1) == 80,
            "MINIDUMP_PROCESS_VM_COUNTERS_1 必须是 pack(4) 的 80 字节");

        // MinidumpProcessVmCounters2: Revision 2 layout.
        // Key difference: **PeakVirtualSize** and **VirtualSize** were **inserted** after **PeakPagefileUsage**,
        // shifting **PrivateUsage** down by 16 bytes. Reading a Revision 2 stream using the Revision 1 layout
        // would misinterpret "peak virtual address space" as "private bytes"—for processes like Chromium/WebView2
        // that reserve massive address spaces, this would falsely report hundreds of GB of private memory.
        struct MinidumpProcessVmCounters2
        {
            std::uint16_t revision;                  // Revision: structure version; use this layout for version 2 and above.
            std::uint16_t flags;                     // Flags: Which field groups are valid (MINIDUMP_PROCESS_VM_COUNTERS_*).
            std::uint32_t pageFaultCount;            // PageFaultCount: Cumulative page fault count for the process.
            std::uint64_t peakWorkingSetSize;        // PeakWorkingSetSize: Peak working set size.
            std::uint64_t workingSetSize;            // WorkingSetSize: Working set at crash time.
            std::uint64_t quotaPeakPagedPoolUsage;   // QuotaPeakPagedPoolUsage: Peak paged pool usage.
            std::uint64_t quotaPagedPoolUsage;       // QuotaPagedPoolUsage: Current paged pool usage.
            std::uint64_t quotaPeakNonPagedPoolUsage; // QuotaPeakNonPagedPoolUsage: Peak non-paged pool usage.
            std::uint64_t quotaNonPagedPoolUsage;    // QuotaNonPagedPoolUsage: Current non-paged pool usage.
            std::uint64_t pagefileUsage;             // PagefileUsage: Current committed amount.
            std::uint64_t peakPagefileUsage;         // PeakPagefileUsage: Peak committed memory.
            std::uint64_t peakVirtualSize;           // PeakVirtualSize: Peak virtual address space (VIRTUALSIZE group).
            std::uint64_t virtualSize;               // VirtualSize: current virtual address space size (VIRTUALSIZE group).
            std::uint64_t privateUsage;              // PrivateUsage: Private commit amount (EX group).
            std::uint64_t privateWorkingSetSize;     // PrivateWorkingSetSize: Private working set (EX2 group).
            std::uint64_t sharedCommitUsage;         // SharedCommitUsage: shared commit amount (EX2 group).
        };
        static_assert(sizeof(MinidumpProcessVmCounters2) == 112,
            "MINIDUMP_PROCESS_VM_COUNTERS_2 前 112 字节必须与官方布局一致");
        static_assert(offsetof(MinidumpProcessVmCounters2, privateUsage) == 88,
            "Revision 2 的 PrivateUsage 必须位于 0x58，比 Revision 1 后移 16 字节");
#pragma pack(pop)

        // kVmCountersVirtualSize/kVmCountersEx/kVmCountersEx2：
        // Revision 2 Flags bit indicating whether the corresponding field group has actually been populated.
        constexpr std::uint16_t kVmCountersVirtualSize = 0x0002;
        constexpr std::uint16_t kVmCountersEx = 0x0004;
        constexpr std::uint16_t kVmCountersEx2 = 0x0008;

        // guidToText: Formats a GUID into a hexadecimal string enclosed in curly braces.
        // Accepts a GUID; returns text in the format {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
        QString guidToText(const GUID& guid)
        {
            return QStringLiteral("{%1-%2-%3-%4%5-%6%7%8%9%10%11}")
                .arg(guid.Data1, 8, 16, QLatin1Char('0'))
                .arg(guid.Data2, 4, 16, QLatin1Char('0'))
                .arg(guid.Data3, 4, 16, QLatin1Char('0'))
                .arg(guid.Data4[0], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[1], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[2], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[3], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[4], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[5], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[6], 2, 16, QLatin1Char('0'))
                .arg(guid.Data4[7], 2, 16, QLatin1Char('0'))
                .toUpper();
        }

        // readCodeViewRecord purpose: Parse the module's CodeView debug record (RSDS/NB10).
        // Takes view and record location; outputs PDB path and GUID/Age text, leaving both empty if parsing fails.
        void readCodeViewRecord(
            const DumpFileView& view,
            const MINIDUMP_LOCATION_DESCRIPTOR& location,
            QString* const pdbNameOut,
            QString* const pdbGuidAgeOut)
        {
            // kRsdsSignature/kNb10Signature: Magic numbers for the headers of two CodeView record types.
            constexpr std::uint32_t kRsdsSignature = 0x53445352; // 'RSDS'
            constexpr std::uint32_t kNb10Signature = 0x3031424E; // 'NB10'
            std::uint32_t signature = 0;
            if (location.DataSize < sizeof(std::uint32_t) ||
                !view.readStruct(location.Rva, &signature))
            {
                return;
            }
            if (signature == kRsdsSignature && location.DataSize >= 24)
            {
                // RSDS layout: DWORD magic + GUID (16 bytes) + DWORD Age + UTF-8 path.
                GUID pdbGuid{};
                std::uint32_t age = 0;
                if (!view.readStruct(location.Rva + 4, &pdbGuid) ||
                    !view.readStruct(location.Rva + 20, &age))
                {
                    return;
                }
                *pdbGuidAgeOut = QStringLiteral("%1 / %2").arg(guidToText(pdbGuid)).arg(age);
                // nameBytes: Maximum length of the path region; truncated to UTF-8 text at NUL.
                const std::uint64_t kNameBytes = location.DataSize - 24;
                const unsigned char* const kNameData = view.at(location.Rva + 24, kNameBytes);
                if (kNameData != nullptr && kNameBytes > 0)
                {
                    std::uint64_t nameLength = 0;
                    while (nameLength < kNameBytes && kNameData[nameLength] != 0)
                    {
                        ++nameLength;
                    }
                    *pdbNameOut = QString::fromUtf8(
                        reinterpret_cast<const char*>(kNameData),
                        static_cast<qsizetype>(nameLength));
                }
            }
            else if (signature == kNb10Signature && location.DataSize >= 16)
            {
                // NB10 layout: Magic number + Offset + timestamp signature + Age + ANSI path.
                std::uint32_t timeSignature = 0;
                std::uint32_t age = 0;
                if (!view.readStruct(location.Rva + 8, &timeSignature) ||
                    !view.readStruct(location.Rva + 12, &age))
                {
                    return;
                }
                *pdbGuidAgeOut = QStringLiteral("NB10 %1 / %2").arg(hex(timeSignature)).arg(age);
                const std::uint64_t kNameBytes = location.DataSize - 16;
                const unsigned char* const kNameData = view.at(location.Rva + 16, kNameBytes);
                if (kNameData != nullptr && kNameBytes > 0)
                {
                    std::uint64_t nameLength = 0;
                    while (nameLength < kNameBytes && kNameData[nameLength] != 0)
                    {
                        ++nameLength;
                    }
                    *pdbNameOut = QString::fromLocal8Bit(
                        reinterpret_cast<const char*>(kNameData),
                        static_cast<qsizetype>(nameLength));
                }
            }
        }

        // readFixedWideString: Extract text from a fixed-length UTF-16 array, stopping at NUL.
        // Input: buffer pointer and maxChars capacity. Output: text with leading and trailing whitespace removed.
        QString readFixedWideString(const wchar_t* const buffer, const std::size_t maxChars)
        {
            if (buffer == nullptr || maxChars == 0)
            {
                return QString();
            }
            std::size_t length = 0;
            while (length < maxChars && buffer[length] != L'\0')
            {
                ++length;
            }
            return QString::fromWCharArray(buffer, static_cast<qsizetype>(length)).trimmed();
        }

        // integrityLevelText: Converts the Mandatory Integrity Level RID to a Chinese description.
        // Accept level (SECURITY_MANDATORY_*_RID) as input; return text in the format "Level Name (Value)".
        QString integrityLevelText(const std::uint32_t level)
        {
            // Level names follow the standard tiers of Windows Mandatory Integrity Control.
            const char* name = nullptr;
            if (level >= 0x5000u)       { name = "受保护进程"; }
            else if (level >= 0x4000u)  { name = "系统 (System)"; }
            else if (level >= 0x3000u)  { name = "高 (High，已提权)"; }
            else if (level >= 0x2000u)  { name = "中 (Medium，普通用户进程)"; }
            else if (level >= 0x1000u)  { name = "低 (Low，沙箱进程)"; }
            else                        { name = "不可信 (Untrusted)"; }
            return QStringLiteral("%1（0x%2）")
                .arg(QString::fromUtf8(name))
                .arg(QString::number(level, 16).toUpper());
        }

        // executeFlagsText purpose: explain the process's DEP (Data Execution Protection) policy bits.
        // Input flags (MEM_EXECUTE_OPTION_*); return Chinese description.
        QString executeFlagsText(const std::uint32_t flags)
        {
            // Bit 0 set indicates execution is allowed (DEP disabled); bit 1 set indicates execution is prohibited (DEP enabled).
            QStringList parts;
            if ((flags & 0x1u) != 0)
            {
                parts.append(QStringLiteral("允许执行数据页（DEP 已关闭）"));
            }
            if ((flags & 0x2u) != 0)
            {
                parts.append(QStringLiteral("禁止执行数据页（DEP 已开启）"));
            }
            if ((flags & 0x4u) != 0)
            {
                parts.append(QStringLiteral("禁用 ATL thunk 模拟"));
            }
            if ((flags & 0x8u) != 0)
            {
                parts.append(QStringLiteral("策略已锁定，运行期不可更改"));
            }
            if (parts.isEmpty())
            {
                parts.append(QStringLiteral("使用系统默认策略"));
            }
            return QStringLiteral("0x%1（%2）")
                .arg(QString::number(flags, 16).toUpper())
                .arg(parts.join(QStringLiteral("；")));
        }

        // appendMemoryRow: Append a memory region row limited by kMaxMemoryRows.
        void appendMemoryRow(DumpParseResult& result, MemoryRegionEntry entry)
        {
            ++result.memoryRegionTotal;
            if (result.memoryRegionShown >= kMaxMemoryRows)
            {
                return;
            }
            ++result.memoryRegionShown;
            result.memoryRegions.push_back(std::move(entry));
        }
    }

    void parseSystemInfo(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result,
        std::uint16_t* const architectureOut)
    {
        MINIDUMP_SYSTEM_INFO info{};
        if (location.DataSize < sizeof(info) || !view.readStruct(location.Rva, &info))
        {
            result.diagnostics.append(QStringLiteral("系统信息流长度不足，已跳过。"));
            return;
        }
        *architectureOut = info.ProcessorArchitecture;
        result.overview.push_back({ QStringLiteral("CPU 架构"),
            processorArchitectureText(info.ProcessorArchitecture) });
        result.overview.push_back({ QStringLiteral("逻辑处理器数"),
            QString::number(info.NumberOfProcessors) });
        // versionText: Major.Minor.Build; append CSD (Service Pack text) if non-empty.
        QString versionText = QStringLiteral("%1.%2.%3")
            .arg(info.MajorVersion)
            .arg(info.MinorVersion)
            .arg(info.BuildNumber);
        const QString kCsdText = readMinidumpString(view, info.CSDVersionRva);
        if (!kCsdText.isEmpty())
        {
            versionText += QStringLiteral(" (%1)").arg(kCsdText);
        }
        result.overview.push_back({ QStringLiteral("操作系统版本"), versionText });
        // productText: Distinguish between workstation and server (VER_NT_* constants).
        QString productText;
        switch (info.ProductType)
        {
        case 1: productText = QStringLiteral("工作站 (VER_NT_WORKSTATION)"); break;
        case 2: productText = QStringLiteral("域控制器 (VER_NT_DOMAIN_CONTROLLER)"); break;
        case 3: productText = QStringLiteral("服务器 (VER_NT_SERVER)"); break;
        default: productText = QString::number(info.ProductType); break;
        }
        result.overview.push_back({ QStringLiteral("产品类型"), productText });
    }

    void parseMiscInfo(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        // baseInfo: The common prefix shared by all MISC_INFO versions; older versions guarantee only the prefix fields are valid.
        MINIDUMP_MISC_INFO baseInfo{};
        if (location.DataSize < sizeof(baseInfo) || !view.readStruct(location.Rva, &baseInfo))
        {
            result.diagnostics.append(QStringLiteral("杂项信息流长度不足，已跳过。"));
            return;
        }
        if ((baseInfo.Flags1 & MINIDUMP_MISC1_PROCESS_ID) != 0)
        {
            result.overview.push_back({ QStringLiteral("进程 ID"),
                QString::number(baseInfo.ProcessId) });
        }
        if ((baseInfo.Flags1 & MINIDUMP_MISC1_PROCESS_TIMES) != 0)
        {
            result.overview.push_back({ QStringLiteral("进程创建时间"),
                timeTToText(baseInfo.ProcessCreateTime) });
            result.overview.push_back({ QStringLiteral("进程 CPU 时间"),
                QStringLiteral("用户态 %1 秒 / 内核态 %2 秒")
                    .arg(baseInfo.ProcessUserTime)
                    .arg(baseInfo.ProcessKernelTime) });
        }
        // Processor frequency belongs to the MISC_INFO_2 extension; read only if the stream length is sufficient.
        if (location.DataSize >= sizeof(MINIDUMP_MISC_INFO_2))
        {
            MINIDUMP_MISC_INFO_2 info2{};
            if (view.readStruct(location.Rva, &info2) &&
                (info2.Flags1 & MINIDUMP_MISC1_PROCESSOR_POWER_INFO) != 0)
            {
                result.overview.push_back({ QStringLiteral("处理器频率"),
                    QStringLiteral("当前 %1 MHz / 最大 %2 MHz")
                        .arg(info2.ProcessorCurrentMhz)
                        .arg(info2.ProcessorMaxMhz) });
            }
        }

#if defined(MINIDUMP_MISC3_TIMEZONE)
        // MISC_INFO_3 extension: integrity level, DEP policy, protected processes, and time zone.
        // Integrity level directly indicates whether the crashing process was running with elevated privileges, which is useful for troubleshooting permission issues.
        if (location.DataSize >= sizeof(MINIDUMP_MISC_INFO_3))
        {
            MINIDUMP_MISC_INFO_3 info3{};
            if (view.readStruct(location.Rva, &info3))
            {
                if ((info3.Flags1 & MINIDUMP_MISC3_PROCESS_INTEGRITY) != 0)
                {
                    result.overview.push_back({ QStringLiteral("进程完整性级别"),
                        integrityLevelText(info3.ProcessIntegrityLevel) });
                }
                if ((info3.Flags1 & MINIDUMP_MISC3_PROCESS_EXECUTE_FLAGS) != 0)
                {
                    result.overview.push_back({ QStringLiteral("DEP 策略"),
                        executeFlagsText(info3.ProcessExecuteFlags) });
                }
                if ((info3.Flags1 & MINIDUMP_MISC3_PROTECTED_PROCESS) != 0)
                {
                    result.overview.push_back({ QStringLiteral("受保护进程"),
                        info3.ProtectedProcess != 0
                            ? QStringLiteral("是（PPL/PP，调试受限）")
                            : QStringLiteral("否") });
                }
                if ((info3.Flags1 & MINIDUMP_MISC3_TIMEZONE) != 0)
                {
                    // Bias is in minutes, defined as UTC = Local Time + Bias; therefore, the Bias for UTC+8
                    // is -480, and it must be negated for display to match the common UTC+08:00 format.
                    const int kBiasMinutes = -static_cast<int>(info3.TimeZone.Bias);
                    result.overview.push_back({ QStringLiteral("时区偏移"),
                        QStringLiteral("UTC%1%2:%3")
                            .arg(kBiasMinutes < 0 ? QStringLiteral("-") : QStringLiteral("+"))
                            .arg(qAbs(kBiasMinutes) / 60, 2, 10, QLatin1Char('0'))
                            .arg(qAbs(kBiasMinutes) % 60, 2, 10, QLatin1Char('0')) });
                }
            }
        }
#endif

#if defined(MINIDUMP_MISC4_BUILDSTRING)
        // MISC_INFO_4 extension: System build string, far more precise than the three-segment
        // version in SystemInfo, directly mapping to specific Windows versions and update branches.
        if (location.DataSize >= sizeof(MINIDUMP_MISC_INFO_4))
        {
            MINIDUMP_MISC_INFO_4 info4{};
            if (view.readStruct(location.Rva, &info4) &&
                (info4.Flags1 & MINIDUMP_MISC4_BUILDSTRING) != 0)
            {
                const QString kBuildString = readFixedWideString(
                    info4.BuildString,
                    sizeof(info4.BuildString) / sizeof(info4.BuildString[0]));
                if (!kBuildString.isEmpty())
                {
                    result.overview.push_back({ QStringLiteral("系统构建串"), kBuildString });
                }
                const QString kDebuggerBuild = readFixedWideString(
                    info4.DbgBldStr,
                    sizeof(info4.DbgBldStr) / sizeof(info4.DbgBldStr[0]));
                if (!kDebuggerBuild.isEmpty())
                {
                    result.overview.push_back({ QStringLiteral("调试器构建串"), kDebuggerBuild });
                }
            }
        }
#endif
    }

    void parseProcessVmCounters(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        // revision: structure version, determines whether two virtual size fields are inserted before PrivateUsage.
        std::uint16_t revision = 0;
        if (location.DataSize < sizeof(MinidumpProcessVmCounters1) ||
            !view.readStruct(location.Rva, &revision))
        {
            return;
        }

        // First read the common prefix fields (offsets are identical), then read the version-specific suffix fields.
        MinidumpProcessVmCounters1 base{};
        if (!view.readStruct(location.Rva, &base))
        {
            return;
        }
        std::uint64_t privateUsage = 0;
        std::uint64_t peakVirtualSize = 0;
        std::uint64_t virtualSize = 0;
        std::uint64_t privateWorkingSet = 0;
        if (revision >= 2)
        {
            MinidumpProcessVmCounters2 extended{};
            if (location.DataSize < sizeof(extended) ||
                !view.readStruct(location.Rva, &extended))
            {
                return;
            }
            if ((extended.flags & kVmCountersVirtualSize) != 0)
            {
                peakVirtualSize = extended.peakVirtualSize;
                virtualSize = extended.virtualSize;
            }
            if ((extended.flags & kVmCountersEx) != 0)
            {
                privateUsage = extended.privateUsage;
            }
            if ((extended.flags & kVmCountersEx2) != 0)
            {
                privateWorkingSet = extended.privateWorkingSetSize;
            }
        }
        else
        {
            privateUsage = base.privateUsage;
        }

        // Private bytes and committed memory are the primary data for determining whether a crash was caused by memory exhaustion:
        // When private bytes of a 32-bit process approach 2GB / 4GB, it is almost certain that the address space is exhausted.
        if (privateUsage != 0)
        {
            result.overview.push_back({ QStringLiteral("私有字节"),
                byteCountText(privateUsage) });
        }
        if (privateWorkingSet != 0)
        {
            result.overview.push_back({ QStringLiteral("私有工作集"),
                byteCountText(privateWorkingSet) });
        }
        result.overview.push_back({ QStringLiteral("提交量 (当前/峰值)"),
            QStringLiteral("%1 / %2")
                .arg(byteCountText(base.pagefileUsage))
                .arg(byteCountText(base.peakPagefileUsage)) });
        result.overview.push_back({ QStringLiteral("工作集 (当前/峰值)"),
            QStringLiteral("%1 / %2")
                .arg(byteCountText(base.workingSetSize))
                .arg(byteCountText(base.peakWorkingSetSize)) });
        if (virtualSize != 0 || peakVirtualSize != 0)
        {
            // Virtual address space contains many 'reserved but not committed' regions; values significantly larger than actual memory
            // usage are normal. However, when a 32-bit process approaches 2GB, it is direct evidence of address space exhaustion.
            result.overview.push_back({ QStringLiteral("虚拟地址空间 (当前/峰值)"),
                QStringLiteral("%1 / %2")
                    .arg(byteCountText(virtualSize))
                    .arg(byteCountText(peakVirtualSize)) });
        }
        result.overview.push_back({ QStringLiteral("页错误次数"),
            QString::number(base.pageFaultCount) });
        if (base.quotaNonPagedPoolUsage != 0 || base.quotaPagedPoolUsage != 0)
        {
            result.overview.push_back({ QStringLiteral("内核池用量 (分页/非分页)"),
                QStringLiteral("%1 / %2")
                    .arg(byteCountText(base.quotaPagedPoolUsage))
                    .arg(byteCountText(base.quotaNonPagedPoolUsage)) });
        }
    }

    void parseExceptionStream(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        const std::uint16_t architecture,
        const ModuleIndex& modules,
        DumpParseResult& result,
        std::uint32_t* const faultingThreadIdOut,
        MINIDUMP_LOCATION_DESCRIPTOR* const contextLocationOut)
    {
        MINIDUMP_EXCEPTION_STREAM stream{};
        if (location.DataSize < sizeof(stream) || !view.readStruct(location.Rva, &stream))
        {
            result.diagnostics.append(QStringLiteral("异常流长度不足，已跳过。"));
            return;
        }
        *faultingThreadIdOut = stream.ThreadId;
        *contextLocationOut = stream.ThreadContext;
        // record: The exception record itself; code/address are the core of diagnosis.
        const MINIDUMP_EXCEPTION& record = stream.ExceptionRecord;
        const std::uint32_t kCode = static_cast<std::uint32_t>(record.ExceptionCode);
        result.exceptionCode = kCode;
        result.faultingThreadId = stream.ThreadId;
        result.exceptionInfo.push_back({ QStringLiteral("异常线程 ID"),
            QString::number(stream.ThreadId) });
        // codeText: Numeric value + constant name; meaning provided on a separate line in Chinese.
        QString codeText = hex(kCode);
        const QString kCodeName = exceptionCodeName(kCode);
        if (!kCodeName.isEmpty())
        {
            codeText += QStringLiteral(" (%1)").arg(kCodeName);
        }
        result.exceptionInfo.push_back({ QStringLiteral("异常代码"), codeText });
        const QString kMeaning = exceptionCodeMeaning(kCode);
        if (!kMeaning.isEmpty())
        {
            result.exceptionInfo.push_back({ QStringLiteral("异常含义"), kMeaning });
        }
        // Exception address with module ownership: a bare address alone cannot identify the crashing module.
        const QString kAddressNote = modules.annotate(record.ExceptionAddress);
        result.exceptionInfo.push_back({ QStringLiteral("异常地址"),
            kAddressNote.isEmpty()
                ? hex(record.ExceptionAddress)
                : QStringLiteral("%1  —  %2").arg(hex(record.ExceptionAddress), kAddressNote) });
        if (record.ExceptionFlags != 0)
        {
            result.exceptionInfo.push_back({ QStringLiteral("异常标志"),
                QStringLiteral("%1%2")
                    .arg(hex(record.ExceptionFlags))
                    .arg((record.ExceptionFlags & 1) != 0
                        ? QStringLiteral("（不可继续）")
                        : QString()) });
        }

        // Perform specialized analysis based on exception categories: these parameters contain the actual information pointing to the root cause.
        const std::uint32_t kParameterCount = std::min<std::uint32_t>(
            record.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
        if ((kCode == 0xC0000005u || kCode == 0xC0000006u) && kParameterCount >= 2)
        {
            // Access violation / page fault: Parameter 0 is the operation type, and Parameter 1 is the faulting address.
            const std::uint64_t kFaultAddress = record.ExceptionInformation[1];
            result.exceptionInfo.push_back({ QStringLiteral("违例详情"),
                accessViolationDetailText(record.ExceptionInformation[0], kFaultAddress) });
            // The nature of the fault address often directly determines the problem type: null pointer, sentinel value, or valid module address.
            const AddressNote kFaultNote = modules.resolve(kFaultAddress);
            QString faultDescription = kFaultNote.symbolText.isEmpty()
                ? kFaultNote.description
                : QStringLiteral("%1（%2）").arg(kFaultNote.symbolText, kFaultNote.description);
            if (kFaultNote.kind == AddressKind::kNullPage)
            {
                faultDescription = kFaultAddress == 0
                    ? QStringLiteral("空指针解引用：指针本身为 NULL。")
                    : QStringLiteral("空指针解引用：基指针为 NULL，再加上约 0x%1 的成员偏移。")
                        .arg(QString::number(kFaultAddress, 16).toUpper());
            }
            if (!faultDescription.isEmpty())
            {
                result.exceptionInfo.push_back({
                    QStringLiteral("出错地址性质"), faultDescription });
            }
            if (kCode == 0xC0000006u && kParameterCount >= 3)
            {
                // Parameter 2 of the page fault is the underlying I/O NTSTATUS, explaining why the page read failed.
                const std::uint32_t kPageStatus =
                    static_cast<std::uint32_t>(record.ExceptionInformation[2]);
                const QString kStatusName = exceptionCodeName(kPageStatus);
                result.exceptionInfo.push_back({ QStringLiteral("换页失败的 NTSTATUS"),
                    kStatusName.isEmpty()
                        ? hex(kPageStatus)
                        : QStringLiteral("%1 (%2)").arg(hex(kPageStatus), kStatusName) });
            }
        }
        else if ((kCode == 0xC0000409u || kCode == 0xC0000602u) && kParameterCount >= 1)
        {
            // fast-fail: Only the sub-code in parameter 0 indicates which security check was triggered.
            const std::uint64_t kFailFastCode = record.ExceptionInformation[0];
            const QString kFailFastText = fastFailCodeText(kFailFastCode);
            result.exceptionInfo.push_back({ QStringLiteral("fast-fail 子码"),
                kFailFastText.isEmpty()
                    ? QStringLiteral("%1（未收录的子码）").arg(hex(kFailFastCode))
                    : QStringLiteral("%1  —  %2").arg(hex(kFailFastCode), kFailFastText) });
            result.exceptionInfo.push_back({ QStringLiteral("性质"),
                QStringLiteral("这是进程主动终止，不是被动崩溃：安全检查发现状态已被破坏，"
                    "为避免继续执行造成更大危害而立即退出。") });
        }
        else if (isCppException(kCode) && kParameterCount >= 2)
        {
            // MSVC C++ exception: The crash point is the throw location, not the location where the defect occurred.
            const QString kMagicText = cppExceptionMagicText(record.ExceptionInformation[0]);
            result.exceptionInfo.push_back({ QStringLiteral("C++ 异常记录"),
                kMagicText.isEmpty()
                    ? QStringLiteral("魔数 %1（未知版本）").arg(hex(record.ExceptionInformation[0]))
                    : kMagicText });
            result.exceptionInfo.push_back({ QStringLiteral("异常对象地址"),
                hex(record.ExceptionInformation[1]) });
            if (kParameterCount >= 3)
            {
                const QString kThrowInfoNote = modules.annotate(record.ExceptionInformation[2]);
                result.exceptionInfo.push_back({ QStringLiteral("ThrowInfo 地址"),
                    kThrowInfoNote.isEmpty()
                        ? hex(record.ExceptionInformation[2])
                        : QStringLiteral("%1  —  %2")
                              .arg(hex(record.ExceptionInformation[2]), kThrowInfoNote) });
            }
            if (kParameterCount >= 4)
            {
                // On 64-bit systems, parameter 3 is the base address of the module that threw the exception, directly identifying the source.
                const QString kModuleNote = modules.annotate(record.ExceptionInformation[3]);
                result.exceptionInfo.push_back({ QStringLiteral("抛出方模块基址"),
                    kModuleNote.isEmpty()
                        ? hex(record.ExceptionInformation[3])
                        : QStringLiteral("%1  —  %2")
                              .arg(hex(record.ExceptionInformation[3]), kModuleNote) });
            }
            result.exceptionInfo.push_back({ QStringLiteral("性质"),
                QStringLiteral("未被接住的 C++ 异常：崩溃点是 throw 的位置，"
                    "缺陷通常在更上游；需要 PDB 才能还原异常类型名。") });
        }
        else if (isManagedException(kCode))
        {
            result.exceptionInfo.push_back({ QStringLiteral("性质"),
                QStringLiteral("这是 .NET 托管异常：本工具只能解析原生层信息，"
                    "托管调用栈与异常类型需要用 SOS/dotnet-dump 分析同一份转储。") });
            for (std::uint32_t index = 0; index < kParameterCount; ++index)
            {
                result.exceptionInfo.push_back({
                    QStringLiteral("参数 %1").arg(index + 1),
                    hex(record.ExceptionInformation[index]) });
            }
        }
        else
        {
            for (std::uint32_t index = 0; index < kParameterCount; ++index)
            {
                // Also process parameters without fixed semantics for module attribution, as many parameters are actually addresses.
                const std::uint64_t kParameter = record.ExceptionInformation[index];
                const QString kNote = kParameter != 0 ? modules.annotate(kParameter) : QString();
                result.exceptionInfo.push_back({
                    QStringLiteral("参数 %1").arg(index + 1),
                    kNote.isEmpty() ? hex(kParameter)
                                   : QStringLiteral("%1  —  %2").arg(hex(kParameter), kNote) });
            }
        }

        // Note: Crash point instruction pointer: retrieved from the exception thread context, as the exception address may be rewritten by inner dispatch.
        const std::uint64_t kContextIp = instructionPointerFromContext(
            view, stream.ThreadContext, architecture);
        if (kContextIp != 0)
        {
            const QString kIpNote = modules.annotate(kContextIp);
            result.exceptionInfo.push_back({ QStringLiteral("上下文指令指针"),
                kIpNote.isEmpty() ? hex(kContextIp)
                                 : QStringLiteral("%1  —  %2").arg(hex(kContextIp), kIpNote) });
        }
        // faultingAddress: Prefer the context IP for attribution; fall back to the address in the exception record if the context IP is unavailable.
        result.faultingAddress = kContextIp != 0 ? kContextIp : record.ExceptionAddress;
    }

    void parseThreadList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        const bool isExtendedList,
        const std::uint16_t architecture,
        const std::uint32_t faultingThreadId,
        const ModuleIndex& modules,
        DumpParseResult& result,
        std::vector<StackScanInput>* const scanInputsOut,
        DumpMemoryReader* const memory)
    {
        // threadCount: Number of array entries; both stream headers use a ULONG32 count.
        ULONG32 threadCount = 0;
        if (!view.readStruct(location.Rva, &threadCount))
        {
            result.diagnostics.append(QStringLiteral("线程列表流头部读取失败。"));
            return;
        }
        // entrySize: 48 bytes for a normal thread; an extended thread has one additional background storage descriptor.
        const std::uint64_t kEntrySize = isExtendedList
            ? sizeof(MINIDUMP_THREAD_EX)
            : sizeof(MINIDUMP_THREAD);
        const std::uint64_t kSafeCount = std::min<std::uint64_t>(threadCount, kMaxListEntries);
        if (kSafeCount != threadCount)
        {
            result.diagnostics.append(
                QStringLiteral("线程数 %1 超过解析上限，仅展示前 %2 条。")
                    .arg(threadCount)
                    .arg(kSafeCount));
        }
        result.threads.reserve(static_cast<std::size_t>(kSafeCount));
        for (std::uint64_t index = 0; index < kSafeCount; ++index)
        {
            // thread: A single thread record; the first half of the extended stream layout matches the standard stream layout.
            MINIDUMP_THREAD thread{};
            const std::uint64_t kEntryOffset =
                location.Rva + sizeof(ULONG32) + index * kEntrySize;
            if (!view.readStruct(kEntryOffset, &thread))
            {
                result.diagnostics.append(QStringLiteral("线程条目越界，列表提前结束。"));
                break;
            }
            ThreadEntry entry{};
            entry.threadId = thread.ThreadId;
            entry.suspendCount = thread.SuspendCount;
            entry.priorityClass = thread.PriorityClass;
            entry.priority = thread.Priority;
            entry.teb = thread.Teb;
            entry.stackBase = thread.Stack.StartOfMemoryRange;
            entry.stackSize = thread.Stack.Memory.DataSize;
            entry.instructionPointer = instructionPointerFromContext(
                view, thread.ThreadContext, architecture);
            entry.faulting = (thread.ThreadId == faultingThreadId);
            // Module ownership of the instruction pointer: the thread table directly shows which module each thread is stopped in.
            if (entry.instructionPointer != 0)
            {
                entry.ipSymbolText = modules.symbolText(entry.instructionPointer);
            }
            // The stack pointer comes from the same CONTEXT and serves as the starting point for stack scanning.
            const ContextArch kContextArch =
                contextArchFromProcessorArchitecture(architecture);
            std::uint64_t threadIp = 0;
            std::uint64_t threadSp = 0;
            readContextPointers(
                view,
                thread.ThreadContext.Rva,
                thread.ThreadContext.DataSize,
                kContextArch,
                &threadIp,
                &threadSp,
                nullptr);

            // The thread stack itself is captured memory; register it in the index for address reading.
            if (memory != nullptr && thread.Stack.Memory.DataSize != 0)
            {
                memory->addRange(
                    thread.Stack.StartOfMemoryRange,
                    thread.Stack.Memory.Rva,
                    thread.Stack.Memory.DataSize,
                    QStringLiteral("线程栈"));
            }
            // Collect stack scan inputs: actual scanning must wait until both module and memory indices are ready.
            if (scanInputsOut != nullptr && thread.Stack.Memory.DataSize != 0)
            {
                StackScanInput input{};
                input.stackFileOffset = thread.Stack.Memory.Rva;
                input.stackBytes = thread.Stack.Memory.DataSize;
                input.stackBaseAddress = thread.Stack.StartOfMemoryRange;
                input.stackPointer = threadSp;
                input.instructionPointer = entry.instructionPointer;
                input.pointerSize = contextPointerSize(kContextArch);
                input.threadId = thread.ThreadId;
                scanInputsOut->push_back(input);
            }
            result.threads.push_back(std::move(entry));
        }
    }

    void parseThreadInfoList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        MINIDUMP_THREAD_INFO_LIST header{};
        if (!view.readStruct(location.Rva, &header) ||
            header.SizeOfHeader < sizeof(header) ||
            header.SizeOfEntry < sizeof(MINIDUMP_THREAD_INFO))
        {
            return;
        }
        const std::uint64_t kCount = std::min<std::uint64_t>(
            header.NumberOfEntries, kMaxListEntries);
        for (std::uint64_t index = 0; index < kCount; ++index)
        {
            MINIDUMP_THREAD_INFO info{};
            if (!view.readStruct(
                    location.Rva + header.SizeOfHeader + index * header.SizeOfEntry,
                    &info))
            {
                break;
            }
            // When a resolved thread is matched, supplement the start address and CPU time (100ns → ms).
            for (ThreadEntry& entry : result.threads)
            {
                if (entry.threadId != info.ThreadId)
                {
                    continue;
                }
                entry.startAddress = info.StartAddress;
                const double kUserMs = static_cast<double>(info.UserTime) / 10000.0;
                const double kKernelMs = static_cast<double>(info.KernelTime) / 10000.0;
                if (info.UserTime != 0 || info.KernelTime != 0)
                {
                    entry.cpuTimeText = QStringLiteral("%1 / %2 ms")
                        .arg(QString::number(kUserMs, 'f', 1))
                        .arg(QString::number(kKernelMs, 'f', 1));
                }
                break;
            }
        }
    }

    void parseThreadNames(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        MinidumpThreadNameHeader header{};
        if (!view.readStruct(location.Rva, &header))
        {
            return;
        }
        const std::uint64_t kCount = std::min<std::uint64_t>(
            header.numberOfThreadNames, kMaxListEntries);
        for (std::uint64_t index = 0; index < kCount; ++index)
        {
            MinidumpThreadNameEntry entry{};
            if (!view.readStruct(
                    location.Rva + sizeof(header) + index * sizeof(entry),
                    &entry))
            {
                break;
            }
            const QString kThreadName = readMinidumpString(view, entry.rvaOfThreadName);
            if (kThreadName.isEmpty())
            {
                continue;
            }
            for (ThreadEntry& thread : result.threads)
            {
                if (thread.threadId == entry.threadId)
                {
                    thread.name = kThreadName;
                    break;
                }
            }
        }
    }

    void parseModuleList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        ULONG32 moduleCount = 0;
        if (!view.readStruct(location.Rva, &moduleCount))
        {
            result.diagnostics.append(QStringLiteral("模块列表流头部读取失败。"));
            return;
        }
        const std::uint64_t kSafeCount = std::min<std::uint64_t>(moduleCount, kMaxListEntries);
        if (kSafeCount != moduleCount)
        {
            result.diagnostics.append(
                QStringLiteral("模块数 %1 超过解析上限，仅展示前 %2 条。")
                    .arg(moduleCount)
                    .arg(kSafeCount));
        }
        result.modules.reserve(static_cast<std::size_t>(kSafeCount));
        for (std::uint64_t index = 0; index < kSafeCount; ++index)
        {
            MINIDUMP_MODULE module{};
            if (!view.readStruct(
                    location.Rva + sizeof(ULONG32) + index * sizeof(MINIDUMP_MODULE),
                    &module))
            {
                result.diagnostics.append(QStringLiteral("模块条目越界，列表提前结束。"));
                break;
            }
            ModuleEntry entry{};
            entry.name = readMinidumpString(view, module.ModuleNameRva);
            entry.base = module.BaseOfImage;
            entry.size = module.SizeOfImage;
            entry.checksum = module.CheckSum;
            entry.timeDateStamp = module.TimeDateStamp;
            entry.timestampText = timeTToText(module.TimeDateStamp);
            // The version number is only trustworthy when the VS_FIXEDFILEINFO magic number is valid.
            if (module.VersionInfo.dwSignature == 0xFEEF04BDu)
            {
                entry.version = QStringLiteral("%1.%2.%3.%4")
                    .arg(HIWORD(module.VersionInfo.dwFileVersionMS))
                    .arg(LOWORD(module.VersionInfo.dwFileVersionMS))
                    .arg(HIWORD(module.VersionInfo.dwFileVersionLS))
                    .arg(LOWORD(module.VersionInfo.dwFileVersionLS));
            }
            readCodeViewRecord(view, module.CvRecord, &entry.pdbName, &entry.pdbGuidAge);
            result.modules.push_back(std::move(entry));
        }
    }

    void parseUnloadedModuleList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        MINIDUMP_UNLOADED_MODULE_LIST header{};
        if (!view.readStruct(location.Rva, &header) ||
            header.SizeOfHeader < sizeof(header) ||
            header.SizeOfEntry < sizeof(MINIDUMP_UNLOADED_MODULE))
        {
            return;
        }
        const std::uint64_t kCount = std::min<std::uint64_t>(
            header.NumberOfEntries, kMaxListEntries);
        result.unloadedModules.reserve(static_cast<std::size_t>(kCount));
        for (std::uint64_t index = 0; index < kCount; ++index)
        {
            MINIDUMP_UNLOADED_MODULE module{};
            if (!view.readStruct(
                    location.Rva + header.SizeOfHeader + index * header.SizeOfEntry,
                    &module))
            {
                break;
            }
            UnloadedModuleEntry entry{};
            entry.name = readMinidumpString(view, module.ModuleNameRva);
            entry.base = module.BaseOfImage;
            entry.size = module.SizeOfImage;
            entry.checksum = module.CheckSum;
            entry.timeDateStamp = module.TimeDateStamp;
            entry.timestampText = timeTToText(module.TimeDateStamp);
            result.unloadedModules.push_back(std::move(entry));
        }
    }

    void parseMemoryLists(
        const DumpFileView& view,
        const std::uint64_t directoryRva,
        const std::uint32_t streamCount,
        DumpParseResult& result,
        DumpMemoryReader* const memory)
    {
        MINIDUMP_LOCATION_DESCRIPTOR location{};
        // hasDataList: Whether the Memory64List has already provided table data for display.
        // When MemoryInfoList is hit, this remains false; the display table follows the path with more complete information.
        bool hasDataList = false;
        // useInfoList: Whether MemoryInfoList is available; if available, use it for the table display, but
        // memory indices must still be built from Memory64List/MemoryList (the former contains no data).
        bool useInfoList = false;
        MINIDUMP_LOCATION_DESCRIPTOR infoLocation{};
        MINIDUMP_MEMORY_INFO_LIST infoHeader{};
        if (findStream(view, directoryRva, streamCount, MemoryInfoListStream, &infoLocation) &&
            view.readStruct(infoLocation.Rva, &infoHeader) &&
            infoHeader.SizeOfHeader >= sizeof(infoHeader) &&
            infoHeader.SizeOfEntry >= sizeof(MINIDUMP_MEMORY_INFO))
        {
            useInfoList = true;
        }

        // ---- Step 1: Build a virtual address index from memory streams with data (and populate the display table if needed) ----
        if (findStream(view, directoryRva, streamCount, Memory64ListStream, &location))
        {
            // The header consists of 16 bytes for the count and data base offset; the SDK structure includes a
            // zero-length array member and cannot be instantiated by value, so fields are read individually here.
            std::uint64_t numberOfRanges = 0;
            std::uint64_t baseRva = 0;
            constexpr std::uint64_t kMemory64HeaderBytes = 16;
            if (view.readStruct(location.Rva, &numberOfRanges) &&
                view.readStruct(location.Rva + 8, &baseRva))
            {
                // The data area of Memory64List is laid out contiguously: the file offset of each segment is
                // accumulated sequentially from baseRva; the descriptor does not record the offset separately.
                std::uint64_t dataOffset = baseRva;
                const std::uint64_t kSafeCount =
                    std::min<std::uint64_t>(numberOfRanges, kMaxListEntries);
                for (std::uint64_t index = 0; index < kSafeCount; ++index)
                {
                    MINIDUMP_MEMORY_DESCRIPTOR64 descriptor{};
                    if (!view.readStruct(
                            location.Rva + kMemory64HeaderBytes +
                                index * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64),
                            &descriptor))
                    {
                        break;
                    }
                    if (memory != nullptr)
                    {
                        memory->addRange(
                            descriptor.StartOfMemoryRange,
                            dataOffset,
                            descriptor.DataSize,
                            QStringLiteral("64 位内存列表"));
                    }
                    // DataSize is entirely controlled by the file; accumulating segment by segment can wrap around.
                    // Once wrapped, all subsequent segment file offsets point to unrelated bytes, and the file
                    // boundary check in addRange happens to allow it—virtual addresses get aliased to wrong data,
                    // and the 'call stack' derived from stack scanning is a complete illusion. Stop on overflow.
                    if (dataOffset + descriptor.DataSize < dataOffset)
                    {
                        result.diagnostics.append(
                            QStringLiteral("64 位内存列表的数据区偏移累加越界，"
                                "其余内存段已跳过。"));
                        break;
                    }
                    dataOffset += descriptor.DataSize;
                    if (!useInfoList)
                    {
                        MemoryRegionEntry entry{};
                        entry.base = descriptor.StartOfMemoryRange;
                        entry.size = descriptor.DataSize;
                        entry.source = QStringLiteral("64 位内存列表");
                        appendMemoryRow(result, std::move(entry));
                    }
                }
                hasDataList = true;
            }
        }
        if (findStream(view, directoryRva, streamCount, MemoryListStream, &location))
        {
            ULONG32 rangeCount = 0;
            if (view.readStruct(location.Rva, &rangeCount))
            {
                const std::uint64_t kSafeCount =
                    std::min<std::uint64_t>(rangeCount, kMaxListEntries);
                for (std::uint64_t index = 0; index < kSafeCount; ++index)
                {
                    MINIDUMP_MEMORY_DESCRIPTOR descriptor{};
                    if (!view.readStruct(
                            location.Rva + sizeof(ULONG32) +
                                index * sizeof(MINIDUMP_MEMORY_DESCRIPTOR),
                            &descriptor))
                    {
                        break;
                    }
                    if (memory != nullptr)
                    {
                        memory->addRange(
                            descriptor.StartOfMemoryRange,
                            descriptor.Memory.Rva,
                            descriptor.Memory.DataSize,
                            QStringLiteral("内存列表"));
                    }
                    if (!useInfoList && !hasDataList)
                    {
                        MemoryRegionEntry entry{};
                        entry.base = descriptor.StartOfMemoryRange;
                        entry.size = descriptor.Memory.DataSize;
                        entry.source = QStringLiteral("内存列表");
                        appendMemoryRow(result, std::move(entry));
                    }
                }
            }
        }

        // ---- Step 2: Prefer MemoryInfoList for the display table as it includes State, Protection, and Type columns ----
        if (useInfoList)
        {
            const std::uint64_t kSafeCount =
                std::min<std::uint64_t>(infoHeader.NumberOfEntries, kMaxListEntries);
            for (std::uint64_t index = 0; index < kSafeCount; ++index)
            {
                MINIDUMP_MEMORY_INFO info{};
                if (!view.readStruct(
                        infoLocation.Rva + infoHeader.SizeOfHeader +
                            index * infoHeader.SizeOfEntry,
                        &info))
                {
                    break;
                }
                MemoryRegionEntry entry{};
                entry.base = info.BaseAddress;
                entry.size = info.RegionSize;
                entry.state = memoryStateText(info.State);
                entry.protect = memoryProtectText(info.Protect);
                entry.type = memoryTypeText(info.Type);
                entry.source = QStringLiteral("内存信息列表");
                appendMemoryRow(result, std::move(entry));
            }
        }
    }

    void parseHandleData(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result)
    {
        MINIDUMP_HANDLE_DATA_STREAM header{};
        if (!view.readStruct(location.Rva, &header) ||
            header.SizeOfHeader < sizeof(header) ||
            header.SizeOfDescriptor < sizeof(MINIDUMP_HANDLE_DESCRIPTOR))
        {
            return;
        }
        const std::uint64_t kCount = std::min<std::uint64_t>(
            header.NumberOfDescriptors, kMaxListEntries);
        result.handles.reserve(static_cast<std::size_t>(kCount));
        for (std::uint64_t index = 0; index < kCount; ++index)
        {
            // descriptor: V1 descriptors are a prefix of V2; reading as V1 is safe for both versions.
            MINIDUMP_HANDLE_DESCRIPTOR descriptor{};
            if (!view.readStruct(
                    location.Rva + header.SizeOfHeader + index * header.SizeOfDescriptor,
                    &descriptor))
            {
                break;
            }
            HandleEntry entry{};
            entry.handleValue = descriptor.Handle;
            entry.typeName = readMinidumpString(view, descriptor.TypeNameRva);
            entry.objectName = readMinidumpString(view, descriptor.ObjectNameRva);
            entry.attributes = descriptor.Attributes;
            entry.grantedAccess = descriptor.GrantedAccess;
            entry.handleCount = descriptor.HandleCount;
            entry.pointerCount = descriptor.PointerCount;
            result.handles.push_back(std::move(entry));
        }
    }

    void parseComments(
        const DumpFileView& view,
        const std::uint64_t directoryRva,
        const std::uint32_t streamCount,
        DumpParseResult& result)
    {
        MINIDUMP_LOCATION_DESCRIPTOR location{};
        if (findStream(view, directoryRva, streamCount, CommentStreamW, &location))
        {
            // wideBytes: Comments are truncated to the limit; UTF-16 requires an even number of bytes.
            const std::uint64_t kWideBytes =
                std::min<std::uint64_t>(location.DataSize, kMaxCommentBytes) & ~1ull;
            const unsigned char* const kWideData = view.at(location.Rva, kWideBytes);
            if (kWideData != nullptr && kWideBytes > 0)
            {
                const QString kComment = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(kWideData),
                    static_cast<qsizetype>(kWideBytes / 2)).trimmed();
                if (!kComment.isEmpty())
                {
                    result.overview.push_back({ QStringLiteral("注释 (Unicode)"), kComment });
                }
            }
        }
        if (findStream(view, directoryRva, streamCount, CommentStreamA, &location))
        {
            const std::uint64_t kAnsiBytes =
                std::min<std::uint64_t>(location.DataSize, kMaxCommentBytes);
            const unsigned char* const kAnsiData = view.at(location.Rva, kAnsiBytes);
            if (kAnsiData != nullptr && kAnsiBytes > 0)
            {
                const QString kComment = QString::fromLocal8Bit(
                    reinterpret_cast<const char*>(kAnsiData),
                    static_cast<qsizetype>(kAnsiBytes)).trimmed();
                if (!kComment.isEmpty())
                {
                    result.overview.push_back({ QStringLiteral("注释 (ANSI)"), kComment });
                }
            }
        }
    }

    QString dumpTypeFlagText(const std::uint64_t flags)
    {
        if (flags == 0)
        {
            return QStringLiteral("MiniDumpNormal");
        }
        // FlagName: Mapping for a single bit and its constant name, covering common dump type bits.
        struct FlagName
        {
            std::uint64_t bit; // bit: flag.
            const char* name;  // name: The name of a MiniDumpWith* constant.
        };
        static constexpr FlagName kFlags[] = {
            { 0x00000001, "MiniDumpWithDataSegs" },
            { 0x00000002, "MiniDumpWithFullMemory" },
            { 0x00000004, "MiniDumpWithHandleData" },
            { 0x00000008, "MiniDumpFilterMemory" },
            { 0x00000010, "MiniDumpScanMemory" },
            { 0x00000020, "MiniDumpWithUnloadedModules" },
            { 0x00000040, "MiniDumpWithIndirectlyReferencedMemory" },
            { 0x00000080, "MiniDumpFilterModulePaths" },
            { 0x00000100, "MiniDumpWithProcessThreadData" },
            { 0x00000200, "MiniDumpWithPrivateReadWriteMemory" },
            { 0x00000400, "MiniDumpWithoutOptionalData" },
            { 0x00000800, "MiniDumpWithFullMemoryInfo" },
            { 0x00001000, "MiniDumpWithThreadInfo" },
            { 0x00002000, "MiniDumpWithCodeSegs" },
            { 0x00004000, "MiniDumpWithoutAuxiliaryState" },
            { 0x00008000, "MiniDumpWithFullAuxiliaryState" },
            { 0x00010000, "MiniDumpWithPrivateWriteCopyMemory" },
            { 0x00020000, "MiniDumpIgnoreInaccessibleMemory" },
            { 0x00040000, "MiniDumpWithTokenInformation" },
            { 0x00080000, "MiniDumpWithModuleHeaders" },
            { 0x00100000, "MiniDumpFilterTriage" },
            { 0x00200000, "MiniDumpWithAvxXStateContext" },
            { 0x00400000, "MiniDumpWithIptTrace" },
            { 0x00800000, "MiniDumpScanInaccessiblePartialPages" },
        };
        QStringList names;
        for (const FlagName& flag : kFlags)
        {
            if ((flags & flag.bit) != 0)
            {
                names.append(QString::fromLatin1(flag.name));
            }
        }
        if (names.isEmpty())
        {
            return hex(flags);
        }
        return QStringLiteral("%1 (%2)").arg(hex(flags)).arg(names.join(QStringLiteral(" | ")));
    }
}
