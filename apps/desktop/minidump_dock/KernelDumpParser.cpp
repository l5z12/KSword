// ============================================================
// KernelDumpParser.cpp
// Purpose:
// - Parse Windows kernel dumps (blue screen DMPs);
//   64-bit PAGEDU64 header (0x2000 bytes) and 32-bit PAGEDUMP header (0x1000 bytes);
// - 64-bit minidumps (DumpType=4, i.e., C:\Windows\Minidump\*.dmp) are additionally parsed
//   TRIAGE_DUMP64: Driver list, unloaded driver table, crashed thread kernel stack, and TRIAGE data block;
// - Parse physical memory segment descriptions for full/kernel dumps.
// After extracting raw facts, unify the analysis chain:
//   Build module address index → extract crash-point registers → scan stack to reconstruct call stack
//   → interpret stop code parameters one by one → generate attribution conclusion (DumpAnalyzer).
// Layout source:
// - DUMP_HEADER64/TRIAGE_DUMP64/KLDR_DATA_TABLE_ENTRY64 are declared locally according
//   to the WinDbg SDK (wdbgexts.h) layout, with key offsets locked via static_assert;
// - All offset accesses are boundary-checked via DumpFileView, ensuring safe degradation for malformed samples.
// ============================================================

#include "KernelDumpParser.h"

#include "DumpAnalyzer.h"
#include "DumpBugCheckText.h"
#include "DumpContextRegisters.h"
#include "DumpKernelModuleList.h"
#include "DumpMemoryReader.h"
#include "DumpPageTable.h"
#include "DumpPhysicalMemory.h"
#include "DumpStackWalker.h"
#include "DumpSymbolIndex.h"
#include "MinidumpCodeText.h"

#include <QDateTime>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <optional>
#include <vector>

namespace ks::minidump
{
    namespace
    {
        // kKernelHeader64Bytes/kKernelHeader32Bytes: Fixed lengths for two types of kernel dump headers.
        constexpr std::uint64_t kKernelHeader64Bytes = 0x2000;
        constexpr std::uint64_t kKernelHeader32Bytes = 0x1000;
        // kMaxDriverEntries: Upper limit for parsing the driver list (hundreds on a normal system).
        constexpr std::uint32_t kMaxDriverEntries = 4096;
        // kMaxTriageDataBlocks: Upper limit for parsing TRIAGE data blocks.
        constexpr std::uint32_t kMaxTriageDataBlocks = 65536;
        // kMaxTriageByteBlockPreviews: maximum number of data blocks retained for the original preview page. The directory may contain hundreds of entries;
        // copying all of them into the results would unnecessarily increase memory and UI costs, as the first few entries already cover the core scene.
        constexpr std::uint32_t kMaxTriageByteBlockPreviews = 128;
        // kTriageByteBlockPreviewBytes: Maximum raw preview size per data block.
        constexpr std::uint32_t kTriageByteBlockPreviewBytes = 512;
        // kMaximumSecondaryDumpDataSearchBytes: Maximum search window for auxiliary black-box records.
        // Scanning a full memory dump byte-by-byte across tens of GB is infeasible; Windows triage records are located
        // at the file's beginning, and 16 MiB already covers the Secondary Dump Data region for common small dumps.
        constexpr std::uint64_t kMaximumSecondaryDumpDataSearchBytes = 16ull * 1024ull * 1024ull;
        // kMaxDriverNameChars: Maximum character count for DUMP_STRING driver names (prevents malformed lengths).
        constexpr std::uint32_t kMaxDriverNameChars = 1024;
        // kUnloadedDriverSlots: Fixed number of slots in the kernel MmUnloadedDrivers array.
        constexpr std::uint32_t kUnloadedDriverSlots = 50;
        // kMaxKernelStackFrames: Maximum number of frames to display in the kernel call stack.
        constexpr int kMaxKernelStackFrames = 64;
        // kPageBytes: Base page size; the read granularity when translating stack memory in a full dump on a page-by-page basis.
        constexpr std::uint64_t kPageBytes = 0x1000;
        // kMaxKernelStackScanBytes: Upper limit for reading upward from the stack pointer in a full dump.
        // x64 kernel stack default is 24 KiB; 64 KiB is sufficient to cover an expanded stack.
        constexpr std::uint64_t kMaxKernelStackScanBytes = 64ull * 1024ull;
        // kContext64Offset/kContext64Bytes: Position and available length of CONTEXT within DUMP_HEADER64.
        constexpr std::uint64_t kContext64Offset = 0x348;
        constexpr std::uint64_t kContext64Bytes = 0xF00 - 0x348;
        // kException64Offset: Location of EXCEPTION_RECORD64 within DUMP_HEADER64.
        constexpr std::uint64_t kException64Offset = 0xF00;
        // kContext32Offset/kContext32Bytes: Position and available length of CONTEXT within DUMP_HEADER32.
        constexpr std::uint64_t kContext32Offset = 0x320;
        constexpr std::uint64_t kContext32Bytes = 0x2CC;

#pragma pack(push, 8)
        // KernelDumpHeader64Prefix: fixed 0x60-byte prefix preceding DUMP_HEADER64.
        // Only cover fields required for discrimination and BugCheck; read other fields separately by explicit offset.
        struct KernelDumpHeader64Prefix
        {
            std::uint32_t signature;           // 0x00：'PAGE'。
            std::uint32_t validDump;           // 0x04：'DU64'。
            std::uint32_t majorVersion;        // 0x08: 15 = Free kernel, 0xC = Checked.
            std::uint32_t minorVersion;        // 0x0C: Kernel Build Number (e.g., 26100).
            std::uint64_t directoryTableBase;  // 0x10: CR3 at the time of the crash.
            std::uint64_t pfnDataBase;         // 0x18: PFN database pointer.
            std::uint64_t psLoadedModuleList;  // 0x20: Kernel module list head address.
            std::uint64_t psActiveProcessHead; // 0x28: Process list head address.
            std::uint32_t machineImageType;    // 0x30: PE machine type (0x8664 = x64).
            std::uint32_t numberProcessors;    // 0x34: Number of logical processors.
            std::uint32_t bugCheckCode;        // 0x38: Blue screen stop code.
            std::uint32_t alignmentPad;        // 0x3C: Structure alignment padding.
            std::uint64_t bugCheckParameter[4]; // 0x40: Four parameters of the stop code.
        };
        static_assert(sizeof(KernelDumpHeader64Prefix) == 0x60,
            "DUMP_HEADER64 前缀必须是 0x60 字节");
        static_assert(offsetof(KernelDumpHeader64Prefix, bugCheckParameter) == 0x40,
            "BugCheckParameter 必须位于 0x40");

        // ExceptionRecord64: EXCEPTION_RECORD64 layout (located at header offset 0xF00).
        struct ExceptionRecord64
        {
            std::uint32_t exceptionCode;    // 0x00: NTSTATUS exception code.
            std::uint32_t exceptionFlags;   // 0x04: Exception flags.
            std::uint64_t exceptionRecord;  // 0x08: Pointer to the next record in the chain.
            std::uint64_t exceptionAddress; // 0x10: Exception address.
            std::uint32_t numberParameters; // 0x18: Number of parameters.
            std::uint32_t unusedAlignment;  // 0x1C: Alignment padding.
            std::uint64_t exceptionInformation[15]; // 0x20: Parameter array.
        };
        static_assert(sizeof(ExceptionRecord64) == 0x98,
            "EXCEPTION_RECORD64 必须是 0x98 字节");

        // TriageDump64: TRIAGE_DUMP64 layout (located at file offset 0x2000).
        // All *Offset values are file offsets; SizeOfDump is the total length of triage data.
        struct TriageDump64
        {
            std::uint32_t servicePackBuild;     // 0x00: Service Pack build number.
            std::uint32_t sizeOfDump;           // 0x04: Total bytes in the triage section.
            std::uint32_t validOffset;          // 0x08: Validity marker offset.
            std::uint32_t contextOffset;        // 0x0C: Offset to the CONTEXT copy.
            std::uint32_t exceptionOffset;      // 0x10: Offset of the exception record.
            std::uint32_t mmOffset;             // 0x14: Memory management information offset.
            std::uint32_t unloadedDriversOffset; // 0x18: Unloaded drivers table offset.
            std::uint32_t prcbOffset;           // 0x1C: KPRCB copy offset.
            std::uint32_t processOffset;        // 0x20: EPROCESS copy offset.
            std::uint32_t threadOffset;         // 0x24: Offset to the ETHREAD copy.
            std::uint32_t callStackOffset;      // 0x28: Call stack raw byte offset.
            std::uint32_t sizeOfCallStack;      // 0x2C: Size of the call stack in bytes.
            std::uint32_t driverListOffset;     // 0x30: Offset of the driver list.
            std::uint32_t driverCount;          // 0x34: Driver entry count.
            std::uint32_t stringPoolOffset;     // 0x38: Offset of the string pool.
            std::uint32_t stringPoolSize;       // 0x3C: String pool size in bytes.
            std::uint32_t brokenDriverOffset;   // 0x40: Offset to the broken driver record.
            std::uint32_t triageOptions;        // 0x44: Triage option bits.
            std::uint64_t topOfStack;           // 0x48: Virtual address of the crashing thread's stack top.
            std::uint8_t architectureSpecific[16]; // 0x50: Architecture-specific reserved area.
            std::uint64_t dataPageAddress;      // 0x60: Virtual address of the additional data page.
            std::uint32_t dataPageOffset;       // 0x68: File offset of the additional data page.
            std::uint32_t dataPageSize;         // 0x6C: Size in bytes of the additional data page.
            std::uint32_t debuggerDataOffset;   // 0x70: KDDEBUGGER_DATA64 offset.
            std::uint32_t debuggerDataSize;     // 0x74: size of KDDEBUGGER_DATA64 in bytes.
            std::uint32_t dataBlocksOffset;     // 0x78: Offset of the TRIAGE_DATA_BLOCK array.
            std::uint32_t dataBlocksCount;      // 0x7C: Number of TRIAGE_DATA_BLOCK entries.
        };
        static_assert(sizeof(TriageDump64) == 0x80,
            "TRIAGE_DUMP64 必须是 0x80 字节");
        static_assert(offsetof(TriageDump64, topOfStack) == 0x48,
            "TopOfStack 必须位于 0x48");

        // TriageDump64Prefix: Stable prefix from TRIAGE_DUMP64 to DebuggerDataSize.
        // The crash context relies solely on the preceding fields. The explicit prefix locks the read range, preventing
        // arbitrary bytes after the TRIAGE region from being misinterpreted as valid fields when encountering truncated files.
        struct TriageDump64Prefix
        {
            std::uint32_t servicePackBuild;
            std::uint32_t sizeOfDump;
            std::uint32_t validOffset;
            std::uint32_t contextOffset;
            std::uint32_t exceptionOffset;
            std::uint32_t mmOffset;
            std::uint32_t unloadedDriversOffset;
            std::uint32_t prcbOffset;
            std::uint32_t processOffset;
            std::uint32_t threadOffset;
            std::uint32_t callStackOffset;
            std::uint32_t sizeOfCallStack;
            std::uint32_t driverListOffset;
            std::uint32_t driverCount;
            std::uint32_t stringPoolOffset;
            std::uint32_t stringPoolSize;
            std::uint32_t brokenDriverOffset;
            std::uint32_t triageOptions;
            std::uint64_t topOfStack;
            std::uint8_t architectureSpecific[16];
            std::uint64_t dataPageAddress;
            std::uint32_t dataPageOffset;
            std::uint32_t dataPageSize;
            std::uint32_t debuggerDataOffset;
            std::uint32_t debuggerDataSize;
        };
        static_assert(sizeof(TriageDump64Prefix) == 0x78,
            "TRIAGE_DUMP64 稳定前缀必须是 0x78 字节");

        // UnicodeString64: UNICODE_STRING64 layout (Buffer is the target machine's virtual address).
        struct UnicodeString64
        {
            std::uint16_t length;        // Length: string byte count.
            std::uint16_t maximumLength; // MaximumLength: Buffer size in bytes.
            std::uint32_t padding;       // Padding: alignment reserved.
            std::uint64_t buffer;        // Buffer: Target machine address (requires memory indexing to read).
        };
        static_assert(sizeof(UnicodeString64) == 0x10,
            "UNICODE_STRING64 必须是 0x10 字节");

        // KldrDataTableEntry64: KLDR_DATA_TABLE_ENTRY64 (public layout from wdbgexts.h).
        struct KldrDataTableEntry64
        {
            std::uint64_t inLoadOrderLinksFlink; // 0x00: Forward pointer in the linked list.
            std::uint64_t inLoadOrderLinksBlink; // 0x08: Backward pointer in the linked list.
            std::uint64_t undefined1;            // 0x10: Reserved.
            std::uint64_t undefined2;            // 0x18: Reserved.
            std::uint64_t undefined3;            // 0x20: Reserved.
            std::uint64_t nonPagedDebugInfo;     // 0x28: Pointer to non-paged debug info.
            std::uint64_t dllBase;               // 0x30: Base address where the driver is loaded.
            std::uint64_t entryPoint;            // 0x38: Entry point address.
            std::uint32_t sizeOfImage;           // 0x40: Image size.
            std::uint32_t sizePad;               // 0x44: Alignment padding.
            UnicodeString64 fullDllName;         // 0x48: Full path (buffer unavailable).
            UnicodeString64 baseDllName;         // 0x58: Base name (buffer unavailable).
            std::uint32_t flags;                 // 0x68: Load flags.
            std::uint16_t loadCount;             // 0x6C: Load count.
            std::uint16_t undefined5;            // 0x6E: Reserved.
            std::uint64_t undefined6;            // 0x70: Reserved.
            std::uint32_t checkSum;              // 0x78：PE CheckSum。
            std::uint32_t padding1;              // 0x7C: Alignment padding.
            std::uint32_t timeDateStamp;         // 0x80: PE timestamp.
            std::uint32_t padding2;              // 0x84: Alignment padding.
        };
        static_assert(sizeof(KldrDataTableEntry64) == 0x88,
            "KLDR_DATA_TABLE_ENTRY64 必须是 0x88 字节");

        // DumpDriverEntry64: triage driver list entry = name offset + KLDR snapshot.
        struct DumpDriverEntry64
        {
            std::uint32_t driverNameOffset; // DriverNameOffset: File offset of the DUMP_STRING.
            std::uint32_t alignment;        // Alignment: Alignment reserved.
            KldrDataTableEntry64 ldrEntry;  // LdrEntry: Snapshot of driver load information.
        };
        static_assert(sizeof(DumpDriverEntry64) == 0x90,
            "DUMP_DRIVER_ENTRY64 必须是 0x90 字节");

        // UnloadedDriver64: An item in the MmUnloadedDrivers array (MI_UNLOADED_DRIVER).
        // Record the address range occupied before driver unloading; this is essential for detecting calls made after the driver has been unloaded.
        struct UnloadedDriver64
        {
            UnicodeString64 name;    // 0x00: Driver name (Buffer is the target machine address).
            std::uint64_t startAddress; // 0x10: Image start address before unloading.
            std::uint64_t endAddress;   // 0x18: Image end address before unloading.
            std::uint64_t unloadTime;   // 0x20: Unload Time (FILETIME).
        };
        static_assert(sizeof(UnloadedDriver64) == 0x28,
            "MI_UNLOADED_DRIVER(64) 必须是 0x28 字节");

        // TriageDataBlock: TRIAGE_DATA_BLOCK (description of memory blocks captured in the dump).
        struct TriageDataBlock
        {
            std::uint64_t address; // Address: Target machine virtual address.
            std::uint32_t offset;  // Offset: Offset within the file.
            std::uint32_t size;    // Size: Number of data bytes.
        };
        static_assert(sizeof(TriageDataBlock) == 0x10,
            "TRIAGE_DATA_BLOCK 必须是 0x10 字节");

        // DbgKdDataHeader64: The fixed prefix of the KDDEBUGGER_DATA64 header.
        struct DbgKdDataHeader64
        {
            std::uint64_t flink;
            std::uint64_t blink;
            std::uint32_t ownerTag;
            std::uint32_t size;
        };
        static_assert(sizeof(DbgKdDataHeader64) == 0x18,
            "DBGKD_DEBUG_DATA_HEADER64 必须是 0x18 字节");

        // PhysicalMemoryRun64: physical memory segment (in pages).
        struct PhysicalMemoryRun64
        {
            std::uint64_t basePage;  // BasePage: Starting physical page number.
            std::uint64_t pageCount; // PageCount: page count.
        };
#pragma pack(pop)

        constexpr std::uint32_t kKdDebuggerOwnerTag = 0x4742444Bu;
        // Field offsets in KDDEBUGGER_DATA64 come from the publicly compatible layout in wdbgexts.h.
        // Perform boundary checks against Header.Size and snapshot length before reading.
        constexpr std::uint32_t kKdOffsetKThreadKernelStack = 0x29C;
        constexpr std::uint32_t kKdOffsetKThreadInitialStack = 0x29E;
        constexpr std::uint32_t kKdOffsetKThreadApcProcess = 0x2A0;
        constexpr std::uint32_t kKdOffsetKThreadState = 0x2A2;
        constexpr std::uint32_t kKdSizeEProcess = 0x2A8;
        constexpr std::uint32_t kKdOffsetEprocessPeb = 0x2AA;
        constexpr std::uint32_t kKdOffsetEprocessParentCid = 0x2AC;
        constexpr std::uint32_t kKdOffsetEprocessDirectoryTableBase = 0x2AE;
        constexpr std::uint32_t kKdSizePrcb = 0x2B0;
        constexpr std::uint32_t kKdOffsetPrcbCurrentThread = 0x2B4;
        constexpr std::uint32_t kKdOffsetPrcbNumber = 0x2BE;
        constexpr std::uint32_t kKdSizeEThread = 0x2C0;
        // EPROCESS ImageFileName is a fixed 15-byte ANSI field. The field offset varies by kernel version and
        // cannot be guessed solely from the EPROCESS snapshot size. The following offsets cover only the Win10
        // 20H1 (19041) version verified with Microsoft PDBs; for other kernel versions, it is better not to
        // display them than to misreport arbitrary text from the snapshot as the crashing process name.
        constexpr std::uint32_t kEprocessImageFileNameBytes = 15;
        constexpr std::uint32_t kEprocessImageFileNameOffsetWin1020H1 = 0x5A8;

        // eprocessImageFileNameOffset: Returns the verified offset of _EPROCESS.ImageFileName for the
        // current kernel build. Accepts the build number from the kernel BuildLab; returns 0 if unknown.
        std::uint32_t eprocessImageFileNameOffset(const std::uint32_t kernelBuild)
        {
            // Currently only validates Windows 10 2004 (19041) x64 PDB. Newer versions must first be verified
            // against their corresponding ntkrnlmp PDB; do not extrapolate the 19041 layout to other versions.
            return kernelBuild == 19041
                ? kEprocessImageFileNameOffsetWin1020H1
                : 0;
        }

        // Hex function: Format an unsigned integer as uppercase hexadecimal text with a 0x prefix.
        QString hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
        }

        // fileTimeToText purpose: Converts FILETIME (100ns intervals since 1601) to local time text.
        // Input: fileTime100ns; Output: yyyy-MM-dd HH:mm:ss; returns an empty string if 0.
        QString fileTimeToText(const std::uint64_t fileTime100ns)
        {
            if (fileTime100ns == 0)
            {
                return QString();
            }
            // kEpochDelta100ns: The 100ns difference between 1601-01-01 and 1970-01-01.
            constexpr std::uint64_t kEpochDelta100ns = 116444736000000000ull;
            if (fileTime100ns <= kEpochDelta100ns)
            {
                return QString();
            }
            const std::uint64_t kUnixSeconds = (fileTime100ns - kEpochDelta100ns) / 10000000ull;
            return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(kUnixSeconds))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }

        // uptimeToText: Converts a 100ns duration into 'X days HH:MM:SS' text.
        QString uptimeToText(const std::uint64_t duration100ns)
        {
            if (duration100ns == 0)
            {
                return QString();
            }
            const std::uint64_t kTotalSeconds = duration100ns / 10000000ull;
            const std::uint64_t kDays = kTotalSeconds / 86400;
            const std::uint64_t kHours = (kTotalSeconds % 86400) / 3600;
            const std::uint64_t kMinutes = (kTotalSeconds % 3600) / 60;
            const std::uint64_t kSeconds = kTotalSeconds % 60;
            return QStringLiteral("%1 天 %2:%3:%4")
                .arg(kDays)
                .arg(kHours, 2, 10, QLatin1Char('0'))
                .arg(kMinutes, 2, 10, QLatin1Char('0'))
                .arg(kSeconds, 2, 10, QLatin1Char('0'));
        }

        // machineImageTypeText: Converts PE machine type to architecture text.
        QString machineImageTypeText(const std::uint32_t machineType)
        {
            switch (machineType)
            {
            case 0x014C: return QStringLiteral("x86");
            case 0x8664: return QStringLiteral("x64 (AMD64)");
            case 0xAA64: return QStringLiteral("ARM64");
            case 0x01C4: return QStringLiteral("ARM (Thumb-2)");
            default:
                return QStringLiteral("机器类型 %1").arg(hex(machineType));
            }
        }

        // dumpTypeText: Convert a kernel-dump DumpType number into a Chinese description.
        QString dumpTypeText(const std::uint32_t dumpType)
        {
            switch (dumpType)
            {
            case 1: return QStringLiteral("完整内存转储 (Full)");
            case 2: return QStringLiteral("内核内存转储 (Summary/Kernel)");
            case 3: return QStringLiteral("仅转储头 (Header)");
            case 4: return QStringLiteral("小型内存转储 (Triage/Minidump)");
            case 5: return QStringLiteral("活动内存转储 (Bitmap Full)");
            case 6: return QStringLiteral("活动内核内存转储 (Bitmap Kernel)");
            case 7: return QStringLiteral("自动内存转储 (Automatic)");
            default:
                return QStringLiteral("类型 %1").arg(dumpType);
            }
        }

        // productTypeText purpose: Convert VER_NT_* product types to Chinese.
        QString productTypeText(const std::uint32_t productType)
        {
            switch (productType)
            {
            case 1: return QStringLiteral("工作站 (VER_NT_WORKSTATION)");
            case 2: return QStringLiteral("域控制器 (VER_NT_DOMAIN_CONTROLLER)");
            case 3: return QStringLiteral("服务器 (VER_NT_SERVER)");
            default: return QString::number(productType);
            }
        }

        // kPageFillDword: Fill value for unused regions in the kernel dump header (ASCII 'PAGE').
        // The dump writer only fills fields it cares about, leaving others with this fill pattern. Therefore,
        // reading this pattern means 'the field was never filled' and must never be interpreted as a real value.
        constexpr std::uint32_t kPageFillDword = 0x45474150u;

        // writerStatusText purpose: explains the dump writer status and indicates whether the dump is complete.
        QString writerStatusText(const std::uint32_t writerStatus)
        {
            switch (writerStatus)
            {
            case 0: return QStringLiteral("0 —— 写入成功，转储完整");
            case 1: return QStringLiteral("1 —— 写入过程中出现错误，内容可能不完整");
            case 2: return QStringLiteral("2 —— 转储被截断（磁盘空间不足或页面文件太小）");
            case 3: return QStringLiteral("3 —— 转储设备不可用");
            case kPageFillDword:
                return QStringLiteral("未记录（该字段仍是 PAGE 填充，转储写入器没有填写）");
            default: return QStringLiteral("%1 —— 未收录的写入器状态").arg(writerStatus);
            }
        }

        // kernelBuildText purpose: Combine kernel version numbers into readable text.
        // The lower 4 bits of MajorVersion represent the build flavor (15=Free retail, 12=Checked debug), not
        // the major version number. Directly concatenating them as 15.26100 would be misread as version 15.
        QString kernelBuildText(const std::uint32_t majorVersion, const std::uint32_t minorVersion)
        {
            const std::uint32_t kFlavor = majorVersion & 0xFu;
            const QString kFlavorText = kFlavor == 15
                ? QStringLiteral("Free 零售版内核")
                : (kFlavor == 12 ? QStringLiteral("Checked 调试版内核")
                                : QStringLiteral("构建风格编号 %1").arg(kFlavor));
            return QStringLiteral("%1（%2）").arg(minorVersion).arg(kFlavorText);
        }

        // triageRangeValid: Checks if an 'offset + length' range within the triage area is valid.
        // TRIAGE_DUMP64 starts at offset 0x50 as an architecture-specific union; since its size is not definitively defined
        // across architectures, the subsequent DataPage, DebuggerData, and DataBlocks fields may be globally misaligned.
        // Apply two hard constraints—file boundaries and 'must fall after the triage range'—to filter first. When
        // fields are misaligned, these values almost certainly fall outside the range and are safely discarded.
        bool triageRangeValid(
            const DumpFileView& view,
            const std::uint64_t offset,
            const std::uint64_t bytes)
        {
            if (offset < kKernelHeader64Bytes || bytes == 0)
            {
                return false;
            }
            return view.contains(offset, bytes);
        }

        template <typename ValueType>
        bool triageSnapshotRead(
            const DumpFileView& view,
            const std::uint32_t snapshotOffset,
            const std::uint32_t snapshotBytes,
            const std::uint32_t fieldOffset,
            ValueType* const valueOut)
        {
            if (valueOut == nullptr || fieldOffset > snapshotBytes ||
                sizeof(ValueType) > snapshotBytes - fieldOffset)
            {
                return false;
            }
            return view.readStruct(
                static_cast<std::uint64_t>(snapshotOffset) + fieldOffset,
                valueOut);
        }

        QString kthreadStateText(const std::uint32_t rawState)
        {
            const std::uint8_t kState = static_cast<std::uint8_t>(rawState & 0xFFu);
            QString name;
            switch (kState)
            {
            case 0: name = QStringLiteral("Initialized"); break;
            case 1: name = QStringLiteral("Ready"); break;
            case 2: name = QStringLiteral("Running"); break;
            case 3: name = QStringLiteral("Standby"); break;
            case 4: name = QStringLiteral("Terminated"); break;
            case 5: name = QStringLiteral("Waiting"); break;
            case 6: name = QStringLiteral("Transition"); break;
            case 7: name = QStringLiteral("DeferredReady"); break;
            case 8: name = QStringLiteral("GateWaitObsolete"); break;
            case 9: name = QStringLiteral("WaitingForProcessInSwap"); break;
            default: name = QStringLiteral("未知状态"); break;
            }
            return rawState == kState
                ? name
                : QStringLiteral("%1（原始值 %2）").arg(name, hex(rawState));
        }

        // SecondaryDumpDataRecordHeader: Common record header for Windows kernel Secondary Dump Data.
        // Records are wrapped first with a provider GUID and length, followed by the specific blackbox body.
        // GUID and field offsets verified against local WinDbg !blackboxpnp; string length, offsets, and field values are
        // boundary-checked during parsing. If confirmation fails, only 'not found' is reported; device state is never guessed.
#pragma pack(push, 1)
        struct BlackboxGuid
        {
            std::uint32_t data1;
            std::uint16_t data2;
            std::uint16_t data3;
            std::uint8_t data4[8];
        };

        struct SecondaryDumpDataRecordHeader
        {
            BlackboxGuid providerId;         // 0x00：PnP blackbox provider GUID。
            std::uint32_t recordBytes;       // 0x10: Provider Payload Byte Count.
            std::uint32_t reserved;          // 0x14: Reserved.
        };

        struct BlackboxPnpBodyPrefix
        {
            std::uint32_t version;           // 0x00: PnP blackbox body version.
            std::uint32_t reserved[4];       // 0x04: Currently public extension reserved field.
            std::uint64_t activityTime;      // 0x14: Activity time (FILETIME).
            std::uint32_t eventInformation;  // 0x1C: PnP event information.
            std::uint32_t eventInProgress;   // 0x20: Indicates whether processing is still in progress.
            std::uint32_t problemCode;       // 0x24: CM_PROB_* device problem code.
            std::uint32_t vetoType;          // 0x28: PnP veto type.
            std::uint32_t reserved2;         // 0x2C: Reserved, followed by a NUL-terminated DeviceId.
        };

        // BlackboxBsdBodyPrefix: Stable prefix for BSD (Boot Status Data) blackbox.
        // Offsets for Version, ProductType, and LastReferenceTime have been verified field-by-field against
        // WinDbg !blackboxbsd output; other bitfields and version-related fields are not speculated.
        struct BlackboxBsdBodyPrefix
        {
            std::uint32_t reserved;             // 0x00: Internal reserved field.
            std::uint32_t version;              // 0x04: BSD record version/size.
            std::uint32_t productType;          // 0x08: VER_NT_* product type.
            std::uint8_t reservedToReferenceTime[0x18]; // 0x0C..0x23: Version-related status bits.
            std::uint64_t lastReferenceTime;    // 0x24: Recent boot status reference time (FILETIME).
        };
#pragma pack(pop)
        static_assert(sizeof(BlackboxGuid) == 0x10);
        static_assert(sizeof(SecondaryDumpDataRecordHeader) == 0x18);
        static_assert(sizeof(BlackboxPnpBodyPrefix) == 0x30);
        static_assert(sizeof(BlackboxBsdBodyPrefix) == 0x2C);

        constexpr BlackboxGuid kBlackboxPnpProviderId = {
            0xB7631941u, 0x532Au, 0x4CD6u,
            { 0xB1u, 0xB1u, 0xEDu, 0xB5u, 0x91u, 0x7Du, 0x45u, 0x57u } };
        constexpr BlackboxGuid kBlackboxBsdProviderId = {
            0xF57308DFu, 0xCC45u, 0x4E01u,
            { 0xADu, 0x76u, 0x29u, 0xA4u, 0xEBu, 0xB0u, 0x10u, 0xECu } };
        constexpr BlackboxGuid kBlackboxNtfsProviderId = {
            0x00AFE9C4u, 0x940Du, 0x4213u,
            { 0x80u, 0x16u, 0xCDu, 0x37u, 0x19u, 0xB5u, 0xBCu, 0x20u } };
        constexpr BlackboxGuid kBlackboxWinlogonProviderId = {
            0x80CC79CFu, 0xA719u, 0x4AF1u,
            { 0xBFu, 0x97u, 0xFEu, 0x29u, 0xFFu, 0x76u, 0xEBu, 0xC1u } };
        constexpr BlackboxGuid kBlackboxCodeIntegrityProviderId = {
            0x4EE76BD8u, 0x3CF4u, 0x44A0u,
            { 0xA0u, 0xACu, 0x39u, 0x37u, 0x64u, 0x3Eu, 0x37u, 0xA3u } };
        constexpr std::uint32_t kMaximumBlackboxPnpRecordBytes = 64u * 1024u;
        constexpr std::uint32_t kMaximumBlackboxPnpDeviceIdBytes = 8u * 1024u;

        bool guidEquals(const BlackboxGuid& left, const BlackboxGuid& right)
        {
            return std::memcmp(&left, &right, sizeof(BlackboxGuid)) == 0;
        }

        // appendSecondaryDumpPreview purpose: Retain the original payload preview of verified Secondary Dump Data.
        // These records lack target machine virtual addresses and must be marked by file offset; they cannot be mixed into virtual memory read indices.
        void appendSecondaryDumpPreview(
            const DumpFileView& view,
            const std::uint64_t recordOffset,
            const SecondaryDumpDataRecordHeader& header,
            const QString& source,
            DumpParseResult& result)
        {
            constexpr std::uint64_t kPreviewBytes = 512;
            const std::uint64_t kRecordBytes = sizeof(SecondaryDumpDataRecordHeader) +
                static_cast<std::uint64_t>(header.recordBytes);
            if (!view.contains(recordOffset, kRecordBytes))
            {
                return;
            }
            const std::uint64_t kPreviewBytesValue = std::min(kRecordBytes, kPreviewBytes);
            const unsigned char* const kData = view.at(recordOffset, kPreviewBytesValue);
            if (kData == nullptr)
            {
                return;
            }
            DumpByteBlock block{};
            block.fileOffset = recordOffset;
            block.capturedBytes = kRecordBytes;
            block.source = source;
            block.hasVirtualAddress = false;
            block.previewBytes.assign(kData, kData + kPreviewBytesValue);
            result.byteBlocks.push_back(std::move(block));
        }

        // secondaryDumpDataSearchEnd: Returns the position after the file end allowed for searching within the auxiliary black box.
        // Full scan for mini-dumps; full dumps are limited to a fixed window to prevent background parsing from going out of control due to file size.
        std::uint64_t secondaryDumpDataSearchEnd(const DumpFileView& view)
        {
            return std::min(view.size,
                kKernelHeader64Bytes + kMaximumSecondaryDumpDataSearchBytes);
        }

        QString pnpProblemCodeText(const std::uint32_t code)
        {
            switch (code)
            {
            case 0: return QStringLiteral("无设备问题");
            case 10: return QStringLiteral("Code 10：设备无法启动");
            case 14: return QStringLiteral("Code 14：设备需要重启");
            case 18: return QStringLiteral("Code 18：需要重新安装设备驱动");
            case 22: return QStringLiteral("Code 22：设备已被禁用");
            case 24: return QStringLiteral("Code 24：设备不存在、工作异常，或其驱动未正确安装");
            case 28: return QStringLiteral("Code 28：未安装设备驱动");
            case 31: return QStringLiteral("Code 31：Windows 无法加载设备所需驱动");
            case 32: return QStringLiteral("Code 32：设备驱动服务已被禁用");
            case 39: return QStringLiteral("Code 39：设备驱动无法加载");
            case 43: return QStringLiteral("Code 43：设备报告了问题并已停止");
            default: return QStringLiteral("CM_PROB=%1").arg(code);
            }
        }

        // tryParseBlackboxPnp: locates and parses the PnP blackbox within the triage attachment area.
        // The provider GUID is strongly signed; subsequently, length, UTF-16 device ID, and bug check
        // code are validated to prevent arbitrary byte sequences from being misreported as device events.
        void tryParseBlackboxPnp(const DumpFileView& view, DumpParseResult& result)
        {
            constexpr std::uint64_t kSearchStart = kKernelHeader64Bytes;
            const std::uint64_t kSearchEnd = secondaryDumpDataSearchEnd(view);
            if (kSearchEnd <= kSearchStart ||
                kSearchEnd - kSearchStart <
                    sizeof(SecondaryDumpDataRecordHeader) + sizeof(BlackboxPnpBodyPrefix))
            {
                return;
            }

            for (std::uint64_t offset = kSearchStart;
                 offset <= kSearchEnd - sizeof(SecondaryDumpDataRecordHeader) - sizeof(BlackboxPnpBodyPrefix);
                 offset += sizeof(std::uint32_t))
            {
                SecondaryDumpDataRecordHeader recordHeader{};
                if (!view.readStruct(offset, &recordHeader) ||
                    !guidEquals(recordHeader.providerId, kBlackboxPnpProviderId) ||
                    recordHeader.recordBytes < sizeof(BlackboxPnpBodyPrefix) ||
                    recordHeader.recordBytes > kMaximumBlackboxPnpRecordBytes)
                {
                    continue;
                }

                const std::uint64_t kBodyOffset = offset + sizeof(SecondaryDumpDataRecordHeader);
                if (recordHeader.recordBytes > view.size - kBodyOffset)
                {
                    continue;
                }
                BlackboxPnpBodyPrefix evidence{};
                if (!view.readStruct(kBodyOffset, &evidence) || evidence.version == 0)
                {
                    continue;
                }

                const std::uint64_t kDeviceIdOffset = kBodyOffset + sizeof(BlackboxPnpBodyPrefix);
                const std::uint64_t kMaximumDeviceIdBytes = std::min<std::uint64_t>(
                    kMaximumBlackboxPnpDeviceIdBytes,
                    recordHeader.recordBytes - sizeof(BlackboxPnpBodyPrefix));
                std::uint64_t deviceIdByteCount = 0;
                while (deviceIdByteCount + sizeof(char16_t) <= kMaximumDeviceIdBytes)
                {
                    std::uint16_t character = 0;
                    if (!view.readStruct(kDeviceIdOffset + deviceIdByteCount, &character))
                    {
                        break;
                    }
                    if (character == 0)
                    {
                        break;
                    }
                    deviceIdByteCount += sizeof(char16_t);
                }
                if (deviceIdByteCount == 0 ||
                    deviceIdByteCount + sizeof(char16_t) > kMaximumDeviceIdBytes)
                {
                    continue;
                }

                const unsigned char* const kDeviceIdData = view.at(
                    kDeviceIdOffset, deviceIdByteCount);
                if (kDeviceIdData == nullptr)
                {
                    continue;
                }
                const QString kDeviceId = QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(kDeviceIdData),
                    static_cast<qsizetype>(deviceIdByteCount / sizeof(char16_t)))
                    .trimmed();
                if (kDeviceId.isEmpty() || kDeviceId.contains(QChar::ReplacementCharacter))
                {
                    continue;
                }

                result.overview.push_back({ QStringLiteral("PnP 黑盒"),
                    QStringLiteral("已捕获（版本 %1，记录偏移 %2）")
                        .arg(evidence.version)
                        .arg(hex(offset)) });
                appendSecondaryDumpPreview(view, offset, recordHeader,
                    QStringLiteral("PnP 黑盒"), result);
                result.exceptionInfo.push_back({ QStringLiteral("PnP 黑盒设备 ID"), kDeviceId });
                result.exceptionInfo.push_back({ QStringLiteral("PnP 黑盒设备问题"),
                    pnpProblemCodeText(evidence.problemCode) });
                result.exceptionInfo.push_back({ QStringLiteral("PnP 黑盒活动时间"),
                    fileTimeToText(evidence.activityTime) });
                result.exceptionInfo.push_back({ QStringLiteral("PnP 黑盒事件信息"),
                    QStringLiteral("%1（活动中：%2，Veto 类型：%3）")
                        .arg(evidence.eventInformation)
                        .arg(evidence.eventInProgress)
                        .arg(evidence.vetoType) });
                if (evidence.problemCode != 0)
                {
                    result.diagnostics.append(
                        QStringLiteral("PnP 黑盒记录到设备问题：%1，设备 ID：%2。")
                            .arg(pnpProblemCodeText(evidence.problemCode), kDeviceId));
                }
                return;
            }
        }

        // tryParseBlackboxBsd purpose: Extracts verified stable fields from the system boot/shutdown state blackbox.
        // BSD records contain numerous bitfields evolving with Windows versions; currently, only the version, product type, and last
        // reference time (cross-validated by WinDbg) are displayed, avoiding interpretation of undocumented fields as "abnormal boot".
        void tryParseBlackboxBsd(const DumpFileView& view, DumpParseResult& result)
        {
            constexpr std::uint64_t kSearchStart = kKernelHeader64Bytes;
            const std::uint64_t kSearchEnd = secondaryDumpDataSearchEnd(view);
            if (kSearchEnd <= kSearchStart ||
                kSearchEnd - kSearchStart <
                    sizeof(SecondaryDumpDataRecordHeader) + sizeof(BlackboxBsdBodyPrefix))
            {
                return;
            }

            for (std::uint64_t offset = kSearchStart;
                 offset <= kSearchEnd - sizeof(SecondaryDumpDataRecordHeader) -
                     sizeof(BlackboxBsdBodyPrefix);
                 offset += sizeof(std::uint32_t))
            {
                SecondaryDumpDataRecordHeader recordHeader{};
                if (!view.readStruct(offset, &recordHeader) ||
                    !guidEquals(recordHeader.providerId, kBlackboxBsdProviderId) ||
                    recordHeader.recordBytes < sizeof(BlackboxBsdBodyPrefix) ||
                    recordHeader.recordBytes > kMaximumBlackboxPnpRecordBytes)
                {
                    continue;
                }

                const std::uint64_t kBodyOffset = offset + sizeof(SecondaryDumpDataRecordHeader);
                if (recordHeader.recordBytes > view.size - kBodyOffset)
                {
                    continue;
                }
                BlackboxBsdBodyPrefix evidence{};
                if (!view.readStruct(kBodyOffset, &evidence) || evidence.version == 0)
                {
                    continue;
                }

                result.overview.push_back({ QStringLiteral("BSD 启动状态黑盒"),
                    QStringLiteral("已捕获（版本 %1，产品类型 %2，记录偏移 %3）")
                        .arg(hex(evidence.version))
                        .arg(productTypeText(evidence.productType))
                        .arg(hex(offset)) });
                appendSecondaryDumpPreview(view, offset, recordHeader,
                    QStringLiteral("BSD 启动状态黑盒"), result);
                const QString kReferenceTime = fileTimeToText(evidence.lastReferenceTime);
                if (!kReferenceTime.isEmpty())
                {
                    result.overview.push_back({ QStringLiteral("最近启动状态参考时间"),
                        kReferenceTime });
                }
                return;
            }
        }

        // tryReportBlackboxNtfs: Reports whether the NTFS blackbox was actually saved by the dump.
        // NTFS event array layout varies by version. Until verified per version, only display provider, record
        // offset, and payload length to avoid misinterpreting version-specific entries as I/O or oplock failures.
        void tryReportBlackboxNtfs(const DumpFileView& view, DumpParseResult& result)
        {
            constexpr std::uint64_t kSearchStart = kKernelHeader64Bytes;
            const std::uint64_t kSearchEnd = secondaryDumpDataSearchEnd(view);
            if (kSearchEnd <= kSearchStart ||
                kSearchEnd - kSearchStart < sizeof(SecondaryDumpDataRecordHeader))
            {
                return;
            }

            for (std::uint64_t offset = kSearchStart;
                 offset <= kSearchEnd - sizeof(SecondaryDumpDataRecordHeader);
                 offset += sizeof(std::uint32_t))
            {
                SecondaryDumpDataRecordHeader recordHeader{};
                if (!view.readStruct(offset, &recordHeader) ||
                    !guidEquals(recordHeader.providerId, kBlackboxNtfsProviderId) ||
                    recordHeader.recordBytes == 0 ||
                    recordHeader.recordBytes > kMaximumBlackboxPnpRecordBytes)
                {
                    continue;
                }
                const std::uint64_t kBodyOffset = offset + sizeof(SecondaryDumpDataRecordHeader);
                if (recordHeader.recordBytes > view.size - kBodyOffset)
                {
                    continue;
                }
                result.overview.push_back({ QStringLiteral("NTFS 黑盒"),
                    QStringLiteral("已捕获（载荷 %1 字节，记录偏移 %2）")
                        .arg(recordHeader.recordBytes)
                        .arg(hex(offset)) });
                appendSecondaryDumpPreview(view, offset, recordHeader,
                    QStringLiteral("NTFS 黑盒"), result);
                return;
            }
        }

        // tryReportBlackboxPresence: Reports auxiliary black boxes that have been dumped but lack a stable, publicly documented
        // field layout in the current version. Only outputs provider payload metadata to avoid misrepresenting private binary fields
        // as login or code integrity conclusions. Field parsing can be extended here once per-version layout validation is obtained.
        void tryReportBlackboxPresence(
            const DumpFileView& view,
            const BlackboxGuid& providerId,
            const QString& name,
            DumpParseResult& result)
        {
            constexpr std::uint64_t kSearchStart = kKernelHeader64Bytes;
            const std::uint64_t kSearchEnd = secondaryDumpDataSearchEnd(view);
            if (kSearchEnd <= kSearchStart ||
                kSearchEnd - kSearchStart < sizeof(SecondaryDumpDataRecordHeader))
            {
                return;
            }
            for (std::uint64_t offset = kSearchStart;
                 offset <= kSearchEnd - sizeof(SecondaryDumpDataRecordHeader);
                 offset += sizeof(std::uint32_t))
            {
                SecondaryDumpDataRecordHeader recordHeader{};
                if (!view.readStruct(offset, &recordHeader) ||
                    !guidEquals(recordHeader.providerId, providerId) ||
                    recordHeader.recordBytes == 0 ||
                    recordHeader.recordBytes > kMaximumBlackboxPnpRecordBytes)
                {
                    continue;
                }
                const std::uint64_t kBodyOffset = offset + sizeof(SecondaryDumpDataRecordHeader);
                if (recordHeader.recordBytes > view.size - kBodyOffset)
                {
                    continue;
                }
                result.overview.push_back({ name,
                    QStringLiteral("已捕获（载荷 %1 字节，记录偏移 %2，详细字段待版本验证）")
                        .arg(recordHeader.recordBytes)
                        .arg(hex(offset)) });
                appendSecondaryDumpPreview(view, offset, recordHeader, name, result);
                return;
            }
        }

        // parseTriageExecutionContext: Converts the TRIAGE-saved current processor, thread, and process snapshots
        // into independent 'crash context' fact pages. Field offsets are derived from the dump's own
        // KDDEBUGGER_DATA64-compatible block to avoid dependency on fixed Windows version private structure offsets.
        void parseTriageExecutionContext(
            const DumpFileView& view,
            const TriageDump64& triage,
            const std::uint32_t kernelBuild,
            DumpParseResult& result)
        {
            constexpr std::uint32_t kKdDebuggerDataMaximumBytes = 0x380;
            if (!triageRangeValid(view, triage.debuggerDataOffset,
                    std::min<std::uint32_t>(triage.debuggerDataSize,
                        kKdDebuggerDataMaximumBytes)) ||
                triage.debuggerDataSize < sizeof(DbgKdDataHeader64))
            {
                result.diagnostics.append(QStringLiteral(
                    "TRIAGE 未提供完整 KD 调试数据块，无法解析崩溃现场对象。") );
                return;
            }

            DbgKdDataHeader64 kdHeader{};
            if (!view.readStruct(triage.debuggerDataOffset, &kdHeader) ||
                kdHeader.ownerTag != kKdDebuggerOwnerTag ||
                kdHeader.size < kKdSizeEThread ||
                kdHeader.size > triage.debuggerDataSize)
            {
                result.diagnostics.append(QStringLiteral(
                    "TRIAGE KD 调试数据块校验失败，已跳过崩溃现场对象解析。"));
                return;
            }

            const auto kReadKdU16 = [&view, &triage, kdBytes = kdHeader.size] (
                const std::uint32_t offset, std::uint16_t* const value) -> bool
            {
                return triageSnapshotRead(view, triage.debuggerDataOffset, kdBytes, offset, value);
            };
            std::uint16_t kdOffsetKThreadKernelStack = 0;
            std::uint16_t kdOffsetKThreadInitialStack = 0;
            std::uint16_t kdOffsetKThreadApcProcess = 0;
            std::uint16_t kdOffsetKThreadState = 0;
            std::uint16_t kdSizeEProcess = 0;
            std::uint16_t kdOffsetEprocessPeb = 0;
            std::uint16_t kdOffsetEprocessParentCid = 0;
            std::uint16_t kdOffsetEprocessDirectoryTableBase = 0;
            std::uint16_t kdSizePrcb = 0;
            std::uint16_t kdOffsetPrcbCurrentThread = 0;
            std::uint16_t kdOffsetPrcbNumber = 0;
            std::uint16_t kdSizeEThread = 0;
            if (!kReadKdU16(kKdOffsetKThreadKernelStack, &kdOffsetKThreadKernelStack) ||
                !kReadKdU16(kKdOffsetKThreadInitialStack, &kdOffsetKThreadInitialStack) ||
                !kReadKdU16(kKdOffsetKThreadApcProcess, &kdOffsetKThreadApcProcess) ||
                !kReadKdU16(kKdOffsetKThreadState, &kdOffsetKThreadState) ||
                !kReadKdU16(kKdSizeEProcess, &kdSizeEProcess) ||
                !kReadKdU16(kKdOffsetEprocessPeb, &kdOffsetEprocessPeb) ||
                !kReadKdU16(kKdOffsetEprocessParentCid, &kdOffsetEprocessParentCid) ||
                !kReadKdU16(kKdOffsetEprocessDirectoryTableBase,
                    &kdOffsetEprocessDirectoryTableBase) ||
                !kReadKdU16(kKdSizePrcb, &kdSizePrcb) ||
                !kReadKdU16(kKdOffsetPrcbCurrentThread, &kdOffsetPrcbCurrentThread) ||
                !kReadKdU16(kKdOffsetPrcbNumber, &kdOffsetPrcbNumber) ||
                !kReadKdU16(kKdSizeEThread, &kdSizeEThread) ||
                kdSizePrcb == 0 || kdSizeEThread == 0 || kdSizeEProcess == 0)
            {
                result.diagnostics.append(QStringLiteral(
                    "KD 调试数据块缺少对象偏移元数据，已跳过崩溃现场对象解析。"));
                return;
            }

            std::uint16_t cpuNumber = 0;
            std::uint64_t currentThread = 0;
            std::uint64_t threadProcess = 0;
            std::uint64_t kernelStack = 0;
            std::uint64_t initialStack = 0;
            std::uint32_t threadState = 0;
            std::uint64_t processDirectoryTableBase = 0;
            std::uint64_t parentProcessId = 0;
            std::uint64_t processPeb = 0;
            const bool kHaveCpu = triageSnapshotRead(
                view, triage.prcbOffset, kdSizePrcb, kdOffsetPrcbNumber, &cpuNumber);
            const bool kHaveCurrentThread = triageSnapshotRead(
                view, triage.prcbOffset, kdSizePrcb, kdOffsetPrcbCurrentThread,
                &currentThread);
            const bool kHaveThreadProcess = triageSnapshotRead(
                view, triage.threadOffset, kdSizeEThread, kdOffsetKThreadApcProcess,
                &threadProcess);
            const bool kHaveKernelStack = triageSnapshotRead(
                view, triage.threadOffset, kdSizeEThread, kdOffsetKThreadKernelStack,
                &kernelStack);
            const bool kHaveInitialStack = triageSnapshotRead(
                view, triage.threadOffset, kdSizeEThread, kdOffsetKThreadInitialStack,
                &initialStack);
            const bool kHaveThreadState = triageSnapshotRead(
                view, triage.threadOffset, kdSizeEThread, kdOffsetKThreadState,
                &threadState);
            const bool kHaveDirectoryTableBase = triageSnapshotRead(
                view, triage.processOffset, kdSizeEProcess,
                kdOffsetEprocessDirectoryTableBase, &processDirectoryTableBase);
            const bool kHaveParentProcessId = triageSnapshotRead(
                view, triage.processOffset, kdSizeEProcess,
                kdOffsetEprocessParentCid, &parentProcessId);
            const bool kHavePeb = triageSnapshotRead(
                view, triage.processOffset, kdSizeEProcess, kdOffsetEprocessPeb,
                &processPeb);
            const std::uint32_t kImageNameOffset = eprocessImageFileNameOffset(kernelBuild);
            char imageNameBytes[kEprocessImageFileNameBytes]{};
            bool haveImageName = false;
            if (kImageNameOffset != 0 && kImageNameOffset <= kdSizeEProcess &&
                kEprocessImageFileNameBytes <= kdSizeEProcess - kImageNameOffset)
            {
                const unsigned char* const kImageNameData = view.at(
                    static_cast<std::uint64_t>(triage.processOffset) + kImageNameOffset,
                    kEprocessImageFileNameBytes);
                if (kImageNameData != nullptr)
                {
                    std::memcpy(imageNameBytes, kImageNameData, sizeof(imageNameBytes));
                    haveImageName = true;
                }
            }

            result.executionContext.push_back({
                QStringLiteral("KD 调试数据大小"), hex(kdHeader.size) });
            result.executionContext.push_back({
                QStringLiteral("KPRCB 快照偏移"), hex(triage.prcbOffset) });
            result.executionContext.push_back({
                QStringLiteral("KTHREAD 快照偏移"), hex(triage.threadOffset) });
            result.executionContext.push_back({
                QStringLiteral("EPROCESS 快照偏移"), hex(triage.processOffset) });
            if (kHaveCpu)
            {
                result.executionContext.push_back({
                    QStringLiteral("崩溃处理器编号"), QString::number(cpuNumber) });
            }
            if (kHaveCurrentThread)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前 KTHREAD"), hex(currentThread) });
            }
            if (kHaveThreadProcess)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前 EPROCESS"), hex(threadProcess) });
            }
            if (kHaveKernelStack)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前内核栈"), hex(kernelStack) });
            }
            if (kHaveInitialStack)
            {
                result.executionContext.push_back({
                    QStringLiteral("内核初始栈"), hex(initialStack) });
            }
            if (kHaveThreadState)
            {
                result.executionContext.push_back({
                    QStringLiteral("KTHREAD 状态"), kthreadStateText(threadState) });
            }
            if (kHaveDirectoryTableBase)
            {
                result.executionContext.push_back({
                    QStringLiteral("进程目录表基址 (CR3)"),
                    hex(processDirectoryTableBase) });
            }
            if (kHaveParentProcessId)
            {
                result.executionContext.push_back({
                    QStringLiteral("父进程 ID"), hex(parentProcessId) });
            }
            if (kHavePeb)
            {
                result.executionContext.push_back({
                    QStringLiteral("进程 PEB"), hex(processPeb) });
            }
            if (haveImageName)
            {
                std::size_t imageNameLength = 0;
                while (imageNameLength < kEprocessImageFileNameBytes &&
                    imageNameBytes[imageNameLength] != '\0')
                {
                    ++imageNameLength;
                }
                const QString kImageName = QString::fromLatin1(
                    imageNameBytes, static_cast<qsizetype>(imageNameLength)).trimmed();
                const bool kPrintable = !kImageName.isEmpty() &&
                    std::all_of(
                        kImageName.cbegin(), kImageName.cend(),
                        [](const QChar character)
                        {
                            return character.unicode() >= 0x20 && character.unicode() <= 0x7E;
                        });
                if (kPrintable)
                {
                    result.executionContext.push_back({
                        QStringLiteral("崩溃时当前进程映像"), kImageName });
                }
            }
            else if (kImageNameOffset == 0)
            {
                result.diagnostics.append(QStringLiteral(
                    "当前内核版本的 EPROCESS 映像名偏移未经验证，未展示崩溃进程名。"));
            }
        }

        // plausibleTimestamp: Checks if a PE timestamp falls within a reasonable date range.
        // Note: The offset of TimeDateStamp in the triage driver list varies with Windows versions (since Win10, this location
        //is occupied by other fields). Reading it directly may yield a timestamp forged from the lower 32 bits of a pointer.
        // Validate against a date range here; leave impossible values empty instead of displaying implausible dates such as 1970 or 2100.
        bool plausibleTimestamp(const std::uint32_t timeDateStamp)
        {
            // Lower bound set to 1995, upper bound to 2038: values earlier than Windows NT's commercial
            // release or later than the 32-bit time_t limit cannot be valid build timestamps.
            constexpr std::uint32_t kMinTimestamp = 0x2F000000u;
            constexpr std::uint32_t kMaxTimestamp = 0x7FFFFFFFu;
            return timeDateStamp >= kMinTimestamp && timeDateStamp <= kMaxTimestamp;
        }

        // looksLikeDriverName purpose: determine if decoded text resembles a driver name or path.
        // Driver names consist entirely of ASCII path characters; a high count of non-printable code points indicates a misunderstanding of the length unit.
        bool looksLikeDriverName(const QString& text)
        {
            if (text.isEmpty())
            {
                return false;
            }
            int printable = 0;
            for (const QChar kCharacter : text)
            {
                const char16_t kUnit = kCharacter.unicode();
                if (kUnit >= 0x20 && kUnit < 0x7F)
                {
                    ++printable;
                }
            }
            // Allow a small amount of non-ASCII (localized paths), but the main content must be printable ASCII.
            return printable * 5 >= text.size() * 4;
        }

        // readDumpString purpose: Read the triage driver name DUMP_STRING (length + UTF-16 text).
        // The unit for the length field is not officially standardized: it is described as either 'character count' or 'byte count'. A
        // 2x difference would truncate the driver name by half or read garbage. This implementation first decodes as character count;
        // if the result does not resemble a driver name, it retries as byte count and selects the result that looks like a driver name.
        // Accepts view and file offset; returns the driver name, or an empty string if neither interpretation holds.
        QString readDumpString(const DumpFileView& view, const std::uint64_t offset)
        {
            if (offset == 0)
            {
                return QString();
            }
            // length: Original length field; any value exceeding the limit is treated as malformed data.
            std::uint32_t length = 0;
            if (!view.readStruct(offset, &length) || length == 0 ||
                length > kMaxDriverNameChars * 2)
            {
                return QString();
            }
            // decode: decode text by the given character count; return an empty string if out of bounds.
            const auto kDecode = [&view, offset](const std::uint32_t charCount) -> QString
            {
                if (charCount == 0 || charCount > kMaxDriverNameChars)
                {
                    return QString();
                }
                const std::uint64_t kTextBytes = static_cast<std::uint64_t>(charCount) * 2;
                const unsigned char* const kTextData =
                    view.at(offset + sizeof(std::uint32_t), kTextBytes);
                if (kTextData == nullptr)
                {
                    return QString();
                }
                return QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(kTextData),
                    static_cast<qsizetype>(charCount));
            };

            const QString kAsCharCount = kDecode(length);
            if (looksLikeDriverName(kAsCharCount))
            {
                return kAsCharCount;
            }
            const QString kAsByteCount = kDecode(length / 2);
            if (looksLikeDriverName(kAsByteCount))
            {
                return kAsByteCount;
            }
            // When neither interpretation resembles a driver name, return the longer one to at least preserve a recognizable fragment.
            return kAsCharCount.isEmpty() ? kAsByteCount : kAsCharCount;
        }

        // readUnicodeStringFromMemory purpose: Read the content of a UNICODE_STRING from the target machine's address.
        // Input: view, memory index, and name string descriptor.
        // Returns an empty string if the buffer is not found in the dump (common in minidumps).
        QString readUnicodeStringFromMemory(
            const DumpFileView& view,
            const DumpMemoryReader& memory,
            const UnicodeString64& name)
        {
            if (name.buffer == 0 || name.length == 0 || name.length > kMaxDriverNameChars * 2)
            {
                return QString();
            }
            // textBytes: Align length down to even, then use for both allocation and reading.
            // Length comes directly from the dump file and is completely untrusted. If it is odd and we
            // allocate using Length/2 but read using Length, memcpy will write 1 byte past the buffer—a
            // genuine heap buffer overflow. The length must be derived from the same variable.
            const std::uint32_t kTextBytes = static_cast<std::uint32_t>(name.length) & ~1u;
            if (kTextBytes == 0)
            {
                return QString();
            }
            // buffer: Read UTF-16 content based on textBytes; read fails across blocks or if uncaught.
            std::vector<char16_t> buffer(kTextBytes / sizeof(char16_t));
            if (!memory.read(view, name.buffer, kTextBytes, buffer.data()))
            {
                return QString();
            }
            return QString::fromUtf16(buffer.data(), static_cast<qsizetype>(buffer.size()));
        }

        // appendLayoutEntry purpose: Register a layout segment from the triage area into the 'Data Layout' page.
        void appendLayoutEntry(
            DumpParseResult& result,
            const std::uint32_t type,
            const QString& name,
            const std::uint64_t offset,
            const std::uint64_t size,
            const QString& note)
        {
            if (offset == 0)
            {
                return;
            }
            StreamEntry entry{};
            entry.type = type;
            entry.typeName = name;
            entry.rva = offset;
            entry.size = size;
            entry.note = note;
            result.streams.push_back(std::move(entry));
        }

        // parseTriageDrivers purpose: Parse the triage driver list into a module table.
        void parseTriageDrivers(
            const DumpFileView& view,
            const TriageDump64& triage,
            DumpParseResult& result)
        {
            const std::uint32_t kDriverCount =
                std::min<std::uint32_t>(triage.driverCount, kMaxDriverEntries);
            if (kDriverCount != triage.driverCount)
            {
                result.diagnostics.append(
                    QStringLiteral("驱动数 %1 超过解析上限，仅展示前 %2 条。")
                        .arg(triage.driverCount)
                        .arg(kDriverCount));
            }
            result.modules.reserve(kDriverCount);
            for (std::uint32_t index = 0; index < kDriverCount; ++index)
            {
                DumpDriverEntry64 driver{};
                if (!view.readStruct(
                        static_cast<std::uint64_t>(triage.driverListOffset) +
                            static_cast<std::uint64_t>(index) * sizeof(DumpDriverEntry64),
                        &driver))
                {
                    result.diagnostics.append(QStringLiteral("驱动条目越界，列表提前结束。"));
                    break;
                }
                ModuleEntry entry{};
                entry.name = readDumpString(view, driver.driverNameOffset);
                if (entry.name.isEmpty())
                {
                    entry.name = QStringLiteral("(名称不可用)");
                }
                entry.base = driver.ldrEntry.dllBase;
                entry.size = driver.ldrEntry.sizeOfImage;
                entry.checksum = driver.ldrEntry.checkSum;
                // The offset of the timestamp varies with kernel version; only accept it if the value falls within a reasonable date range.
                if (plausibleTimestamp(driver.ldrEntry.timeDateStamp))
                {
                    entry.timeDateStamp = driver.ldrEntry.timeDateStamp;
                    entry.timestampText =
                        QDateTime::fromSecsSinceEpoch(driver.ldrEntry.timeDateStamp)
                            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
                }
                result.modules.push_back(std::move(entry));
            }
        }

        // plausibleDriverRange: Determines whether a pair of start and end addresses resembles a driver image range.
        // Criteria: Start address falls within kernel space, end address is greater than start, and span does not exceed 256MB.
        bool plausibleDriverRange(const std::uint64_t start, const std::uint64_t end)
        {
            // kKernelSpaceStart: Lower bound of the high half of the x64 address space.
            constexpr std::uint64_t kKernelSpaceStart = 0xFFFF800000000000ull;
            constexpr std::uint64_t kMaxImageBytes = 256ull * 1024ull * 1024ull;
            if (start < kKernelSpaceStart || end <= start)
            {
                return false;
            }
            return end - start <= kMaxImageBytes;
        }

        // scoreUnloadedDriverStride: Attempt to read the unloaded driver table with a given stride and score it.
        // Returns a plausible number of slots to choose between two candidate layouts.
        std::uint32_t scoreUnloadedDriverStride(
            const DumpFileView& view,
            const std::uint64_t tableOffset,
            const std::uint64_t stride)
        {
            std::uint32_t score = 0;
            for (std::uint32_t index = 0; index < kUnloadedDriverSlots; ++index)
            {
                // The start and end addresses immediately follow UNICODE_STRING64 in both layouts, with consistent offsets.
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                const std::uint64_t kSlotOffset =
                    tableOffset + static_cast<std::uint64_t>(index) * stride;
                if (!view.readStruct(kSlotOffset + sizeof(UnicodeString64), &start) ||
                    !view.readStruct(kSlotOffset + sizeof(UnicodeString64) + 8, &end))
                {
                    break;
                }
                if (plausibleDriverRange(start, end))
                {
                    ++score;
                }
            }
            return score;
        }

        // parseTriageUnloadedDrivers: Parses the unloaded driver table in the triage area.
        // This structure has no public definition; in reality, there are two layouts: 0x28 bytes (including unload time) and 0x20
        // bytes (excluding it). Here, we attempt to read both step sizes, count how many slots have reasonable address ranges, and
        // then use the layout with the higher score for formal parsing—this is far more robust than hardcoding a single layout.
        // The array capacity follows the kernel side's 50 slots (inferred, not guaranteed by documentation), so each
        // slot independently performs boundary and validity checks; any extra garbage read is naturally discarded.
        void parseTriageUnloadedDrivers(
            const DumpFileView& view,
            const DumpMemoryReader& memory,
            const TriageDump64& triage,
            DumpParseResult& result)
        {
            const std::uint64_t kTableOffset = triage.unloadedDriversOffset;
            if (!triageRangeValid(view, kTableOffset, sizeof(UnloadedDriver64)))
            {
                return;
            }
            // kStrideWithTime/kStrideWithoutTime: Entry stride for two candidate layouts.
            constexpr std::uint64_t kStrideWithTime = sizeof(UnloadedDriver64);
            constexpr std::uint64_t kStrideWithoutTime = 0x20;
            const std::uint32_t kScoreWithTime =
                scoreUnloadedDriverStride(view, kTableOffset, kStrideWithTime);
            const std::uint32_t kScoreWithoutTime =
                scoreUnloadedDriverStride(view, kTableOffset, kStrideWithoutTime);
            if (kScoreWithTime == 0 && kScoreWithoutTime == 0)
            {
                // Neither layout yields a reasonable interval, indicating the offset itself is incorrect; abandon immediately.
                return;
            }
            const bool kUseTimeLayout = kScoreWithTime >= kScoreWithoutTime;
            const std::uint64_t kStride = kUseTimeLayout ? kStrideWithTime : kStrideWithoutTime;

            for (std::uint32_t index = 0; index < kUnloadedDriverSlots; ++index)
            {
                const std::uint64_t kSlotOffset =
                    kTableOffset + static_cast<std::uint64_t>(index) * kStride;
                UnicodeString64 name{};
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                std::uint64_t unloadTime = 0;
                if (!view.readStruct(kSlotOffset, &name) ||
                    !view.readStruct(kSlotOffset + sizeof(UnicodeString64), &start) ||
                    !view.readStruct(kSlotOffset + sizeof(UnicodeString64) + 8, &end))
                {
                    break;
                }
                if (kUseTimeLayout)
                {
                    view.readStruct(kSlotOffset + sizeof(UnicodeString64) + 16, &unloadTime);
                }
                // Skip empty slots and slots with unreasonable address ranges without adding them to the table.
                if (!plausibleDriverRange(start, end))
                {
                    continue;
                }
                UnloadedModuleEntry entry{};
                entry.name = readUnicodeStringFromMemory(view, memory, name);
                if (entry.name.isEmpty())
                {
                    entry.name = QStringLiteral("(名称未捕获)");
                }
                entry.base = start;
                entry.endAddress = end;
                entry.size = static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(end - start, 0xFFFFFFFFull));
                entry.timestampText = fileTimeToText(unloadTime);
                result.unloadedModules.push_back(std::move(entry));
            }
        }

        // parseTriageArea: Parses the TRIAGE_DUMP64 region of a mini-dump:
        // Layout offset → data layout pages, driver list → module table, unloaded drivers
        // → unloaded module table, TRIAGE data block → memory table and memory index.
        // The passed memory is filled; triageOut outputs the triage header for subsequent stack scanning.
        bool parseTriageArea(
            const DumpFileView& view,
            DumpParseResult& result,
            DumpMemoryReader& memory,
            TriageDump64* const triageOut)
        {
            TriageDump64Prefix triagePrefix{};
            if (!view.readStruct(kKernelHeader64Bytes, &triagePrefix))
            {
                result.diagnostics.append(QStringLiteral("TRIAGE 区读取失败，文件可能被截断。"));
                return false;
            }

            // triage: The subsequent path uses the full structure. First, copy the verified stable prefix; when the full structure
            // is out of file bounds, the tail remains zero-initialized to avoid reading bytes beyond the truncated file.
            TriageDump64 triage{};
            std::memcpy(&triage, &triagePrefix, sizeof(triagePrefix));
            if (view.contains(kKernelHeader64Bytes, sizeof(triage)))
            {
                view.readStruct(kKernelHeader64Bytes, &triage);
            }

            // Layout offset table: allows users to intuitively see the position and size of each segment in the triage area.
            appendLayoutEntry(result, 1, QStringLiteral("Context"), triage.contextOffset, 0,
                QStringLiteral("崩溃处理器的 CONTEXT 副本"));
            appendLayoutEntry(result, 2, QStringLiteral("Exception"), triage.exceptionOffset,
                sizeof(ExceptionRecord64),
                QStringLiteral("异常记录（KeBugCheckEx 构造）"));
            appendLayoutEntry(result, 3, QStringLiteral("Mm"), triage.mmOffset, 0,
                QStringLiteral("内存管理器 triage 信息"));
            appendLayoutEntry(result, 4, QStringLiteral("UnloadedDrivers"),
                triage.unloadedDriversOffset,
                static_cast<std::uint64_t>(kUnloadedDriverSlots) * sizeof(UnloadedDriver64),
                QStringLiteral("最近卸载的驱动记录（含卸载前地址区间）"));
            appendLayoutEntry(result, 5, QStringLiteral("Prcb"), triage.prcbOffset, 0,
                QStringLiteral("崩溃处理器 KPRCB 副本"));
            appendLayoutEntry(result, 6, QStringLiteral("Process"), triage.processOffset, 0,
                QStringLiteral("崩溃时当前 EPROCESS 副本"));
            appendLayoutEntry(result, 7, QStringLiteral("Thread"), triage.threadOffset, 0,
                QStringLiteral("崩溃时当前 ETHREAD 副本"));
            appendLayoutEntry(result, 8, QStringLiteral("CallStack"), triage.callStackOffset,
                triage.sizeOfCallStack,
                QStringLiteral("崩溃线程内核栈原始字节（调用栈重建的数据源）"));
            appendLayoutEntry(result, 9, QStringLiteral("DriverList"), triage.driverListOffset,
                static_cast<std::uint64_t>(triage.driverCount) * sizeof(DumpDriverEntry64),
                QStringLiteral("已加载驱动列表（KLDR 快照）"));
            appendLayoutEntry(result, 10, QStringLiteral("StringPool"), triage.stringPoolOffset,
                triage.stringPoolSize,
                QStringLiteral("驱动名字符串池"));
            appendLayoutEntry(result, 11, QStringLiteral("BrokenDriver"), triage.brokenDriverOffset,
                sizeof(std::uint64_t),
                QStringLiteral("转储自报的肇事驱动记录"));
            appendLayoutEntry(result, 12, QStringLiteral("DebuggerData"), triage.debuggerDataOffset,
                triage.debuggerDataSize,
                QStringLiteral("KDDEBUGGER_DATA64 调试器数据块"));
            appendLayoutEntry(result, 13, QStringLiteral("DataBlocks"), triage.dataBlocksOffset,
                static_cast<std::uint64_t>(triage.dataBlocksCount) * sizeof(TriageDataBlock),
                QStringLiteral("附加抓取的内存块目录"));

            // Supplement overview with key triage information.
            if (triage.servicePackBuild != 0)
            {
                result.overview.push_back({ QStringLiteral("Service Pack 构建"),
                    QString::number(triage.servicePackBuild) });
            }
            if (triage.topOfStack != 0)
            {
                result.overview.push_back({ QStringLiteral("崩溃线程栈顶"),
                    hex(triage.topOfStack) });
            }
            if (triage.sizeOfCallStack != 0)
            {
                result.overview.push_back({ QStringLiteral("捕获调用栈大小"),
                    QStringLiteral("%1 字节").arg(triage.sizeOfCallStack) });
            }

            parseTriageDrivers(view, triage, result);

            // TRIAGE data blocks: Memory fragments captured as extra dump data, included in both the memory table and memory index.
            // DataBlocksOffset and Count are located after architecture-specific unions, making them the two fields most prone to
            // misalignment; therefore, first validate that the directory itself falls within the file, then validate each block individually.
            const std::uint32_t kBlockCount =
                std::min<std::uint32_t>(triage.dataBlocksCount, kMaxTriageDataBlocks);
            const bool kDataBlocksValid = triageRangeValid(
                view,
                triage.dataBlocksOffset,
                static_cast<std::uint64_t>(kBlockCount) * sizeof(TriageDataBlock));
            if (kBlockCount != 0 && !kDataBlocksValid)
            {
                result.diagnostics.append(
                    QStringLiteral("TRIAGE 数据块目录越界，本转储的附加内存块信息已跳过。"));
            }
            for (std::uint32_t index = 0; kDataBlocksValid && index < kBlockCount; ++index)
            {
                TriageDataBlock block{};
                if (!view.readStruct(
                        static_cast<std::uint64_t>(triage.dataBlocksOffset) +
                            static_cast<std::uint64_t>(index) * sizeof(TriageDataBlock),
                        &block))
                {
                    break;
                }
                if (!triageRangeValid(view, block.offset, block.size))
                {
                    continue;
                }
                MemoryRegionEntry entry{};
                entry.base = block.address;
                entry.size = block.size;
                entry.source = QStringLiteral("TRIAGE 数据块");
                ++result.memoryRegionTotal;
                ++result.memoryRegionShown;
                result.memoryRegions.push_back(std::move(entry));
                memory.addRange(
                    block.address,
                    block.offset,
                    block.size,
                    QStringLiteral("TRIAGE 数据块"));

                // Original preview: Copy only the first few blocks and limited bytes verified by triageRangeValid to
                // prevent malicious DMPs from exhausting memory with excessive blocks or oversized lengths. Full block
                // lengths remain in metadata, and the UI explicitly notes that trailing bytes are not displayed.
                if (result.byteBlocks.size() < kMaxTriageByteBlockPreviews)
                {
                    const std::uint32_t kPreviewBytes = std::min<std::uint32_t>(
                        block.size, kTriageByteBlockPreviewBytes);
                    const unsigned char* const kPreview = view.at(block.offset, kPreviewBytes);
                    if (kPreview != nullptr)
                    {
                        DumpByteBlock byteBlock{};
                        byteBlock.address = block.address;
                        byteBlock.fileOffset = block.offset;
                        byteBlock.capturedBytes = block.size;
                        byteBlock.source = QStringLiteral("TRIAGE 数据块");
                        byteBlock.previewBytes.assign(kPreview, kPreview + kPreviewBytes);
                        result.byteBlocks.push_back(std::move(byteBlock));
                    }
                }
            }
            if (kBlockCount > kMaxTriageByteBlockPreviews)
            {
                result.diagnostics.append(
                    QStringLiteral("TRIAGE 数据块共有 %1 条，原始预览仅保留前 %2 条。")
                        .arg(kBlockCount)
                        .arg(kMaxTriageByteBlockPreviews));
            }
            // Additional data pages are registered in the memory index alongside the kernel stack for address access.
            if (triage.dataPageAddress != 0 &&
                triageRangeValid(view, triage.dataPageOffset, triage.dataPageSize))
            {
                memory.addRange(
                    triage.dataPageAddress,
                    triage.dataPageOffset,
                    triage.dataPageSize,
                    QStringLiteral("TRIAGE 附加数据页"));
            }
            if (triage.topOfStack != 0 &&
                triageRangeValid(view, triage.callStackOffset, triage.sizeOfCallStack))
            {
                memory.addRange(
                    triage.topOfStack,
                    triage.callStackOffset,
                    triage.sizeOfCallStack,
                    QStringLiteral("崩溃线程内核栈"));
            }
            memory.finalize(view);

            // The unloaded driver table must be parsed after the memory index is built to read the name buffer.
            parseTriageUnloadedDrivers(view, memory, triage, result);

            // After reading the unloaded driver name, the memory index is no longer used during parsing. Here we export a
            // verified lightweight mapping for the UI to safely reopen the DMP and browse by address after parsing completes.
            // Place here rather than immediately after calling memory.finalize() to avoid missing subsequent steps.
            memory.appendCapturedRanges(&result.capturedMemoryRanges);

            *triageOut = triage;
            return true;
        }

        // parsePhysicalMemoryRuns: Parses physical memory segment descriptors from a full or kernel dump header.
        // Input view and descriptor offset; converts each segment to bytes and adds to the memory table.
        void parsePhysicalMemoryRuns(
            const DumpFileView& view,
            const std::uint64_t descriptorOffset,
            DumpParseResult& result)
        {
            // kMaxRuns: The union section can hold at most 42 segments in 700 bytes; exceeding this is treated as an invalid marker.
            constexpr std::uint32_t kMaxRuns = 42;
            std::uint32_t numberOfRuns = 0;
            std::uint64_t numberOfPages = 0;
            if (!view.readStruct(descriptorOffset, &numberOfRuns) ||
                !view.readStruct(descriptorOffset + 8, &numberOfPages))
            {
                return;
            }
            if (numberOfRuns == 0 || numberOfRuns > kMaxRuns)
            {
                return;
            }
            result.overview.push_back({ QStringLiteral("物理内存总页数"),
                QStringLiteral("%1 (约 %2 MB)")
                    .arg(numberOfPages)
                    .arg(numberOfPages / 256) });
            for (std::uint32_t index = 0; index < numberOfRuns; ++index)
            {
                PhysicalMemoryRun64 run{};
                if (!view.readStruct(
                        descriptorOffset + 16 +
                            static_cast<std::uint64_t>(index) * sizeof(PhysicalMemoryRun64),
                        &run))
                {
                    break;
                }
                MemoryRegionEntry entry{};
                entry.base = run.basePage * 0x1000ull;
                entry.size = run.pageCount * 0x1000ull;
                entry.source = QStringLiteral("物理内存段");
                ++result.memoryRegionTotal;
                ++result.memoryRegionShown;
                result.memoryRegions.push_back(std::move(entry));
            }
        }

        // appendBugCheckDetails: Writes the stop code, name, meaning, category, and detailed interpretation of the four parameters
        // into the exception details page. This is the section with the highest information density in kernel dump parsing.
        void appendBugCheckDetails(
            const std::uint32_t code,
            const std::uint64_t parameters[4],
            const ModuleIndex& modules,
            const std::uint32_t pointerSize,
            DumpParseResult& result)
        {
            // codeText: value + official name (if table lookup succeeds).
            QString codeText = hex(code);
            const QString kCodeName = bugCheckCodeNameEx(code);
            if (!kCodeName.isEmpty())
            {
                codeText += QStringLiteral(" (%1)").arg(kCodeName);
            }
            result.exceptionInfo.push_back({ QStringLiteral("停止代码"), codeText });

            const QString kMeaning = bugCheckMeaning(code);
            if (!kMeaning.isEmpty())
            {
                result.exceptionInfo.push_back({ QStringLiteral("停止码含义"), kMeaning });
            }
            result.exceptionInfo.push_back({ QStringLiteral("故障归类"),
                bugCheckCategoryText(bugCheckCategoryOf(code)) });

            // Expand the four parameters item by item: parameter name + value + interpretation combined with the value.
            const std::vector<BugCheckParameterInfo> kParameterInfos =
                describeBugCheckParameters(code, parameters, modules, pointerSize);
            for (std::size_t index = 0; index < kParameterInfos.size(); ++index)
            {
                const BugCheckParameterInfo& info = kParameterInfos[index];
                // name: Falls back to "Parameter N" when no known semantics exist.
                const QString kName = info.label.isEmpty()
                    ? QStringLiteral("参数 %1").arg(index + 1)
                    : QStringLiteral("参数 %1：%2").arg(index + 1).arg(info.label);
                const QString kValue = info.detail.isEmpty()
                    ? info.value
                    : QStringLiteral("%1  —  %2").arg(info.value, info.detail);
                result.exceptionInfo.push_back({ kName, kValue });
            }

            // Nested NTSTATUS is extracted on a separate line: the true cause of stop codes like 0x1E/0x7E/0x3B is found here.
            const std::uint32_t kNestedStatus = nestedStatusFromBugCheck(code, parameters);
            if (kNestedStatus != 0)
            {
                const QString kNestedName = exceptionCodeName(kNestedStatus);
                const QString kNestedMeaning = exceptionCodeMeaning(kNestedStatus);
                if (!kNestedName.isEmpty() || !kNestedMeaning.isEmpty())
                {
                    result.exceptionInfo.push_back({
                        QStringLiteral("真正的异常原因"),
                        QStringLiteral("%1 %2 %3")
                            .arg(hex(kNestedStatus), kNestedName, kNestedMeaning)
                            .trimmed() });
                }
            }
        }
    }

    void parseKernelDump64(const DumpFileView& view, DumpParseResult& result)
    {
        result.kind = DumpKind::kKernelDump64;
        result.recognized = true;
        if (view.size < kKernelHeader64Bytes)
        {
            result.errorText = QStringLiteral("文件小于 0x2000 字节，PAGEDU64 头不完整。");
            return;
        }
        KernelDumpHeader64Prefix header{};
        if (!view.readStruct(0, &header))
        {
            result.errorText = QStringLiteral("PAGEDU64 头读取失败。");
            return;
        }

        // The dumpType/systemTime fields are located in the latter part of the header and are read with explicit offsets according to the official layout.
        std::uint32_t dumpType = 0;
        std::uint64_t systemTime = 0;
        std::uint64_t systemUpTime = 0;
        std::uint64_t requiredDumpSpace = 0;
        std::uint32_t miniDumpFields = 0;
        std::uint32_t secondaryDataState = 0;
        std::uint32_t productType = 0;
        std::uint32_t suiteMask = 0;
        std::uint32_t writerStatus = 0;
        view.readStruct(0xF98, &dumpType);
        view.readStruct(0xFA0, &requiredDumpSpace);
        view.readStruct(0xFA8, &systemTime);
        view.readStruct(0x1030, &systemUpTime);
        view.readStruct(0x1038, &miniDumpFields);
        view.readStruct(0x103C, &secondaryDataState);
        view.readStruct(0x1040, &productType);
        view.readStruct(0x1044, &suiteMask);
        view.readStruct(0x1048, &writerStatus);

        // arch/pointerSize: Required for subsequent CONTEXT and stack scanning operations.
        const ContextArch kArch = contextArchFromMachineImageType(header.machineImageType);
        result.pointerSize = contextPointerSize(kArch);
        result.bugCheckCode = header.bugCheckCode;
        for (int index = 0; index < 4; ++index)
        {
            result.bugCheckParameters[index] = header.bugCheckParameter[index];
        }

        // ---------- Overview ----------
        result.overview.push_back({ QStringLiteral("转储类别"),
            QStringLiteral("64 位内核转储 (PAGEDU64)") });
        result.overview.push_back({ QStringLiteral("转储类型"), dumpTypeText(dumpType) });
        // bugCheckLine: Include a stop code line in the overview so users see it immediately.
        QString bugCheckLine = hex(header.bugCheckCode);
        const QString kBugCheckName = bugCheckCodeNameEx(header.bugCheckCode);
        if (!kBugCheckName.isEmpty())
        {
            bugCheckLine += QStringLiteral(" (%1)").arg(kBugCheckName);
        }
        result.overview.push_back({ QStringLiteral("停止代码"), bugCheckLine });
        const QString kCrashTime = fileTimeToText(systemTime);
        if (!kCrashTime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃时间"), kCrashTime });
        }
        const QString kUptime = uptimeToText(systemUpTime);
        if (!kUptime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃前运行时长"), kUptime });
        }
        result.overview.push_back({ QStringLiteral("内核构建号"),
            kernelBuildText(header.majorVersion, header.minorVersion) });
        result.overview.push_back({ QStringLiteral("CPU 架构"),
            machineImageTypeText(header.machineImageType) });
        result.overview.push_back({ QStringLiteral("逻辑处理器数"),
            QString::number(header.numberProcessors) });
        if (productType != 0 && productType != kPageFillDword)
        {
            result.overview.push_back({ QStringLiteral("产品类型"), productTypeText(productType) });
        }
        if (suiteMask != 0 && suiteMask != kPageFillDword)
        {
            result.overview.push_back({ QStringLiteral("套件掩码"), hex(suiteMask) });
        }
        // The writer status directly determines whether this dump can be trusted; always display it.
        result.overview.push_back({ QStringLiteral("转储写入器状态"),
            writerStatusText(writerStatus) });
        // Only alert on states that were actually written and are non-zero; PAGE fill indicates the field was not populated.
        if (writerStatus != 0 && writerStatus != kPageFillDword)
        {
            result.diagnostics.append(
                QStringLiteral("转储写入器报告了非零状态（%1），本文件可能不完整，"
                    "解析结果仅供参考。").arg(writerStatus));
        }
        if (requiredDumpSpace != 0)
        {
            result.overview.push_back({ QStringLiteral("转储所需空间"),
                QStringLiteral("%1 字节").arg(requiredDumpSpace) });
        }
        if (miniDumpFields != 0)
        {
            result.overview.push_back({ QStringLiteral("小型转储字段位"), hex(miniDumpFields) });
        }
        if (secondaryDataState != 0)
        {
            result.overview.push_back({ QStringLiteral("附加数据状态"), hex(secondaryDataState) });
        }
        result.overview.push_back({ QStringLiteral("PsLoadedModuleList"),
            hex(header.psLoadedModuleList) });
        result.overview.push_back({ QStringLiteral("PsActiveProcessHead"),
            hex(header.psActiveProcessHead) });
        result.overview.push_back({ QStringLiteral("DirectoryTableBase (CR3)"),
            hex(header.directoryTableBase) });
        std::uint64_t kdDebuggerDataBlock = 0;
        view.readStruct(0x80, &kdDebuggerDataBlock);
        if (kdDebuggerDataBlock != 0)
        {
            result.overview.push_back({ QStringLiteral("KdDebuggerDataBlock"),
                hex(kdDebuggerDataBlock) });
        }
        // comment: Administrator-configured comment text via CrashControl (usually empty).
        // When not configured, this region remains filled with 'PAGE', appearing as a long
        // string of 'PAGEPAGE…'; this is pure noise and must be detected and skipped.
        const unsigned char* const kCommentData = view.at(0xFB0, 128);
        if (kCommentData != nullptr && kCommentData[0] != 0 &&
            std::memcmp(kCommentData, "PAGE", 4) != 0)
        {
            std::uint32_t commentLength = 0;
            while (commentLength < 128 && kCommentData[commentLength] != 0)
            {
                ++commentLength;
            }
            result.overview.push_back({ QStringLiteral("注释"),
                QString::fromLocal8Bit(
                    reinterpret_cast<const char*>(kCommentData),
                    static_cast<qsizetype>(commentLength)) });
        }

        // ---------- Memory/Drivers: Must complete before attribution is finalized ----------
        // memory: Virtual address index of captured memory; stack scanning and name reading depend on it.
        // physical and walker must be declared before memory: memory holds a raw pointer to walker. Since later-declared
        // members are destroyed first, this order ensures memory is destroyed while its backend (walker) is still alive.
        PhysicalMemoryMap physical;
        std::optional<PageTableWalker> walker;
        DumpMemoryReader memory;
        TriageDump64 triage{};
        bool hasTriage = false;
        if (dumpType == 4)
        {
            hasTriage = parseTriageArea(view, result, memory, &triage);
            if (hasTriage)
            {
                parseTriageExecutionContext(view, triage, header.minorVersion, result);
            }
        }
        else
        {
            // Full or kernel dumps lack a TRIAGE driver table, but the dump header provides CR3 and
            // PsLoadedModuleList. Once physical pages are indexed and page tables are traversed, drivers can be
            // enumerated via the linked list, making the entire attribution chain available without requiring PDBs.
            //
            // Layout determination relies on the bitmap header signature, not just the DumpType field: the DumpType field is
            // inconsistent with the actual on-disk layout in some samples, whereas the signature is the definitive evidence.
            if (!physical.buildBitmap(view, kKernelHeader64Bytes))
            {
                physical.buildClassic(view, 0x88, kKernelHeader64Bytes);
            }

            if (!physical.valid())
            {
                // Fall back to displaying only the physical segments declared in the header, at least ensuring the memory pages have content.
                parsePhysicalMemoryRuns(view, 0x88, result);
                result.diagnostics.append(
                    QStringLiteral("未能建立物理内存映射（文件可能被截断或采用未知布局），"
                        "无法枚举驱动与重建调用栈。"));
            }
            else
            {
                physical.appendRegions(result);
                result.overview.push_back(
                    { QStringLiteral("物理内存布局"), physical.layoutText() });
                result.overview.push_back({ QStringLiteral("转储覆盖物理页数"),
                    QStringLiteral("%1 (约 %2 MB)")
                        .arg(physical.pageCount())
                        .arg(physical.pageCount() / 256) });

                walker.emplace(view, physical, header.directoryTableBase);
                if (!walker->usable())
                {
                    result.diagnostics.append(
                        QStringLiteral("转储头未提供可用的页目录基址（DirectoryTableBase），"
                            "无法把内核虚拟地址翻译到物理页，驱动列表与调用栈不可用。"));
                }
                else
                {
                    // After attaching the page table backend, the stack scan's call instruction validation and
                    // name resolution, which depend on virtual address capabilities, also apply to full dumps.
                    memory.attachPageTable(&walker.value());
                    result.overview.push_back({ QStringLiteral("页目录基址 (CR3)"),
                        hex(walker->directoryTableBase()) });

                    const KernelModuleScanResult kScan = enumerateLoadedDrivers(
                        *walker, header.psLoadedModuleList, result.modules);
                    if (kScan.acceptedCount > 0)
                    {
                        result.overview.push_back({ QStringLiteral("驱动列表来源"),
                            QStringLiteral("PsLoadedModuleList 链表遍历（无需符号）") });
                    }
                    if (!kScan.listReadable)
                    {
                        result.diagnostics.append(
                            QStringLiteral("驱动链表头 %1 所在内存页不在转储中，无法枚举驱动。")
                                .arg(hex(header.psLoadedModuleList)));
                    }
                    else if (kScan.acceptedCount == 0)
                    {
                        result.diagnostics.append(
                            QStringLiteral("沿 PsLoadedModuleList 未取得任何通过校验的驱动条目"
                                "（丢弃 %1 项）：%2")
                                .arg(kScan.rejectedCount)
                                .arg(kScan.stopReason.isEmpty()
                                    ? QStringLiteral("链表结构与预期布局不符")
                                    : kScan.stopReason));
                    }
                    else if (kScan.truncated || kScan.rejectedCount > 0)
                    {
                        // Clearly report partial success to avoid treating an incomplete driver list as
                        // the full set, which could lead to falsely judging that 'a driver is not loaded'.
                        result.diagnostics.append(
                            QStringLiteral("驱动链表遍历未走完：已取得 %1 项，丢弃 %2 项。%3")
                                .arg(kScan.acceptedCount)
                                .arg(kScan.rejectedCount)
                                .arg(kScan.stopReason));
                    }
                }
            }
            memory.finalize(view);
        }

        // PnP blackbox is Secondary Dump Data written by the kernel, unrelated to the triage directory and page tables.
        // Regardless of whether the current DMP can still establish page tables, attempt to read-only extract by provider GUID.
        tryParseBlackboxPnp(view, result);
        tryParseBlackboxBsd(view, result);
        tryReportBlackboxNtfs(view, result);
        tryReportBlackboxPresence(
            view,
            kBlackboxWinlogonProviderId,
            QStringLiteral("Winlogon 黑盒"),
            result);
        tryReportBlackboxPresence(
            view,
            kBlackboxCodeIntegrityProviderId,
            QStringLiteral("代码完整性黑盒"),
            result);

        // modules: Module address index; all subsequent 'address → module' translations depend on it.
        ModuleIndex modules;
        modules.build(result.modules, result.unloadedModules, result.pointerSize);

        // ---------- Crash Point Registers ---------- CONTEXT value
        // priority: copy in triage region → copy at 0x348 in dump header.
        // The header portion is all zeros or stale content on many Win10/11 samples; using it
        // directly yields a meaningless 'crash point', so the triage copy takes precedence.
        std::uint64_t contextOffset = kContext64Offset;
        std::uint64_t contextBytes = kContext64Bytes;
        if (hasTriage &&
            triageRangeValid(view, triage.contextOffset, contextMinimumBytes(kArch)))
        {
            contextOffset = triage.contextOffset;
            // Note: In the triage region, other segments immediately follow CONTEXT; the length defaults to the
            // remaining file size, and readContextRegisters performs boundary checks on each field internally.
            contextBytes = view.size - triage.contextOffset;
        }
        result.registers = readContextRegisters(
            view, contextOffset, contextBytes, kArch, 0, modules);
        std::uint64_t contextIp = 0;
        std::uint64_t contextSp = 0;
        // Frame pointer is currently unused (stack reconstruction uses scanning, not frame chaining); pass nullptr per interface contract to skip.
        readContextPointers(
            view, contextOffset, contextBytes, kArch, &contextIp, &contextSp, nullptr);

        // ---------- Exception Details ----------
        // parameterFaultPreview: The faulting instruction address from the stop code parameters.
        // It is more accurate than the IP in CONTEXT, which often stops inside KeBugCheckEx.
        const std::uint64_t kParameterFaultPreview =
            faultingAddressFromBugCheck(header.bugCheckCode, header.bugCheckParameter);
        appendBugCheckDetails(
            header.bugCheckCode, header.bugCheckParameter, modules, result.pointerSize, result);

        // exceptionRecord: Filled for paths outside KeBugCheckEx (e.g., unhandled kernel exceptions).
        ExceptionRecord64 exceptionRecord{};
        if (view.readStruct(kException64Offset, &exceptionRecord) &&
            exceptionRecord.exceptionCode != 0)
        {
            QString codeText = hex(exceptionRecord.exceptionCode);
            const QString kCodeName = exceptionCodeName(exceptionRecord.exceptionCode);
            if (!kCodeName.isEmpty())
            {
                codeText += QStringLiteral(" (%1)").arg(kCodeName);
            }
            result.exceptionInfo.push_back({ QStringLiteral("异常代码"), codeText });
            const QString kExceptionMeaning = exceptionCodeMeaning(exceptionRecord.exceptionCode);
            if (!kExceptionMeaning.isEmpty())
            {
                result.exceptionInfo.push_back({ QStringLiteral("异常含义"), kExceptionMeaning });
            }
            const QString kAddressNote = modules.annotate(exceptionRecord.exceptionAddress);
            result.exceptionInfo.push_back({ QStringLiteral("异常地址"),
                kAddressNote.isEmpty()
                    ? hex(exceptionRecord.exceptionAddress)
                    : QStringLiteral("%1  —  %2")
                        .arg(hex(exceptionRecord.exceptionAddress), kAddressNote) });
            result.exceptionCode = exceptionRecord.exceptionCode;
        }

        // Crash point instruction/stack pointer: prioritize CONTEXT, then fall back to the instruction address in stop code parameters.
        if (contextIp != 0)
        {
            // The IP here comes from the CONTEXT captured during the dump, typically stopped at an internal breakpoint within
            // KeBugCheckEx, not the actual faulting instruction; the true faulting address is provided by the stop code parameters.
            // The name must be explicit; otherwise, someone might use it to identify the culprit driver, leading the investigation in the wrong direction.
            const QString kIpNote = modules.annotate(contextIp);
            result.exceptionInfo.push_back({
                QStringLiteral("捕获时的指令指针（多为 KeBugCheckEx 内部，非故障点）"),
                kIpNote.isEmpty() ? hex(contextIp)
                                 : QStringLiteral("%1  —  %2").arg(hex(contextIp), kIpNote) });
        }
        if (contextSp != 0)
        {
            result.exceptionInfo.push_back({ QStringLiteral("捕获时的栈指针"), hex(contextSp) });
        }
        // Fault instruction address on a separate line: this is the address to focus on for troubleshooting.
        if (kParameterFaultPreview != 0)
        {
            const QString kFaultNote = modules.annotate(kParameterFaultPreview);
            result.exceptionInfo.push_back({ QStringLiteral("故障指令地址（停止码参数给出）"),
                kFaultNote.isEmpty()
                    ? hex(kParameterFaultPreview)
                    : QStringLiteral("%1  —  %2").arg(hex(kParameterFaultPreview), kFaultNote) });
        }

        // faultingAddress: the core input for attribution; prefer the faulting instruction address provided by the stop code parameters.
        // faultingAddress accepts only the faulting instruction address provided by the stop code parameter.
        // Do not fall back to contextIp: The CONTEXT in a kernel dump is a snapshot of the KeBugCheckEx
        // call site, which always resides within ntoskrnl. Treating it as the 'crashing instruction
        // address' would cause the attribution to assign the highest weight to ntoskrnl and assert the
        // crash occurred there, purely misleading the user. When no credible faulting address exists,
        // it is better to leave it empty and let attribution fall back to call stack evidence.
        result.faultingAddress = kParameterFaultPreview;

        // ---------- Dump-reported culprit driver ----------
        if (hasTriage &&
            triageRangeValid(view, triage.brokenDriverOffset, sizeof(std::uint64_t)))
        {
            std::uint64_t brokenDriver = 0;
            // The meaning of these 8 bytes varies by version and may not actually be a driver address;
            // Only display as the 'faulting driver' if it can be attributed to a known module; otherwise, a random
            // value could be mistaken by readers as definitive evidence. If unattributable, list only the raw value.
            if (view.readStruct(triage.brokenDriverOffset, &brokenDriver) && brokenDriver != 0)
            {
                const AddressNote kBrokenNote = modules.resolve(brokenDriver);
                if (!kBrokenNote.symbolText.isEmpty())
                {
                    result.exceptionInfo.push_back({ QStringLiteral("转储自报的肇事驱动"),
                        QStringLiteral("%1  —  %2")
                            .arg(hex(brokenDriver), kBrokenNote.symbolText) });
                }
                else
                {
                    result.exceptionInfo.push_back({
                        QStringLiteral("TRIAGE 肇事驱动字段（未能归属到模块，仅供参考）"),
                        hex(brokenDriver) });
                }
            }
        }

        // ---------- Call Stack Reconstruction ----------
        if (hasTriage &&
            triageRangeValid(view, triage.callStackOffset, triage.sizeOfCallStack))
        {
            StackScanInput input{};
            input.stackFileOffset = triage.callStackOffset;
            input.stackBytes = triage.sizeOfCallStack;
            input.stackBaseAddress = triage.topOfStack;
            input.stackPointer = contextSp;
            input.instructionPointer = result.faultingAddress != 0 ? result.faultingAddress : contextIp;
            input.pointerSize = result.pointerSize;
            input.threadId = 0;
            result.stackFrames =
                scanStackFrames(view, input, modules, memory, kMaxKernelStackFrames);
        }
        else if (walker.has_value() && walker->usable() && contextSp != 0)
        {
            // Full/kernel dumps lack a TRIAGE stack block. The kernel stack of the crashing thread is
            // scattered across physical pages by virtual address, so file offsets are discontinuous. First,
            // translate and read page-by-page into a contiguous buffer, then pass it to the same scanner.
            //
            // The buffer itself forms a temporary view; the scanner uses it only to fetch stack slots. The call instruction
            // validation for candidate addresses traverses the page table backend via memory, using the real file view. The two are
            // never mixed, which is why DumpMemoryReader::read ignores the input view parameter when taking the page table branch.
            const std::uint64_t kStackBase = contextSp & ~0xFFFull;
            std::vector<unsigned char> stackBuffer(kMaxKernelStackScanBytes, 0);
            std::uint64_t stackBytes = 0;
            while (stackBytes < kMaxKernelStackScanBytes)
            {
                if (!walker->readVirtual(
                        kStackBase + stackBytes, kPageBytes, stackBuffer.data() + stackBytes))
                {
                    // Unmapped pages mark the stack boundary; this is a normal termination, not an error.
                    break;
                }
                stackBytes += kPageBytes;
            }

            if (stackBytes == 0)
            {
                result.diagnostics.append(
                    QStringLiteral("崩溃线程栈所在页不在转储中（栈指针 %1），无法重建调用栈。")
                        .arg(hex(contextSp)));
            }
            else
            {
                stackBuffer.resize(static_cast<std::size_t>(stackBytes));
                const DumpFileView kStackView{ stackBuffer.data(), stackBytes };
                StackScanInput input{};
                input.stackFileOffset = 0;
                input.stackBytes = stackBytes;
                input.stackBaseAddress = kStackBase;
                input.stackPointer = contextSp;
                input.instructionPointer =
                    result.faultingAddress != 0 ? result.faultingAddress : contextIp;
                input.pointerSize = result.pointerSize;
                input.threadId = 0;
                result.stackFrames =
                    scanStackFrames(kStackView, input, modules, memory, kMaxKernelStackFrames);
            }
        }
        else if (dumpType != 4 && contextSp == 0)
        {
            // The CONTEXT copy in a full dump header is all zeros in many Win10/11 samples. Without a stack
            // pointer, there is no scan start point. Clarify the cause to avoid implying a parsing failure.
            result.diagnostics.append(
                QStringLiteral("转储头中的 CONTEXT 未提供栈指针，无法定位崩溃线程栈，"
                    "调用栈不可重建。"));
        }

        if (!result.modules.empty())
        {
            result.overview.push_back({ QStringLiteral("已加载驱动数"),
                QString::number(result.modules.size()) });
        }
        if (!result.unloadedModules.empty())
        {
            result.overview.push_back({ QStringLiteral("已卸载驱动数"),
                QString::number(result.unloadedModules.size()) });
        }

        // ---------- Attribution Conclusion ----------
        buildAnalysis(modules, result);
        result.success = true;
    }

    void parseKernelDump32(const DumpFileView& view, DumpParseResult& result)
    {
        result.kind = DumpKind::kKernelDump32;
        result.recognized = true;
        if (view.size < kKernelHeader32Bytes)
        {
            result.errorText = QStringLiteral("文件小于 0x1000 字节，PAGEDUMP 头不完整。");
            return;
        }

        // 32-bit header fields are explicitly read using official offsets (simple structure, no local structs needed).
        std::uint32_t majorVersion = 0;
        std::uint32_t minorVersion = 0;
        std::uint32_t machineImageType = 0;
        std::uint32_t numberProcessors = 0;
        std::uint32_t bugCheckCode = 0;
        std::uint32_t bugCheckParameters32[4] = {};
        std::uint32_t dumpType = 0;
        std::uint64_t systemTime = 0;
        view.readStruct(0x08, &majorVersion);
        view.readStruct(0x0C, &minorVersion);
        view.readStruct(0x20, &machineImageType);
        view.readStruct(0x24, &numberProcessors);
        view.readStruct(0x28, &bugCheckCode);
        view.readStruct(0x2C, &bugCheckParameters32[0]);
        view.readStruct(0x30, &bugCheckParameters32[1]);
        view.readStruct(0x34, &bugCheckParameters32[2]);
        view.readStruct(0x38, &bugCheckParameters32[3]);
        view.readStruct(0xF88, &dumpType);
        view.readStruct(0xFC0, &systemTime);

        const ContextArch kArch = contextArchFromMachineImageType(machineImageType);
        result.pointerSize = contextPointerSize(kArch);
        result.bugCheckCode = bugCheckCode;
        // After promoting parameters to 64-bit, reuse the same BugCheck details output.
        for (int index = 0; index < 4; ++index)
        {
            result.bugCheckParameters[index] = bugCheckParameters32[index];
        }

        result.overview.push_back({ QStringLiteral("转储类别"),
            QStringLiteral("32 位内核转储 (PAGEDUMP)") });
        result.overview.push_back({ QStringLiteral("转储类型"), dumpTypeText(dumpType) });
        QString bugCheckLine = hex(bugCheckCode);
        const QString kBugCheckName = bugCheckCodeNameEx(bugCheckCode);
        if (!kBugCheckName.isEmpty())
        {
            bugCheckLine += QStringLiteral(" (%1)").arg(kBugCheckName);
        }
        result.overview.push_back({ QStringLiteral("停止代码"), bugCheckLine });
        const QString kCrashTime = fileTimeToText(systemTime);
        if (!kCrashTime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃时间"), kCrashTime });
        }
        result.overview.push_back({ QStringLiteral("内核构建号"),
            kernelBuildText(majorVersion, minorVersion) });
        result.overview.push_back({ QStringLiteral("CPU 架构"),
            machineImageTypeText(machineImageType) });
        result.overview.push_back({ QStringLiteral("逻辑处理器数"),
            QString::number(numberProcessors) });

        // 32-bit dumps do not include a TRIAGE driver list, so the module index is empty. However, parameter
        // interpretation can still provide IRQL, access type, and nested NTSTATUS details that do not depend on modules.
        ModuleIndex modules;
        modules.build(result.modules, result.unloadedModules, result.pointerSize);
        appendBugCheckDetails(
            bugCheckCode, result.bugCheckParameters, modules, result.pointerSize, result);

        // Crash point registers: x86 CONTEXT is at header offset 0x320.
        result.registers = readContextRegisters(
            view, kContext32Offset, kContext32Bytes, kArch, 0, modules);
        std::uint64_t contextIp = 0;
        std::uint64_t contextSp = 0;
        readContextPointers(
            view, kContext32Offset, kContext32Bytes, kArch, &contextIp, &contextSp, nullptr);
        if (contextIp != 0)
        {
            result.exceptionInfo.push_back({ QStringLiteral("崩溃点指令指针"), hex(contextIp) });
        }
        // Same as 64-bit path: trust only the faulting address from the stop code parameters; do not fall back to the IP in CONTEXT.
        result.faultingAddress =
            faultingAddressFromBugCheck(bugCheckCode, result.bugCheckParameters);

        result.diagnostics.append(
            QStringLiteral("32 位内核转储只解析头部信息：本格式不含 TRIAGE 驱动列表，"
                "无法把崩溃地址归属到具体驱动。"));
        buildAnalysis(modules, result);
        result.success = true;
    }
}
