#pragma once

// ============================================================
// MinidumpFormat.h
// Purpose:
// - Define a format-neutral data model used by the dump parsing page (MinidumpDock).
// - The same model simultaneously supports user-mode MDMP minidumps and kernel-mode PAGEDUMP/PAGEDU64 dumps;
// - Provide a read-only file view DumpFileView with boundary checks:
//   All accesses based on RVA/file offset must go through it to prevent out-of-bounds reads caused by malformed dumps.
// Call method:
// - See MinidumpParser.h's ks::minidump::parseDumpFile for the parsing entry point.
// - UI rendering consumes only the structs defined in this file and does not access raw file bytes.
// ============================================================

#include <QString>
#include <QStringList>

// CrashHistoryEntry: The parsed result must include the crash timeline from the system event log.
// CrashHistory.h depends only on Qt and the standard library, avoiding circular dependencies.
#include "CrashHistory.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace ks::minidump
{
    // DumpKind: The overall category of the parsed file, determined by the file signature.
    enum class DumpKind
    {
        kUnknown,      // Unknown: Signature unrecognized; not a supported dump file.
        kUserMinidump, // UserMinidump: User-mode MDMP mini-dump (output of MiniDumpWriteDump).
        kKernelDump64, // KernelDump64: 64-bit kernel dump (signature PAGEDU64, blue screen artifact).
        kKernelDump32, // KernelDump32: 32-bit kernel dump (signature PAGEDUMP, artifact of old system BSODs).
    };

    // DumpProperty: A 'property-value' row in the overview/details table.
    // name and value are both Chinese standard texts; the rendering layer translates the entire string via ks::i18n::sourceText.
    struct DumpProperty
    {
        QString name;  // name: Attribute name (Chinese standard text).
        QString value; // value: Attribute value text (dynamic parts remain unchanged; status words may be translated).
    };

    // StreamEntry: An entry in the MDMP stream directory; used to display TRIAGE data block layout during kernel dump.
    struct StreamEntry
    {
        std::uint32_t type = 0; // type: Stream type ID (MINIDUMP_STREAM_TYPE value).
        QString typeName;       // typeName: Stream type name (e.g., ThreadListStream).
        std::uint64_t rva = 0;  // rva: Offset of stream data within the file.
        std::uint64_t size = 0; // size: Stream data byte count.
        QString note;           // note: Chinese description (information carried by this stream).
    };

    // ModuleEntry: One loaded module (user-mode module or kernel driver).
    struct ModuleEntry
    {
        QString name;                   // name: Module full path or name.
        std::uint64_t base = 0;         // base: Load base address.
        std::uint64_t size = 0;         // size: image size (bytes).
        std::uint32_t checksum = 0;     // checksum: PE header CheckSum field.
        std::uint32_t timeDateStamp = 0; // timeDateStamp: PE header timestamp (time_t).
        QString timestampText;          // timestampText: Local time text of the timestamp.
        QString version;                // version: File version (VS_FIXEDFILEINFO), may be null.
        QString pdbName;                // pdbName: PDB path in the CodeView record; may be null.
        QString pdbGuidAge;             // pdbGuidAge: Text combining PDB GUID and Age, may be empty.
    };

    // AddressKind: The nature of a value when treated as an address, used to annotate parameters/registers.
    enum class AddressKind
    {
        kUnknown,      // Unknown: Unable to determine.
        kNullPage,     // NullPage: Falls within the NULL page (< 64KB), almost certainly indicating a null pointer dereference.
        kUserSpace,    // UserSpace: User-mode address range.
        kKernelSpace,  // KernelSpace: Kernel address range (upper half of x64).
        kPoison,       // Poison: Sentinel values filled by debuggers/allocators (used after uninitialized or freed).
    };

    // AddressNote: Complete interpretation result for a value (module ownership + nature description).
    struct AddressNote
    {
        AddressKind kind = AddressKind::kUnknown; // kind: address type classification.
        QString moduleName;      // moduleName: The matched module name; empty if no match.
        std::uint64_t moduleBase = 0; // moduleBase: Base address of the matched module.
        std::uint64_t offset = 0;     // offset: Offset relative to the module base address.
        bool unloadedModule = false;  // unloadedModule: Hit on an unloaded module (highly suspicious).
        QString symbolText;      // symbolText: "ModuleName+0xOffset"; empty if the module is not found.
        QString description;     // description: Chinese property description, may be null.
    };

    // StackFrameEntry: Represents a single 'suspected call stack frame'. Since this project does not load PDBs or perform unwinding, frames are derived
    // from stack memory scanning. Consequently, the order is approximate and false positives are inevitable; the UI must explicitly indicate this.
    struct StackFrameEntry
    {
        std::uint32_t threadId = 0;   // threadId: Thread ID belonging to the context; 0 indicates the crashing thread in kernel dumps.
        int index = 0;                // index: Frame sequence number; 0 is the current instruction pointer.
        std::uint64_t stackAddress = 0; // stackAddress: The stack virtual address where the return address resides.
        std::uint64_t address = 0;    // address: return address value.
        QString symbolText;           // symbolText: "ModuleName+0xOffset".
        QString moduleName;           // moduleName: Owning module name; may be null.
        QString functionText;         // functionText: "Module!Function+0xOffset"; empty if unsigned.
        QString sourceText;           // sourceText: Format "Source File:Line Number"; populated only when both the image and PDB match.
        bool fromContext = false;     // fromContext: true indicates the IP is taken from CONTEXT (trusted frame).
        bool unloadedModule = false;  // unloadedModule: Belongs to an unloaded module.
    };

    // SymbolMatchState: indicates the availability of symbols for a module and the matching conclusion.
    // Keep this separate because the reliability of a function name is part of the conclusion. The dump
    // records the image at crash time, but the disk image may have been rebuilt, shifting all line numbers.
    enum class SymbolMatchState
    {
        kNotChecked,    // NotChecked: Not attempted (module base address/size, etc., missing).
        kImageMissing,  // ImageMissing: The image is not found on disk and cannot be symbolicated.
        kImageMismatch, // ImageMismatch: Found a different image than the one at crash time; symbolication rejected.
        kNoSymbols,     // NoSymbols: Image matches but lacks a corresponding PDB; only module + offset can be provided.
        kMatched,       // Matched: Both image and PDB match; function names and line numbers are trusted.
    };

    // PoolTagCandidate: An identified pool tag and its attribution clues.
    // In pool corruption stop codes, determining 'who owns the corrupted block' is often more indicative of the culprit than the call
    // stack; the stack typically only shows the 'discoverer'—the next entity to allocate memory and thus collide with the bad list.
    struct PoolTagCandidate
    {
        std::uint32_t rawValue = 0; // rawValue: Raw 32-bit value.
        QString tagText;            // tagText: The restored 4-character tag, e.g., KsFi.
        QString source;             // source: which stop code parameter or which register it came from.
        QString knownPurpose;       // knownPurpose: Known purpose from pooltag.txt; may be empty.
        QStringList ownerModules;   // ownerModules: Modules that contained this marker in the disk image; may be null.
    };

    // ModuleSymbolStatus: Symbol loading result for a single module; displayed faithfully in the UI without hiding mismatches.
    struct ModuleSymbolStatus
    {
        QString moduleName;                                    // moduleName: Module name (no path).
        SymbolMatchState state = SymbolMatchState::kNotChecked;  // state: Matching conclusion.
        QString imagePath;                                     // imagePath: Actual disk image path in use; may be null.
        QString pdbPath;                                       // pdbPath: The actual loaded PDB path, which may be null.
        QString detail;                                        // detail: Chinese note, including specific differences.
    };

    // RegisterEntry: A register and its value interpretation from the CONTEXT at the crash point.
    struct RegisterEntry
    {
        std::uint32_t threadId = 0; // threadId: Thread ID belonging to the thread; use 0 for kernel dumps.
        QString name;               // name: Register name (Rip/Rsp/Rax...).
        std::uint64_t value = 0;    // value: Register value.
        QString note;               // note: Interpretation of value semantics (module ownership / poison / null pointer).
    };

    // BlameEntry: A candidate 'culprit module'. Multiple evidence hits on the same module accumulate weight.
    struct BlameEntry
    {
        QString moduleName;        // moduleName: Candidate module name.
        std::uint64_t moduleBase = 0; // moduleBase: Module base address.
        std::uint64_t address = 0;    // address: Representative address hit.
        std::uint64_t offset = 0;     // offset: offset relative to the base address.
        QString functionText;         // functionText: "Module!Function+0xOffset"; empty if unsigned.
        int weight = 0;               // weight: Total evidence weight; higher values indicate higher suspicion.
        bool unloadedModule = false;  // unloadedModule: The hit is on an unloaded module.
        QStringList evidence;         // evidence: Description of evidence supporting this candidate (Chinese).
    };

    // AnalysisConfidence: Confidence level of the diagnostic conclusion.
    enum class AnalysisConfidence
    {
        kNone,   // None: No conclusion reached.
        kLow,    // Low: Classified solely by stop code inference, without address-level evidence.
        kMedium, // Medium: Address-level evidence exists but is attributed to a system module or has multiple candidates.
        kHigh,   // High: The crashing instruction address directly belongs to a third-party module.
    };

    // DumpAnalysis: comprehensive diagnostic conclusion for the dump; serves as the data source for the 'Report' and 'Diagnosis' pages.
    struct DumpAnalysis
    {
        AnalysisConfidence confidence = AnalysisConfidence::kNone; // confidence: The conclusion's confidence level.
        QString headline;             // headline: One-sentence conclusion.
        QString category;             // category: Failure classification (driver/hardware/file system/power/software...).
        QStringList findings;         // findings: individual findings (chain of evidence).
        QStringList suggestions;      // suggestions: Next steps for troubleshooting.
        std::vector<BlameEntry> blame; // blame: Candidate modules for blame, sorted by weight in descending order.
    };

    // ThreadEntry: A line of thread information (including supplementary fields for ThreadInfo/ThreadNames streams).
    struct ThreadEntry
    {
        std::uint32_t threadId = 0;      // threadId: Thread ID.
        QString name;                    // name: Thread name (ThreadNamesStream); may be null.
        std::uint32_t suspendCount = 0;  // suspendCount: Suspend count.
        std::uint32_t priorityClass = 0; // priorityClass: Priority class.
        std::uint32_t priority = 0;      // priority: Base priority.
        std::uint64_t teb = 0;           // teb: TEB address.
        std::uint64_t stackBase = 0;     // stackBase: Starting address of the stack memory captured in the dump.
        std::uint64_t stackSize = 0;     // stackSize: number of bytes captured in the dump stack.
        std::uint64_t instructionPointer = 0; // instructionPointer: Instruction pointer in the context (Rip/Eip/Pc).
        std::uint64_t startAddress = 0;  // startAddress: Thread start address (ThreadInfoListStream).
        QString cpuTimeText;             // cpuTimeText: User-mode/kernel-mode CPU time text; may be null.
        QString ipSymbolText;            // ipSymbolText: Instruction pointer in the format 'module_name+0xoffset'; may be null.
        QString startSymbolText;         // startSymbolText: 'ModuleName+0xOffset' for the start address; may be null.
        bool faulting = false;           // faulting: Whether this is the crashing thread pointed to by the faulting stream.
    };

    // MemoryRegionEntry: One memory region line. Source may be MemoryList, Memory64List, or
    // MemoryInfoList; these three have different field coverage, with missing fields left empty.
    struct MemoryRegionEntry
    {
        std::uint64_t base = 0;  // base: Starting virtual address of the region.
        std::uint64_t size = 0;  // size: Number of bytes in the region.
        QString state;           // state: text representation of MEM_COMMIT/RESERVE/FREE (only present in MemoryInfoList).
        QString protect;         // protect: PAGE_* protection attribute text (only present in MemoryInfoList).
        QString type;            // type: Text representation of MEM_IMAGE/MAPPED/PRIVATE (only present in MemoryInfoList).
        QString source;          // source: Data source (Memory List / 64-bit Memory List / Memory Info List).
    };

    // DumpMemoryRange: a range of virtual memory that can be re-read from the raw dump file.
    // Unlike memoryRegions (which can come solely from MemoryInfoList containing only attributes), this structure only saves
    // ranges where bytes were actually captured and whose file offsets passed boundary validation during the parsing phase.
    // UI uses this to safely reopen file reads by virtual address without retaining the entire DMP mapping.
    struct DumpMemoryRange
    {
        std::uint64_t virtualAddress = 0; // virtualAddress: Virtual address of the first byte on the target machine.
        std::uint64_t fileOffset = 0;     // fileOffset: File offset of the first byte within the DMP.
        std::uint64_t bytes = 0;          // bytes: continuous and actually captured byte count.
        QString source;                   // source: Capture source, e.g., TRIAGE data block or thread stack.
    };

    // DumpByteBlock: A block of raw dump bytes that can be previewed in the UI.
    // Data comes only from a continuous capture range that has passed file-boundary validation; previewBytes is confined
    // to a safe small window. The full range and cross-page/cross-block reads are handled by subsequent memory viewers.
    struct DumpByteBlock
    {
        std::uint64_t address = 0;      // address: Target machine virtual address of the first byte to preview.
        std::uint64_t fileOffset = 0;   // fileOffset: The offset of this byte in the dump file.
        std::uint64_t capturedBytes = 0; // capturedBytes: Total byte count of this capture block.
        QString source;                 // source: Capture source, e.g., TRIAGE data block.
        bool hasVirtualAddress = true; // hasVirtualAddress: false indicates auxiliary data in the file, not virtual memory.
        std::vector<unsigned char> previewBytes; // previewBytes: Restricted raw preview bytes.
    };

    // HandleEntry: One line of handle information (HandleDataStream).
    struct HandleEntry
    {
        std::uint64_t handleValue = 0;   // handleValue: handle value.
        QString typeName;                // typeName: Object type name (e.g., File, Mutant).
        QString objectName;              // objectName: Object name, may be null.
        std::uint32_t attributes = 0;    // attributes: Handle attribute bits.
        std::uint32_t grantedAccess = 0; // grantedAccess: Granted access mask.
        std::uint32_t handleCount = 0;   // handleCount: object handle count.
        std::uint32_t pointerCount = 0;  // pointerCount: Object pointer count.
    };

    // UnloadedModuleEntry: A single entry for an unloaded module.
    // User-mode comes from UnloadedModuleListStream; kernel mode comes from the unloaded driver table in the TRIAGE region.
    struct UnloadedModuleEntry
    {
        QString name;                    // name: Module name.
        std::uint64_t base = 0;          // base: Load base address before unloading.
        std::uint64_t endAddress = 0;    // endAddress: Image end address before unloading (provided directly by the kernel table).
        std::uint32_t size = 0;          // size: Image size.
        std::uint32_t checksum = 0;      // checksum：PE CheckSum。
        std::uint32_t timeDateStamp = 0; // timeDateStamp: PE timestamp.
        QString timestampText;           // timestampText: Local time text of the timestamp.
    };

    // DumpParseResult: All results from a single dump parse; the UI consumes only this structure.
    struct DumpParseResult
    {
        bool success = false;    // success: Whether core displayable information was parsed.
        bool recognized = false; // recognized: Whether the signature is recognized (success=false if recognized but corrupted).
        DumpKind kind = DumpKind::kUnknown; // kind: Dump category.
        QString errorText;       // errorText: Failure reason (in standardized Chinese text); empty on success.
        QString filePath;        // filePath: full path of the parsed file.
        std::uint64_t fileSize = 0; // fileSize: File size in bytes.
        // fileLastModifiedUtcMs: The UTC modification timestamp of the file at parse time, used by the memory viewer to reject
        // reading a DMP that was replaced at the same path after parsing; -1 indicates the file system did not provide this time.
        std::int64_t fileLastModifiedUtcMs = -1;

        std::vector<DumpProperty> overview;      // overview: Overview page 'property-value' collection.
        std::vector<DumpProperty> exceptionInfo; // exceptionInfo: Collection of exception/BugCheck details; may be empty.
        // executionContext: Snapshot of the current CPU / KTHREAD / EPROCESS at the crash site.
        // Currently dynamically parsed from the KDDEBUGGER_DATA64 structure in x64 TRIAGE_DUMP64.
        // Do not disguise fields that were not captured in the dump or cannot be verified as zero values.
        std::vector<DumpProperty> executionContext;
        std::vector<StreamEntry> streams;        // streams: Stream directory (or kernel TRIAGE layout).
        std::vector<ModuleEntry> modules;        // modules: Module/driver list.
        std::vector<ThreadEntry> threads;        // threads: Thread list (typically empty in kernel dumps).
        std::vector<MemoryRegionEntry> memoryRegions; // memoryRegions: List of memory regions.
        // capturedMemoryRanges: Virtual memory ranges that can be re-read from the DMP by a memory viewer.
        // It holds no file mappings to avoid dangling file views after asynchronous parsing completes.
        std::vector<DumpMemoryRange> capturedMemoryRanges;
        std::vector<DumpByteBlock> byteBlocks; // byteBlocks: Raw memory blocks safe for preview.
        std::vector<HandleEntry> handles;        // handles: Handle list (user-mode dumps with handle stream only).
        std::vector<UnloadedModuleEntry> unloadedModules; // unloadedModules: List of unloaded modules.
        std::vector<StackFrameEntry> stackFrames; // stackFrames: Suspected call stack (stack scan result, may contain false positives).
        std::vector<RegisterEntry> registers;     // registers: register snapshot at crash point
        DumpAnalysis analysis;                    // analysis: Comprehensive diagnostic conclusion and candidate module for the incident.
        std::vector<ModuleSymbolStatus> symbolStatus; // symbolStatus: Symbol matching conclusions per module.
        std::vector<PoolTagCandidate> poolTags;   // poolTags: identified pool tags and their ownership clues.
        std::vector<CrashHistoryEntry> crashHistory; // crashHistory: Crash timeline from system event logs.
        QString symbolSearchPath;                 // symbolSearchPath: The symbol search path actually used in this session.
        QStringList diagnostics;                 // diagnostics: Non-fatal warnings during parsing (Chinese text).

        std::uint64_t memoryRegionTotal = 0; // memoryRegionTotal: total number of memory regions in the file (including those not displayed).
        std::uint64_t memoryRegionShown = 0; // memoryRegionShown: The actual number of entries filled into memoryRegions.
        std::uint32_t pointerSize = 8;       // pointerSize: Target machine pointer width (4 or 8), stack scan step size.
        std::uint32_t bugCheckCode = 0;      // bugCheckCode: kernel dump stop code; 0 for user-mode dumps.
        std::uint64_t bugCheckParameters[4] = {}; // bugCheckParameters: The four parameters of the stop code.
        std::uint32_t exceptionCode = 0;     // exceptionCode: User-mode exception code; may be 0 in kernel dumps.
        std::uint64_t faultingAddress = 0;   // faultingAddress: crash instruction address (IP); 0 indicates unknown.
        std::uint32_t faultingThreadId = 0;  // faultingThreadId: ID of the crashing thread, valid in user mode.
    };

    // DumpFileView: Read-only file view responsible for all byte access with bounds checking.
    // Usage: parser first constructs { data, size }, then exclusively uses contains/at/readStruct to retrieve data.
    struct DumpFileView
    {
        const unsigned char* data = nullptr; // data: The pointer to the first byte of the mapped file.
        std::uint64_t size = 0;              // size: total file byte count.

        // contains purpose: Determine if [offset, offset+bytes) is fully within the file.
        // Input: file offset and byte length. Output: whether it is safe to read (prevents addition overflow).
        bool contains(const std::uint64_t offset, const std::uint64_t bytes) const
        {
            if (data == nullptr || offset > size || bytes > size)
            {
                return false;
            }
            return offset + bytes <= size;
        }

        // at: Retrieve the raw pointer at the given offset; return nullptr if out of bounds.
        // Takes file offset and byte count to read; returns a readable pointer or nullptr.
        const unsigned char* at(const std::uint64_t offset, const std::uint64_t bytes) const
        {
            return contains(offset, bytes) ? data + offset : nullptr;
        }

        // readStruct: Safely copies bytes from the specified offset into a POD structure.
        // Input offset (file offset) and output pointer valueOut; return whether the read was successful.
        template <typename PodType>
        bool readStruct(const std::uint64_t offset, PodType* const valueOut) const
        {
            const unsigned char* const kSource = at(offset, sizeof(PodType)); // source: Pointer to the start of the region to be copied.
            if (kSource == nullptr || valueOut == nullptr)
            {
                return false;
            }
            std::memcpy(valueOut, kSource, sizeof(PodType));
            return true;
        }
    };
}
