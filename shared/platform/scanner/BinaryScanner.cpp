#include "BinaryScanner.h"

#include "ScannerInternal.h"
#include "../file/PeAnalyzer.h"

// ============================================================
// ksword/scanner/binary_scanner.cpp
// Purpose:
// - Bound and load one file, dispatch by magic, and adapt parser results.
// - Reuse ks::file::analyzePeBytes as the canonical PE implementation.
// - Add only the structured PE export information absent from that API.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <new>
#include <span>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ks::scanner
{
    namespace
    {
        using detail::addDiagnostic;
        using detail::addDiagnosticAt;
        using detail::addField;
        using detail::appendRow;
        using detail::decimal;
        using detail::EndianReader;
        using detail::hex;

        struct PeSectionMap
        {
            std::uint32_t virtualAddress = 0;
            std::uint32_t virtualSize = 0;
            std::uint32_t rawOffset = 0;
            std::uint32_t rawSize = 0;
        };

        std::string wideToUtf8(const std::wstring& text)
        {
            if (text.empty())
            {
                return {};
            }
            const int kRequiredBytes = ::WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(std::min<std::size_t>(
                    text.size(),
                    static_cast<std::size_t>(std::numeric_limits<int>::max()))),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (kRequiredBytes <= 0)
            {
                return "PE analyzer rejected the file.";
            }
            std::string output(static_cast<std::size_t>(kRequiredBytes), '\0');
            if (::WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    text.data(),
                    static_cast<int>(text.size()),
                    output.data(),
                    kRequiredBytes,
                    nullptr,
                    nullptr) <= 0)
            {
                return "PE analyzer rejected the file.";
            }
            return output;
        }

        const char* peMachineName(const std::uint16_t machine)
        {
            switch (machine)
            {
            case 0x014CU: return "x86";
            case 0x8664U: return "x86-64";
            case 0x01C0U: return "ARM";
            case 0x01C4U: return "ARM Thumb-2";
            case 0xAA64U: return "ARM64";
            case 0x0200U: return "IA-64";
            default: return "Unknown";
            }
        }

        const char* peSubsystemName(const std::uint16_t subsystem)
        {
            switch (subsystem)
            {
            case 1: return "Native";
            case 2: return "Windows GUI";
            case 3: return "Windows Console";
            case 7: return "POSIX Console";
            case 9: return "Windows CE GUI";
            case 10: return "EFI Application";
            case 11: return "EFI Boot Driver";
            case 12: return "EFI Runtime Driver";
            case 13: return "EFI ROM";
            case 14: return "Xbox";
            case 16: return "Windows Boot Application";
            default: return "Unknown";
            }
        }

        std::string formatEntropy(const double value)
        {
            std::ostringstream stream;
            stream << std::fixed << std::setprecision(4) << value;
            return stream.str();
        }

        bool readWholeFile(
            const std::wstring& filePath,
            const ScanOptions& options,
            std::vector<std::uint8_t>& bytesOut,
            BinaryScanResult& result)
        {
            bytesOut.clear();
            HANDLE fileHandle = ::CreateFileW(
                filePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                const DWORD kError = ::GetLastError();
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.open_failed",
                    "CreateFileW failed with error " + decimal(kError) + ".");
                return false;
            }

            BY_HANDLE_FILE_INFORMATION information{};
            if (::GetFileInformationByHandle(fileHandle, &information) == FALSE)
            {
                const DWORD kError = ::GetLastError();
                ::CloseHandle(fileHandle);
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.info_failed",
                    "GetFileInformationByHandle failed with error " + decimal(kError) + ".");
                return false;
            }
            if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                ::CloseHandle(fileHandle);
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.not_ordinary",
                    "The selected path is a directory, not an ordinary file.");
                return false;
            }

            LARGE_INTEGER fileSize{};
            if (::GetFileSizeEx(fileHandle, &fileSize) == FALSE ||
                fileSize.QuadPart < 0)
            {
                const DWORD kError = ::GetLastError();
                ::CloseHandle(fileHandle);
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.size_failed",
                    "GetFileSizeEx failed with error " + decimal(kError) + ".");
                return false;
            }
            result.fileSize = static_cast<std::uint64_t>(fileSize.QuadPart);
            if (result.fileSize > options.maxFileBytes ||
                result.fileSize > static_cast<std::uint64_t>(
                    std::numeric_limits<std::size_t>::max()))
            {
                ::CloseHandle(fileHandle);
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.too_large",
                    "The file exceeds ScanOptions.maxFileBytes.");
                return false;
            }

            try
            {
                bytesOut.assign(static_cast<std::size_t>(result.fileSize), 0);
            }
            catch (const std::bad_alloc&)
            {
                ::CloseHandle(fileHandle);
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.allocation_failed",
                    "Memory allocation for the input file failed.");
                return false;
            }

            std::size_t totalRead = 0;
            while (totalRead < bytesOut.size())
            {
                const DWORD kRequested = static_cast<DWORD>(std::min<std::size_t>(
                    bytesOut.size() - totalRead,
                    1024U * 1024U));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        fileHandle,
                        bytesOut.data() + totalRead,
                        kRequested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    const DWORD kError = ::GetLastError();
                    ::CloseHandle(fileHandle);
                    addDiagnostic(
                        result,
                        DiagnosticSeverity::kError,
                        "file.read_failed",
                        "ReadFile failed with error " + decimal(kError) + ".");
                    return false;
                }
                if (bytesRead == 0)
                {
                    ::CloseHandle(fileHandle);
                    bytesOut.clear();
                    addDiagnostic(
                        result,
                        DiagnosticSeverity::kError,
                        "file.short_read",
                        "The file changed or became shorter while it was being read.");
                    return false;
                }
                totalRead += bytesRead;
            }

            // A second complete pass rejects mixed snapshots, including most
            // changes made through a writable mapping that predates our
            // non-write-shared handle. A tiny final verification-to-close race is
            // an unavoidable Win32 boundary and is documented by this API.
            LARGE_INTEGER verifiedSize{};
            DWORD verificationError = ERROR_SUCCESS;
            if (::GetFileSizeEx(fileHandle, &verifiedSize) == FALSE)
            {
                verificationError = ::GetLastError();
            }
            else if (verifiedSize.QuadPart != fileSize.QuadPart)
            {
                verificationError = ERROR_REVISION_MISMATCH;
            }
            else
            {
                LARGE_INTEGER beginning{};
                if (::SetFilePointerEx(
                        fileHandle,
                        beginning,
                        nullptr,
                        FILE_BEGIN) == FALSE)
                {
                    verificationError = ::GetLastError();
                }
            }

            std::vector<std::uint8_t> verificationBuffer(1024U * 1024U);
            std::size_t verifiedBytes = 0;
            while (verificationError == ERROR_SUCCESS &&
                verifiedBytes < bytesOut.size())
            {
                const DWORD kRequested = static_cast<DWORD>(std::min<std::size_t>(
                    bytesOut.size() - verifiedBytes,
                    verificationBuffer.size()));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        fileHandle,
                        verificationBuffer.data(),
                        kRequested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    verificationError = ::GetLastError();
                    break;
                }
                if (bytesRead != kRequested ||
                    !std::equal(
                        verificationBuffer.begin(),
                        verificationBuffer.begin() + bytesRead,
                        bytesOut.begin() + verifiedBytes))
                {
                    verificationError = ERROR_REVISION_MISMATCH;
                    break;
                }
                verifiedBytes += bytesRead;
            }
            ::CloseHandle(fileHandle);
            if (verificationError != ERROR_SUCCESS)
            {
                bytesOut.clear();
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "file.changed_during_read",
                    "The file changed while the scanner was building a stable snapshot.");
                return false;
            }
            return true;
        }

        bool readPeSupplementLayout(
            const EndianReader& reader,
            std::uint32_t& exportRvaOut,
            std::uint32_t& exportSizeOut,
            std::uint32_t& sizeOfHeadersOut,
            std::vector<PeSectionMap>& sectionsOut)
        {
            std::uint32_t ntOffset = 0;
            if (!reader.readU32(0x3C, ntOffset))
            {
                return false;
            }
            std::uint32_t signature = 0;
            std::uint16_t sectionCount = 0;
            std::uint16_t optionalSize = 0;
            const std::uint64_t kFileHeaderOffset =
                static_cast<std::uint64_t>(ntOffset) + 4U;
            if (!reader.readU32(ntOffset, signature) ||
                signature != 0x00004550U ||
                !reader.readU16(kFileHeaderOffset + 2, sectionCount) ||
                !reader.readU16(kFileHeaderOffset + 16, optionalSize))
            {
                return false;
            }
            const std::uint64_t kOptionalOffset = kFileHeaderOffset + 20U;
            std::uint16_t optionalMagic = 0;
            if (!reader.readU16(kOptionalOffset, optionalMagic) ||
                !reader.readU32(kOptionalOffset + 60, sizeOfHeadersOut))
            {
                return false;
            }

            std::uint64_t directoryCountOffset = 0;
            std::uint64_t directoryOffset = 0;
            if (optionalMagic == 0x10BU)
            {
                directoryCountOffset = kOptionalOffset + 92U;
                directoryOffset = kOptionalOffset + 96U;
            }
            else if (optionalMagic == 0x20BU)
            {
                directoryCountOffset = kOptionalOffset + 108U;
                directoryOffset = kOptionalOffset + 112U;
            }
            else
            {
                return false;
            }

            std::uint32_t directoryCount = 0;
            if (!reader.readU32(directoryCountOffset, directoryCount))
            {
                return false;
            }
            exportRvaOut = 0;
            exportSizeOut = 0;
            if (directoryCount > 0 &&
                !reader.readU32(directoryOffset, exportRvaOut))
            {
                return false;
            }
            if (directoryCount > 0 &&
                !reader.readU32(directoryOffset + 4, exportSizeOut))
            {
                return false;
            }

            const std::uint64_t kSectionTableOffset = kOptionalOffset + optionalSize;
            sectionsOut.clear();
            sectionsOut.reserve(sectionCount);
            for (std::uint16_t index = 0; index < sectionCount; ++index)
            {
                const std::uint64_t kOffset =
                    kSectionTableOffset + static_cast<std::uint64_t>(index) * 40U;
                PeSectionMap section{};
                if (!reader.readU32(kOffset + 8, section.virtualSize) ||
                    !reader.readU32(kOffset + 12, section.virtualAddress) ||
                    !reader.readU32(kOffset + 16, section.rawSize) ||
                    !reader.readU32(kOffset + 20, section.rawOffset))
                {
                    return false;
                }
                sectionsOut.push_back(section);
            }
            return true;
        }

        bool peRvaToOffset(
            const EndianReader& reader,
            const std::uint32_t rva,
            const std::uint32_t sizeOfHeaders,
            const std::vector<PeSectionMap>& sections,
            std::uint64_t& offsetOut)
        {
            for (const PeSectionMap& section : sections)
            {
                const std::uint64_t kStart = section.virtualAddress;
                const std::uint64_t kSpan = std::max(
                    section.virtualSize,
                    section.rawSize);
                const std::uint64_t kEnd = kStart + kSpan;
                if (kSpan != 0 &&
                    static_cast<std::uint64_t>(rva) >= kStart &&
                    static_cast<std::uint64_t>(rva) < kEnd)
                {
                    const std::uint64_t kDelta =
                        static_cast<std::uint64_t>(rva) - kStart;
                    if (kDelta >= section.rawSize)
                    {
                        // VirtualSize may include zero-fill bytes that have no
                        // file representation; never map them into later data.
                        return false;
                    }
                    const std::uint64_t kCandidate =
                        static_cast<std::uint64_t>(section.rawOffset) + kDelta;
                    const std::uint64_t kRawEnd =
                        static_cast<std::uint64_t>(section.rawOffset) +
                        section.rawSize;
                    if (kCandidate >= kRawEnd || !reader.contains(kCandidate, 1))
                    {
                        return false;
                    }
                    offsetOut = kCandidate;
                    return true;
                }
            }
            if (rva < sizeOfHeaders && reader.contains(rva, 1))
            {
                offsetOut = rva;
                return true;
            }
            return false;
        }

        std::string readPeString(
            const EndianReader& reader,
            const std::uint32_t rva,
            const std::uint32_t sizeOfHeaders,
            const std::vector<PeSectionMap>& sections,
            const ScanOptions& options)
        {
            std::uint64_t offset = 0;
            if (!peRvaToOffset(reader, rva, sizeOfHeaders, sections, offset))
            {
                return {};
            }
            return reader.cString(
                offset,
                reader.size(),
                options.maxStringBytes);
        }

        void appendPeExports(
            const std::span<const std::uint8_t> bytes,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            BinaryTable exports{
                "exports",
                "Exports",
                { "Ordinal", "Name", "RVA", "Forwarder" },
                {},
                false
            };
            const EndianReader kReader(bytes, ByteOrder::kLittleEndian);
            std::uint32_t exportRva = 0;
            std::uint32_t exportSize = 0;
            std::uint32_t sizeOfHeaders = 0;
            std::vector<PeSectionMap> sections;
            if (!readPeSupplementLayout(
                    kReader,
                    exportRva,
                    exportSize,
                    sizeOfHeaders,
                    sections))
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kWarning,
                    "pe.export_layout_unavailable",
                    "PE export supplement could not read the validated header layout.");
                result.tables.push_back(std::move(exports));
                return;
            }
            if (exportRva == 0 || exportSize == 0)
            {
                result.tables.push_back(std::move(exports));
                return;
            }

            std::uint64_t exportOffset = 0;
            if (!peRvaToOffset(
                    kReader,
                    exportRva,
                    sizeOfHeaders,
                    sections,
                    exportOffset) ||
                !kReader.contains(exportOffset, 40))
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kWarning,
                    "pe.export_directory_invalid",
                    "PE export directory is outside the file.",
                    exportOffset);
                result.tables.push_back(std::move(exports));
                return;
            }

            std::uint32_t dllNameRva = 0;
            std::uint32_t ordinalBase = 0;
            std::uint32_t functionCount = 0;
            std::uint32_t nameCount = 0;
            std::uint32_t functionsRva = 0;
            std::uint32_t namesRva = 0;
            std::uint32_t ordinalsRva = 0;
            if (!kReader.readU32(exportOffset + 12, dllNameRva) ||
                !kReader.readU32(exportOffset + 16, ordinalBase) ||
                !kReader.readU32(exportOffset + 20, functionCount) ||
                !kReader.readU32(exportOffset + 24, nameCount) ||
                !kReader.readU32(exportOffset + 28, functionsRva) ||
                !kReader.readU32(exportOffset + 32, namesRva) ||
                !kReader.readU32(exportOffset + 36, ordinalsRva))
            {
                result.tables.push_back(std::move(exports));
                return;
            }

            const std::string kModuleName = readPeString(
                kReader,
                dllNameRva,
                sizeOfHeaders,
                sections,
                options);
            if (!kModuleName.empty())
            {
                addField(result.summary, "Export Module", kModuleName);
            }

            const std::uint32_t kBoundedFunctionCount =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    functionCount,
                    options.maxContainerEntries));
            const std::uint32_t kBoundedNameCount =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    nameCount,
                    options.maxContainerEntries));
            if (kBoundedFunctionCount != functionCount ||
                kBoundedNameCount != nameCount)
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kWarning,
                    "pe.export_count_limited",
                    "PE export counts exceeded maxContainerEntries.");
            }

            std::uint64_t functionsOffset = 0;
            std::uint64_t namesOffset = 0;
            std::uint64_t ordinalsOffset = 0;
            if ((kBoundedFunctionCount != 0 &&
                    (!peRvaToOffset(kReader, functionsRva, sizeOfHeaders, sections, functionsOffset) ||
                     !kReader.contains(functionsOffset, static_cast<std::uint64_t>(kBoundedFunctionCount) * 4U))) ||
                (kBoundedNameCount != 0 &&
                    (!peRvaToOffset(kReader, namesRva, sizeOfHeaders, sections, namesOffset) ||
                     !peRvaToOffset(kReader, ordinalsRva, sizeOfHeaders, sections, ordinalsOffset) ||
                     !kReader.contains(namesOffset, static_cast<std::uint64_t>(kBoundedNameCount) * 4U) ||
                     !kReader.contains(ordinalsOffset, static_cast<std::uint64_t>(kBoundedNameCount) * 2U))))
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kWarning,
                    "pe.export_arrays_invalid",
                    "One or more PE export arrays are outside the file.");
                result.tables.push_back(std::move(exports));
                return;
            }

            std::vector<std::string> namesByFunction(kBoundedFunctionCount);
            for (std::uint32_t index = 0; index < kBoundedNameCount; ++index)
            {
                std::uint32_t nameRva = 0;
                std::uint16_t ordinalIndex = 0;
                if (!kReader.readU32(namesOffset + static_cast<std::uint64_t>(index) * 4U, nameRva) ||
                    !kReader.readU16(ordinalsOffset + static_cast<std::uint64_t>(index) * 2U, ordinalIndex))
                {
                    break;
                }
                if (ordinalIndex < namesByFunction.size())
                {
                    namesByFunction[ordinalIndex] = readPeString(
                        kReader,
                        nameRva,
                        sizeOfHeaders,
                        sections,
                        options);
                }
            }

            const std::uint64_t kExportEnd =
                static_cast<std::uint64_t>(exportRva) + exportSize;
            for (std::uint32_t index = 0; index < kBoundedFunctionCount; ++index)
            {
                std::uint32_t functionRva = 0;
                if (!kReader.readU32(
                        functionsOffset + static_cast<std::uint64_t>(index) * 4U,
                        functionRva))
                {
                    break;
                }
                if (functionRva == 0)
                {
                    continue;
                }
                std::string forwarder;
                if (functionRva >= exportRva &&
                    static_cast<std::uint64_t>(functionRva) < kExportEnd)
                {
                    forwarder = readPeString(
                        kReader,
                        functionRva,
                        sizeOfHeaders,
                        sections,
                        options);
                }
                appendRow(
                    exports,
                    {
                        decimal(static_cast<std::uint64_t>(ordinalBase) + index),
                        namesByFunction[index],
                        hex(functionRva),
                        forwarder
                    },
                    options);
            }
            result.tables.push_back(std::move(exports));
        }

        bool parsePe(
            const std::vector<std::uint8_t>& bytes,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            result.recognized = true;
            result.byteOrder = ByteOrder::kLittleEndian;
            // Analyze the exact already-bounded snapshot instead of reopening the
            // path, so detection, PE adaptation, and export supplement cannot see
            // different file revisions.
            const ks::file::PeAnalysisResult kPe = ks::file::analyzePeBytes(bytes);
            if (!kPe.success)
            {
                result.format = BinaryFormat::kUnknown;
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "pe.analysis_failed",
                    wideToUtf8(kPe.reportText));
                return false;
            }

            result.format = kPe.isPe64
                ? BinaryFormat::kPe32Plus
                : BinaryFormat::kPe32;
            addField(result.summary, "Format", kPe.isPe64 ? "PE32+" : "PE32");
            addField(result.summary, "Byte Order", "Little-endian");
            addField(result.summary, "Architecture", peMachineName(kPe.machine));
            addField(result.summary, "Entry Point RVA", hex(kPe.entryPointRva));
            if (kPe.entryPointFileOffsetValid)
            {
                addField(result.summary, "Entry Point File Offset", hex(kPe.entryPointFileOffset));
            }
            addField(result.summary, "Image Base", hex(kPe.imageBase));
            addField(result.summary, "Sections", decimal(kPe.sections.size()));
            addField(result.summary, "Import Modules", decimal(kPe.importModules.size()));

            addField(result.headers, "Machine", std::string(peMachineName(kPe.machine)) + " (" + hex(kPe.machine) + ")");
            addField(result.headers, "Subsystem", std::string(peSubsystemName(kPe.subsystem)) + " (" + hex(kPe.subsystem) + ")");
            addField(result.headers, "Entry Point RVA", hex(kPe.entryPointRva));
            if (kPe.entryPointFileOffsetValid)
            {
                addField(result.headers, "Entry Point File Offset", hex(kPe.entryPointFileOffset));
            }
            addField(result.headers, "Image Base", hex(kPe.imageBase));

            BinaryTable sections{
                "sections",
                "Sections",
                { "Name", "Virtual Address", "Virtual Size", "Raw Offset",
                  "Raw Size", "Characteristics", "Entropy" },
                {},
                false
            };
            for (const ks::file::PeSectionSummary& section : kPe.sections)
            {
                appendRow(
                    sections,
                    {
                        section.name,
                        hex(section.virtualAddress),
                        hex(section.virtualSize),
                        hex(section.rawOffset),
                        hex(section.rawSize),
                        hex(section.characteristics),
                        formatEntropy(section.entropy)
                    },
                    options);
            }
            result.tables.push_back(std::move(sections));

            BinaryTable imports{
                "imports",
                "Imports",
                { "Module", "Function", "Hint", "Ordinal", "Import Kind",
                  "Thunk RVA", "Diagnostic" },
                {},
                false
            };
            for (const ks::file::PeImportModuleSummary& module : kPe.importModules)
            {
                if (module.imports.empty())
                {
                    appendRow(
                        imports,
                        {
                            module.dllName,
                            {},
                            {},
                            {},
                            {},
                            {},
                            module.diagnosticText
                        },
                        options);
                    continue;
                }
                for (const ks::file::PeImportFunctionSummary& function : module.imports)
                {
                    if (!appendRow(
                            imports,
                            {
                                module.dllName,
                                function.functionName,
                                decimal(function.hint),
                                decimal(function.ordinal),
                                function.importByOrdinal ? "Ordinal" : "Name",
                                hex(function.thunkRva),
                                module.diagnosticText
                            },
                            options))
                    {
                        break;
                    }
                }
            }
            result.tables.push_back(std::move(imports));
            appendPeExports(std::span<const std::uint8_t>(bytes), options, result);
            // Attack path detection reuses the same stable snapshot; it does not reopen the file or call the PE entry point.
            detail::detectAttackPathInPe(
                std::span<const std::uint8_t>(bytes),
                "<selected-file>",
                0,
                options,
                result);
            result.success = true;
            return true;
        }

        bool looksLikeMachO(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 4)
            {
                return false;
            }
            const std::uint32_t kPrefix =
                (static_cast<std::uint32_t>(bytes[0]) << 24U) |
                (static_cast<std::uint32_t>(bytes[1]) << 16U) |
                (static_cast<std::uint32_t>(bytes[2]) << 8U) |
                static_cast<std::uint32_t>(bytes[3]);
            switch (kPrefix)
            {
            case 0xCEFAEDFEU:
            case 0xFEEDFACEU:
            case 0xCFFAEDFEU:
            case 0xFEEDFACFU:
            case 0xCAFEBABEU:
            case 0xBEBAFECAU:
            case 0xCAFEBABFU:
            case 0xBFBAFECAU:
                return true;
            default:
                return false;
            }
        }

        // ISO9660 volume descriptor starts at a fixed offset of sector 16 (2048 bytes); this performs only a dispatch magic number check.
        bool looksLikeIso9660(const std::span<const std::uint8_t> bytes)
        {
            constexpr std::size_t kDescriptorOffset = 16U * 2048U;
            constexpr std::size_t kSignatureOffset = kDescriptorOffset + 1U;
            return bytes.size() >= kDescriptorOffset + 7U &&
                bytes[kSignatureOffset] == 'C' &&
                bytes[kSignatureOffset + 1U] == 'D' &&
                bytes[kSignatureOffset + 2U] == '0' &&
                bytes[kSignatureOffset + 3U] == '0' &&
                bytes[kSignatureOffset + 4U] == '1' &&
                bytes[kDescriptorOffset + 6U] == 1U;
        }
    }

    BinaryScanResult scanBinaryFile(
        const std::wstring& filePath,
        const ScanOptions& options)
    {
        BinaryScanResult result{};
        if (filePath.empty())
        {
            addDiagnostic(
                result,
                DiagnosticSeverity::kError,
                "file.path_empty",
                "The file path is empty.");
            return result;
        }
        if (options.maxFileBytes == 0 ||
            options.maxRowsPerTable == 0 ||
            options.maxStringBytes == 0 ||
            options.maxContainerEntries == 0)
        {
            addDiagnostic(
                result,
                DiagnosticSeverity::kError,
                "options.invalid",
                "All ScanOptions limits must be greater than zero.");
            return result;
        }

        std::vector<std::uint8_t> bytes;
        if (!readWholeFile(filePath, options, bytes, result))
        {
            return result;
        }
        addField(result.summary, "File Size", decimal(result.fileSize));

        const std::span<const std::uint8_t> kView(bytes);
        if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
        {
            parsePe(bytes, options, result);
            return result;
        }
        if (bytes.size() >= 4 &&
            bytes[0] == 0x7FU &&
            bytes[1] == 'E' &&
            bytes[2] == 'L' &&
            bytes[3] == 'F')
        {
            detail::parseElf(kView, options, result);
            return result;
        }
        if (looksLikeMachO(kView))
        {
            detail::parseMachO(kView, options, result);
            return result;
        }
        if (looksLikeIso9660(kView))
        {
            detail::parseIso9660(kView, options, result);
            return result;
        }

        addDiagnostic(
            result,
            DiagnosticSeverity::kInformation,
            "format.unsupported",
            "The file is not PE, ELF, Mach-O, or ISO9660.");
        return result;
    }

    const char* formatName(const BinaryFormat format)
    {
        switch (format)
        {
        case BinaryFormat::kPe32: return "PE32";
        case BinaryFormat::kPe32Plus: return "PE32+";
        case BinaryFormat::kElf32: return "ELF32";
        case BinaryFormat::kElf64: return "ELF64";
        case BinaryFormat::kMachO32: return "Mach-O 32";
        case BinaryFormat::kMachO64: return "Mach-O 64";
        case BinaryFormat::kMachOUniversal: return "Universal Mach-O";
        case BinaryFormat::kIso9660: return "ISO9660";
        case BinaryFormat::kUnknown:
        default:
            return "Unknown";
        }
    }

    const char* byteOrderName(const ByteOrder byteOrder)
    {
        switch (byteOrder)
        {
        case ByteOrder::kLittleEndian: return "Little-endian";
        case ByteOrder::kBigEndian: return "Big-endian";
        case ByteOrder::kBothEndian: return "Both-endian";
        case ByteOrder::kUnknown:
        default:
            return "Unknown";
        }
    }
}
