#include "DumpSymbolResolver.h"

// baseModuleName is here: symbol resolution repeatedly simplifies "full paths" to "file names".
#include "DumpSymbolIndex.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStringList>

#include <algorithm>
#include <array>
#include <mutex>

#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

namespace ks::minidump
{
    namespace
    {
        // g_dbgHelpMutex: DbgHelp session state is process-scoped; only one session is allowed at a time.
        // Parsing runs in a thread pool worker; multiple parses may occur concurrently, making this lock necessary.
        std::mutex gDbgHelpMutex;

        // kFakeProcess: SymInitialize requires a unique handle as a session identifier. For offline symbol resolution where
        // no real process exists, pass a constant that does not conflict with any real handle, following DbgHelp conventions.
        void* fakeProcessHandle()
        {
            return reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x4B53574DU)); // 'KSWM'
        }

        // ImageIdentity: identity fields read from the disk PE header, used to compare against dump records.
        struct ImageIdentity
        {
            bool valid = false;              // valid: indicates successful read.
            std::uint32_t timeDateStamp = 0; // timeDateStamp：PE FileHeader.TimeDateStamp。
            std::uint32_t sizeOfImage = 0;   // sizeOfImage：OptionalHeader.SizeOfImage。
        };

        // ReadLe32: Read a 32-bit value from the byte buffer in little-endian order.
        // Input: pointer to the start of the data buffer; Output: the read value. The caller must ensure at least 4 bytes are readable.
        std::uint32_t readLe32(const unsigned char* const data)
        {
            return static_cast<std::uint32_t>(data[0]) |
                   (static_cast<std::uint32_t>(data[1]) << 8) |
                   (static_cast<std::uint32_t>(data[2]) << 16) |
                   (static_cast<std::uint32_t>(data[3]) << 24);
        }

        // readImageIdentity purpose: Read-only PE header to extract TimeDateStamp and SizeOfImage.
        // Accepts path as a disk file path; returns identity fields. Returns valid=false if any step is invalid.
        // Do not use Windows image loading APIs: only two fields are needed here; manual reading
        // is more efficient than mapping the entire image and avoids failure due to file locks.
        ImageIdentity readImageIdentity(const QString& path)
        {
            ImageIdentity identity; // identity: Identity field to be returned.

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                return identity;
            }

            // header: PE header region. 0x400 bytes are sufficient to cover the DOS header + NT header + optional header.
            const QByteArray kHeader = file.read(0x400);
            const auto* const kBytes = reinterpret_cast<const unsigned char*>(kHeader.constData());
            const int kAvailable = static_cast<int>(kHeader.size());
            if (kAvailable < 0x40 || kBytes[0] != 'M' || kBytes[1] != 'Z')
            {
                return identity;
            }

            // ntOffset：IMAGE_DOS_HEADER.e_lfanew。
            const std::uint32_t kNtOffset = readLe32(kBytes + 0x3C);
            // NT signature (4) + FileHeader (20) + optional header up to SizeOfImage (60).
            if (kNtOffset > static_cast<std::uint32_t>(kAvailable) ||
                static_cast<std::uint64_t>(kNtOffset) + 4 + 20 + 60 >
                    static_cast<std::uint64_t>(kAvailable))
            {
                return identity;
            }
            if (readLe32(kBytes + kNtOffset) != 0x00004550U) // 'PE\0\0'
            {
                return identity;
            }

            // TimeDateStamp is located 4 bytes after the start of IMAGE_FILE_HEADER.
            identity.timeDateStamp = readLe32(kBytes + kNtOffset + 4 + 4);
            // SizeOfImage has an offset of 56 in the optional header for both PE32 and PE32+; no need to distinguish by bit width.
            identity.sizeOfImage = readLe32(kBytes + kNtOffset + 4 + 20 + 56);
            identity.valid = true;
            return identity;
        }

        // normalizeNativePath: Converts kernel-style paths to Win32 paths that can be opened directly.
        // Input: path from the raw module record; Output: converted result, or empty string if conversion fails.
        // Driver paths in kernel dumps are like \SystemRoot\System32\drivers\x.sys
        // or \??\C:\..., which cannot be opened directly via QFile::open.
        QString normalizeNativePath(const QString& raw)
        {
            if (raw.isEmpty())
            {
                return QString();
            }

            QString path = raw; // path: Path during step-by-step conversion.
            if (path.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
            {
                path = path.mid(4);
            }
            else if (path.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
            {
                // systemRoot: the actual Windows directory, not hardcoded to C:\Windows.
                const QString kSystemRoot =
                    QString::fromLocal8Bit(qgetenv("SystemRoot"));
                if (kSystemRoot.isEmpty())
                {
                    return QString();
                }
                path = kSystemRoot + QStringLiteral("\\") + path.mid(12);
            }
            else if (path.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
            {
                // \Device\HarddiskVolumeN\... requires volume device mapping to convert;
                // do not guess here, let the caller search for the path by filename.
                return QString();
            }

            // At this point, the path must already include a drive letter or be a UNC path; otherwise, it is rejected.
            if (path.size() >= 2 && path.at(1) == QLatin1Char(':'))
            {
                return QDir::toNativeSeparators(path);
            }
            if (path.startsWith(QStringLiteral("\\\\")))
            {
                return QDir::toNativeSeparators(path);
            }
            return QString();
        }

        // splitSearchPath: Splits a semicolon-delimited search path into a list of directories.
        // Accepts searchPath; returns the list of directories with empty entries removed.
        QStringList splitSearchPath(const QString& searchPath)
        {
            QStringList directories; // directories: Split results.
            const QStringList kParts = searchPath.split(QLatin1Char(';'), Qt::SkipEmptyParts);
            for (const QString& part : kParts)
            {
                const QString kTrimmed = part.trimmed();
                if (!kTrimmed.isEmpty())
                {
                    directories.append(QDir::toNativeSeparators(kTrimmed));
                }
            }
            return directories;
        }

        // locateImage purpose: Find the image file corresponding to a module on disk.
        // Input: module is the module record and searchDirs lists search directories. Return the matching full path, or an empty string if none is found.
        // First attempts the path recorded by the module itself, then searches by filename in the search
        // directories—this covers the common scenario of 'copying a driver from elsewhere for analysis'.
        QString locateImage(const ModuleEntry& module, const QStringList& searchDirs)
        {
            const QString kNative = normalizeNativePath(module.name);
            if (!kNative.isEmpty() && QFileInfo::exists(kNative))
            {
                return kNative;
            }

            const QString kBaseName = baseModuleName(module.name);
            if (kBaseName.isEmpty())
            {
                return QString();
            }
            for (const QString& directory : searchDirs)
            {
                const QString kCandidate =
                    QDir(directory).absoluteFilePath(kBaseName);
                if (QFileInfo::exists(kCandidate))
                {
                    return QDir::toNativeSeparators(kCandidate);
                }
            }
            return QString();
        }
    }

    QString ResolvedSymbol::functionText() const
    {
        if (!valid || functionName.isEmpty())
        {
            return QString();
        }
        // Do not append +0x0 when the offset is 0 for cleaner readability.
        if (displacement == 0)
        {
            return moduleName.isEmpty()
                       ? functionName
                       : QStringLiteral("%1!%2").arg(moduleName, functionName);
        }
        const QString kSuffix =
            QStringLiteral("+0x%1").arg(displacement, 0, 16);
        return moduleName.isEmpty()
                   ? functionName + kSuffix
                   : QStringLiteral("%1!%2%3").arg(moduleName, functionName, kSuffix);
    }

    QString ResolvedSymbol::sourceText() const
    {
        // Never provide line numbers when the image does not match: an incorrect line number is more
        // harmful than no line number, as it leads one to confidently read code that was never executed.
        if (!valid || match != SymbolMatchState::kMatched ||
            sourceFile.isEmpty() || sourceLine == 0)
        {
            return QString();
        }
        return QStringLiteral("%1:%2").arg(sourceFile).arg(sourceLine);
    }

    SymbolResolver::SymbolResolver() = default;

    SymbolResolver::~SymbolResolver()
    {
        if (initialized_)
        {
            ::SymCleanup(static_cast<HANDLE>(handle_));
            initialized_ = false;
            gDbgHelpMutex.unlock();
        }
    }

    bool SymbolResolver::begin(
        const QString& searchPath,
        const std::vector<ModuleEntry>& modules)
    {
        if (initialized_)
        {
            return true;
        }

        gDbgHelpMutex.lock();
        handle_ = fakeProcessHandle();

        // Do not set SYMOPT_DEFERRED_LOADS: deferred loading makes it impossible to know if symbols actually loaded
        // successfully, while the entire value of this module lies in providing a definitive matching conclusion.
        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_NO_PROMPTS);

        // Pass FALSE for the third parameter fInvadeProcess: offline symbol resolution does not enumerate modules of the current process.
        const std::wstring kPathBuffer = searchPath.toStdWString();
        if (::SymInitializeW(
                static_cast<HANDLE>(handle_),
                kPathBuffer.empty() ? nullptr : kPathBuffer.c_str(),
                FALSE) == FALSE)
        {
            gDbgHelpMutex.unlock();
            handle_ = nullptr;
            return false;
        }
        initialized_ = true;

        const QStringList kSearchDirs = splitSearchPath(searchPath);
        status_.reserve(modules.size());
        loaded_.reserve(modules.size());

        for (const ModuleEntry& module : modules)
        {
            ModuleSymbolStatus status; // status: Conclusion for this module.
            status.moduleName = baseModuleName(module.name);
            if (module.base == 0 || module.size == 0)
            {
                status.state = SymbolMatchState::kNotChecked;
                status.detail = QStringLiteral("模块缺少基址或大小，无法定位。");
                status_.push_back(status);
                continue;
            }

            const QString kImagePath = locateImage(module, kSearchDirs);
            if (kImagePath.isEmpty())
            {
                status.state = SymbolMatchState::kImageMissing;
                status.detail = QStringLiteral(
                    "磁盘上找不到该映像；把它连同 PDB 放进符号搜索路径即可符号化。");
                status_.push_back(status);
                continue;
            }
            status.imagePath = kImagePath;

            // Image identity comparison: this step is the foundation of the entire module. The dump records the
            // specific image loaded at the time of the crash; the version on disk may have been recompiled entirely.
            const ImageIdentity kIdentity = readImageIdentity(kImagePath);
            if (!kIdentity.valid)
            {
                status.state = SymbolMatchState::kImageMissing;
                status.detail = QStringLiteral("文件存在但不是有效的 PE 映像。");
                status_.push_back(status);
                continue;
            }

            const bool kStampDiffers =
                module.timeDateStamp != 0 &&
                kIdentity.timeDateStamp != module.timeDateStamp;
            const bool kSizeDiffers =
                kIdentity.sizeOfImage != 0 &&
                module.size != 0 &&
                kIdentity.sizeOfImage != static_cast<std::uint32_t>(module.size);
            if (kStampDiffers || kSizeDiffers)
            {
                status.state = SymbolMatchState::kImageMismatch;
                QStringList differences; // differences: Item-by-item differences; clearly documenting them helps determine if a self-recompile occurred.
                if (kStampDiffers)
                {
                    differences.append(QStringLiteral("时间戳 转储 0x%1 / 磁盘 0x%2")
                                           .arg(module.timeDateStamp, 8, 16, QLatin1Char('0'))
                                           .arg(kIdentity.timeDateStamp, 8, 16, QLatin1Char('0')));
                }
                if (kSizeDiffers)
                {
                    differences.append(QStringLiteral("映像大小 转储 0x%1 / 磁盘 0x%2")
                                           .arg(module.size, 0, 16)
                                           .arg(kIdentity.sizeOfImage, 0, 16));
                }
                status.detail = QStringLiteral(
                                    "磁盘上的映像不是崩溃时加载的那一份（%1）。"
                                    "该模块的函数名与行号一律不可信，"
                                    "请换回崩溃时那次构建的映像与 PDB。")
                                    .arg(differences.join(QStringLiteral("；")));
                status_.push_back(status);
                // Explicitly skip symbol loading: prefer providing only module + offset rather than function names that could be misleading.
                Loaded loaded;
                loaded.base = module.base;
                loaded.end = module.base + module.size;
                loaded.name = status.moduleName;
                loaded.state = SymbolMatchState::kImageMismatch;
                loaded_.push_back(loaded);
                continue;
            }

            const std::wstring kImageBuffer = kImagePath.toStdWString();
            const std::wstring kNameBuffer = status.moduleName.toStdWString();
            const DWORD64 kLoadedBase = ::SymLoadModuleExW(
                static_cast<HANDLE>(handle_),
                nullptr,
                kImageBuffer.c_str(),
                kNameBuffer.empty() ? nullptr : kNameBuffer.c_str(),
                static_cast<DWORD64>(module.base),
                static_cast<DWORD>(module.size),
                nullptr,
                0);
            if (kLoadedBase == 0)
            {
                status.state = SymbolMatchState::kNoSymbols;
                status.detail = QStringLiteral("映像匹配，但 DbgHelp 未能登记该模块。");
                status_.push_back(status);
                continue;
            }

            IMAGEHLP_MODULEW64 information{};
            information.SizeOfStruct = sizeof(information);
            if (::SymGetModuleInfoW64(
                    static_cast<HANDLE>(handle_),
                    kLoadedBase,
                    &information) != FALSE &&
                information.SymType == SymPdb)
            {
                status.state = SymbolMatchState::kMatched;
                status.pdbPath = QString::fromWCharArray(information.LoadedPdbName);
                status.detail = QStringLiteral("映像与 PDB 均匹配，函数名与行号可信。");
            }
            else
            {
                status.state = SymbolMatchState::kNoSymbols;
                status.detail = QStringLiteral(
                    "映像匹配但没有找到配套 PDB，只能给到模块+偏移。");
            }

            Loaded loaded;
            loaded.base = module.base;
            loaded.end = module.base + module.size;
            loaded.name = status.moduleName;
            loaded.state = status.state;
            loaded_.push_back(loaded);
            status_.push_back(status);
        }

        std::sort(
            loaded_.begin(),
            loaded_.end(),
            [](const Loaded& left, const Loaded& right) { return left.base < right.base; });
        return true;
    }

    ResolvedSymbol SymbolResolver::resolve(const std::uint64_t address) const
    {
        ResolvedSymbol resolved; // resolved: Result to be returned.
        if (!initialized_ || address == 0)
        {
            return resolved;
        }

        // Locate the module first to derive the matching conclusion; function names without a conclusion are unusable.
        const auto kHit = std::find_if(
            loaded_.begin(),
            loaded_.end(),
            [address](const Loaded& range)
            { return address >= range.base && address < range.end; });
        if (kHit == loaded_.end())
        {
            return resolved;
        }
        resolved.moduleName = kHit->name;
        resolved.match = kHit->state;
        if (kHit->state != SymbolMatchState::kMatched)
        {
            return resolved;
        }

        constexpr std::size_t kSymbolBufferSize =
            sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t));
        alignas(SYMBOL_INFOW) std::array<unsigned char, kSymbolBufferSize> symbolBuffer{};
        auto* const kSymbolInfo = reinterpret_cast<SYMBOL_INFOW*>(symbolBuffer.data());
        kSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
        kSymbolInfo->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (::SymFromAddrW(
                static_cast<HANDLE>(handle_),
                static_cast<DWORD64>(address),
                &displacement,
                kSymbolInfo) == FALSE)
        {
            return resolved;
        }
        resolved.valid = true;
        resolved.functionName = QString::fromWCharArray(kSymbolInfo->Name);
        resolved.displacement = static_cast<std::uint64_t>(displacement);

        IMAGEHLP_LINEW64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisplacement = 0;
        if (::SymGetLineFromAddrW64(
                static_cast<HANDLE>(handle_),
                static_cast<DWORD64>(address),
                &lineDisplacement,
                &line) != FALSE)
        {
            resolved.sourceFile = QString::fromWCharArray(line.FileName);
            resolved.sourceLine = static_cast<std::uint32_t>(line.LineNumber);
        }
        return resolved;
    }

    const std::vector<ModuleSymbolStatus>& SymbolResolver::moduleStatus() const
    {
        return status_;
    }

    QString buildDefaultSymbolSearchPath(const QString& dumpFilePath)
    {
        QStringList directories; // directories: Candidate directories, ordered by hit probability from high to low.

        // Dump file's own directory: placing .sys/.pdb and .dmp together is the simplest usage.
        if (!dumpFilePath.isEmpty())
        {
            const QString kDumpDirectory = QFileInfo(dumpFilePath).absolutePath();
            if (!kDumpDirectory.isEmpty())
            {
                directories.append(QDir::toNativeSeparators(kDumpDirectory));
            }
        }

        // Common symbol cache directories on the local machine. Only search locally; no symbol servers are configured:
        // Parsing runs on a worker; network access may cause long-term unresponsiveness.
        directories.append(QStringLiteral("C:\\Symbols"));
        directories.append(QStringLiteral("C:\\ProgramData\\Dbg\\sym"));

        const QString kSystemRoot = QString::fromLocal8Bit(qgetenv("SystemRoot"));
        if (!kSystemRoot.isEmpty())
        {
            directories.append(QDir::toNativeSeparators(
                kSystemRoot + QStringLiteral("\\System32\\drivers")));
            directories.append(QDir::toNativeSeparators(
                kSystemRoot + QStringLiteral("\\System32")));
        }

        QStringList existing; // existing: Retains only existing directories to avoid cluttering the search path with dead paths.
        for (const QString& directory : directories)
        {
            if (!existing.contains(directory, Qt::CaseInsensitive) &&
                QFileInfo(directory).isDir())
            {
                existing.append(directory);
            }
        }
        return existing.join(QLatin1Char(';'));
    }

    QString symbolMatchStateText(const SymbolMatchState state)
    {
        switch (state)
        {
        case SymbolMatchState::kImageMissing:
            return QStringLiteral("映像缺失");
        case SymbolMatchState::kImageMismatch:
            return QStringLiteral("映像不匹配");
        case SymbolMatchState::kNoSymbols:
            return QStringLiteral("无符号");
        case SymbolMatchState::kMatched:
            return QStringLiteral("已匹配");
        case SymbolMatchState::kNotChecked:
        default:
            return QStringLiteral("未检查");
        }
    }

    void applySymbols(const QString& searchPath, DumpParseResult& result)
    {
        // effectivePath: Uses the default local path if the caller does not provide one.
        const QString kEffectivePath =
            searchPath.trimmed().isEmpty()
                ? buildDefaultSymbolSearchPath(result.filePath)
                : searchPath.trimmed();
        result.symbolSearchPath = kEffectivePath;
        if (kEffectivePath.isEmpty() || result.modules.empty())
        {
            return;
        }

        // Only load symbols for modules that actually appear in the call stack and the list of crash candidates: kernel dumps often contain
        // 100+ drivers; loading all PDBs would drag parsing to minutes, yet most of these modules are unrelated to the current crash.
        QSet<QString> wanted; // wanted: Set of module names requiring symbols (lowercase for comparison).
        for (const StackFrameEntry& frame : result.stackFrames)
        {
            if (!frame.moduleName.isEmpty())
            {
                wanted.insert(frame.moduleName.toLower());
            }
        }
        for (const BlameEntry& blame : result.analysis.blame)
        {
            if (!blame.moduleName.isEmpty())
            {
                wanted.insert(blame.moduleName.toLower());
            }
        }
        if (wanted.isEmpty())
        {
            return;
        }

        std::vector<ModuleEntry> selected; // selected: Subset of modules pending symbol resolution.
        selected.reserve(wanted.size());
        for (const ModuleEntry& module : result.modules)
        {
            if (wanted.contains(baseModuleName(module.name).toLower()))
            {
                selected.push_back(module);
            }
        }
        if (selected.empty())
        {
            return;
        }

        SymbolResolver resolver;
        if (!resolver.begin(kEffectivePath, selected))
        {
            result.diagnostics.append(
                QStringLiteral("符号会话建立失败，本次结果只有模块+偏移。"));
            return;
        }
        result.symbolStatus = resolver.moduleStatus();

        for (StackFrameEntry& frame : result.stackFrames)
        {
            const ResolvedSymbol kSymbol = resolver.resolve(frame.address);
            frame.functionText = kSymbol.functionText();
            frame.sourceText = kSymbol.sourceText();
        }
        for (BlameEntry& blame : result.analysis.blame)
        {
            const ResolvedSymbol kSymbol = resolver.resolve(blame.address);
            blame.functionText = kSymbol.functionText();
        }

        // Mismatches must be surfaced to the user. The insidious nature of this issue is that it does not throw an error;
        // it merely silently returns incorrect line numbers, leading users to modify code that was never actually executed.
        QStringList mismatched; // mismatched: Module names with mismatched images.
        for (const ModuleSymbolStatus& status : result.symbolStatus)
        {
            if (status.state == SymbolMatchState::kImageMismatch)
            {
                mismatched.append(status.moduleName);
            }
        }
        if (!mismatched.isEmpty())
        {
            result.diagnostics.append(
                QStringLiteral("以下模块磁盘映像与崩溃时不是同一份构建，"
                               "已拒绝对其符号化：%1")
                    .arg(mismatched.join(QStringLiteral("、"))));
        }
    }
}
