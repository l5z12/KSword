// KvmWatch: Facade implementation for R-1 memory monitoring (first-access attribution).
//
// Placed in a separate file instead of KvmControl.cpp: this group is the only set of facade
// members that must be pulled into the Windows module enumeration, while KvmControl.cpp currently
// depends only on ArkDriverClient and Qt. Dragging NtQuerySystemInformation into that translation
// unit would force every call site that only wants to read KVM state to carry that dependency.

#include "KvmControl.h"

#include "../internationalization/LanguageManager.h"

#include <QDir>
#include <QFile>
#include <QHash>
#include <QLibrary>
#include <QMutex>
#include <QMutexLocker>
#include <QPair>

#include <algorithm>
#include <iterator>
#include <vector>

namespace ksword::kvm
{
    namespace
    {
        /* SystemModuleInformation. ntdll does not export this constant, so it must be hardcoded. */
        constexpr unsigned long kSystemModuleInformationClass = 11UL;

        /*
         * Local replica of RTL_PROCESS_MODULE_INFORMATION.
         *
         * Not taken from WDK headers: this is user-mode code, and that structure is not defined in the
         * public user-mode SDK. Field layout has remained unchanged since Windows XP; out-of-bounds risk is
         * mitigated by reading row-by-row based on count below, with buffer length guaranteed by the kernel.
         */
        struct SystemModuleRow
        {
            void* section;
            void* mappedBase;
            void* imageBase;
            unsigned long imageSize;
            unsigned long flags;
            unsigned short loadOrderIndex;
            unsigned short initOrderIndex;
            unsigned short loadCount;
            unsigned short fileNameOffset;
            unsigned char fullPathName[256];
        };

        struct SystemModuleList
        {
            unsigned long count;
            SystemModuleRow rows[1];
        };

        using NtQuerySystemInformationFunction =
            long(__stdcall*)(unsigned long, void*, unsigned long, unsigned long*);

        /*
         * Translate a PID to an image name.
         *
         * Used only for supplementary display; the criterion is always the PID itself. Driver attribution occurs at one
         * moment, while this query happens at another, and PIDs may be recycled. If the name cannot be retrieved, return
         * an empty string so the caller displays only the PID—a wrong process name is more misleading than no name.
         *
         * Use QueryFullProcessImageNameW instead of GetModuleFileNameEx: it requires only
         * PROCESS_QUERY_LIMITED_INFORMATION, allowing retrieval of names for protected processes,
         * which are precisely the ones most valuable to appear in attribution results.
         */
        QString processImageNameForPid(const unsigned long processId)
        {
            if (processId == 0UL)
            {
                return QString();
            }
            const HANDLE kProcess = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (kProcess == nullptr)
            {
                return QString();
            }
            wchar_t buffer[MAX_PATH] = {};
            DWORD length = static_cast<DWORD>(std::size(buffer));
            const BOOL kOk = ::QueryFullProcessImageNameW(
                kProcess, 0, buffer, &length);
            ::CloseHandle(kProcess);
            if (kOk == FALSE || length == 0UL)
            {
                return QString();
            }
            const QString kFullPath = QString::fromWCharArray(
                buffer, static_cast<int>(length));
            const int kSeparator = kFullPath.lastIndexOf(QLatin1Char('\\'));
            return kSeparator >= 0 ? kFullPath.mid(kSeparator + 1) : kFullPath;
        }

        QString ruleStatusText(const unsigned long status)
        {
            switch (status)
            {
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST:
                return ks::i18n::sourceText(QStringLiteral("请求不合法"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED:
                return ks::i18n::sourceText(QStringLiteral("需要显式确认"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED:
                return ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND:
                return ks::i18n::sourceText(QStringLiteral("没有这条监视"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL:
                return ks::i18n::sourceText(QStringLiteral("规则表已满"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED:
                return ks::i18n::sourceText(QStringLiteral("目标页无法拆成 4 KiB 叶"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL:
                return ks::i18n::sourceText(QStringLiteral("部分处理器未能完成失效"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED:
                return ks::i18n::sourceText(QStringLiteral("这条处置当前未实现"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE:
                return ks::i18n::sourceText(QStringLiteral("这台机器上无法安全实现该处置"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT:
                return ks::i18n::sourceText(QStringLiteral("这一页已经被别的 EPT 机制占着"));
            case KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN:
                return ks::i18n::sourceText(QStringLiteral("常驻运行中：EPT 规则表在常驻期间冻结，安装与撤销都要先停止常驻"));
            default:
                break;
            }
            return ks::i18n::sourceText(QStringLiteral("协议状态 %1")).arg(status);
        }

        /* Translate a protocol snapshot row into a UI structure. */
        KvmWatchEntry toWatchEntry(const KSWORD_ARK_HVM_EPT_WATCH_ROW& row)
        {
            KvmWatchEntry entry;
            entry.watchId = row.watchId;
            entry.state = row.state;
            entry.requestedAccess = row.requestedAccess;
            entry.effectiveAccess = row.effectiveAccess;
            entry.addressKind = row.addressKind;
            entry.hitCount = row.hitCount;
            entry.lastHitSequence = row.lastHitSequence;
            entry.lastHitStatus = row.lastHitStatus;
            entry.armedGeneration = row.armedGeneration;
            entry.requestedAddress = row.requestedAddress;
            entry.requestedLength = row.requestedLength;
            entry.physicalPage = row.physicalPage;
            entry.pageCount = row.pageCount;
            entry.lastHitRip = row.lastHitRip;
            entry.lastHitGuestLinearAddress = row.lastHitGuestLinearAddress;
            entry.lastHitGuestPhysicalAddress = row.lastHitGuestPhysicalAddress;
            entry.lastHitCr3 = row.lastHitCr3;
            entry.lastHitRsp = row.lastHitRsp;
            entry.lastHitTimestamp = row.lastHitTimestamp;
            entry.lastHitProcessorGroup = row.lastHitProcessorGroup;
            entry.lastHitProcessorNumber = row.lastHitProcessorNumber;
            entry.lastHitGuestLinearValid = row.lastHitGuestLinearValid != 0U;
            entry.lastHitRangeMatch = row.lastHitRangeMatch != 0UL;
            return entry;
        }

        /* Translate driver responses into conclusions directly displayable in the UI. */
        KvmWatchResult toWatchResult(
            const ksword::ark::HvmEptRuleResult& result,
            const QString& actionName)
        {
            KvmWatchResult watch;
            watch.protocolStatus = result.response.status;
            watch.lastStatus = result.response.lastStatus;
            watch.conflictOwnerId = result.response.conflictOwnerId;
            watch.conflictOwnerKind = result.response.conflictOwnerKind;
            watch.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
            if (result.io.ok)
            {
                // The table is refilled on both success and failure: even on failure, the caller must see the current contents;
                // otherwise, a 'table full' rejection would only show a number, making it impossible to determine which entry to remove.
                const unsigned long kRows =
                    result.response.returnedWatchRows <=
                        KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS
                        ? result.response.returnedWatchRows
                        : KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS;
                for (unsigned long index = 0; index < kRows; ++index)
                {
                    watch.watches.append(
                        toWatchEntry(result.response.watchRows[index]));
                }
                // Include the corresponding row with a single operation so the caller does not need to query again to see the result.
                if (kRows == 0 && result.response.watch.watchId != 0)
                {
                    watch.watches.append(toWatchEntry(result.response.watch));
                }
                watch.watchCount = result.response.watchRowCount != 0
                    ? result.response.watchRowCount
                    : static_cast<unsigned long>(watch.watches.size());
            }
            if (watch.ok)
            {
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return watch;
            }
            if (!result.io.ok && result.unsupported)
            {
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return watch;
            }
            if (result.response.status ==
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT)
            {
                // Conflicts must be specific: saying just 'conflict' doesn't tell the user which one to remove first.
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：%2。请先移除它，再安装内存监视。"))
                    .arg(actionName)
                    .arg(describeWatchConflict(
                        result.response.conflictOwnerKind,
                        result.response.conflictOwnerId));
                return watch;
            }
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(ruleStatusText(result.response.status));
            return watch;
        }

        /*
         * Convert NT paths to Win32 paths that can be opened directly.
         *
         * SystemModuleInformation returns paths from the kernel's perspective: ntoskrnl is
         * `\SystemRoot\system32\ntoskrnl.exe`, third-party drivers are mostly `\??\C:\...`,
         * and a few are directly `\Windows\...`. All three formats must be recognized; if
         * unrecognized, return an empty string to let the caller silently give up. Using a
         * guessed path to open another file would resolve symbols to a different module.
         */
        QString toWin32Path(const QString& ntPath)
        {
            QString path = ntPath;
            if (path.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
            {
                return path.mid(4);
            }
            if (path.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
            {
                return QDir::toNativeSeparators(
                    QString::fromLocal8Bit(qgetenv("SystemRoot")) +
                    path.mid(11));
            }
            if (path.startsWith(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive))
            {
                return QDir::toNativeSeparators(
                    QString::fromLocal8Bit(qgetenv("SystemDrive")) + path);
            }
            // If the path is already in `C:\...` format, use it directly.
            if (path.size() > 2 && path[1] == QLatin1Char(':'))
            {
                return path;
            }
            return QString();
        }

        /* Export table for a module: RVA-sorted for binary search of the nearest predecessor. */
        struct ExportTable
        {
            bool valid = false;
            QVector<QPair<quint32, QString>> entries;
        };

        /*
         * Parse the export table from the **disk image**.
         *
         * Do not read the in-memory copy: accessing memory requires the R-1 memory interface and write permissions,
         * and in the current troubleshooting scenario, the in-memory copy may have been tampered with. The disk
         * image answers "what the function was originally named," which is what is needed for attribution.
         */
        ExportTable loadExportTable(const QString& ntPath)
        {
            ExportTable table;
            const QString kWin32Path = toWin32Path(ntPath);
            if (kWin32Path.isEmpty())
            {
                return table;
            }
            QFile file(kWin32Path);
            if (!file.open(QIODevice::ReadOnly))
            {
                return table;
            }
            const QByteArray kImage = file.readAll();
            file.close();
            const auto* const kBase =
                reinterpret_cast<const unsigned char*>(kImage.constData());
            const qsizetype kSize = kImage.size();
            if (kSize < static_cast<qsizetype>(sizeof(IMAGE_DOS_HEADER)))
            {
                return table;
            }
            const auto* const kDos =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(kBase);
            if (kDos->e_magic != IMAGE_DOS_SIGNATURE ||
                kDos->e_lfanew <= 0 ||
                kDos->e_lfanew + static_cast<LONG>(sizeof(IMAGE_NT_HEADERS64)) >
                    static_cast<LONG>(kSize))
            {
                return table;
            }
            const auto* const kNt =
                reinterpret_cast<const IMAGE_NT_HEADERS64*>(kBase + kDos->e_lfanew);
            if (kNt->Signature != IMAGE_NT_SIGNATURE ||
                kNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return table;
            }
            const IMAGE_DATA_DIRECTORY& directory =
                kNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (directory.VirtualAddress == 0 || directory.Size == 0)
            {
                return table;
            }
            // Disk images are laid out according to FileAlignment; RVA must be converted to file offsets section by section.
            const auto* const kSections = IMAGE_FIRST_SECTION(kNt);
            const auto kRvaToOffset = [&](const quint32 rva) -> qsizetype {
                for (unsigned index = 0; index < kNt->FileHeader.NumberOfSections; ++index)
                {
                    const IMAGE_SECTION_HEADER& section = kSections[index];
                    if (rva >= section.VirtualAddress &&
                        rva < section.VirtualAddress + section.SizeOfRawData)
                    {
                        return static_cast<qsizetype>(
                            section.PointerToRawData + (rva - section.VirtualAddress));
                    }
                }
                return -1;
            };
            const qsizetype kDirectoryOffset = kRvaToOffset(directory.VirtualAddress);
            if (kDirectoryOffset < 0 ||
                kDirectoryOffset + static_cast<qsizetype>(sizeof(IMAGE_EXPORT_DIRECTORY)) > kSize)
            {
                return table;
            }
            const auto* const kExports =
                reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(kBase + kDirectoryOffset);
            const qsizetype kNamesOffset = kRvaToOffset(kExports->AddressOfNames);
            const qsizetype kOrdinalsOffset = kRvaToOffset(kExports->AddressOfNameOrdinals);
            const qsizetype kFunctionsOffset = kRvaToOffset(kExports->AddressOfFunctions);
            if (kNamesOffset < 0 || kOrdinalsOffset < 0 || kFunctionsOffset < 0)
            {
                return table;
            }
            const auto* const kNameRvas =
                reinterpret_cast<const quint32*>(kBase + kNamesOffset);
            const auto* const kOrdinals =
                reinterpret_cast<const quint16*>(kBase + kOrdinalsOffset);
            const auto* const kFunctionRvas =
                reinterpret_cast<const quint32*>(kBase + kFunctionsOffset);
            table.entries.reserve(static_cast<int>(kExports->NumberOfNames));
            for (quint32 index = 0; index < kExports->NumberOfNames; ++index)
            {
                const qsizetype kNameOffset = kRvaToOffset(kNameRvas[index]);
                if (kNameOffset < 0 || kNameOffset >= kSize)
                {
                    continue;
                }
                const quint16 kOrdinal = kOrdinals[index];
                if (kOrdinal >= kExports->NumberOfFunctions)
                {
                    continue;
                }
                const quint32 kFunctionRva = kFunctionRvas[kOrdinal];
                if (kFunctionRva == 0)
                {
                    continue;
                }
                const char* const kName =
                    reinterpret_cast<const char*>(kBase + kNameOffset);
                const qsizetype kMaximum = kSize - kNameOffset;
                qsizetype length = 0;
                while (length < kMaximum && kName[length] != '\0')
                {
                    ++length;
                }
                table.entries.append(
                    { kFunctionRva, QString::fromLatin1(kName, static_cast<int>(length)) });
            }
            std::sort(table.entries.begin(), table.entries.end(),
                [](const QPair<quint32, QString>& left,
                   const QPair<quint32, QString>& right) {
                    return left.first < right.first;
                });
            table.valid = !table.entries.isEmpty();
            return table;
        }

        /*
         * Cache export tables by module path.
         *
         * Each refresh of the monitoring table attributes every hit individually, while kernel images are often several MB in size.
         * Without caching, a single refresh would re-read and re-parse the same ntoskrnl file over a
         * dozen times. The module's disk image does not change within a session, so caching is safe.
         */
        const ExportTable& cachedExportTable(const QString& ntPath)
        {
            static QHash<QString, ExportTable> cache;
            static QMutex mutex;
            QMutexLocker locker(&mutex);
            auto found = cache.find(ntPath);
            if (found == cache.end())
            {
                found = cache.insert(ntPath, loadExportTable(ntPath));
            }
            return found.value();
        }

        /* When write access is disabled, uniformly deny the operation without issuing any IOCTL. */
        KvmWatchResult denyWatchWithoutWriteAccess(const QString& actionName)
        {
            KvmWatchResult watch;
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return watch;
        }
    }

    KvmWatchResult listWatches()
    {
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY;
        const auto kResult = client.controlHvmEptWatch(request);
        return toWatchResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取内存监视")));
    }

    KvmWatchResult addWatch(const KvmWatchTarget& target)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("安装内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(kActionName);
        }
        if (target.access == 0UL ||
            (target.access &
                ~(KSWORD_ARK_HVM_EPT_ACCESS_READ |
                  KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                  KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) != 0UL)
        {
            KvmWatchResult watch;
            watch.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：至少要选一种访问类型。"))
                .arg(kActionName);
            return watch;
        }
        unsigned long long physicalAddress = target.address;
        if (target.virtualAddress)
        {
            // Translate once and fix it.
            //
            // This watch is bound to the physical page resolved at this exact moment; if the guest remaps the same VA
            // elsewhere later, the watch will not follow. This is not an oversight: tracking remapping requires monitoring
            // the guest page tables themselves, which is a mechanism of a different order of magnitude. Here, we can only
            // record the binding time and result faithfully, allowing the UI to later detect and report discrepancies.
            const KvmMemoryResult kTranslated = translate(0, target.address);
            if (!kTranslated.ok || kTranslated.physicalAddress == 0)
            {
                KvmWatchResult watch;
                watch.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：这个内核虚拟地址当前翻译不出物理页（%2）。"))
                    .arg(kActionName)
                    .arg(kTranslated.message);
                return watch;
            }
            physicalAddress = kTranslated.physicalAddress;
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
        request.requestedAccess = target.access;
        request.addressKind = target.virtualAddress
            ? KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
            : KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL;
        // The actual monitored unit is always a full page; the requested address and length are recorded separately and do not participate in alignment.
        request.physicalPage = physicalAddress & ~0xFFFULL;
        request.requestedAddress = target.address;
        request.requestedLength = target.length;
        const auto kResult = client.controlHvmEptWatch(request);
        return toWatchResult(kResult, kActionName);
    }

    KvmWatchResult rearmWatch(const unsigned long watchId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("重新武装内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_REARM;
        request.watchId = watchId;
        const auto kResult = client.controlHvmEptWatch(request);
        return toWatchResult(kResult, kActionName);
    }

    KvmWatchResult removeWatch(const unsigned long watchId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("移除内存监视"));
        if (!isWriteAccessEnabled())
        {
            return denyWatchWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        ksword::ark::DriverClient::HvmEptWatchRequest request;
        request.operation = KSWORD_ARK_HVM_EPT_RULE_REMOVE;
        request.watchId = watchId;
        const auto kResult = client.controlHvmEptWatch(request);
        return toWatchResult(kResult, kActionName);
    }

    KvmWatchAttribution attributeKernelAddress(const unsigned long long address)
    {
        KvmWatchAttribution attribution;
        static const auto kQuery =
            reinterpret_cast<NtQuerySystemInformationFunction>(
                QLibrary::resolve(
                    QStringLiteral("ntdll"),
                    "NtQuerySystemInformation"));

        if (kQuery == nullptr ||
            address == 0)
        {
            // Failure to parse is a conclusion, not a failure: the caller uses this to display 'Unknown Executable
            // Region' and provide an entry point for opening memory or disassembly, rather than just writing 'Unknown'.
            return attribution;
        }
        unsigned long needed = 0UL;
        // Query length first. Since the module table can change, request extra buffer and retry once rather than looping
        // until success; on a system where drivers may load every second, such a loop has no termination guarantee.
        (void)kQuery(kSystemModuleInformationClass, nullptr, 0UL, &needed);
        if (needed == 0UL)
        {
            return attribution;
        }
        std::vector<unsigned char> buffer;
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            buffer.assign(needed + 0x4000U, 0U);
            unsigned long written = 0UL;
            const long kStatus = kQuery(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<unsigned long>(buffer.size()),
                &written);
            if (kStatus >= 0)
            {
                break;
            }
            if (attempt == 1)
            {
                return attribution;
            }
            needed = written != 0UL ? written : needed * 2U;
        }
        const auto* const kList =
            reinterpret_cast<const SystemModuleList*>(buffer.data());
        const unsigned long kCount = kList->count;
        const size_t kCapacity =
            (buffer.size() - sizeof(unsigned long)) / sizeof(SystemModuleRow);
        const unsigned long kBounded = kCount <= kCapacity
            ? kCount
            : static_cast<unsigned long>(kCapacity);
        for (unsigned long index = 0; index < kBounded; ++index)
        {
            const SystemModuleRow& row = kList->rows[index];
            const auto kBase =
                reinterpret_cast<unsigned long long>(row.imageBase);
            if (row.imageSize == 0UL ||
                address < kBase ||
                address >= kBase + row.imageSize)
            {
                continue;
            }
            attribution.resolved = true;
            attribution.moduleBase = kBase;
            attribution.moduleSize = row.imageSize;
            attribution.relativeAddress = address - kBase;
            // fullPathName is an ANSI NT path guaranteed to be null-terminated;
            // fileNameOffset points to the filename portion within it.
            const auto* const kPath =
                reinterpret_cast<const char*>(row.fullPathName);
            const size_t kLimit = sizeof(row.fullPathName);
            size_t length = 0;
            while (length < kLimit && kPath[length] != '\0')
            {
                ++length;
            }
            attribution.modulePath = QString::fromLatin1(
                kPath, static_cast<int>(length));
            attribution.moduleName = row.fileNameOffset < length
                ? QString::fromLatin1(
                    kPath + row.fileNameOffset,
                    static_cast<int>(length - row.fileNameOffset))
                : attribution.modulePath;
            /*
             * Go one level deeper: find the nearest exported symbol preceding this RVA.
             *
             * If not found, leave it empty; the caller displays `module.sys+0xRVA`. An incorrect function
             * name is harder to correct than no name, as it misleads users into reading unrelated code.
             */
            {
                const ExportTable& table = cachedExportTable(attribution.modulePath);
                if (table.valid &&
                    attribution.relativeAddress <= 0xFFFFFFFFULL)
                {
                    const quint32 kRva =
                        static_cast<quint32>(attribution.relativeAddress);
                    // The first position greater than rva; the element immediately preceding it is the nearest predecessor.
                    const auto kUpper = std::upper_bound(
                        table.entries.cbegin(), table.entries.cend(), kRva,
                        [](const quint32 value, const QPair<quint32, QString>& entry) {
                            return value < entry.first;
                        });
                    if (kUpper != table.entries.cbegin())
                    {
                        const auto& entry = *(kUpper - 1);
                        attribution.symbolName = entry.second;
                        attribution.symbolOffset = kRva - entry.first;
                    }
                }
            }
            break;
        }
        return attribution;
    }

    QString toWin32ModulePath(const QString& ntPath)
    {
        return toWin32Path(ntPath);
    }

    KvmProcessAttribution attributeProcessByCr3(
        const unsigned long long directoryBase)
    {
        KvmProcessAttribution attribution;
        if (directoryBase == 0ULL)
        {
            // No CR3 to attribute. This differs from 'unattributable': the former means not queried, the latter means queried but failed.
            return attribution;
        }

        ksword::ark::DriverClient client;
        const auto kResult = client.resolveHvmDirectoryBase(directoryBase);
        attribution.scannedProcesses = kResult.response.resolvedScannedProcesses;
        if (!kResult.io.ok)
        {
            // IOCTL itself failed: driver not present, handle could not be opened, or protocol version mismatch.
            attribution.kind = KvmProcessAttributionKind::kFailed;
            return attribution;
        }
        if (kResult.response.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK &&
            kResult.response.resolvedProcessId != 0UL)
        {
            attribution.kind = KvmProcessAttributionKind::kResolved;
            attribution.processId = kResult.response.resolvedProcessId;
            attribution.imageName = processImageNameForPid(
                kResult.response.resolvedProcessId);
            return attribution;
        }
        if (kResult.response.status ==
            KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND)
        {
            /*
             * Scanned but no match found.
             *
             * Here, **must** check the scan count rather than just the status code: if nothing was scanned,
             * the driver returns PROCESS_LOOKUP_FAILED, but an implementation that "scanned 0 items so
             * nothing was found" also returns NOT_FOUND. The actions required by these two cases are
             * opposite. Using multiple cores as a single criterion ensures this branch stands on its own.
             */
            attribution.kind = attribution.scannedProcesses != 0UL
                ? KvmProcessAttributionKind::kNotFound
                : KvmProcessAttributionKind::kFailed;
            return attribution;
        }
        attribution.kind = KvmProcessAttributionKind::kFailed;
        return attribution;
    }

    QString describeProcessAttribution(const KvmProcessAttribution& attribution)
    {
        switch (attribution.kind)
        {
        case KvmProcessAttributionKind::kResolved:
            return attribution.imageName.isEmpty()
                ? ks::i18n::sourceText(
                      QStringLiteral("PID %1（由当前进程快照解析，不是命中那一刻的事实）"))
                      .arg(attribution.processId)
                : ks::i18n::sourceText(
                      QStringLiteral("%1 (PID %2)（由当前进程快照解析，不是命中那一刻的事实）"))
                      .arg(attribution.imageName)
                      .arg(attribution.processId);
        case KvmProcessAttributionKind::kNotFound:
            return ks::i18n::sourceText(
                QStringLiteral("扫过 %1 个进程都没有这个地址空间——它多半已经退出了"))
                .arg(attribution.scannedProcesses);
        case KvmProcessAttributionKind::kFailed:
            return ks::i18n::sourceText(
                QStringLiteral("这次归因没跑起来，一个进程都没问成"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("命中现场没有记下地址空间"));
    }

    QString describeWatchState(const unsigned long state)
    {
        switch (state)
        {
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED:
            return ks::i18n::sourceText(QStringLiteral("监视中"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED:
            return ks::i18n::sourceText(QStringLiteral("正在处理命中"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED:
            return ks::i18n::sourceText(QStringLiteral("已命中并解除"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED:
            return ks::i18n::sourceText(QStringLiteral("已失效，需重新武装"));
        case KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED:
            return ks::i18n::sourceText(QStringLiteral("安装失败"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未武装"));
    }

    QString describeWatchAccess(const unsigned long access)
    {
        QStringList parts;
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("读"));
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("写"));
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL)
        {
            parts << ks::i18n::sourceText(QStringLiteral("执行"));
        }
        if (parts.isEmpty())
        {
            return ks::i18n::sourceText(QStringLiteral("无"));
        }
        return parts.join(ks::i18n::sourceText(QStringLiteral(" + ")));
    }

    QString describeWatchConflict(
        const unsigned long ownerKind,
        const unsigned long ownerId)
    {
        switch (ownerKind)
        {
        case KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被 EPT 分离视图 #%1 占着")).arg(ownerId);
        case KSWORD_ARK_HVM_WATCH_CONFLICT_RULE:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被 EPT 规则 #%1 占着")).arg(ownerId);
        case KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH:
            return ks::i18n::sourceText(
                QStringLiteral("这一页已经被内存监视 #%1 占着")).arg(ownerId);
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("这一页已经被别的 EPT 机制占着"));
    }
}
