#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>
#include "../ui/VisibleTableWidget.h"

#include "KernelCleanImageBaseline.h"
// I-02 / I-03: The disk baseline for Inline Hooks uses the unique PE normalization core in shared/evidence.
#include "../../../shared/evidence/PeImageMap.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QComboBox>
#include <QColor>
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QIODevice>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QVariant>
#include <QStringList>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <functional>
#include <limits>
#include <thread>
#include <utility>
#include <vector>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString kernelHookButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString kernelHookInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // friendlyKernelHookIoMessage:
    // - Convert the underlying io.message from Hook audit/scan/patch wrappers into human-readable descriptions.
    // - Input messageText: ArkDriverClient::IoResult::message;
    // - Return: Short text suitable for the status bar, details editor, and QMessageBox.
    QString friendlyKernelHookIoMessage(const std::string& messageText)
    {
        const QString kRawText = QString::fromUtf8(messageText.data(), static_cast<int>(messageText.size())).trimmed();
        if (kRawText.isEmpty())
        {
            return kernelText("kernel.hooks.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.hooks.message.communication_failure", QStringLiteral("驱动接口调用失败或当前驱动版本不支持该 Hook 审计入口。"));
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.hooks.message.unsupported", QStringLiteral("当前驱动不支持该 Hook 审计/操作入口。"));
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.hooks.message.capability", QStringLiteral("动态偏移能力不足，Hook 详情暂不可用。"));
        }
        if (kRawText.contains(QStringLiteral("access"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("denied"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.hooks.message.access_denied", QStringLiteral("请求被权限或安全策略拒绝，未修改目标。"));
        }
        return kRawText;
    }

    QString kernelHookHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    QString kernelHookSelectionStyle()
    {
        return QString();
    }

    QString kernelHookStatusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString kernelHookSafeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString kernelHookSafeText(const QString& valueText)
    {
        return kernelHookSafeText(valueText, kernelText("kernel.hooks.placeholder.empty", QStringLiteral("<空>")));
    }

    QString kernelHookFormatAddress(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar('0'))
            .toUpper();
    }

    QString kernelHookFormatNtStatus(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(statusValue)), 8, 16, QChar('0'))
            .toUpper();
    }

    QString kernelHookBytesToText(const std::vector<std::uint8_t>& bytes, const std::uint32_t byteCount)
    {
        // Purpose: Convert function header bytes returned by R0 into copyable and comparable hexadecimal text.
        // Returns: Text in the format "48 8B ..."; returns a placeholder if no bytes are present.
        QStringList byteTextList;
        const std::size_t kCount = std::min<std::size_t>(bytes.size(), static_cast<std::size_t>(byteCount));
        byteTextList.reserve(static_cast<int>(kCount));
        for (std::size_t index = 0U; index < kCount; ++index)
        {
            byteTextList.push_back(QStringLiteral("%1")
                .arg(static_cast<unsigned int>(bytes[index]), 2, 16, QChar('0'))
                .toUpper());
        }
        return byteTextList.isEmpty()
            ? kernelText("kernel.hooks.placeholder.no_bytes", QStringLiteral("<无字节>"))
            : byteTextList.join(' ');
    }

    struct KernelHookLoadedModuleInfo
    {
        // Input: a single kernel module entry from NtQuerySystemInformation(SystemModuleInformation).
        // Processing: Cache load base address, image size, NT path, and filename to enable reverse lookup of disk files from Inline Hook results by base address.
        // Return: The structure only stores data and does not provide member function return values.
        std::uint64_t imageBase = 0;  // imageBase: Kernel module load base address.
        std::uint32_t imageSize = 0;  // imageSize: Kernel module image size.
        QString ntPathText;           // ntPathText: NT-style path returned by R0/SystemModuleInformation.
        QString fileNameText;         // fileNameText: module file name, used as a fallback path for matching.
    };

    struct KernelHookDiskBaselineResult
    {
        // Input: Derived from the Inline Hook line's moduleBase, functionAddress, and currentByteCount.
        // Processing: Record the result of reading baseline bytes from the disk PE at the same RVA in R3 and the comparison status with memory bytes.
        // Return: The structure only stores data and does not provide member function return values.
        bool available = false;              // available: Whether the disk baseline was successfully read.
        bool differsFromMemory = false;      // differsFromMemory: Whether the disk baseline differs from currentBytes in memory.
        // notComparable: PE mapping succeeded, but this RVA span lacks a usable disk reference (due to
        // zero-padding, section gaps, malformed sections, non-normalized images, or PE dynamic relocation sites).
        // This must be separated from other cases where available=false: those indicate 'failed to read', whereas this
        // means 'read successfully, but there was nothing comparable here' — it must never degrade to 'consistent' (I-05).
        bool notComparable = false;
        std::uint32_t byteCount = 0;         // byteCount: The number of bytes actually involved in the comparison.
        std::uint64_t rva = 0;               // rva: RVA of the function entry relative to the module base address.
        QString filePathText;                // filePathText: The actual disk file path opened in R3.
        QString statusText;                  // statusText: Chinese status difference or failure reason.
        std::vector<std::uint8_t> bytes;     // bytes: Normalized bytes read from the disk file at the same RVA.
    };

    struct KernelHookMappedModule
    {
        // Input: Disk module path and the module's actual load base address.
        // Processing: Save the one-time built normalized image for reuse by multiple inline hooks within the same module.
        //       Keep only the image, not the file bytes: the image already contains all valid content; keeping both would double resident memory usage.
        // Return: The structure only stores data and does not provide member function return values.
        ksword::evidence::PeImageMap imageMap;  // imageMap: Image normalized by loadedBase.
        std::uint64_t loadedBase = 0;           // loadedBase: Load base address used at build time.
        bool built = false;                     // built: Whether a build attempt has already been made.
        QString errorText;                      // errorText: Chinese reason for build failure.
    };

    enum class KernelHookDiskReadOutcome
    {
        kOk,             // Normalized available disk bytes
        kNotComparable,  // PE mapping succeeded, but this RVA span is outside the comparable range.
        kFailed,         // Failed to open the file or parse the PE.
    };

    using KernelHookModulePathMap = QHash<qulonglong, KernelHookLoadedModuleInfo>;
    // The cache stores normalized images, not raw file bytes: multiple Inline Hooks for the same module
    // need to be built only once, whereas fetching bytes by RVA must be done from the normalized image.
    using KernelHookDiskFileCache = QHash<QString, KernelHookMappedModule>;

    struct KernelHookSystemModuleEntry
    {
        // Input: Layout aligned to Windows SystemModuleInformation's RTL_PROCESS_MODULE_INFORMATION.
        // Processing: This structure is used only for R3 parsing of kernel module snapshots and does not modify system state.
        // Returns: None; struct has no member function return value.
        void* section;
        void* mappedBase;
        void* imageBase;
        unsigned long imageSize;
        unsigned long flags;
        unsigned short loadOrderIndex;
        unsigned short initOrderIndex;
        unsigned short loadCount;
        unsigned short offsetToFileName;
        unsigned char fullPathName[256];
    };

    struct KernelHookSystemModuleInformation
    {
        // Input: Output buffer header for NtQuerySystemInformation(SystemModuleInformation).
        // Handling: The variable-length module array follows numberOfModules; the caller is responsible for boundary checks.
        // Returns: None; struct has no member function return value.
        unsigned long numberOfModules;
        KernelHookSystemModuleEntry modules[1];
    };

    QString kernelHookBoundedAnsiPathToText(const unsigned char* textBuffer, const std::size_t maxBytes)
    {
        // Input: Fixed-length ANSI path buffer from SystemModuleInformation.
        // Processing: Search for NUL within maxBytes to avoid out-of-bounds strlen on non-terminated kernel paths.
        // Returns: the QString decoded as local 8-bit; returns an empty string if the input is null or has length 0.
        if (textBuffer == nullptr || maxBytes == 0U)
        {
            return QString();
        }

        std::size_t textBytes = 0U;
        while (textBytes < maxBytes && textBuffer[textBytes] != '\0')
        {
            ++textBytes;
        }
        return QString::fromLocal8Bit(reinterpret_cast<const char*>(textBuffer), static_cast<int>(textBytes));
    }

    QString kernelHookWindowsDirectoryPath()
    {
        // Input: None; reads the current system Windows directory.
        // Note: prefer calling GetWindowsDirectoryW, with fallback to the SystemRoot environment variable on failure.
        // Returns: Normalized Windows directory; returns C:\Windows if it still fails.
        wchar_t windowsPathBuffer[MAX_PATH] = {};
        const UINT kCopiedChars = ::GetWindowsDirectoryW(windowsPathBuffer, MAX_PATH);
        if (kCopiedChars > 0U && kCopiedChars < MAX_PATH)
        {
            return QDir::toNativeSeparators(QString::fromWCharArray(windowsPathBuffer));
        }

        const QString kEnvPath = qEnvironmentVariable("SystemRoot");
        return kEnvPath.isEmpty()
            ? QStringLiteral("C:\\Windows")
            : QDir::toNativeSeparators(kEnvPath);
    }

    QString kernelHookSystemDrivePrefix()
    {
        // Input: none; depends on the drive letter of the Windows directory.
        // Processing: Extract the drive letter from paths like C:\Windows to resolve \Windows... kernel paths.
        // Returns: drive letter in the format C:; conservatively returns C: if unable to determine.
        const QString kWindowsPath = kernelHookWindowsDirectoryPath();
        if (kWindowsPath.size() >= 2 && kWindowsPath.at(1) == QLatin1Char(':'))
        {
            return kWindowsPath.left(2);
        }
        return QStringLiteral("C:");
    }

    QString kernelHookMapNtDevicePathToDosPath(const QString& ntPathText)
    {
        // Input: NT path in the format \Device\HarddiskVolumeX\...
        // Processing: enumerate QueryDosDeviceW mappings for A: to Z:, and replace the matched prefix with the drive letter path.
        // Returns: a Win32 path suitable for QFile; returns an empty string if mapping fails.
        const QString kNormalizedNtPath = QDir::toNativeSeparators(ntPathText.trimmed());
        if (!kNormalizedNtPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            return QString();
        }

        for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
        {
            const QString kDriveName = QStringLiteral("%1:").arg(QChar(driveLetter));
            wchar_t deviceNameBuffer[1024] = {};
            const DWORD kCopiedChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(kDriveName.utf16()),
                deviceNameBuffer,
                static_cast<DWORD>(sizeof(deviceNameBuffer) / sizeof(deviceNameBuffer[0])));
            if (kCopiedChars == 0U)
            {
                continue;
            }

            const QString kDeviceName = QDir::toNativeSeparators(QString::fromWCharArray(deviceNameBuffer));
            if (kDeviceName.isEmpty() || !kNormalizedNtPath.startsWith(kDeviceName, Qt::CaseInsensitive))
            {
                continue;
            }

            const QString kSuffixText = kNormalizedNtPath.mid(kDeviceName.size());
            return QDir::toNativeSeparators(kDriveName + kSuffixText);
        }

        return QString();
    }

    QString kernelHookNormalizeKernelModulePath(const QString& rawPathText)
    {
        // Input: R0/SystemModuleInformation may return NT, SystemRoot, or Win32 module paths.
        // Processing: Convert common kernel paths to R3-accessible Win32 file paths while preserving existing drive letter paths.
        // Returns: A local path that can be attempted to open; returns an empty string if conversion fails.
        QString pathText = QDir::toNativeSeparators(rawPathText.trimmed());
        if (pathText.isEmpty() || pathText == QStringLiteral("<未解析>"))
        {
            return QString();
        }

        if (pathText.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
        {
            pathText = pathText.mid(4);
        }
        if (pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = kernelHookWindowsDirectoryPath() + pathText.mid(QStringLiteral("\\SystemRoot").size());
        }
        else if (pathText.startsWith(QStringLiteral("SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = kernelHookWindowsDirectoryPath() + QStringLiteral("\\") + pathText.mid(QStringLiteral("SystemRoot\\").size());
        }
        else if (pathText.startsWith(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive))
        {
            pathText = kernelHookSystemDrivePrefix() + pathText;
        }
        else if (pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            pathText = kernelHookMapNtDevicePathToDosPath(pathText);
        }

        if (pathText.size() >= 2 && pathText.at(1) == QLatin1Char(':'))
        {
            return QDir::toNativeSeparators(QFileInfo(pathText).absoluteFilePath());
        }
        return QString();
    }

    KernelHookModulePathMap kernelHookQueryLoadedModulePathMap()
    {
        // Input: none. Call: ntdll!NtQuerySystemInformation(SystemModuleInformation) for the current system.
        // Processing: Read the snapshot of loaded kernel modules and map module load base addresses to NT paths, file names, and image sizes.
        // Returns: A module path table keyed by imageBase; on query failure, returns an empty table, and the caller continues to observe the baseline in R0.
        using NtQuerySystemInformationFn = long (NTAPI*)(unsigned long, void*, unsigned long, unsigned long*);
        constexpr unsigned long kSystemModuleInformationClass = 11UL;
        constexpr long kStatusInfoLengthMismatch = static_cast<long>(0xC0000004L);

        KernelHookModulePathMap modulePathMap;
        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            return modulePathMap;
        }

        const auto kQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            ::GetProcAddress(ntdllModule, "NtQuerySystemInformation"));
        if (kQuerySystemInformation == nullptr)
        {
            return modulePathMap;
        }

        unsigned long requiredBytes = 0UL;
        long status = kQuerySystemInformation(kSystemModuleInformationClass, nullptr, 0UL, &requiredBytes);
        if (requiredBytes == 0UL)
        {
            requiredBytes = 1024UL * 1024UL;
        }

        std::vector<std::uint8_t> snapshotBuffer(static_cast<std::size_t>(requiredBytes) + (64U * 1024U));
        for (int attemptIndex = 0; attemptIndex < 4; ++attemptIndex)
        {
            status = kQuerySystemInformation(
                kSystemModuleInformationClass,
                snapshotBuffer.data(),
                static_cast<unsigned long>(snapshotBuffer.size()),
                &requiredBytes);
            if (status == 0)
            {
                break;
            }

            if (requiredBytes > snapshotBuffer.size())
            {
                snapshotBuffer.resize(static_cast<std::size_t>(requiredBytes) + (64U * 1024U));
                continue;
            }
            if (status == kStatusInfoLengthMismatch)
            {
                snapshotBuffer.resize(snapshotBuffer.size() * 2U);
                continue;
            }
            return modulePathMap;
        }
        if (status != 0 || snapshotBuffer.size() < offsetof(KernelHookSystemModuleInformation, modules))
        {
            return modulePathMap;
        }

        const auto* moduleInfo = reinterpret_cast<const KernelHookSystemModuleInformation*>(snapshotBuffer.data());
        const std::size_t kModuleArrayOffset = offsetof(KernelHookSystemModuleInformation, modules);
        const std::size_t kAvailableModuleBytes = snapshotBuffer.size() - kModuleArrayOffset;
        const std::size_t kMaxModuleCount = kAvailableModuleBytes / sizeof(KernelHookSystemModuleEntry);
        const std::size_t kModuleCount = std::min<std::size_t>(
            static_cast<std::size_t>(moduleInfo->numberOfModules),
            kMaxModuleCount);

        modulePathMap.reserve(static_cast<int>(kModuleCount));
        for (std::size_t moduleIndex = 0U; moduleIndex < kModuleCount; ++moduleIndex)
        {
            const KernelHookSystemModuleEntry& moduleEntry = moduleInfo->modules[moduleIndex];
            const auto kImageBase = static_cast<qulonglong>(
                reinterpret_cast<std::uintptr_t>(moduleEntry.imageBase));
            if (kImageBase == 0ULL)
            {
                continue;
            }

            const QString kNtPathText = QDir::toNativeSeparators(
                kernelHookBoundedAnsiPathToText(moduleEntry.fullPathName, sizeof(moduleEntry.fullPathName)));
            const std::size_t kFileNameOffset = moduleEntry.offsetToFileName < sizeof(moduleEntry.fullPathName)
                ? static_cast<std::size_t>(moduleEntry.offsetToFileName)
                : 0U;
            const QString kFileNameText = kernelHookBoundedAnsiPathToText(
                moduleEntry.fullPathName + kFileNameOffset,
                sizeof(moduleEntry.fullPathName) - kFileNameOffset);

            KernelHookLoadedModuleInfo loadedModule{};
            loadedModule.imageBase = static_cast<std::uint64_t>(kImageBase);
            loadedModule.imageSize = static_cast<std::uint32_t>(moduleEntry.imageSize);
            loadedModule.ntPathText = kNtPathText;
            loadedModule.fileNameText = kFileNameText;
            modulePathMap.insert(kImageBase, loadedModule);
        }

        return modulePathMap;
    }

    QString kernelHookResolveModuleForAddress(
        const KernelHookModulePathMap& modulePathMap,
        const std::uint64_t address)
    {
        if (address == 0U)
        {
            return QString();
        }
        for (auto iterator = modulePathMap.constBegin(); iterator != modulePathMap.constEnd(); ++iterator)
        {
            const KernelHookLoadedModuleInfo& module = iterator.value();
            const std::uint64_t kBase = module.imageBase;
            const std::uint64_t kSize = module.imageSize;
            if (kBase != 0U && kSize != 0U && address >= kBase && address - kBase < kSize)
            {
                return module.fileNameText.trimmed().isEmpty()
                    ? module.ntPathText
                    : module.fileNameText;
            }
        }
        return QString();
    }

    // I-02 / I-03: The PE mapping for the disk baseline goes through the unique normalization core in shared/evidence.
    //
    // Originally, this section had its own PE parsing logic (kernelHookReadPodAtOffset /
    // kernelHookRvaToFileOffset / old kernelHookReadPeBytesAtRva), which reads raw bytes,
    // **No relocations are applied**, so differences are falsely reported at any location modified by relocation. It is also the
    // third PE parser in this repository, violating the I module's hard constraint that no second PE parser may be introduced.
    // The entire block has been removed and replaced with a call to buildPeImageMap + readNormalizedBytes.

    // Build a normalized image of a module based on its actual loaded base address.
    // Input: Disk PE path and module actual load base address.
    // Handling: After reading the entire file, pass it to the unique PE normalization core, which applies .relocs based on the actual base
    //       address, parses DVRT, and excludes zero-padding, section gaps, malformed sections, and dynamic relocation sites from the comparable range.
    // Return: No return value; on failure, only write to errorText, leaving imageMap in an invalid state.
    void kernelHookBuildNormalizedImage(
        const QString& filePath,
        const std::uint64_t loadedBase,
        KernelHookMappedModule* moduleOut)
    {
        if (moduleOut == nullptr)
        {
            return;
        }
        moduleOut->loadedBase = loadedBase;
        moduleOut->built = true;
        moduleOut->errorText.clear();
        moduleOut->imageMap = ksword::evidence::PeImageMap{};

        QFile fileObject(filePath);
        if (!fileObject.open(QIODevice::ReadOnly))
        {
            moduleOut->errorText = kernelText("kernel.hooks.pe.error.open_module", QStringLiteral("打开磁盘模块文件失败：%1。"))
                .arg(fileObject.errorString());
            return;
        }

        const QByteArray kFileBytes = fileObject.readAll();
        if (kFileBytes.isEmpty())
        {
            moduleOut->errorText = kernelText("kernel.hooks.pe.error.module_empty", QStringLiteral("磁盘模块文件为空或读取失败。"));
            return;
        }

        moduleOut->imageMap = ksword::evidence::buildPeImageMap(
            reinterpret_cast<const std::uint8_t*>(kFileBytes.constData()),
            static_cast<std::size_t>(kFileBytes.size()),
            loadedBase);
        if (!moduleOut->imageMap.valid())
        {
            // The status name is a stable English enum name, not a user-facing sentence; it is sufficient
            // for troubleshooting and avoids losing 'exactly which step failed' due to translation gaps.
            moduleOut->errorText = kernelText("kernel.hooks.pe.error.map_failed", QStringLiteral("PE 映像映射失败：%1。"))
                .arg(QString::fromLatin1(ksword::evidence::peParseStatusName(moduleOut->imageMap.status)));
        }
    }

    // Explain why this segment has no disk reference.
    // Input: Normalized image, target RVA, and read length.
    // Handling: Search downwards from the most explanatory cause; image-level causes take precedence over single-point causes.
    // Returns: Chinese reason text.
    QString kernelHookDescribeNotComparable(
        const ksword::evidence::PeImageMap& imageMap,
        const std::uint32_t rva,
        const std::uint32_t bytesToRead)
    {
        if (imageMap.relocation.imageNotNormalized)
        {
            return kernelText("kernel.hooks.pe.not_comparable.relocation",
                QStringLiteral("模块基址已变化但重定位无法归一化（%1），整份映像都没有可用的磁盘参考。"))
                .arg(QString::fromLatin1(
                    ksword::evidence::relocationStatusName(imageMap.relocation.status)));
        }
        if (imageMap.dynamicRelocation.extentUnknown)
        {
            return kernelText("kernel.hooks.pe.not_comparable.dvrt_extent",
                QStringLiteral("PE 动态重定位表无法界定影响范围（%1），整份映像都没有可用的磁盘参考。"))
                .arg(QString::fromLatin1(
                    ksword::evidence::dvrtStatusName(imageMap.dynamicRelocation.status)));
        }

        ksword::evidence::RvaRange span;
        span.rva = rva;
        span.length = bytesToRead;
        const std::vector<ksword::evidence::RvaRange> kDynamicRanges =
            imageMap.dynamicRelocation.affectedRanges();
        for (const ksword::evidence::RvaRange& range : kDynamicRanges)
        {
            if (range.overlaps(span))
            {
                return kernelText("kernel.hooks.pe.not_comparable.dvrt_site",
                    QStringLiteral("该范围含 PE 动态重定位位点（import optimization / retpoline），由加载器在启动期写入，磁盘文件里不存在改写后的字节。"));
            }
        }

        const ksword::evidence::RvaTranslation kTranslation =
            ksword::evidence::translateRva(imageMap, rva);
        switch (kTranslation.kind)
        {
        case ksword::evidence::RvaKind::kOutsideImage:
            return kernelText("kernel.hooks.pe.not_comparable.outside_image", QStringLiteral("目标 RVA 超出映像范围。"));
        case ksword::evidence::RvaKind::kSectionZeroFill:
            return kernelText("kernel.hooks.pe.not_comparable.zero_fill", QStringLiteral("目标落在区段零填充区：映像里是 0，磁盘文件里没有对应字节。"));
        case ksword::evidence::RvaKind::kSectionGap:
            return kernelText("kernel.hooks.pe.not_comparable.section_gap", QStringLiteral("目标落在区段对齐间隙：不属于任何区段，磁盘文件里没有对应字节。"));
        case ksword::evidence::RvaKind::kNotComparable:
            return kernelText("kernel.hooks.pe.not_comparable.bad_section", QStringLiteral("目标所在区段头畸形，已被标记为不可比较。"));
        case ksword::evidence::RvaKind::kHeader:
        case ksword::evidence::RvaKind::kSectionRawBacked:
            break;
        }
        return kernelText("kernel.hooks.pe.not_comparable.span", QStringLiteral("读取跨度未完整落在可比较范围内，可能跨越了区段或零填充边界。"));
    }

    KernelHookDiskReadOutcome kernelHookReadPeBytesAtRva(
        const QString& filePath,
        const std::uint64_t loadedBase,
        const std::uint32_t rva,
        const std::uint32_t bytesToRead,
        KernelHookDiskFileCache* fileCache,
        std::vector<std::uint8_t>* bytesOut,
        QString* errorTextOut)
    {
        // Input: Disk PE path, actual module load base address, target RVA, and read length.
        // Processing: Build (or reuse the cached) normalized image, then take bytes only after the entire range falls within a comparable scope.
        // Return: Ok with bytesOut filled; NotComparable indicates no comparable disk bytes existed at that location.
        //       Failed indicates an open or parse failure. The latter two cases will populate the Chinese reason.
        auto fail = [errorTextOut](const QString& messageText) -> KernelHookDiskReadOutcome
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = messageText;
                }
                return KernelHookDiskReadOutcome::kFailed;
            };

        if (bytesOut == nullptr)
        {
            return fail(kernelText("kernel.hooks.pe.error.disk_bytes_output", QStringLiteral("内部错误：磁盘字节输出为空。")));
        }
        bytesOut->clear();

        KernelHookMappedModule localModule;
        const KernelHookMappedModule* mappedModule = nullptr;
        if (fileCache != nullptr)
        {
            // operator[] performs in-place default construction when the key is missing, so the image does not need to be copied once.
            KernelHookMappedModule& slot = (*fileCache)[filePath];
            // Within a single scan, there is only one load base address for a given path; if the base address changes, reconstruction is required.
            // Otherwise, comparing bytes normalized using the previous base address will cause false positives at every relocation point.
            if (!slot.built || slot.loadedBase != loadedBase)
            {
                kernelHookBuildNormalizedImage(filePath, loadedBase, &slot);
            }
            mappedModule = &slot;
        }
        else
        {
            kernelHookBuildNormalizedImage(filePath, loadedBase, &localModule);
            mappedModule = &localModule;
        }

        if (!mappedModule->errorText.isEmpty())
        {
            return fail(mappedModule->errorText);
        }
        if (!mappedModule->imageMap.valid())
        {
            return fail(kernelText("kernel.hooks.pe.error.map_unavailable", QStringLiteral("PE 映像映射不可用。")));
        }

        if (!ksword::evidence::readNormalizedBytes(
                mappedModule->imageMap, rva, bytesToRead, *bytesOut))
        {
            // This is **not** "no difference." When falling into zero-filled regions, segment gaps, malformed segments, non-normalized
            // images, or dynamic relocation points, there are no corresponding bytes on the disk. The old implementation directly
            // compared non-normalized raw bytes at these locations (causing false positives) or threw an error indistinguishable from
            // a real read failure: "raw data insufficient." Now they are separated: this is "uncomparable."
            bytesOut->clear();
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelHookDescribeNotComparable(
                    mappedModule->imageMap, rva, bytesToRead);
            }
            return KernelHookDiskReadOutcome::kNotComparable;
        }
        return KernelHookDiskReadOutcome::kOk;
    }

    KernelHookDiskBaselineResult kernelHookReadDiskBaselineForInlineHook(
        const KernelInlineHookEntry& row,
        const KernelHookModulePathMap& modulePathMap,
        KernelHookDiskFileCache* fileCache)
    {
        // Input: Inline Hook UI row mapped to current system module path.
        // Processing: Calculate RVA using functionAddress-moduleBase, read bytes at the same RVA from the disk module file, and compare them with memory bytes.
        // Returns: disk baseline result containing availability, disk bytes, and a brief difference status.
        KernelHookDiskBaselineResult baselineResult{};
        baselineResult.statusText = kernelText("kernel.hooks.baseline.not_comparable", QStringLiteral("不可比较"));
        const std::size_t kAvailableCurrentBytes = std::min<std::size_t>(
            row.currentBytes.size(),
            static_cast<std::size_t>(row.currentByteCount));
        baselineResult.byteCount = static_cast<std::uint32_t>(std::min<std::size_t>(
            kAvailableCurrentBytes,
            static_cast<std::size_t>(KSWORD_ARK_KERNEL_HOOK_BYTES)));

        if (baselineResult.byteCount == 0U)
        {
            return baselineResult;
        }
        if (row.moduleBase == 0U || row.functionAddress < row.moduleBase)
        {
            return baselineResult;
        }

        const std::uint64_t kRva64 = row.functionAddress - row.moduleBase;
        baselineResult.rva = kRva64;
        if (kRva64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return baselineResult;
        }

        const auto kModuleIterator = modulePathMap.constFind(static_cast<qulonglong>(row.moduleBase));
        if (kModuleIterator == modulePathMap.constEnd())
        {
            return baselineResult;
        }

        baselineResult.filePathText = kernelHookNormalizeKernelModulePath(kModuleIterator->ntPathText);
        if (baselineResult.filePathText.isEmpty())
        {
            return baselineResult;
        }
        if (!QFileInfo::exists(baselineResult.filePathText))
        {
            return baselineResult;
        }

        QString readErrorText;
        // Build the image using the actual load base address: relocations are thus correctly normalized, and the disk baseline and
        // memory bytes are on the same base address scale, preventing false positives for locations modified by relocations (I-03).
        const KernelHookDiskReadOutcome kReadOutcome = kernelHookReadPeBytesAtRva(
            baselineResult.filePathText,
            row.moduleBase,
            static_cast<std::uint32_t>(kRva64),
            baselineResult.byteCount,
            fileCache,
            &baselineResult.bytes,
            &readErrorText);
        if (kReadOutcome == KernelHookDiskReadOutcome::kNotComparable)
        {
            // I-05: If it cannot be read, it is missing. Here, we must never fall back to 'compare against a block of zeros' or 'treat
            // as consistent'; that was the error in the old implementation, which would report bytes written by the loader as Hooks.
            baselineResult.notComparable = true;
            return baselineResult;
        }
        if (kReadOutcome != KernelHookDiskReadOutcome::kOk)
        {
            return baselineResult;
        }

        baselineResult.available = true;
        baselineResult.differsFromMemory = !std::equal(
            baselineResult.bytes.begin(),
            baselineResult.bytes.end(),
            row.currentBytes.begin());
        baselineResult.statusText = baselineResult.differsFromMemory
            ? kernelText("kernel.hooks.baseline.different", QStringLiteral("不同"))
            : kernelText("kernel.hooks.baseline.same", QStringLiteral("一致"));
        return baselineResult;
    }

    void kernelHookCopyTextToClipboard(const QString& text)
    {
        if (QApplication::clipboard() != nullptr)
        {
            QApplication::clipboard()->setText(text);
        }
    }

    enum class ShadowSsdtColumn : int
    {
        kIndex = 0,
        kServiceName,
        kStubAddress,
        kServiceAddress,
        kSlotAddress,
        kModule,
        kCount
    };

    enum class InlineHookColumn : int
    {
        kModule = 0,
        kFunction,
        kFunctionAddress,
        kHookType,
        kTargetAddress,
        kTargetModule,
        kStatus,
        kCurrentBytes,
        kDiskBytes,
        kDiskDiff,
        kCount
    };

    enum class IatEatHookColumn : int
    {
        kClass = 0,
        kModule,
        kImportModule,
        kFunction,
        kThunkAddress,
        kCurrentTarget,
        kExpectedTarget,
        kTargetModule,
        kStatus,
        kCount
    };

    enum class TimerDpcColumn : int
    {
        kCpu = 0,
        kBucket,
        kTimer,
        kDueTime,
        kPeriod,
        kType,
        kDpc,
        kRoutine,
        kContext,
        kModule,
        kStatus,
        kCount
    };

    QString kernelHookStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN:
            return kernelText("kernel.hooks.status.clean", QStringLiteral("干净"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS:
            return kernelText("kernel.hooks.status.suspicious", QStringLiteral("可疑外跳"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH:
            return kernelText("kernel.hooks.status.internal_branch", QStringLiteral("模块内跳转"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED:
            return kernelText("kernel.hooks.status.read_failed", QStringLiteral("读取失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED:
            return kernelText("kernel.hooks.status.parse_failed", QStringLiteral("解析失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED:
            return kernelText("kernel.hooks.status.force_required", QStringLiteral("需要强制确认"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED:
            return kernelText("kernel.hooks.status.patched", QStringLiteral("已修复/摘除"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED:
            return kernelText("kernel.hooks.status.patch_failed", QStringLiteral("修复失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN:
        default:
            return kernelText("kernel.hooks.status.unknown", QStringLiteral("未知(%1)")).arg(status);
        }
    }

    QString inlineHookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case KSWORD_ARK_INLINE_HOOK_TYPE_NONE:
            return kernelText("kernel.hooks.type.none", QStringLiteral("无明显补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32:
            return QStringLiteral("JMP rel32");
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8:
            return QStringLiteral("JMP rel8");
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT:
            return QStringLiteral("JMP [RIP+rel32]");
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX:
            return QStringLiteral("MOV RAX; JMP RAX");
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11:
            return QStringLiteral("MOV R11; JMP R11");
        case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH:
            return kernelText("kernel.hooks.type.ret_patch", QStringLiteral("RET 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
            return kernelText("kernel.hooks.type.int3_patch", QStringLiteral("INT3 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_UNKNOWN_PATCH:
            return kernelText("kernel.hooks.type.unknown_patch", QStringLiteral("未知补丁"));
        default:
            return kernelText("kernel.hooks.type.unknown", QStringLiteral("未知(%1)")).arg(hookType);
        }
    }

    std::uint32_t inlineHookPatchLength(const std::uint32_t hookType, const std::uint32_t availableBytes)
    {
        // Purpose: Calculate a conservative patch length for NOP removal to avoid overwriting non-instruction immediate bytes following the jump.
        // Returns: The number of bytes to write as NOPs; 0 indicates the current type is not suitable for automatic handling.
        std::uint32_t desiredBytes = 0U;
        switch (hookType)
        {
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32:
            desiredBytes = 5U;
            break;
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8:
            desiredBytes = 2U;
            break;
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT:
            desiredBytes = 6U;
            break;
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX:
            desiredBytes = 12U;
            break;
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11:
            desiredBytes = 13U;
            break;
        case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH:
        case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
            desiredBytes = 1U;
            break;
        default:
            desiredBytes = 0U;
            break;
        }
        return std::min<std::uint32_t>(desiredBytes, availableBytes);
    }

    QString iatEatClassText(const std::uint32_t hookClass)
    {
        switch (hookClass)
        {
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT:
            return QStringLiteral("IAT");
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT:
            return QStringLiteral("EAT");
        default:
            return kernelText("kernel.hooks.iat.class.unknown", QStringLiteral("未知(%1)")).arg(hookClass);
        }
    }

    QColor statusColor(const std::uint32_t status)
    {
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS ||
            status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED ||
            status == KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED ||
            status == KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED)
        {
            return ksword_theme::errorColor();
        }
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH ||
            status == KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED)
        {
            return ksword_theme::warningColor();
        }
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED ||
            status == KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN)
        {
            return ksword_theme::successColor();
        }
        return ksword_theme::textSecondaryColor();
    }

    void prepareTable(QTableWidget* tableWidget)
    {
        // Purpose: Unify the basic interaction behavior of the three Hook tables.
        // Returns: None; Qt controls are owned by the caller.
        if (tableWidget == nullptr)
        {
            return;
        }
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setAlternatingRowColors(true);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setStyleSheet(kernelHookSelectionStyle());
        tableWidget->setCornerButtonEnabled(false);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setStyleSheet(kernelHookHeaderStyle());
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    }

    QString shadowSsdtColumnHeader(const ShadowSsdtColumn column)
    {
        switch (column)
        {
        case ShadowSsdtColumn::kIndex:
            return kernelText("kernel.ssdt.header.index", QStringLiteral("索引"));
        case ShadowSsdtColumn::kServiceName:
            return kernelText("kernel.ssdt.header.service_name", QStringLiteral("服务名"));
        case ShadowSsdtColumn::kStubAddress:
            return kernelText("kernel.hooks.shadow.header.stub_address", QStringLiteral("Stub地址"));
        case ShadowSsdtColumn::kServiceAddress:
            return kernelText("kernel.hooks.shadow.header.service_routine", QStringLiteral("服务例程"));
        case ShadowSsdtColumn::kSlotAddress:
            return kernelText(
                "kernel.hooks.shadow.header.slot_address",
                QStringLiteral("槽位地址"));
        case ShadowSsdtColumn::kModule:
            return kernelText("kernel.ssdt.header.module", QStringLiteral("模块"));
        default:
            return kernelText("kernel.hooks.header.unknown", QStringLiteral("未知列"));
        }
    }

    QString inlineHookColumnHeader(const InlineHookColumn column)
    {
        switch (column)
        {
        case InlineHookColumn::kModule:
            return kernelText("kernel.hooks.inline.header.module", QStringLiteral("模块"));
        case InlineHookColumn::kFunction:
            return kernelText("kernel.hooks.inline.header.function", QStringLiteral("函数"));
        case InlineHookColumn::kFunctionAddress:
            return kernelText("kernel.hooks.inline.header.function_address", QStringLiteral("函数地址"));
        case InlineHookColumn::kHookType:
            return kernelText("kernel.hooks.inline.header.type", QStringLiteral("类型"));
        case InlineHookColumn::kTargetAddress:
            return kernelText("kernel.hooks.inline.header.target_address", QStringLiteral("目标地址"));
        case InlineHookColumn::kTargetModule:
            return kernelText("kernel.hooks.inline.header.target_module", QStringLiteral("目标模块"));
        case InlineHookColumn::kStatus:
            return kernelText("kernel.hooks.inline.header.status", QStringLiteral("状态"));
        case InlineHookColumn::kCurrentBytes:
            return kernelText("kernel.hooks.inline.header.memory_bytes", QStringLiteral("内存字节"));
        case InlineHookColumn::kDiskBytes:
            return kernelText("kernel.hooks.inline.header.disk_bytes", QStringLiteral("磁盘字节"));
        case InlineHookColumn::kDiskDiff:
            return kernelText("kernel.hooks.inline.header.disk_diff", QStringLiteral("差异状态"));
        default:
            return kernelText("kernel.hooks.header.unknown", QStringLiteral("未知列"));
        }
    }

    QString iatEatColumnHeader(const IatEatHookColumn column)
    {
        switch (column)
        {
        case IatEatHookColumn::kClass:
            return kernelText("kernel.hooks.iat.header.class", QStringLiteral("类别"));
        case IatEatHookColumn::kModule:
            return kernelText("kernel.hooks.iat.header.module", QStringLiteral("模块"));
        case IatEatHookColumn::kImportModule:
            return kernelText("kernel.hooks.iat.header.import_module", QStringLiteral("导入模块"));
        case IatEatHookColumn::kFunction:
            return kernelText("kernel.hooks.iat.header.function_or_ordinal", QStringLiteral("函数/序号"));
        case IatEatHookColumn::kThunkAddress:
            return kernelText("kernel.hooks.iat.header.thunk_eat_item", QStringLiteral("Thunk/EAT项"));
        case IatEatHookColumn::kCurrentTarget:
            return kernelText("kernel.hooks.iat.header.current_target", QStringLiteral("当前目标"));
        case IatEatHookColumn::kExpectedTarget:
            return kernelText("kernel.hooks.iat.header.expected_target", QStringLiteral("期望目标"));
        case IatEatHookColumn::kTargetModule:
            return kernelText("kernel.hooks.iat.header.target_module", QStringLiteral("目标模块"));
        case IatEatHookColumn::kStatus:
            return kernelText("kernel.hooks.iat.header.status", QStringLiteral("状态"));
        default:
            return kernelText("kernel.hooks.header.unknown", QStringLiteral("未知列"));
        }
    }

    QString timerDpcColumnHeader(const TimerDpcColumn column)
    {
        switch (column)
        {
        case TimerDpcColumn::kCpu: return kernelText("kernel.timer_dpc.header.cpu", QStringLiteral("CPU"));
        case TimerDpcColumn::kBucket: return kernelText("kernel.timer_dpc.header.bucket", QStringLiteral("Bucket"));
        case TimerDpcColumn::kTimer: return kernelText("kernel.timer_dpc.header.timer", QStringLiteral("Timer"));
        case TimerDpcColumn::kDueTime: return kernelText("kernel.timer_dpc.header.due_time", QStringLiteral("DueTime"));
        case TimerDpcColumn::kPeriod: return kernelText("kernel.timer_dpc.header.period", QStringLiteral("Period"));
        case TimerDpcColumn::kType: return kernelText("kernel.timer_dpc.header.type", QStringLiteral("类型"));
        case TimerDpcColumn::kDpc: return kernelText("kernel.timer_dpc.header.dpc", QStringLiteral("DPC"));
        case TimerDpcColumn::kRoutine: return kernelText("kernel.timer_dpc.header.routine", QStringLiteral("例程"));
        case TimerDpcColumn::kContext: return kernelText("kernel.timer_dpc.header.context", QStringLiteral("上下文"));
        case TimerDpcColumn::kModule: return kernelText("kernel.timer_dpc.header.module", QStringLiteral("模块"));
        case TimerDpcColumn::kStatus: return kernelText("kernel.timer_dpc.header.status", QStringLiteral("状态"));
        default: return kernelText("kernel.hooks.header.unknown", QStringLiteral("未知列"));
        }
    }

    QString timerDpcTypeText(const std::uint32_t timerType)
    {
        if (timerType == 8U)
        {
            return kernelText("kernel.timer_dpc.type.notification", QStringLiteral("通知定时器(8)"));
        }
        if (timerType == 9U)
        {
            return kernelText("kernel.timer_dpc.type.synchronization", QStringLiteral("同步定时器(9)"));
        }
        return kernelText("kernel.timer_dpc.type.unknown", QStringLiteral("未知(%1)")).arg(timerType);
    }

    QString timerDpcEntryStatusText(const std::uint32_t flags, const QString& moduleName)
    {
        QStringList parts;
        if ((flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_PRESENT) == 0U)
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.no_dpc", QStringLiteral("无DPC")));
        }
        else if ((flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT) == 0U)
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.dpc_unreadable", QStringLiteral("DPC字段不可读")));
        }
        else
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.dpc", QStringLiteral("DPC已解析")));
        }
        if ((flags & KSWORD_ARK_TIMER_DPC_ENTRY_PERIODIC) != 0U)
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.periodic", QStringLiteral("周期")));
        }
        if ((flags & KSWORD_ARK_TIMER_DPC_ENTRY_READ_PARTIAL) != 0U)
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.partial", QStringLiteral("字段部分读取")));
        }
        if (moduleName.trimmed().isEmpty() && (flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT) != 0U)
        {
            parts.push_back(kernelText("kernel.timer_dpc.status.module_unresolved", QStringLiteral("模块未解析")));
        }
        return parts.join(QStringLiteral(" / "));
    }

    QString timerDpcColumnText(const KernelTimerDpcEntry& entry, const TimerDpcColumn column)
    {
        switch (column)
        {
        case TimerDpcColumn::kCpu:
            return QStringLiteral("%1:%2").arg(entry.processorGroup).arg(entry.processorNumber);
        case TimerDpcColumn::kBucket:
            return QString::number(entry.bucketIndex);
        case TimerDpcColumn::kTimer:
            return kernelHookFormatAddress(entry.timerAddress);
        case TimerDpcColumn::kDueTime:
            return QString::number(entry.dueTime);
        case TimerDpcColumn::kPeriod:
            return QString::number(entry.period);
        case TimerDpcColumn::kType:
            return timerDpcTypeText(entry.timerType);
        case TimerDpcColumn::kDpc:
            return entry.dpcAddress == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(entry.dpcAddress);
        case TimerDpcColumn::kRoutine:
            return entry.deferredRoutine == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(entry.deferredRoutine);
        case TimerDpcColumn::kContext:
            return entry.deferredContext == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(entry.deferredContext);
        case TimerDpcColumn::kModule:
            return kernelHookSafeText(entry.moduleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>")));
        case TimerDpcColumn::kStatus:
            return kernelHookSafeText(entry.statusText);
        default:
            return QString();
        }
    }

    QString timerDpcRowAsTsv(const KernelTimerDpcEntry& entry)
    {
        QStringList fields;
        fields.reserve(static_cast<int>(TimerDpcColumn::kCount));
        for (int index = 0; index < static_cast<int>(TimerDpcColumn::kCount); ++index)
        {
            fields.push_back(timerDpcColumnText(entry, static_cast<TimerDpcColumn>(index)));
        }
        return fields.join('\t');
    }

    QString shadowSsdtColumnText(const KernelSsdtEntry& entry, const ShadowSsdtColumn column)
    {
        switch (column)
        {
        case ShadowSsdtColumn::kIndex:
            return entry.indexResolved ? QString::number(entry.serviceIndex) : kernelText("kernel.hooks.placeholder.unknown", QStringLiteral("<未知>"));
        case ShadowSsdtColumn::kServiceName:
            return kernelHookSafeText(entry.serviceNameText);
        case ShadowSsdtColumn::kStubAddress:
            return kernelHookFormatAddress(entry.zwRoutineAddress);
        case ShadowSsdtColumn::kServiceAddress:
            return kernelHookFormatAddress(entry.serviceRoutineAddress);
        case ShadowSsdtColumn::kSlotAddress:
            return kernelHookFormatAddress(entry.tableEntryAddress);
        case ShadowSsdtColumn::kModule:
            return kernelHookSafeText(entry.moduleNameText);
        default:
            return QString();
        }
    }

    QString inlineHookColumnText(const KernelInlineHookEntry& entry, const InlineHookColumn column)
    {
        switch (column)
        {
        case InlineHookColumn::kModule:
            return kernelHookSafeText(entry.moduleNameText);
        case InlineHookColumn::kFunction:
            return kernelHookSafeText(entry.functionNameText);
        case InlineHookColumn::kFunctionAddress:
            return kernelHookFormatAddress(entry.functionAddress);
        case InlineHookColumn::kHookType:
            return entry.hookTypeText;
        case InlineHookColumn::kTargetAddress:
            return kernelHookFormatAddress(entry.targetAddress);
        case InlineHookColumn::kTargetModule:
            return kernelHookSafeText(entry.targetModuleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>")));
        case InlineHookColumn::kStatus:
            return entry.statusText;
        case InlineHookColumn::kCurrentBytes:
            return entry.currentBytesText;
        case InlineHookColumn::kDiskBytes:
            return entry.diskBytesText;
        case InlineHookColumn::kDiskDiff:
            return entry.diskBaselineStatusText;
        default:
            return QString();
        }
    }

    QString iatEatColumnText(const KernelIatEatHookEntry& entry, const IatEatHookColumn column)
    {
        switch (column)
        {
        case IatEatHookColumn::kClass:
            return entry.classText;
        case IatEatHookColumn::kModule:
            return kernelHookSafeText(entry.moduleNameText);
        case IatEatHookColumn::kImportModule:
            return kernelHookSafeText(entry.importModuleNameText, kernelText("kernel.hooks.placeholder.not_applicable", QStringLiteral("<不适用>")));
        case IatEatHookColumn::kFunction:
            return kernelHookSafeText(entry.functionNameText, QStringLiteral("#%1").arg(entry.ordinal));
        case IatEatHookColumn::kThunkAddress:
            return kernelHookFormatAddress(entry.thunkAddress);
        case IatEatHookColumn::kCurrentTarget:
            return kernelHookFormatAddress(entry.currentTarget);
        case IatEatHookColumn::kExpectedTarget:
            return kernelHookFormatAddress(entry.expectedTarget);
        case IatEatHookColumn::kTargetModule:
            return kernelHookSafeText(entry.targetModuleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>")));
        case IatEatHookColumn::kStatus:
            return entry.statusText;
        default:
            return QString();
        }
    }

    QString shadowSsdtRowAsTsv(const KernelSsdtEntry& entry)
    {
        QStringList fields;
        fields.reserve(static_cast<int>(ShadowSsdtColumn::kCount));
        for (int index = 0; index < static_cast<int>(ShadowSsdtColumn::kCount); ++index)
        {
            fields.push_back(shadowSsdtColumnText(entry, static_cast<ShadowSsdtColumn>(index)));
        }
        return fields.join('\t');
    }

    QString inlineHookRowAsTsv(const KernelInlineHookEntry& entry)
    {
        QStringList fields;
        fields.reserve(static_cast<int>(InlineHookColumn::kCount));
        for (int index = 0; index < static_cast<int>(InlineHookColumn::kCount); ++index)
        {
            fields.push_back(inlineHookColumnText(entry, static_cast<InlineHookColumn>(index)));
        }
        return fields.join('\t');
    }

    QString iatEatRowAsTsv(const KernelIatEatHookEntry& entry)
    {
        QStringList fields;
        fields.reserve(static_cast<int>(IatEatHookColumn::kCount));
        for (int index = 0; index < static_cast<int>(IatEatHookColumn::kCount); ++index)
        {
            fields.push_back(iatEatColumnText(entry, static_cast<IatEatHookColumn>(index)));
        }
        return fields.join('\t');
    }

    QString headerAsTsv(const int columnCount, const std::function<QString(int)>& headerResolver)
    {
        // Purpose: Construct a copyable TSV header; different tables provide Chinese column names via headerResolver.
        // Returns: A single-line TSV header.
        QStringList headers;
        headers.reserve(columnCount);
        for (int index = 0; index < columnCount; ++index)
        {
            headers.push_back(headerResolver(index));
        }
        return headers.join('\t');
    }

    template <typename RowType>
    std::vector<std::size_t> selectedSourceIndices(
        const QTableWidget* tableWidget,
        const std::vector<RowType>& rows,
        const int fallbackRow)
    {
        // Purpose: Read the source cache index mapped to the selected rows in the table, supporting Ctrl+multi-selection.
        // Returns: deduplicated source indices; uses fallbackRow if no explicit selection.
        std::vector<std::size_t> result;
        if (tableWidget == nullptr)
        {
            return result;
        }

        const QModelIndexList kSelectedRows = tableWidget->selectionModel() != nullptr
            ? tableWidget->selectionModel()->selectedRows()
            : QModelIndexList();
        for (const QModelIndex& modelIndex : kSelectedRows)
        {
            const QTableWidgetItem* item = tableWidget->item(modelIndex.row(), 0);
            if (item == nullptr)
            {
                continue;
            }
            const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
            if (kSourceIndex < rows.size())
            {
                result.push_back(kSourceIndex);
            }
        }

        if (result.empty() && fallbackRow >= 0)
        {
            const QTableWidgetItem* item = tableWidget->item(fallbackRow, 0);
            if (item != nullptr)
            {
                const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
                if (kSourceIndex < rows.size())
                {
                    result.push_back(kSourceIndex);
                }
            }
        }

        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
        return result;
    }

    QString buildInlineHookDetailText(const KernelInlineHookEntry& row)
    {
        // Input: Inline Hook row with converted and potentially supplemented disk baseline.
        // Note: Uniformly generate CodeEditorWidget detail text, clearly distinguishing between memory bytes, R0 observation baselines, and R3 disk baselines.
        // Returns: Chinese multi-line detail text; performs no kernel writes or automatic repairs.
        const QString kDiskBytesText = row.diskBaselineAvailable
            ? row.diskBytesText
            : kernelText("kernel.hooks.placeholder.unavailable", QStringLiteral("<不可用>"));
        const QString kDiskByteCountText = row.diskBaselineAvailable
            ? QString::number(std::min<std::size_t>(row.diskBytes.size(), static_cast<std::size_t>(row.currentByteCount)))
            : QStringLiteral("0");
        const QString kDiskPathText = row.diskBaselinePathText.trimmed().isEmpty()
            ? kernelText("kernel.hooks.placeholder.unavailable", QStringLiteral("<不可用>"))
            : QDir::toNativeSeparators(row.diskBaselinePathText);
        const QString kRvaText = (row.moduleBase != 0U && row.functionAddress >= row.moduleBase)
            ? kernelHookFormatAddress(row.functionAddress - row.moduleBase)
            : kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>"));

        // The body of kernel.hooks.inline.detail contains the statement 'Disk baseline is raw bytes at the same RVA as the file,
        // without applying relocations'—this describes an obsolete read path and is no longer valid. The translation for this
        // entry is now handled by languages/*.json. This round does not modify that entry; instead, an independent supplementary
        // note is added to correct the discrepancy and ensure consistent wording between Chinese and English versions.
        return kernelText("kernel.hooks.inline.detail", QStringLiteral(
            "Inline Hook 检测详情\n"
            "模块: %1\n"
            "函数: %2\n"
            "函数地址: %3\n"
            "Hook类型: %4\n"
            "目标地址: %5\n"
            "目标模块: %6\n"
            "状态: %7\n"
            "模块基址: %8\n"
            "目标模块基址: %9\n"
            "当前内存字节(%10): %11\n"
            "R0 观察基线(%12): %13\n"
            "磁盘基线字节(%14): %15\n"
            "差异状态: %16\n"
            "磁盘路径: %17\n"
            "RVA: %18\n"
            "标志: 0x%19\n\n"
            "说明: 当前协议字段 expectedBytes 在 R0 中来自内存观察，通常是 currentBytes 的同源快照，不代表磁盘原始字节。"
            "本页额外由 R3 按模块基址和 RVA 从磁盘模块文件读取基线字节并与当前内存字节比较；"
            "如果磁盘基线不可用，请只把 R0 观察基线当作诊断快照，不要把它理解为干净基线。"
            "磁盘基线由统一 PE 映射核按模块的实际加载基址归一化，已应用 .reloc 基址重定位；"
            "落在零填充区、区段对齐间隙、畸形区段或 PE 动态重定位位点（import optimization / retpoline，由加载器在启动期写入）"
            "上的 RVA 会被单独标为\"不可比较\"，而不是拿磁盘原值硬比 —— 那样会把加载器写入的字节报成 Hook。"
            "热补丁与厂商运行时改写仍未校正，差异仍需结合 Hook 类型和目标地址判断。"
            "摘除操作保持原有 NOP 流程，不新增自动修复能力。"))
            .arg(kernelHookSafeText(row.moduleNameText))
            .arg(kernelHookSafeText(row.functionNameText))
            .arg(kernelHookFormatAddress(row.functionAddress))
            .arg(row.hookTypeText)
            .arg(kernelHookFormatAddress(row.targetAddress))
            .arg(kernelHookSafeText(row.targetModuleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>"))))
            .arg(row.statusText)
            .arg(kernelHookFormatAddress(row.moduleBase))
            .arg(kernelHookFormatAddress(row.targetModuleBase))
            .arg(row.currentByteCount)
            .arg(row.currentBytesText)
            .arg(row.originalByteCount)
            .arg(row.observedBytesText)
            .arg(kDiskByteCountText)
            .arg(kDiskBytesText)
            .arg(row.diskBaselineStatusText)
            .arg(kDiskPathText)
            .arg(kRvaText)
            .arg(static_cast<qulonglong>(row.flags), 8, 16, QChar('0'))
            ;
    }

    void applyDiskBaselineToInlineHookEntry(
        KernelInlineHookEntry* row,
        const KernelHookModulePathMap& modulePathMap,
        KernelHookDiskFileCache* fileCache)
    {
        // Input: Inline Hook row to be added and the module base address/path mapping queried from R3.
        // Processing: Read the disk baseline at the same RVA, then write disk bytes, difference status, path, and detail text.
        // Return: No return value; on read failure, only log the reason in Chinese without affecting the scan result display.
        if (row == nullptr)
        {
            return;
        }

        const KernelHookDiskBaselineResult kBaselineResult =
            kernelHookReadDiskBaselineForInlineHook(*row, modulePathMap, fileCache);
        row->diskBaselineAvailable = kBaselineResult.available;
        row->diskBaselineDiffers = kBaselineResult.differsFromMemory;
        row->diskBaselineRva = kBaselineResult.rva;
        row->diskBaselineStatusText = kBaselineResult.statusText.trimmed().isEmpty()
            ? kernelText("kernel.hooks.baseline.not_comparable", QStringLiteral("不可比较"))
            : kBaselineResult.statusText;
        row->diskBaselinePathText = kBaselineResult.filePathText.trimmed().isEmpty()
            ? kernelText("kernel.hooks.placeholder.unavailable", QStringLiteral("<不可用>"))
            : QDir::toNativeSeparators(kBaselineResult.filePathText);
        row->diskBytes = kBaselineResult.bytes;
        // "Not comparable" and "unavailable" must be displayed separately: the former indicates that no comparable bytes originally existed on that disk location, while
        // the latter indicates that we failed to read them. Merging them into a single placeholder would mislead users into thinking they are the same issue (I-05).
        row->diskBytesText = row->diskBaselineAvailable
            ? kernelHookBytesToText(row->diskBytes, kBaselineResult.byteCount)
            : (kBaselineResult.notComparable
                ? kernelText("kernel.hooks.placeholder.not_comparable", QStringLiteral("<不可比较>"))
                : kernelText("kernel.hooks.placeholder.unavailable", QStringLiteral("<不可用>")));
        row->detailText = buildInlineHookDetailText(*row);
    }

    std::vector<std::uint8_t> shadowTableValueBytes(
        const std::uint64_t value,
        const std::uint32_t byteCount)
    {
        std::vector<std::uint8_t> bytes;
        const std::uint32_t kSafeCount = std::min<std::uint32_t>(
            byteCount,
            sizeof(value));
        bytes.reserve(kSafeCount);
        for (std::uint32_t index = 0; index < kSafeCount; ++index)
        {
            bytes.push_back(static_cast<std::uint8_t>(
                (value >> (index * 8U)) & 0xFFU));
        }
        return bytes;
    }

    std::uint64_t shadowTableValueFromBytes(
        const std::vector<std::uint8_t>& bytes)
    {
        std::uint64_t value = 0U;
        const std::size_t kCount = std::min<std::size_t>(
            bytes.size(),
            sizeof(value));
        for (std::size_t index = 0; index < kCount; ++index)
        {
            value |= static_cast<std::uint64_t>(bytes[index])
                << (index * 8U);
        }
        return value;
    }

    KernelSsdtEntry convertShadowSsdtEntry(
        const ksword::ark::SsdtEntry& source,
        const ksword::ark::SsdtEnumResult& enumResult,
        const ks::kernel::CleanImageBaselineResult& tableBaseline)
    {
        KernelSsdtEntry row{};
        row.serviceIndex = source.serviceIndex;
        row.flags = source.flags;
        row.zwRoutineAddress = source.zwRoutineAddress;
        row.serviceRoutineAddress = source.serviceRoutineAddress;
        row.serviceTableBase = enumResult.serviceTableBase;
        row.tableEntryAddress = source.tableEntryAddress;
        row.currentTableValue = source.currentTableValue;
        row.tableEntrySize = source.tableEntrySize;
        row.currentTableBytes = shadowTableValueBytes(
            row.currentTableValue,
            row.tableEntrySize);
        row.cleanBaselineStatus = tableBaseline.statusText;
        row.cleanBaselinePath = tableBaseline.imagePath;
        if (tableBaseline.available
            && row.tableEntryAddress >= enumResult.serviceTableBase)
        {
            const std::uint64_t kByteOffset =
                row.tableEntryAddress - enumResult.serviceTableBase;
            if (kByteOffset <= tableBaseline.cleanBytes.size()
                && row.tableEntrySize
                    <= tableBaseline.cleanBytes.size() - kByteOffset)
            {
                const auto kFirst =
                    tableBaseline.cleanBytes.cbegin()
                    + static_cast<std::ptrdiff_t>(kByteOffset);
                row.cleanTableBytes.assign(
                    kFirst,
                    kFirst + row.tableEntrySize);
                row.cleanTableValue =
                    shadowTableValueFromBytes(row.cleanTableBytes);
                row.cleanBaselineAvailable = true;
                row.cleanBaselineDiffers =
                    row.cleanTableBytes != row.currentTableBytes;
                row.cleanBaselineStatus = row.cleanBaselineDiffers
                    ? kernelText(
                        "kernel.hooks.shadow.baseline.status.differs",
                        QStringLiteral(
                            "当前编码槽值与已验证磁盘映像不同"))
                    : kernelText(
                        "kernel.hooks.shadow.baseline.status.clean",
                        QStringLiteral(
                            "当前编码槽值与已验证磁盘映像一致"));
            }
        }
        row.serviceNameText = QString::fromLocal8Bit(source.serviceName.data(), static_cast<int>(source.serviceName.size()));
        row.moduleNameText = QString::fromLocal8Bit(source.moduleName.data(), static_cast<int>(source.moduleName.size()));
        row.indexResolved = (row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U;
        row.querySucceeded = true;

        QStringList statusParts;
        statusParts.push_back(kernelText("kernel.hooks.shadow.status.table", QStringLiteral("Shadow/GUI表")));
        statusParts.push_back(row.indexResolved
            ? kernelText("kernel.hooks.shadow.status.index_resolved", QStringLiteral("索引已解析"))
            : kernelText("kernel.hooks.shadow.status.index_unresolved", QStringLiteral("索引未解析")));
        statusParts.push_back((row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT) != 0U
            ? kernelText("kernel.hooks.shadow.status.stub_export", QStringLiteral("Stub导出"))
            : kernelText("kernel.hooks.shadow.status.not_stub_export", QStringLiteral("非Stub导出")));
        statusParts.push_back(row.serviceRoutineAddress != 0U
            ? kernelText("kernel.hooks.shadow.status.entry_resolved", QStringLiteral("表项已解析"))
            : kernelText("kernel.hooks.shadow.status.entry_unavailable", QStringLiteral("表项地址暂不可用")));
        statusParts.push_back(row.cleanBaselineAvailable
            ? (row.cleanBaselineDiffers
                ? kernelText(
                    "kernel.hooks.shadow.baseline.differs",
                    QStringLiteral("磁盘基线差异"))
                : kernelText(
                    "kernel.hooks.shadow.baseline.clean",
                    QStringLiteral("磁盘基线一致")))
            : kernelText(
                "kernel.hooks.shadow.baseline.unavailable",
                QStringLiteral("磁盘基线不可用")));
        row.statusText = statusParts.join(QStringLiteral(" | "));
        row.detailText = kernelText("kernel.hooks.shadow.detail", QStringLiteral(
            "SSSDT/Shadow SSDT 解析\n"
            "协议版本: %1\n"
            "总条目: %2\n"
            "返回条目: %3\n"
            "服务名: %4\n"
            "模块: %5\n"
            "服务索引: %6\n"
            "Stub地址: %7\n"
            "Shadow服务表基址: %8\n"
            "服务例程地址: %9\n"
            "槽位地址: %10\n"
            "当前编码槽值: 0x%11\n"
            "磁盘基线槽值: 0x%12\n"
            "当前槽字节: %13\n"
            "基线槽字节: %14\n"
            "基线状态: %15\n"
            "基线映像: %16\n"
            "驱动标志: 0x%17\n\n"
            "说明: 服务例程地址为 0 表示当前资料不足或该表项暂不可读。"))
            .arg(enumResult.version)
            .arg(enumResult.totalCount)
            .arg(enumResult.returnedCount)
            .arg(kernelHookSafeText(row.serviceNameText))
            .arg(kernelHookSafeText(row.moduleNameText))
            .arg(row.indexResolved ? QString::number(row.serviceIndex) : kernelText("kernel.hooks.placeholder.unknown", QStringLiteral("<未知>")))
            .arg(kernelHookFormatAddress(row.zwRoutineAddress))
            .arg(kernelHookFormatAddress(row.serviceTableBase))
            .arg(kernelHookFormatAddress(row.serviceRoutineAddress))
            .arg(kernelHookFormatAddress(row.tableEntryAddress))
            .arg(static_cast<qulonglong>(row.currentTableValue), 0, 16)
            .arg(static_cast<qulonglong>(row.cleanTableValue), 0, 16)
            .arg(kernelHookBytesToText(
                row.currentTableBytes,
                row.tableEntrySize))
            .arg(kernelHookBytesToText(
                row.cleanTableBytes,
                row.tableEntrySize))
            .arg(row.cleanBaselineStatus)
            .arg(row.cleanBaselinePath)
            .arg(static_cast<qulonglong>(row.flags), 8, 16, QChar('0'));
        return row;
    }

    KernelInlineHookEntry convertInlineHookEntry(const ksword::ark::KernelInlineHookEntry& source)
    {
        KernelInlineHookEntry row{};
        row.status = source.status;
        row.hookType = source.hookType;
        row.flags = source.flags;
        row.originalByteCount = source.originalByteCount;
        row.currentByteCount = source.currentByteCount;
        row.functionAddress = source.functionAddress;
        row.targetAddress = source.targetAddress;
        row.moduleBase = source.moduleBase;
        row.targetModuleBase = source.targetModuleBase;
        row.moduleNameText = QString::fromStdWString(source.moduleName);
        row.functionNameText = QString::fromLocal8Bit(source.functionName.data(), static_cast<int>(source.functionName.size()));
        row.targetModuleNameText = QString::fromStdWString(source.targetModuleName);
        row.hookTypeText = inlineHookTypeText(row.hookType);
        row.statusText = kernelHookStatusText(row.status);
        row.currentBytes = source.currentBytes;
        row.currentBytesText = kernelHookBytesToText(row.currentBytes, row.currentByteCount);
        row.observedBytes = source.expectedBytes;
        row.observedBytesText = kernelHookBytesToText(row.observedBytes, row.originalByteCount);
        row.diskBaselineAvailable = false;
        row.diskBaselineDiffers = false;
        row.diskBaselineRva = 0U;
        row.diskBaselineStatusText = kernelText("kernel.hooks.baseline.not_comparable", QStringLiteral("不可比较"));
        row.diskBaselinePathText = kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>"));
        row.diskBytesText = kernelText("kernel.hooks.placeholder.not_fetched", QStringLiteral("<未获取>"));
        row.detailText = buildInlineHookDetailText(row);
        return row;
    }

    KernelIatEatHookEntry convertIatEatHookEntry(const ksword::ark::KernelIatEatHookEntry& source)
    {
        KernelIatEatHookEntry row{};
        row.hookClass = source.hookClass;
        row.status = source.status;
        row.flags = source.flags;
        row.ordinal = source.ordinal;
        row.moduleBase = source.moduleBase;
        row.thunkAddress = source.thunkAddress;
        row.currentTarget = source.currentTarget;
        row.expectedTarget = source.expectedTarget;
        row.targetModuleBase = source.targetModuleBase;
        row.classText = iatEatClassText(row.hookClass);
        row.statusText = kernelHookStatusText(row.status);
        row.moduleNameText = QString::fromStdWString(source.moduleName);
        row.importModuleNameText = QString::fromStdWString(source.importModuleName);
        row.functionNameText = QString::fromLocal8Bit(source.functionName.data(), static_cast<int>(source.functionName.size()));
        row.targetModuleNameText = QString::fromStdWString(source.targetModuleName);
        row.detailText = kernelText("kernel.hooks.iat.detail", QStringLiteral(
            "IAT/EAT Hook 检测详情\n"
            "类别: %1\n"
            "模块: %2\n"
            "导入模块: %3\n"
            "函数/序号: %4 / #%5\n"
            "Thunk/EAT项: %6\n"
            "当前目标: %7\n"
            "期望目标: %8\n"
            "目标模块: %9\n"
            "所属模块基址: %10\n"
            "目标模块基址: %11\n"
            "状态: %12\n"
            "标志: 0x%13\n\n"
            "说明: IAT 检测比较 thunk 当前目标是否仍落在声明导入模块内；EAT 检测导出 RVA 是否落在自身映像或转发导出区域内。"))
            .arg(row.classText)
            .arg(kernelHookSafeText(row.moduleNameText))
            .arg(kernelHookSafeText(row.importModuleNameText, kernelText("kernel.hooks.placeholder.not_applicable", QStringLiteral("<不适用>"))))
            .arg(kernelHookSafeText(row.functionNameText))
            .arg(row.ordinal)
            .arg(kernelHookFormatAddress(row.thunkAddress))
            .arg(kernelHookFormatAddress(row.currentTarget))
            .arg(kernelHookFormatAddress(row.expectedTarget))
            .arg(kernelHookSafeText(row.targetModuleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>"))))
            .arg(kernelHookFormatAddress(row.moduleBase))
            .arg(kernelHookFormatAddress(row.targetModuleBase))
            .arg(row.statusText)
            .arg(static_cast<qulonglong>(row.flags), 8, 16, QChar('0'));
        return row;
    }

    void setTableItem(QTableWidget* tableWidget, const int row, const int column, QTableWidgetItem* item)
    {
        // Purpose: Uniformly set non-editable items to reduce duplicate code at the table construction site.
        // Return: None. Directly ignore if the table or item is null.
        if (tableWidget == nullptr || item == nullptr)
        {
            delete item;
            return;
        }
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        tableWidget->setItem(row, column, item);
    }
}

void KernelDock::initializeShadowSsdtTab()
{
    if (shadowSsdtPage_ == nullptr || shadowSsdtLayout_ != nullptr)
    {
        return;
    }

    shadowSsdtLayout_ = new QVBoxLayout(shadowSsdtPage_);
    shadowSsdtLayout_->setContentsMargins(4, 4, 4, 4);
    shadowSsdtLayout_->setSpacing(6);

    shadowSsdtToolLayout_ = new QHBoxLayout();
    shadowSsdtToolLayout_->setContentsMargins(0, 0, 0, 0);
    shadowSsdtToolLayout_->setSpacing(6);

    refreshShadowSsdtButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), shadowSsdtPage_);
    refreshShadowSsdtButton_->setToolTip(kernelText("kernel.hooks.shadow.toolbar.refresh.tooltip", QStringLiteral("刷新 SSSDT/Shadow SSDT 解析结果")));
    refreshShadowSsdtButton_->setStyleSheet(kernelHookButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshShadowSsdtButton_);

    shadowSsdtFilterEdit_ = new QLineEdit(shadowSsdtPage_);
    shadowSsdtFilterEdit_->setPlaceholderText(kernelText("kernel.hooks.shadow.toolbar.filter.placeholder", QStringLiteral("按索引/服务名/模块/地址筛选")));
    shadowSsdtFilterEdit_->setClearButtonEnabled(true);
    shadowSsdtFilterEdit_->setStyleSheet(kernelHookInputStyle());

    shadowSsdtStatusLabel_ = new QLabel(kernelText("kernel.hooks.shadow.status.waiting", QStringLiteral("状态：等待刷新")), shadowSsdtPage_);
    shadowSsdtStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::textSecondaryHex()));

    shadowSsdtToolLayout_->addWidget(refreshShadowSsdtButton_, 0);
    shadowSsdtToolLayout_->addWidget(shadowSsdtFilterEdit_, 1);
    shadowSsdtToolLayout_->addWidget(shadowSsdtStatusLabel_, 0);
    shadowSsdtLayout_->addLayout(shadowSsdtToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, shadowSsdtPage_);
    shadowSsdtLayout_->addWidget(splitter, 1);

    shadowSsdtTable_ = new ks::ui::VisibleTableWidget(splitter);
    shadowSsdtTable_->setColumnCount(static_cast<int>(ShadowSsdtColumn::kCount));
    shadowSsdtTable_->setHorizontalHeaderLabels(QStringList{
        shadowSsdtColumnHeader(ShadowSsdtColumn::kIndex),
        shadowSsdtColumnHeader(ShadowSsdtColumn::kServiceName),
        shadowSsdtColumnHeader(ShadowSsdtColumn::kStubAddress),
        shadowSsdtColumnHeader(ShadowSsdtColumn::kServiceAddress),
        shadowSsdtColumnHeader(ShadowSsdtColumn::kSlotAddress),
        shadowSsdtColumnHeader(ShadowSsdtColumn::kModule)
        });
    prepareTable(shadowSsdtTable_);
    shadowSsdtTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(ShadowSsdtColumn::kServiceName), QHeaderView::Stretch);

    shadowSsdtDetailEditor_ = new CodeEditorWidget(splitter);
    shadowSsdtDetailEditor_->setReadOnly(true);
    shadowSsdtDetailEditor_->setText(kernelText("kernel.hooks.shadow.detail.initial", QStringLiteral("请选择一条 SSSDT 记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        shadowSsdtTable_, shadowSsdtDetailEditor_, shadowSsdtPage_);

    connect(refreshShadowSsdtButton_, &QPushButton::clicked, this, [this]() {
        refreshShadowSsdtAsync();
    });
    connect(shadowSsdtFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildShadowSsdtTable(filterText.trimmed());
    });
    connect(shadowSsdtTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showShadowSsdtDetailByCurrentRow();
    });
    connect(shadowSsdtTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showShadowSsdtContextMenu(position);
    });
}

void KernelDock::initializeInlineHookTab()
{
    if (inlineHookPage_ == nullptr || inlineHookLayout_ != nullptr)
    {
        return;
    }

    inlineHookLayout_ = new QVBoxLayout(inlineHookPage_);
    inlineHookLayout_->setContentsMargins(4, 4, 4, 4);
    inlineHookLayout_->setSpacing(6);

    inlineHookToolLayout_ = new QHBoxLayout();
    inlineHookToolLayout_->setContentsMargins(0, 0, 0, 0);
    inlineHookToolLayout_->setSpacing(6);

    refreshInlineHookButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), inlineHookPage_);
    refreshInlineHookButton_->setToolTip(kernelText("kernel.hooks.inline.toolbar.scan.tooltip", QStringLiteral("扫描内核模块导出函数 Inline Hook")));
    refreshInlineHookButton_->setStyleSheet(kernelHookButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshInlineHookButton_);

    patchInlineHookButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), kernelText("kernel.hooks.inline.toolbar.patch", QStringLiteral("NOP 摘除选中")), inlineHookPage_);
    patchInlineHookButton_->setToolTip(kernelText("kernel.hooks.inline.toolbar.patch.tooltip", QStringLiteral("对当前选中 Hook 先普通请求，再经强制确认后写入 NOP")));
    patchInlineHookButton_->setStyleSheet(kernelHookButtonStyle());

    inlineHookModuleEdit_ = new QLineEdit(inlineHookPage_);
    inlineHookModuleEdit_->setPlaceholderText(kernelText("kernel.hooks.inline.toolbar.module.placeholder", QStringLiteral("模块过滤，如 ntoskrnl.exe / win32k.sys（留空扫描全部）")));
    inlineHookModuleEdit_->setClearButtonEnabled(true);
    inlineHookModuleEdit_->setStyleSheet(kernelHookInputStyle());

    inlineHookFilterEdit_ = new QLineEdit(inlineHookPage_);
    inlineHookFilterEdit_->setPlaceholderText(kernelText("kernel.hooks.inline.toolbar.filter.placeholder", QStringLiteral("本地筛选：模块/函数/地址/类型/状态/字节")));
    inlineHookFilterEdit_->setClearButtonEnabled(true);
    inlineHookFilterEdit_->setStyleSheet(kernelHookInputStyle());

    inlineHookIncludeCombo_ = new QComboBox(inlineHookPage_);
    inlineHookIncludeCombo_->addItem(kernelText("kernel.hooks.inline.combo.suspicious_only", QStringLiteral("仅可疑外跳")), QVariant::fromValue<qulonglong>(0ULL));
    inlineHookIncludeCombo_->addItem(kernelText("kernel.hooks.inline.combo.suspicious_internal", QStringLiteral("可疑 + 模块内跳转")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL));
    inlineHookIncludeCombo_->addItem(kernelText("kernel.hooks.inline.combo.include_clean", QStringLiteral("包含干净项")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN));
    inlineHookIncludeCombo_->setToolTip(kernelText("kernel.hooks.inline.combo.tooltip", QStringLiteral("控制 R0 扫描结果返回范围，包含干净项会明显增多")));

    inlineHookStatusLabel_ = new QLabel(kernelText("kernel.hooks.inline.status.waiting", QStringLiteral("状态：等待扫描")), inlineHookPage_);
    inlineHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::textSecondaryHex()));

    inlineHookToolLayout_->addWidget(refreshInlineHookButton_, 0);
    inlineHookToolLayout_->addWidget(patchInlineHookButton_, 0);
    inlineHookToolLayout_->addWidget(inlineHookModuleEdit_, 2);
    inlineHookToolLayout_->addWidget(inlineHookFilterEdit_, 2);
    inlineHookToolLayout_->addWidget(inlineHookIncludeCombo_, 0);
    inlineHookToolLayout_->addWidget(inlineHookStatusLabel_, 0);
    inlineHookLayout_->addLayout(inlineHookToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, inlineHookPage_);
    inlineHookLayout_->addWidget(splitter, 1);

    inlineHookTable_ = new ks::ui::VisibleTableWidget(splitter);
    inlineHookTable_->setColumnCount(static_cast<int>(InlineHookColumn::kCount));
    inlineHookTable_->setHorizontalHeaderLabels(QStringList{
        inlineHookColumnHeader(InlineHookColumn::kModule),
        inlineHookColumnHeader(InlineHookColumn::kFunction),
        inlineHookColumnHeader(InlineHookColumn::kFunctionAddress),
        inlineHookColumnHeader(InlineHookColumn::kHookType),
        inlineHookColumnHeader(InlineHookColumn::kTargetAddress),
        inlineHookColumnHeader(InlineHookColumn::kTargetModule),
        inlineHookColumnHeader(InlineHookColumn::kStatus),
        inlineHookColumnHeader(InlineHookColumn::kCurrentBytes),
        inlineHookColumnHeader(InlineHookColumn::kDiskBytes),
        inlineHookColumnHeader(InlineHookColumn::kDiskDiff)
        });
    prepareTable(inlineHookTable_);
    inlineHookTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(InlineHookColumn::kFunction), QHeaderView::Stretch);

    inlineHookDetailEditor_ = new CodeEditorWidget(splitter);
    inlineHookDetailEditor_->setReadOnly(true);
    inlineHookDetailEditor_->setText(kernelText("kernel.hooks.inline.detail.initial", QStringLiteral("请选择一条 Inline Hook 记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        inlineHookTable_, inlineHookDetailEditor_, inlineHookPage_);

    connect(refreshInlineHookButton_, &QPushButton::clicked, this, [this]() {
        refreshInlineHooksAsync();
    });
    connect(patchInlineHookButton_, &QPushButton::clicked, this, [this]() {
        patchSelectedInlineHookWithNop();
    });
    connect(inlineHookFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildInlineHookTable(filterText.trimmed());
    });
    connect(inlineHookTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showInlineHookDetailByCurrentRow();
    });
    connect(inlineHookTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showInlineHookContextMenu(position);
    });
}

void KernelDock::initializeIatEatHookTab()
{
    if (iatEatHookPage_ == nullptr || iatEatHookLayout_ != nullptr)
    {
        return;
    }

    iatEatHookLayout_ = new QVBoxLayout(iatEatHookPage_);
    iatEatHookLayout_->setContentsMargins(4, 4, 4, 4);
    iatEatHookLayout_->setSpacing(6);

    iatEatHookToolLayout_ = new QHBoxLayout();
    iatEatHookToolLayout_->setContentsMargins(0, 0, 0, 0);
    iatEatHookToolLayout_->setSpacing(6);

    refreshIatEatHookButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), iatEatHookPage_);
    refreshIatEatHookButton_->setToolTip(kernelText("kernel.hooks.iat.toolbar.scan.tooltip", QStringLiteral("扫描内核模块 IAT/EAT Hook")));
    refreshIatEatHookButton_->setStyleSheet(kernelHookButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshIatEatHookButton_);

    iatEatHookModuleEdit_ = new QLineEdit(iatEatHookPage_);
    iatEatHookModuleEdit_->setPlaceholderText(kernelText("kernel.hooks.iat.toolbar.module.placeholder", QStringLiteral("模块过滤，如 ntoskrnl.exe / fltmgr.sys（留空扫描全部）")));
    iatEatHookModuleEdit_->setClearButtonEnabled(true);
    iatEatHookModuleEdit_->setStyleSheet(kernelHookInputStyle());

    iatEatHookFilterEdit_ = new QLineEdit(iatEatHookPage_);
    iatEatHookFilterEdit_->setPlaceholderText(kernelText("kernel.hooks.iat.toolbar.filter.placeholder", QStringLiteral("本地筛选：类别/模块/导入模块/函数/地址/状态")));
    iatEatHookFilterEdit_->setClearButtonEnabled(true);
    iatEatHookFilterEdit_->setStyleSheet(kernelHookInputStyle());

    iatEatHookIncludeCombo_ = new QComboBox(iatEatHookPage_);
    iatEatHookIncludeCombo_->addItem(kernelText("kernel.hooks.iat.combo.suspicious_both", QStringLiteral("IAT + EAT 可疑项")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS));
    iatEatHookIncludeCombo_->addItem(kernelText("kernel.hooks.iat.combo.suspicious_iat", QStringLiteral("仅 IAT 可疑项")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS));
    iatEatHookIncludeCombo_->addItem(kernelText("kernel.hooks.iat.combo.suspicious_eat", QStringLiteral("仅 EAT 可疑项")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS));
    iatEatHookIncludeCombo_->addItem(kernelText("kernel.hooks.iat.combo.include_clean", QStringLiteral("IAT + EAT + 干净项")), QVariant::fromValue<qulonglong>(KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN));
    iatEatHookIncludeCombo_->setToolTip(kernelText("kernel.hooks.iat.combo.tooltip", QStringLiteral("控制 R0 扫描 IAT/EAT 范围，包含干净项会明显增多")));

    iatEatHookStatusLabel_ = new QLabel(kernelText("kernel.hooks.iat.status.waiting", QStringLiteral("状态：等待扫描")), iatEatHookPage_);
    iatEatHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::textSecondaryHex()));

    iatEatHookToolLayout_->addWidget(refreshIatEatHookButton_, 0);
    iatEatHookToolLayout_->addWidget(iatEatHookModuleEdit_, 2);
    iatEatHookToolLayout_->addWidget(iatEatHookFilterEdit_, 2);
    iatEatHookToolLayout_->addWidget(iatEatHookIncludeCombo_, 0);
    iatEatHookToolLayout_->addWidget(iatEatHookStatusLabel_, 0);
    iatEatHookLayout_->addLayout(iatEatHookToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, iatEatHookPage_);
    iatEatHookLayout_->addWidget(splitter, 1);

    iatEatHookTable_ = new ks::ui::VisibleTableWidget(splitter);
    iatEatHookTable_->setColumnCount(static_cast<int>(IatEatHookColumn::kCount));
    iatEatHookTable_->setHorizontalHeaderLabels(QStringList{
        iatEatColumnHeader(IatEatHookColumn::kClass),
        iatEatColumnHeader(IatEatHookColumn::kModule),
        iatEatColumnHeader(IatEatHookColumn::kImportModule),
        iatEatColumnHeader(IatEatHookColumn::kFunction),
        iatEatColumnHeader(IatEatHookColumn::kThunkAddress),
        iatEatColumnHeader(IatEatHookColumn::kCurrentTarget),
        iatEatColumnHeader(IatEatHookColumn::kExpectedTarget),
        iatEatColumnHeader(IatEatHookColumn::kTargetModule),
        iatEatColumnHeader(IatEatHookColumn::kStatus)
        });
    prepareTable(iatEatHookTable_);
    iatEatHookTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(IatEatHookColumn::kFunction), QHeaderView::Stretch);

    iatEatHookDetailEditor_ = new CodeEditorWidget(splitter);
    iatEatHookDetailEditor_->setReadOnly(true);
    iatEatHookDetailEditor_->setText(kernelText("kernel.hooks.iat.detail.initial", QStringLiteral("请选择一条 IAT/EAT 记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        iatEatHookTable_, iatEatHookDetailEditor_, iatEatHookPage_);

    connect(refreshIatEatHookButton_, &QPushButton::clicked, this, [this]() {
        refreshIatEatHooksAsync();
    });
    connect(iatEatHookFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildIatEatHookTable(filterText.trimmed());
    });
    connect(iatEatHookTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showIatEatHookDetailByCurrentRow();
    });
    connect(iatEatHookTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showIatEatHookContextMenu(position);
    });
}

void KernelDock::initializeTimerDpcTab()
{
    if (timerDpcPage_ == nullptr || timerDpcLayout_ != nullptr)
    {
        return;
    }

    timerDpcLayout_ = new QVBoxLayout(timerDpcPage_);
    timerDpcLayout_->setContentsMargins(4, 4, 4, 4);
    timerDpcLayout_->setSpacing(6);
    timerDpcToolLayout_ = new QHBoxLayout();
    timerDpcToolLayout_->setContentsMargins(0, 0, 0, 0);
    timerDpcToolLayout_->setSpacing(6);

    refreshTimerDpcButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), timerDpcPage_);
    refreshTimerDpcButton_->setToolTip(kernelText("kernel.timer_dpc.refresh.tooltip", QStringLiteral("刷新每 CPU KTIMER/KDPC 快照")));
    refreshTimerDpcButton_->setStyleSheet(kernelHookButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshTimerDpcButton_);

    timerDpcFilterEdit_ = new QLineEdit(timerDpcPage_);
    timerDpcFilterEdit_->setPlaceholderText(kernelText("kernel.timer_dpc.filter.placeholder", QStringLiteral("筛选 CPU/Bucket/Timer/DPC/例程/模块/状态")));
    timerDpcFilterEdit_->setClearButtonEnabled(true);
    timerDpcFilterEdit_->setStyleSheet(kernelHookInputStyle());

    timerDpcStatusLabel_ = new QLabel(kernelText("kernel.timer_dpc.status.waiting", QStringLiteral("状态：等待刷新")), timerDpcPage_);
    timerDpcStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::textSecondaryHex()));

    timerDpcToolLayout_->addWidget(refreshTimerDpcButton_, 0);
    timerDpcToolLayout_->addWidget(timerDpcFilterEdit_, 1);
    timerDpcToolLayout_->addWidget(timerDpcStatusLabel_, 0);
    timerDpcLayout_->addLayout(timerDpcToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, timerDpcPage_);
    timerDpcLayout_->addWidget(splitter, 1);
    timerDpcTable_ = new ks::ui::VisibleTableWidget(splitter);
    timerDpcTable_->setColumnCount(static_cast<int>(TimerDpcColumn::kCount));
    QStringList headers;
    for (int column = 0; column < static_cast<int>(TimerDpcColumn::kCount); ++column)
    {
        headers.push_back(timerDpcColumnHeader(static_cast<TimerDpcColumn>(column)));
    }
    timerDpcTable_->setHorizontalHeaderLabels(headers);
    prepareTable(timerDpcTable_);
    timerDpcTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(TimerDpcColumn::kModule), QHeaderView::Stretch);

    timerDpcDetailEditor_ = new CodeEditorWidget(splitter);
    timerDpcDetailEditor_->setReadOnly(true);
    timerDpcDetailEditor_->setText(kernelText("kernel.timer_dpc.detail.initial", QStringLiteral("请选择一条 KTIMER/DPC 记录查看详情。")));
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        timerDpcTable_, timerDpcDetailEditor_, timerDpcPage_);

    connect(refreshTimerDpcButton_, &QPushButton::clicked, this, [this]() { refreshTimerDpcAfterDynDataAsync(); });
    connect(timerDpcFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& text) { rebuildTimerDpcTable(text.trimmed()); });
    connect(timerDpcTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) { showTimerDpcDetailByCurrentRow(); });
    connect(timerDpcTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showTimerDpcContextMenu(position); });
}

void KernelDock::refreshShadowSsdtAsync()
{
    if (shadowSsdtRefreshRunning_.exchange(true))
    {
        return;
    }

    if (refreshShadowSsdtButton_ != nullptr)
    {
        refreshShadowSsdtButton_->setEnabled(false);
    }
    if (shadowSsdtStatusLabel_ != nullptr)
    {
        shadowSsdtStatusLabel_->setText(kernelText("kernel.hooks.shadow.status.parsing", QStringLiteral("状态：SSSDT 解析中...")));
        shadowSsdtStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelSsdtEntry> resultRows;
        QString errorText;
        std::uint32_t totalCount = 0U;
        std::uint32_t returnedCount = 0U;
        bool success = false;

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::SsdtEnumResult kEnumResult = kDriverClient.enumerateShadowSsdt(
            KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
        success = kEnumResult.io.ok;
        if (success)
        {
            totalCount = kEnumResult.totalCount;
            returnedCount = kEnumResult.returnedCount;
            std::uint32_t tableEntrySize = 0U;
            for (const ksword::ark::SsdtEntry& entry : kEnumResult.entries)
            {
                if (entry.tableEntrySize != 0U)
                {
                    tableEntrySize = entry.tableEntrySize;
                    break;
                }
            }
            ks::kernel::CleanImageBaselineResult tableBaseline;
            if (kEnumResult.serviceTableBase != 0U
                && kEnumResult.serviceCountFromTable != 0U
                && tableEntrySize != 0U
                && tableEntrySize <= sizeof(std::uint64_t)
                && static_cast<std::uint64_t>(
                    kEnumResult.serviceCountFromTable)
                    * tableEntrySize <= 64U * 1024U)
            {
                tableBaseline =
                    ks::kernel::KernelCleanImageBaseline::compareAddress(
                        kEnumResult.serviceTableBase,
                        kEnumResult.serviceCountFromTable
                            * tableEntrySize);
            }
            resultRows.reserve(kEnumResult.entries.size());
            for (const ksword::ark::SsdtEntry& sourceEntry : kEnumResult.entries)
            {
                resultRows.push_back(convertShadowSsdtEntry(
                    sourceEntry,
                    kEnumResult,
                    tableBaseline));
            }
            std::sort(resultRows.begin(), resultRows.end(), [](const KernelSsdtEntry& left, const KernelSsdtEntry& right) {
                if (left.indexResolved != right.indexResolved)
                {
                    return left.indexResolved && !right.indexResolved;
                }
                if (left.serviceIndex != right.serviceIndex)
                {
                    return left.serviceIndex < right.serviceIndex;
                }
                return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
            });
        }
        else
        {
            errorText = kernelText("kernel.hooks.shadow.error.io", QStringLiteral("SSSDT 解析 IOCTL 调用失败。\nWin32=%1\n详情=%2"))
                .arg(kEnumResult.io.win32Error)
                .arg(friendlyKernelHookIoMessage(kEnumResult.io.message));
        }

        QMetaObject::invokeMethod(guardThis, [guardThis, success, errorText, totalCount, returnedCount, resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelSsdtEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, success, errorText, totalCount, returnedCount, kDeferredRows]() mutable
            {
            std::vector<KernelSsdtEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->shadowSsdtRefreshRunning_.store(false);
            if (guardThis->refreshShadowSsdtButton_ != nullptr)
            {
                guardThis->refreshShadowSsdtButton_->setEnabled(true);
            }

            if (!success)
            {
                guardThis->shadowSsdtStatusLabel_->setText(kernelText("kernel.hooks.shadow.status.failed", QStringLiteral("状态：解析失败")));
                guardThis->shadowSsdtStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::errorHex()));
                guardThis->shadowSsdtDetailEditor_->setText(errorText);
                return;
            }

            guardThis->shadowSsdtRows_ = std::move(resultRows);
            guardThis->rebuildShadowSsdtTable(guardThis->shadowSsdtFilterEdit_->text().trimmed());
            guardThis->shadowSsdtStatusLabel_->setText(
                kernelText("kernel.hooks.shadow.status.summary", QStringLiteral("状态：已解析 %1/%2 项，显示 %3 项"))
                .arg(returnedCount)
                .arg(totalCount)
                .arg(guardThis->shadowSsdtRows_.size()));
            guardThis->shadowSsdtStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::successHex()));

            if (guardThis->shadowSsdtTable_->rowCount() > 0)
            {
                guardThis->shadowSsdtTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->shadowSsdtDetailEditor_->setText(kernelText("kernel.hooks.shadow.empty", QStringLiteral("当前环境未返回 SSSDT stub 解析结果。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-shadow-ssdt-snapshot-apply"),
                { guardThis->shadowSsdtTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshInlineHooksAsync()
{
    if (inlineHookRefreshRunning_.exchange(true))
    {
        return;
    }

    if (refreshInlineHookButton_ != nullptr)
    {
        refreshInlineHookButton_->setEnabled(false);
    }
    if (inlineHookStatusLabel_ != nullptr)
    {
        inlineHookStatusLabel_->setText(kernelText("kernel.hooks.inline.status.scanning", QStringLiteral("状态：Inline Hook 扫描中...")));
        inlineHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::kPrimaryBlueHex));
    }

    const unsigned long kFlags = inlineHookIncludeCombo_ != nullptr
        ? static_cast<unsigned long>(inlineHookIncludeCombo_->currentData().toULongLong())
        : 0UL;
    const QString kModuleFilterText = inlineHookModuleEdit_ != nullptr
        ? inlineHookModuleEdit_->text().trimmed()
        : QString();

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis, kFlags, kModuleFilterText]() {
        std::vector<KernelInlineHookEntry> resultRows;
        QString errorText;
        std::uint32_t totalCount = 0U;
        std::uint32_t moduleCount = 0U;
        long lastStatus = 0;
        bool success = false;

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::KernelInlineHookScanResult kScanResult = kDriverClient.scanInlineHooks(
            kFlags,
            KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
            kModuleFilterText.toStdWString());
        success = kScanResult.io.ok;
        if (success)
        {
            const KernelHookModulePathMap kModulePathMap = kernelHookQueryLoadedModulePathMap();
            KernelHookDiskFileCache diskFileCache;
            totalCount = kScanResult.totalCount;
            moduleCount = kScanResult.moduleCount;
            lastStatus = kScanResult.lastStatus;
            resultRows.reserve(kScanResult.entries.size());
            for (const ksword::ark::KernelInlineHookEntry& sourceEntry : kScanResult.entries)
            {
                KernelInlineHookEntry row = convertInlineHookEntry(sourceEntry);
                applyDiskBaselineToInlineHookEntry(&row, kModulePathMap, &diskFileCache);
                resultRows.push_back(std::move(row));
            }
        }
        else
        {
            errorText = kernelText("kernel.hooks.inline.error.io", QStringLiteral("Inline Hook 扫描 IOCTL 调用失败。\nWin32=%1\n详情=%2"))
                .arg(kScanResult.io.win32Error)
                .arg(friendlyKernelHookIoMessage(kScanResult.io.message));
        }

        QMetaObject::invokeMethod(guardThis, [guardThis, success, errorText, totalCount, moduleCount, lastStatus, resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelInlineHookEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, success, errorText, totalCount, moduleCount, lastStatus, kDeferredRows]() mutable
            {
            std::vector<KernelInlineHookEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->inlineHookRefreshRunning_.store(false);
            if (guardThis->refreshInlineHookButton_ != nullptr)
            {
                guardThis->refreshInlineHookButton_->setEnabled(true);
            }

            if (!success)
            {
                guardThis->inlineHookStatusLabel_->setText(kernelText("kernel.hooks.inline.status.failed", QStringLiteral("状态：扫描失败")));
                guardThis->inlineHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::errorHex()));
                guardThis->inlineHookDetailEditor_->setText(errorText);
                return;
            }

            std::size_t suspiciousCount = 0U;
            std::size_t internalCount = 0U;
            for (const KernelInlineHookEntry& entry : resultRows)
            {
                if (entry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    ++suspiciousCount;
                }
                else if (entry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH)
                {
                    ++internalCount;
                }
            }

            guardThis->inlineHookRows_ = std::move(resultRows);
            guardThis->rebuildInlineHookTable(guardThis->inlineHookFilterEdit_->text().trimmed());
            guardThis->inlineHookStatusLabel_->setText(
                kernelText("kernel.hooks.inline.status.summary", QStringLiteral("状态：模块=%1，总命中=%2，返回=%3，可疑=%4，内部跳转=%5，Last=%6"))
                .arg(moduleCount)
                .arg(totalCount)
                .arg(guardThis->inlineHookRows_.size())
                .arg(suspiciousCount)
                .arg(internalCount)
                .arg(kernelHookFormatNtStatus(lastStatus)));
            guardThis->inlineHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(
                suspiciousCount == 0U ? ksword_theme::successHex() : ksword_theme::errorHex()));

            if (guardThis->inlineHookTable_->rowCount() > 0)
            {
                guardThis->inlineHookTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->inlineHookDetailEditor_->setText(kernelText("kernel.hooks.inline.empty", QStringLiteral("当前过滤条件下未返回 Inline Hook 记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-inline-hook-snapshot-apply"),
                { guardThis->inlineHookTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshIatEatHooksAsync()
{
    if (iatEatHookRefreshRunning_.exchange(true))
    {
        return;
    }

    if (refreshIatEatHookButton_ != nullptr)
    {
        refreshIatEatHookButton_->setEnabled(false);
    }
    if (iatEatHookStatusLabel_ != nullptr)
    {
        iatEatHookStatusLabel_->setText(kernelText("kernel.hooks.iat.status.scanning", QStringLiteral("状态：IAT/EAT 扫描中...")));
        iatEatHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::kPrimaryBlueHex));
    }

    const unsigned long kFlags = iatEatHookIncludeCombo_ != nullptr
        ? static_cast<unsigned long>(iatEatHookIncludeCombo_->currentData().toULongLong())
        : (KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS);
    const QString kModuleFilterText = iatEatHookModuleEdit_ != nullptr
        ? iatEatHookModuleEdit_->text().trimmed()
        : QString();

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis, kFlags, kModuleFilterText]() {
        std::vector<KernelIatEatHookEntry> resultRows;
        QString errorText;
        std::uint32_t totalCount = 0U;
        std::uint32_t moduleCount = 0U;
        long lastStatus = 0;
        bool success = false;

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::KernelIatEatHookScanResult kScanResult = kDriverClient.enumerateIatEatHooks(
            kFlags,
            KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
            kModuleFilterText.toStdWString());
        success = kScanResult.io.ok;
        if (success)
        {
            totalCount = kScanResult.totalCount;
            moduleCount = kScanResult.moduleCount;
            lastStatus = kScanResult.lastStatus;
            resultRows.reserve(kScanResult.entries.size());
            for (const ksword::ark::KernelIatEatHookEntry& sourceEntry : kScanResult.entries)
            {
                resultRows.push_back(convertIatEatHookEntry(sourceEntry));
            }
        }
        else
        {
            errorText = kernelText("kernel.hooks.iat.error.io", QStringLiteral("IAT/EAT 扫描 IOCTL 调用失败。\nWin32=%1\n详情=%2"))
                .arg(kScanResult.io.win32Error)
                .arg(friendlyKernelHookIoMessage(kScanResult.io.message));
        }

        QMetaObject::invokeMethod(guardThis, [guardThis, success, errorText, totalCount, moduleCount, lastStatus, resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelIatEatHookEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, success, errorText, totalCount, moduleCount, lastStatus, kDeferredRows]() mutable
            {
            std::vector<KernelIatEatHookEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->iatEatHookRefreshRunning_.store(false);
            if (guardThis->refreshIatEatHookButton_ != nullptr)
            {
                guardThis->refreshIatEatHookButton_->setEnabled(true);
            }

            if (!success)
            {
                guardThis->iatEatHookStatusLabel_->setText(kernelText("kernel.hooks.iat.status.failed", QStringLiteral("状态：扫描失败")));
                guardThis->iatEatHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::errorHex()));
                guardThis->iatEatHookDetailEditor_->setText(errorText);
                return;
            }

            std::size_t suspiciousCount = 0U;
            for (const KernelIatEatHookEntry& entry : resultRows)
            {
                if (entry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    ++suspiciousCount;
                }
            }

            guardThis->iatEatHookRows_ = std::move(resultRows);
            guardThis->rebuildIatEatHookTable(guardThis->iatEatHookFilterEdit_->text().trimmed());
            guardThis->iatEatHookStatusLabel_->setText(
                kernelText("kernel.hooks.iat.status.summary", QStringLiteral("状态：模块=%1，总命中=%2，返回=%3，可疑=%4，Last=%5"))
                .arg(moduleCount)
                .arg(totalCount)
                .arg(guardThis->iatEatHookRows_.size())
                .arg(suspiciousCount)
                .arg(kernelHookFormatNtStatus(lastStatus)));
            guardThis->iatEatHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(
                suspiciousCount == 0U ? ksword_theme::successHex() : ksword_theme::errorHex()));

            if (guardThis->iatEatHookTable_->rowCount() > 0)
            {
                guardThis->iatEatHookTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->iatEatHookDetailEditor_->setText(kernelText("kernel.hooks.iat.empty", QStringLiteral("当前过滤条件下未返回 IAT/EAT 记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-iat-eat-hook-snapshot-apply"),
                { guardThis->iatEatHookTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshTimerDpcAsync()
{
    if (timerDpcRefreshRunning_.exchange(true))
    {
        return;
    }
    if (refreshTimerDpcButton_ != nullptr)
    {
        refreshTimerDpcButton_->setEnabled(false);
    }
    if (timerDpcStatusLabel_ != nullptr)
    {
        timerDpcStatusLabel_->setText(kernelText("kernel.timer_dpc.status.enumerating", QStringLiteral("状态：正在遍历 KTIMER/DPC...")));
        timerDpcStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::KernelTimerDpcEnumResult kEnumResult = kDriverClient.enumerateKernelTimerDpc();
        std::vector<KernelTimerDpcEntry> resultRows;
        if (kEnumResult.io.ok)
        {
            const KernelHookModulePathMap kModulePathMap = kernelHookQueryLoadedModulePathMap();
            resultRows.reserve(kEnumResult.entries.size());
            for (const ksword::ark::KernelTimerDpcEntry& source : kEnumResult.entries)
            {
                KernelTimerDpcEntry row{};
                row.processorGroup = source.processorGroup;
                row.processorNumber = source.processorNumber;
                row.bucketIndex = source.bucketIndex;
                row.flags = source.flags;
                row.timerType = source.timerType;
                row.period = source.period;
                row.dueTime = source.dueTime;
                row.timerAddress = source.timerAddress;
                row.dpcAddress = source.dpcAddress;
                row.deferredRoutine = source.deferredRoutine;
                row.deferredContext = source.deferredContext;
                row.moduleNameText = kernelHookResolveModuleForAddress(kModulePathMap, row.deferredRoutine);
                row.statusText = timerDpcEntryStatusText(row.flags, row.moduleNameText);
                row.detailText = kernelText("kernel.timer_dpc.detail", QStringLiteral(
                    "KTIMER / KDPC 详情\n"
                    "CPU: %1:%2\n"
                    "Bucket: %3\n"
                    "Timer: %4\n"
                    "DueTime: %5\n"
                    "Period: %6\n"
                    "类型: %7\n"
                    "DPC: %8\n"
                    "DeferredRoutine: %9\n"
                    "DeferredContext: %10\n"
                    "模块: %11\n"
                    "状态: %12\n"
                    "标志: 0x%13\n\n"
                    "说明: 数据由 R0 使用精确 DynData v4 布局只读遍历当前活动 TimerTable 获得；"
                    "未获取私有 bucket lock，刷新期间并发增删可能导致 partial/corrupt 诊断。"))
                    .arg(row.processorGroup)
                    .arg(row.processorNumber)
                    .arg(row.bucketIndex)
                    .arg(kernelHookFormatAddress(row.timerAddress))
                    .arg(row.dueTime)
                    .arg(row.period)
                    .arg(timerDpcTypeText(row.timerType))
                    .arg(row.dpcAddress == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(row.dpcAddress))
                    .arg(row.deferredRoutine == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(row.deferredRoutine))
                    .arg(row.deferredContext == 0U ? kernelText("kernel.timer_dpc.placeholder.none", QStringLiteral("<无>")) : kernelHookFormatAddress(row.deferredContext))
                    .arg(kernelHookSafeText(row.moduleNameText, kernelText("kernel.hooks.placeholder.not_resolved", QStringLiteral("<未解析>"))))
                    .arg(row.statusText)
                    .arg(static_cast<qulonglong>(row.flags), 8, 16, QChar('0'));
                resultRows.push_back(std::move(row));
            }
        }

        QMetaObject::invokeMethod(guardThis, [guardThis, kEnumResult, resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelTimerDpcEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, kEnumResult, kDeferredRows]() mutable
            {
            std::vector<KernelTimerDpcEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->timerDpcRefreshRunning_.store(false);
            if (guardThis->refreshTimerDpcButton_ != nullptr)
            {
                guardThis->refreshTimerDpcButton_->setEnabled(true);
            }
            if (!kEnumResult.io.ok)
            {
                guardThis->timerDpcStatusLabel_->setText(kernelText("kernel.timer_dpc.status.failed", QStringLiteral("状态：枚举失败")));
                guardThis->timerDpcStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(ksword_theme::errorHex()));
                guardThis->timerDpcDetailEditor_->setText(kernelText("kernel.timer_dpc.error.io", QStringLiteral("KTIMER/DPC 驱动接口调用失败。\nWin32=%1\n详情=%2"))
                    .arg(kEnumResult.io.win32Error)
                    .arg(friendlyKernelHookIoMessage(kEnumResult.io.message)));
                return;
            }

            guardThis->timerDpcRows_ = std::move(resultRows);
            guardThis->rebuildTimerDpcTable(guardThis->timerDpcFilterEdit_->text().trimmed());
            const bool kComplete = kEnumResult.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK && kEnumResult.statusFlags == 0U;
            guardThis->timerDpcStatusLabel_->setText(kernelText("kernel.timer_dpc.status.summary", QStringLiteral(
                "状态：CPU=%1，Bucket=%2/%3，Timer=%4/%5，损坏=%6，读取失败=%7，重复=%8，完整性=%9"))
                .arg(kEnumResult.processorCount)
                .arg(kEnumResult.bucketsVisited)
                .arg(kEnumResult.processorCount * kEnumResult.bucketCount)
                .arg(kEnumResult.entries.size())
                .arg(kEnumResult.totalCount)
                .arg(kEnumResult.corruptBucketCount)
                .arg(kEnumResult.readFailureCount)
                .arg(kEnumResult.duplicateCount)
                .arg(kComplete
                    ? kernelText("kernel.timer_dpc.integrity.complete", QStringLiteral("完整"))
                    : kernelText("kernel.timer_dpc.integrity.partial", QStringLiteral("部分"))));
            guardThis->timerDpcStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(
                kComplete ? ksword_theme::successHex() : ksword_theme::warningHex()));

            if (kEnumResult.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING)
            {
                guardThis->timerDpcDetailEditor_->setText(kernelText("kernel.timer_dpc.error.dyndata", QStringLiteral("当前 ntoskrnl 的 DynData v4 Timer/DPC 布局不可用。请确认偏移包已匹配并下发到驱动。")));
            }
            else if (kEnumResult.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_INVALID_LAYOUT)
            {
                guardThis->timerDpcDetailEditor_->setText(kernelText("kernel.timer_dpc.error.layout", QStringLiteral("驱动拒绝了当前 Timer/DPC 布局，未读取 TimerTable。")));
            }
            else if (guardThis->timerDpcTable_->rowCount() > 0)
            {
                guardThis->timerDpcTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->timerDpcDetailEditor_->setText(kernelText("kernel.timer_dpc.empty", QStringLiteral("当前快照未返回活动 KTIMER 记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-timer-dpc-snapshot-apply"),
                { guardThis->timerDpcTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshTimerDpcAfterDynDataAsync()
{
    // All private fields of TimerTable come from DynData v4. The dynamic offset page is a lazy UI; Timer/DPC cannot rely
    // on the user manually opening this page first. Therefore, profile matching and dispatch must be explicitly completed
    // before business queries. If a DynData task is already running, register it only once for subsequent refreshes.
    if (!dynDataTabInitialized_)
    {
        initializeDynDataTab();
        dynDataTabInitialized_ = true;
    }

    timerDpcRefreshAfterDynData_.store(true);
    refreshDynDataAsync();
}

void KernelDock::rebuildShadowSsdtTable(const QString& filterKeyword)
{
    if (shadowSsdtTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(shadowSsdtDetailEditor_);

    shadowSsdtTable_->setSortingEnabled(false);
    shadowSsdtTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < shadowSsdtRows_.size(); ++sourceIndex)
    {
        const KernelSsdtEntry& entry = shadowSsdtRows_[sourceIndex];
        QStringList matchFields;
        for (int column = 0; column < static_cast<int>(ShadowSsdtColumn::kCount); ++column)
        {
            matchFields.push_back(shadowSsdtColumnText(entry, static_cast<ShadowSsdtColumn>(column)));
        }
        const bool kMatched = filterKeyword.isEmpty() || matchFields.join(' ').contains(filterKeyword, Qt::CaseInsensitive) || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        const int kRowIndex = shadowSsdtTable_->rowCount();
        shadowSsdtTable_->insertRow(kRowIndex);
        for (int column = 0; column < static_cast<int>(ShadowSsdtColumn::kCount); ++column)
        {
            auto* item = new QTableWidgetItem(shadowSsdtColumnText(entry, static_cast<ShadowSsdtColumn>(column)));
            if (column == 0)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            setTableItem(shadowSsdtTable_, kRowIndex, column, item);
        }
    }

    shadowSsdtTable_->setSortingEnabled(true);
}

void KernelDock::rebuildInlineHookTable(const QString& filterKeyword)
{
    if (inlineHookTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(inlineHookDetailEditor_);

    inlineHookTable_->setSortingEnabled(false);
    inlineHookTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < inlineHookRows_.size(); ++sourceIndex)
    {
        const KernelInlineHookEntry& entry = inlineHookRows_[sourceIndex];
        QStringList matchFields;
        for (int column = 0; column < static_cast<int>(InlineHookColumn::kCount); ++column)
        {
            matchFields.push_back(inlineHookColumnText(entry, static_cast<InlineHookColumn>(column)));
        }
        const bool kMatched = filterKeyword.isEmpty() || matchFields.join(' ').contains(filterKeyword, Qt::CaseInsensitive) || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        const int kRowIndex = inlineHookTable_->rowCount();
        inlineHookTable_->insertRow(kRowIndex);
        for (int column = 0; column < static_cast<int>(InlineHookColumn::kCount); ++column)
        {
            auto* item = new QTableWidgetItem(inlineHookColumnText(entry, static_cast<InlineHookColumn>(column)));
            if (column == 0)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            if (column == static_cast<int>(InlineHookColumn::kStatus))
            {
                item->setForeground(QBrush(statusColor(entry.status)));
            }
            if (column == static_cast<int>(InlineHookColumn::kDiskDiff))
            {
                if (!entry.diskBaselineAvailable)
                {
                    item->setForeground(QBrush(ksword_theme::warningColor()));
                }
                else
                {
                    item->setForeground(QBrush(entry.diskBaselineDiffers
                        ? ksword_theme::errorColor()
                        : ksword_theme::successColor()));
                }
            }
            setTableItem(inlineHookTable_, kRowIndex, column, item);
        }
    }

    inlineHookTable_->setSortingEnabled(true);
}

void KernelDock::rebuildIatEatHookTable(const QString& filterKeyword)
{
    if (iatEatHookTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(iatEatHookDetailEditor_);

    iatEatHookTable_->setSortingEnabled(false);
    iatEatHookTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < iatEatHookRows_.size(); ++sourceIndex)
    {
        const KernelIatEatHookEntry& entry = iatEatHookRows_[sourceIndex];
        QStringList matchFields;
        for (int column = 0; column < static_cast<int>(IatEatHookColumn::kCount); ++column)
        {
            matchFields.push_back(iatEatColumnText(entry, static_cast<IatEatHookColumn>(column)));
        }
        const bool kMatched = filterKeyword.isEmpty() || matchFields.join(' ').contains(filterKeyword, Qt::CaseInsensitive) || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        const int kRowIndex = iatEatHookTable_->rowCount();
        iatEatHookTable_->insertRow(kRowIndex);
        for (int column = 0; column < static_cast<int>(IatEatHookColumn::kCount); ++column)
        {
            auto* item = new QTableWidgetItem(iatEatColumnText(entry, static_cast<IatEatHookColumn>(column)));
            if (column == 0)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            if (column == static_cast<int>(IatEatHookColumn::kStatus))
            {
                item->setForeground(QBrush(statusColor(entry.status)));
            }
            setTableItem(iatEatHookTable_, kRowIndex, column, item);
        }
    }

    iatEatHookTable_->setSortingEnabled(true);
}

void KernelDock::rebuildTimerDpcTable(const QString& filterKeyword)
{
    if (timerDpcTable_ == nullptr)
    {
        return;
    }
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(timerDpcDetailEditor_);
    timerDpcTable_->setSortingEnabled(false);
    timerDpcTable_->setRowCount(0);
    for (std::size_t sourceIndex = 0U; sourceIndex < timerDpcRows_.size(); ++sourceIndex)
    {
        const KernelTimerDpcEntry& entry = timerDpcRows_[sourceIndex];
        QStringList fields;
        for (int column = 0; column < static_cast<int>(TimerDpcColumn::kCount); ++column)
        {
            fields.push_back(timerDpcColumnText(entry, static_cast<TimerDpcColumn>(column)));
        }
        if (!filterKeyword.isEmpty() &&
            !fields.join(' ').contains(filterKeyword, Qt::CaseInsensitive) &&
            !entry.detailText.contains(filterKeyword, Qt::CaseInsensitive))
        {
            continue;
        }
        const int kRowIndex = timerDpcTable_->rowCount();
        timerDpcTable_->insertRow(kRowIndex);
        for (int column = 0; column < static_cast<int>(TimerDpcColumn::kCount); ++column)
        {
            auto* item = new QTableWidgetItem(timerDpcColumnText(entry, static_cast<TimerDpcColumn>(column)));
            if (column == 0)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            if (column == static_cast<int>(TimerDpcColumn::kStatus))
            {
                const bool kPartial = (entry.flags & KSWORD_ARK_TIMER_DPC_ENTRY_READ_PARTIAL) != 0U;
                item->setForeground(QBrush(kPartial ? ksword_theme::warningColor() : ksword_theme::successColor()));
            }
            setTableItem(timerDpcTable_, kRowIndex, column, item);
        }
    }
    timerDpcTable_->setSortingEnabled(true);
}

bool KernelDock::currentShadowSsdtSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (shadowSsdtTable_ == nullptr || shadowSsdtTable_->currentRow() < 0)
    {
        return false;
    }
    const QTableWidgetItem* item = shadowSsdtTable_->item(shadowSsdtTable_->currentRow(), 0);
    if (item == nullptr)
    {
        return false;
    }
    sourceIndexOut = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < shadowSsdtRows_.size();
}

bool KernelDock::currentInlineHookSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (inlineHookTable_ == nullptr || inlineHookTable_->currentRow() < 0)
    {
        return false;
    }
    const QTableWidgetItem* item = inlineHookTable_->item(inlineHookTable_->currentRow(), 0);
    if (item == nullptr)
    {
        return false;
    }
    sourceIndexOut = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < inlineHookRows_.size();
}

bool KernelDock::currentIatEatHookSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (iatEatHookTable_ == nullptr || iatEatHookTable_->currentRow() < 0)
    {
        return false;
    }
    const QTableWidgetItem* item = iatEatHookTable_->item(iatEatHookTable_->currentRow(), 0);
    if (item == nullptr)
    {
        return false;
    }
    sourceIndexOut = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < iatEatHookRows_.size();
}

const KernelSsdtEntry* KernelDock::currentShadowSsdtEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentShadowSsdtSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &shadowSsdtRows_[sourceIndex];
}

const KernelInlineHookEntry* KernelDock::currentInlineHookEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentInlineHookSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &inlineHookRows_[sourceIndex];
}

const KernelIatEatHookEntry* KernelDock::currentIatEatHookEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentIatEatHookSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &iatEatHookRows_[sourceIndex];
}

void KernelDock::showShadowSsdtDetailByCurrentRow()
{
    if (shadowSsdtDetailEditor_ == nullptr)
    {
        return;
    }
    const KernelSsdtEntry* entry = currentShadowSsdtEntry();
    shadowSsdtDetailEditor_->setText(entry != nullptr ? entry->detailText : kernelText("kernel.hooks.shadow.detail.initial", QStringLiteral("请选择一条 SSSDT 记录查看详情。")));
}

void KernelDock::restoreSelectedShadowSsdtBaseline()
{
    const KernelSsdtEntry* selected = currentShadowSsdtEntry();
    if (selected == nullptr
        || !selected->cleanBaselineAvailable
        || !selected->cleanBaselineDiffers
        || selected->tableEntryAddress == 0U
        || selected->tableEntrySize == 0U
        || selected->currentTableBytes.size() != selected->tableEntrySize
        || selected->cleanTableBytes.size() != selected->tableEntrySize)
    {
        QMessageBox::information(
            this,
            kernelText(
                "kernel.hooks.shadow.restore.title",
                QStringLiteral("ShadowSSDT 槽位恢复")),
            kernelText(
                "kernel.hooks.shadow.restore.unavailable",
                QStringLiteral(
                    "当前行没有通过映像身份校验的差异基线，不能恢复。")));
        return;
    }

    const KernelSsdtEntry kSnapshot = *selected;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::KernelInlinePatchResult kPreflight =
        kClient.patchInlineHook(
            kSnapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            kSnapshot.tableEntrySize,
            kSnapshot.currentTableBytes,
            kSnapshot.cleanTableBytes,
            0UL);
    if (!kPreflight.io.ok
        || kPreflight.status
            != KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hooks.shadow.restore.title",
                QStringLiteral("ShadowSSDT 槽位恢复")),
            kernelText(
                "kernel.hooks.shadow.restore.preflight_failed",
                QStringLiteral(
                    "R0 恢复预检失败，未写入任何内容。\nWin32=%1\n状态=%2\nNT=0x%3"))
                .arg(kPreflight.io.win32Error)
                .arg(kPreflight.status)
                .arg(static_cast<unsigned long>(kPreflight.lastStatus),
                    8,
                    16,
                    QChar('0')));
        return;
    }

    const QMessageBox::StandardButton kWarning =
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.hooks.shadow.restore.warning.title",
                QStringLiteral("高风险图形系统调用表恢复")),
            kernelText(
                "kernel.hooks.shadow.restore.warning.body",
                QStringLiteral(
                    "即将把 ShadowSSDT[%1] 从当前编码值 0x%2 恢复为磁盘基线 0x%3。\n\n"
                    "R0 写入前会再次逐字节比较当前值；任何并发变化都会拒绝操作。"
                    "错误恢复可能立即导致图形会话或系统崩溃。\n\n映像：%4"))
                .arg(kSnapshot.serviceIndex)
                .arg(static_cast<qulonglong>(kSnapshot.currentTableValue),
                    0,
                    16)
                .arg(static_cast<qulonglong>(kSnapshot.cleanTableValue),
                    0,
                    16)
                .arg(kSnapshot.cleanBaselinePath),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (kWarning != QMessageBox::Yes)
    {
        return;
    }

    bool accepted = false;
    const QString kConfirmation = QInputDialog::getText(
        this,
        kernelText(
            "kernel.hooks.shadow.restore.confirm.title",
            QStringLiteral("最终确认")),
        kernelText(
            "kernel.hooks.shadow.restore.confirm.prompt",
            QStringLiteral("请输入 RESTORE SHADOW SSDT 继续：")),
        QLineEdit::Normal,
        QString(),
        &accepted);
    if (!accepted
        || kConfirmation.trimmed()
            != QStringLiteral("RESTORE SHADOW SSDT"))
    {
        return;
    }

    const ksword::ark::KernelInlinePatchResult kApplied =
        kClient.patchInlineHook(
            kSnapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            kSnapshot.tableEntrySize,
            kSnapshot.currentTableBytes,
            kSnapshot.cleanTableBytes,
            KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE);
    if (!kApplied.io.ok
        || kApplied.status != KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED
        || kApplied.bytesPatched != kSnapshot.tableEntrySize)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.hooks.shadow.restore.title",
                QStringLiteral("ShadowSSDT 槽位恢复")),
            kernelText(
                "kernel.hooks.shadow.restore.failed",
                QStringLiteral(
                    "恢复失败或当前槽值已变化。\nWin32=%1\n状态=%2\nNT=0x%3\n写入=%4"))
                .arg(kApplied.io.win32Error)
                .arg(kApplied.status)
                .arg(static_cast<unsigned long>(kApplied.lastStatus),
                    8,
                    16,
                    QChar('0'))
                .arg(kApplied.bytesPatched));
        refreshShadowSsdtAsync();
        return;
    }

    QMessageBox::information(
        this,
        kernelText(
            "kernel.hooks.shadow.restore.title",
            QStringLiteral("ShadowSSDT 槽位恢复")),
        kernelText(
            "kernel.hooks.shadow.restore.success",
            QStringLiteral(
                "槽位已按验证基线恢复，并已触发重新扫描。")));
    refreshShadowSsdtAsync();
}

void KernelDock::showInlineHookDetailByCurrentRow()
{
    if (inlineHookDetailEditor_ == nullptr)
    {
        return;
    }
    const KernelInlineHookEntry* entry = currentInlineHookEntry();
    inlineHookDetailEditor_->setText(entry != nullptr ? entry->detailText : kernelText("kernel.hooks.inline.detail.initial", QStringLiteral("请选择一条 Inline Hook 记录查看详情。")));
}

void KernelDock::showIatEatHookDetailByCurrentRow()
{
    if (iatEatHookDetailEditor_ == nullptr)
    {
        return;
    }
    const KernelIatEatHookEntry* entry = currentIatEatHookEntry();
    iatEatHookDetailEditor_->setText(entry != nullptr ? entry->detailText : kernelText("kernel.hooks.iat.detail.initial", QStringLiteral("请选择一条 IAT/EAT 记录查看详情。")));
}

void KernelDock::showTimerDpcDetailByCurrentRow()
{
    if (timerDpcDetailEditor_ == nullptr || timerDpcTable_ == nullptr || timerDpcTable_->currentRow() < 0)
    {
        return;
    }
    const QTableWidgetItem* item = timerDpcTable_->item(timerDpcTable_->currentRow(), 0);
    if (item == nullptr)
    {
        return;
    }
    const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    if (kSourceIndex < timerDpcRows_.size())
    {
        timerDpcDetailEditor_->setText(timerDpcRows_[kSourceIndex].detailText);
    }
}

void KernelDock::showTimerDpcContextMenu(const QPoint& localPosition)
{
    if (timerDpcTable_ == nullptr)
    {
        return;
    }
    QTableWidgetItem* clickedItem = timerDpcTable_->itemAt(localPosition);
    const int kClickedRow = clickedItem != nullptr ? clickedItem->row() : timerDpcTable_->currentRow();
    if (clickedItem != nullptr && !clickedItem->isSelected())
    {
        timerDpcTable_->clearSelection();
        timerDpcTable_->setCurrentItem(clickedItem);
        timerDpcTable_->selectRow(kClickedRow);
    }
    const std::vector<std::size_t> kSelectedIndices = selectedSourceIndices(
        timerDpcTable_,
        timerDpcRows_,
        kClickedRow);

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.timer_dpc.menu.refresh", QStringLiteral("刷新 KTIMER/DPC")));
    QAction* copyRowsAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copyDetailAction = menu.addAction(kernelText("kernel.hooks.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyRowsAction->setEnabled(!kSelectedIndices.empty());
    copyDetailAction->setEnabled(!kSelectedIndices.empty());

    const QAction* selectedAction = menu.exec(timerDpcTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == refreshAction)
    {
        refreshTimerDpcAfterDynDataAsync();
    }
    else if (selectedAction == copyRowsAction)
    {
        QStringList lines;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            lines.push_back(timerDpcRowAsTsv(timerDpcRows_[kSourceIndex]));
        }
        kernelHookCopyTextToClipboard(lines.join('\n'));
    }
    else if (selectedAction == copyDetailAction)
    {
        QStringList details;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            details.push_back(timerDpcRows_[kSourceIndex].detailText);
        }
        kernelHookCopyTextToClipboard(details.join(QStringLiteral("\n\n---\n\n")));
    }
}

void KernelDock::showShadowSsdtContextMenu(const QPoint& localPosition)
{
    if (shadowSsdtTable_ == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = shadowSsdtTable_->itemAt(localPosition);
    const int kClickedRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int kClickedColumn = shadowSsdtTable_->columnAt(localPosition.x());
    if (clickedItem != nullptr && !clickedItem->isSelected())
    {
        shadowSsdtTable_->clearSelection();
        shadowSsdtTable_->setCurrentItem(clickedItem);
        shadowSsdtTable_->selectRow(kClickedRow);
    }

    const std::vector<std::size_t> kSelectedIndices = selectedSourceIndices(shadowSsdtTable_, shadowSsdtRows_, kClickedRow >= 0 ? kClickedRow : shadowSsdtTable_->currentRow());
    const bool kHasSelection = !kSelectedIndices.empty();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.hooks.shadow.menu.refresh", QStringLiteral("刷新 SSSDT")));
    QAction* restoreAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        kernelText(
            "kernel.hooks.shadow.menu.restore",
            QStringLiteral("恢复选中槽位为磁盘基线")));
    const KernelSsdtEntry* currentEntry = currentShadowSsdtEntry();
    restoreAction->setEnabled(
        currentEntry != nullptr
        && currentEntry->cleanBaselineAvailable
        && currentEntry->cleanBaselineDiffers
        && kSelectedIndices.size() == 1U);
    menu.addSeparator();
    QMenu* copyMenu = menu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCurrentColumnAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.hooks.menu.copy_current_column", QStringLiteral("复制当前列（选中行）")));
    QAction* copyRowsAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copyRowsWithHeaderAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_header_rows", QStringLiteral("复制表头+选中行（TSV）")));
    QAction* copyDetailAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyMenu->addSeparator();
    QMenu* columnMenu = copyMenu->addMenu(kernelText("kernel.hooks.menu.copy_columns", QStringLiteral("复制指定栏目（选中行）")));
    for (int column = 0; column < static_cast<int>(ShadowSsdtColumn::kCount); ++column)
    {
        QAction* action = columnMenu->addAction(shadowSsdtColumnHeader(static_cast<ShadowSsdtColumn>(column)));
        action->setData(column);
    }
    copyCurrentColumnAction->setEnabled(kHasSelection);
    copyRowsAction->setEnabled(kHasSelection);
    copyRowsWithHeaderAction->setEnabled(kHasSelection);
    copyDetailAction->setEnabled(kHasSelection);
    columnMenu->setEnabled(kHasSelection);

    QAction* selectedAction = menu.exec(shadowSsdtTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == refreshAction)
    {
        refreshShadowSsdtAsync();
        return;
    }
    if (selectedAction == restoreAction)
    {
        restoreSelectedShadowSsdtBaseline();
        return;
    }
    if (!kHasSelection)
    {
        return;
    }

    const auto kCopyColumn = [this, &kSelectedIndices](const ShadowSsdtColumn column) {
        QStringList values;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            values.push_back(shadowSsdtColumnText(shadowSsdtRows_[kSourceIndex], column));
        }
        kernelHookCopyTextToClipboard(values.join('\n'));
    };

    if (selectedAction == copyCurrentColumnAction)
    {
        int column = kClickedColumn >= 0 ? kClickedColumn : shadowSsdtTable_->currentColumn();
        if (column < 0 || column >= static_cast<int>(ShadowSsdtColumn::kCount))
        {
            column = 0;
        }
        kCopyColumn(static_cast<ShadowSsdtColumn>(column));
        return;
    }
    if (selectedAction == copyRowsAction || selectedAction == copyRowsWithHeaderAction)
    {
        QStringList lines;
        if (selectedAction == copyRowsWithHeaderAction)
        {
            lines.push_back(headerAsTsv(static_cast<int>(ShadowSsdtColumn::kCount), [](const int column) {
                return shadowSsdtColumnHeader(static_cast<ShadowSsdtColumn>(column));
            }));
        }
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            lines.push_back(shadowSsdtRowAsTsv(shadowSsdtRows_[kSourceIndex]));
        }
        kernelHookCopyTextToClipboard(lines.join('\n'));
        return;
    }
    if (selectedAction == copyDetailAction)
    {
        QStringList details;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            details.push_back(shadowSsdtRows_[kSourceIndex].detailText);
        }
        kernelHookCopyTextToClipboard(details.join(QStringLiteral("\n\n---\n\n")));
        return;
    }

    if (columnMenu->actions().contains(selectedAction))
    {
        const int kColumn = selectedAction->data().toInt();
        if (kColumn >= 0 && kColumn < static_cast<int>(ShadowSsdtColumn::kCount))
        {
            kCopyColumn(static_cast<ShadowSsdtColumn>(kColumn));
        }
    }
}

void KernelDock::showInlineHookContextMenu(const QPoint& localPosition)
{
    if (inlineHookTable_ == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = inlineHookTable_->itemAt(localPosition);
    const int kClickedRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int kClickedColumn = inlineHookTable_->columnAt(localPosition.x());
    if (clickedItem != nullptr && !clickedItem->isSelected())
    {
        inlineHookTable_->clearSelection();
        inlineHookTable_->setCurrentItem(clickedItem);
        inlineHookTable_->selectRow(kClickedRow);
    }

    const std::vector<std::size_t> kSelectedIndices = selectedSourceIndices(inlineHookTable_, inlineHookRows_, kClickedRow >= 0 ? kClickedRow : inlineHookTable_->currentRow());
    const bool kHasSelection = !kSelectedIndices.empty();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.hooks.inline.menu.rescan", QStringLiteral("重新扫描 Inline Hook")));
    QAction* patchAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), kernelText("kernel.hooks.inline.menu.patch_current", QStringLiteral("NOP 摘除当前 Hook")));
    patchAction->setEnabled(kHasSelection);
    const bool kHasSingleInlineHook = kSelectedIndices.size() == 1U && kSelectedIndices.front() < inlineHookRows_.size();
    const QString kInlineHookDiskPath = kHasSingleInlineHook
        ? inlineHookRows_[kSelectedIndices.front()].diskBaselinePathText.trimmed()
        : QString();
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, kHasSingleInlineHook, kInlineHookDiskPath, kSelectedIndices]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: currently selected row for Inline Hook.
            // Note: Use the disk base path as the module file path; do not infer the path from the module name.
            // Returns: Upload path and source description.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!kHasSingleInlineHook || kSelectedIndices.front() >= inlineHookRows_.size())
            {
                uploadTarget.errorText = kernelText("kernel.hooks.inline.upload.single_row", QStringLiteral("请只选择一条 Inline Hook 记录。"));
                return uploadTarget;
            }
            const KernelInlineHookEntry& entry = inlineHookRows_[kSelectedIndices.front()];
            uploadTarget.filePath = kInlineHookDiskPath;
            uploadTarget.sourceText = kernelText("kernel.hooks.inline.upload.source", QStringLiteral("Inline Hook 模块 %1!%2"))
                .arg(entry.moduleNameText, entry.functionNameText);
            if (uploadTarget.filePath.trimmed().isEmpty())
            {
                uploadTarget.errorText = kernelText("kernel.hooks.inline.upload.no_disk_path", QStringLiteral("当前 Inline Hook 行没有可用磁盘基线路径。"));
            }
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(kHasSingleInlineHook && QFileInfo(kInlineHookDiskPath).isFile());
    }
    menu.addSeparator();
    QMenu* copyMenu = menu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCurrentColumnAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.hooks.menu.copy_current_column", QStringLiteral("复制当前列（选中行）")));
    QAction* copyRowsAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copyRowsWithHeaderAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_header_rows", QStringLiteral("复制表头+选中行（TSV）")));
    QAction* copyDetailAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyMenu->addSeparator();
    QMenu* columnMenu = copyMenu->addMenu(kernelText("kernel.hooks.menu.copy_columns", QStringLiteral("复制指定栏目（选中行）")));
    for (int column = 0; column < static_cast<int>(InlineHookColumn::kCount); ++column)
    {
        QAction* action = columnMenu->addAction(inlineHookColumnHeader(static_cast<InlineHookColumn>(column)));
        action->setData(column);
    }
    copyCurrentColumnAction->setEnabled(kHasSelection);
    copyRowsAction->setEnabled(kHasSelection);
    copyRowsWithHeaderAction->setEnabled(kHasSelection);
    copyDetailAction->setEnabled(kHasSelection);
    columnMenu->setEnabled(kHasSelection);

    QAction* selectedAction = menu.exec(inlineHookTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == refreshAction)
    {
        refreshInlineHooksAsync();
        return;
    }
    if (selectedAction == patchAction)
    {
        patchSelectedInlineHookWithNop();
        return;
    }
    if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    if (!kHasSelection)
    {
        return;
    }

    const auto kCopyColumn = [this, &kSelectedIndices](const InlineHookColumn column) {
        QStringList values;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            values.push_back(inlineHookColumnText(inlineHookRows_[kSourceIndex], column));
        }
        kernelHookCopyTextToClipboard(values.join('\n'));
    };

    if (selectedAction == copyCurrentColumnAction)
    {
        int column = kClickedColumn >= 0 ? kClickedColumn : inlineHookTable_->currentColumn();
        if (column < 0 || column >= static_cast<int>(InlineHookColumn::kCount))
        {
            column = 0;
        }
        kCopyColumn(static_cast<InlineHookColumn>(column));
        return;
    }
    if (selectedAction == copyRowsAction || selectedAction == copyRowsWithHeaderAction)
    {
        QStringList lines;
        if (selectedAction == copyRowsWithHeaderAction)
        {
            lines.push_back(headerAsTsv(static_cast<int>(InlineHookColumn::kCount), [](const int column) {
                return inlineHookColumnHeader(static_cast<InlineHookColumn>(column));
            }));
        }
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            lines.push_back(inlineHookRowAsTsv(inlineHookRows_[kSourceIndex]));
        }
        kernelHookCopyTextToClipboard(lines.join('\n'));
        return;
    }
    if (selectedAction == copyDetailAction)
    {
        QStringList details;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            details.push_back(inlineHookRows_[kSourceIndex].detailText);
        }
        kernelHookCopyTextToClipboard(details.join(QStringLiteral("\n\n---\n\n")));
        return;
    }
    if (columnMenu->actions().contains(selectedAction))
    {
        const int kColumn = selectedAction->data().toInt();
        if (kColumn >= 0 && kColumn < static_cast<int>(InlineHookColumn::kCount))
        {
            kCopyColumn(static_cast<InlineHookColumn>(kColumn));
        }
    }
}

void KernelDock::showIatEatHookContextMenu(const QPoint& localPosition)
{
    if (iatEatHookTable_ == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = iatEatHookTable_->itemAt(localPosition);
    const int kClickedRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int kClickedColumn = iatEatHookTable_->columnAt(localPosition.x());
    if (clickedItem != nullptr && !clickedItem->isSelected())
    {
        iatEatHookTable_->clearSelection();
        iatEatHookTable_->setCurrentItem(clickedItem);
        iatEatHookTable_->selectRow(kClickedRow);
    }

    const std::vector<std::size_t> kSelectedIndices = selectedSourceIndices(iatEatHookTable_, iatEatHookRows_, kClickedRow >= 0 ? kClickedRow : iatEatHookTable_->currentRow());
    const bool kHasSelection = !kSelectedIndices.empty();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.hooks.iat.menu.rescan", QStringLiteral("重新扫描 IAT/EAT")));
    menu.addSeparator();
    QMenu* copyMenu = menu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCurrentColumnAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.hooks.menu.copy_current_column", QStringLiteral("复制当前列（选中行）")));
    QAction* copyRowsAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copyRowsWithHeaderAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_header_rows", QStringLiteral("复制表头+选中行（TSV）")));
    QAction* copyDetailAction = copyMenu->addAction(kernelText("kernel.hooks.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyMenu->addSeparator();
    QMenu* columnMenu = copyMenu->addMenu(kernelText("kernel.hooks.menu.copy_columns", QStringLiteral("复制指定栏目（选中行）")));
    for (int column = 0; column < static_cast<int>(IatEatHookColumn::kCount); ++column)
    {
        QAction* action = columnMenu->addAction(iatEatColumnHeader(static_cast<IatEatHookColumn>(column)));
        action->setData(column);
    }
    copyCurrentColumnAction->setEnabled(kHasSelection);
    copyRowsAction->setEnabled(kHasSelection);
    copyRowsWithHeaderAction->setEnabled(kHasSelection);
    copyDetailAction->setEnabled(kHasSelection);
    columnMenu->setEnabled(kHasSelection);

    QAction* selectedAction = menu.exec(iatEatHookTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == refreshAction)
    {
        refreshIatEatHooksAsync();
        return;
    }
    if (!kHasSelection)
    {
        return;
    }

    const auto kCopyColumn = [this, &kSelectedIndices](const IatEatHookColumn column) {
        QStringList values;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            values.push_back(iatEatColumnText(iatEatHookRows_[kSourceIndex], column));
        }
        kernelHookCopyTextToClipboard(values.join('\n'));
    };

    if (selectedAction == copyCurrentColumnAction)
    {
        int column = kClickedColumn >= 0 ? kClickedColumn : iatEatHookTable_->currentColumn();
        if (column < 0 || column >= static_cast<int>(IatEatHookColumn::kCount))
        {
            column = 0;
        }
        kCopyColumn(static_cast<IatEatHookColumn>(column));
        return;
    }
    if (selectedAction == copyRowsAction || selectedAction == copyRowsWithHeaderAction)
    {
        QStringList lines;
        if (selectedAction == copyRowsWithHeaderAction)
        {
            lines.push_back(headerAsTsv(static_cast<int>(IatEatHookColumn::kCount), [](const int column) {
                return iatEatColumnHeader(static_cast<IatEatHookColumn>(column));
            }));
        }
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            lines.push_back(iatEatRowAsTsv(iatEatHookRows_[kSourceIndex]));
        }
        kernelHookCopyTextToClipboard(lines.join('\n'));
        return;
    }
    if (selectedAction == copyDetailAction)
    {
        QStringList details;
        for (const std::size_t kSourceIndex : kSelectedIndices)
        {
            details.push_back(iatEatHookRows_[kSourceIndex].detailText);
        }
        kernelHookCopyTextToClipboard(details.join(QStringLiteral("\n\n---\n\n")));
        return;
    }
    if (columnMenu->actions().contains(selectedAction))
    {
        const int kColumn = selectedAction->data().toInt();
        if (kColumn >= 0 && kColumn < static_cast<int>(IatEatHookColumn::kCount))
        {
            kCopyColumn(static_cast<IatEatHookColumn>(kColumn));
        }
    }
}

void KernelDock::patchSelectedInlineHookWithNop()
{
    const KernelInlineHookEntry* entry = currentInlineHookEntry();
    if (entry == nullptr)
    {
        QMessageBox::warning(this, kernelText("kernel.hooks.inline.patch.title", QStringLiteral("Inline Hook 摘除")), kernelText("kernel.hooks.inline.patch.no_selection", QStringLiteral("请先选择一条 Inline Hook 记录。")));
        return;
    }

    const std::uint32_t kPatchBytes = inlineHookPatchLength(entry->hookType, entry->currentByteCount);
    if (kPatchBytes == 0U)
    {
        QMessageBox::warning(
            this,
            kernelText("kernel.hooks.inline.patch.title", QStringLiteral("Inline Hook 摘除")),
            kernelText("kernel.hooks.inline.patch.unsuitable", QStringLiteral("当前 Hook 类型不适合自动 NOP 摘除：%1")).arg(entry->hookTypeText));
        return;
    }

    const QMessageBox::StandardButton kFirstConfirm = QMessageBox::warning(
        this,
        kernelText("kernel.hooks.inline.patch.confirm.title", QStringLiteral("Inline Hook 摘除确认")),
        kernelText("kernel.hooks.inline.patch.confirm.message", QStringLiteral("将对内核函数写入 NOP 补丁。\n\n模块: %1\n函数: %2\n地址: %3\n类型: %4\n字节数: %5\n\n普通请求会先提交给 R0，驱动预计会返回需要强制确认。是否继续？"))
        .arg(kernelHookSafeText(entry->moduleNameText))
        .arg(kernelHookSafeText(entry->functionNameText))
        .arg(kernelHookFormatAddress(entry->functionAddress))
        .arg(entry->hookTypeText)
        .arg(kPatchBytes),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFirstConfirm != QMessageBox::Yes)
    {
        return;
    }

    ksword::ark::DriverClient driverClient;
    ksword::ark::KernelInlinePatchResult patchResult = driverClient.patchInlineHook(
        entry->functionAddress,
        KSWORD_ARK_INLINE_PATCH_MODE_NOP_BRANCH,
        kPatchBytes,
        entry->currentBytes,
        {},
        0UL);
    if (!patchResult.io.ok)
    {
        QMessageBox::warning(
            this,
            kernelText("kernel.hooks.inline.patch.title", QStringLiteral("Inline Hook 摘除")),
            kernelText("kernel.hooks.inline.patch.request_failed", QStringLiteral("普通摘除请求失败：\n%1")).arg(friendlyKernelHookIoMessage(patchResult.io.message)));
        return;
    }

    if (patchResult.status == KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED)
    {
        QMessageBox warningBox(this);
        warningBox.setIcon(QMessageBox::Warning);
        warningBox.setWindowTitle(kernelText("kernel.hooks.inline.patch.force.title", QStringLiteral("强制 Inline Hook 摘除")));
        warningBox.setText(kernelText("kernel.hooks.inline.patch.force.rejected", QStringLiteral("R0 已拒绝普通内核补丁请求。")));
        warningBox.setInformativeText(
            kernelText("kernel.hooks.inline.patch.force.message", QStringLiteral("目标函数: %1!%2\n地址: %3\n补丁长度: %4 字节\nR0状态: %5\nLastStatus: %6\n\n强制继续会修改内核代码页，只应在确认目标和字节快照无误时使用。"))
            .arg(kernelHookSafeText(entry->moduleNameText))
            .arg(kernelHookSafeText(entry->functionNameText))
            .arg(kernelHookFormatAddress(entry->functionAddress))
            .arg(kPatchBytes)
            .arg(kernelHookStatusText(patchResult.status))
            .arg(kernelHookFormatNtStatus(patchResult.lastStatus)));
        warningBox.setStandardButtons(QMessageBox::Cancel);
        warningBox.setDefaultButton(QMessageBox::Cancel);
        QPushButton* forceButton = warningBox.addButton(kernelText("kernel.hooks.inline.patch.force.continue", QStringLiteral("强制继续")), QMessageBox::DestructiveRole);
        warningBox.exec();
        if (warningBox.clickedButton() != forceButton)
        {
            if (inlineHookStatusLabel_ != nullptr)
            {
                inlineHookStatusLabel_->setText(kernelText("kernel.hooks.inline.patch.force.cancelled", QStringLiteral("状态：用户取消强制 Inline Hook 摘除")));
            }
            return;
        }

        patchResult = driverClient.patchInlineHook(
            entry->functionAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_NOP_BRANCH,
            kPatchBytes,
            entry->currentBytes,
            {},
            KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE);
    }

    const QString kResultText = kernelText("kernel.hooks.inline.patch.result", QStringLiteral(
        "Inline Hook 摘除结果\n"
        "函数: %1!%2\n"
        "地址: %3\n"
        "状态: %4\n"
        "写入字节: %5\n"
        "LastStatus: %6\n"
        "R3信息: %7"))
        .arg(kernelHookSafeText(entry->moduleNameText))
        .arg(kernelHookSafeText(entry->functionNameText))
        .arg(kernelHookFormatAddress(entry->functionAddress))
        .arg(kernelHookStatusText(patchResult.status))
        .arg(patchResult.bytesPatched)
        .arg(kernelHookFormatNtStatus(patchResult.lastStatus))
        .arg(friendlyKernelHookIoMessage(patchResult.io.message));

    if (inlineHookDetailEditor_ != nullptr)
    {
        inlineHookDetailEditor_->setText(kResultText);
    }
    if (inlineHookStatusLabel_ != nullptr)
    {
        inlineHookStatusLabel_->setText(kernelText("kernel.hooks.inline.patch.status", QStringLiteral("状态：%1，写入 %2 字节"))
            .arg(kernelHookStatusText(patchResult.status))
            .arg(patchResult.bytesPatched));
        inlineHookStatusLabel_->setStyleSheet(kernelHookStatusLabelStyle(
            patchResult.status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED ? ksword_theme::successHex() : ksword_theme::errorHex()));
    }

    if (patchResult.status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED)
    {
        refreshInlineHooksAsync();
    }
    else
    {
        QMessageBox::warning(this, kernelText("kernel.hooks.inline.patch.title", QStringLiteral("Inline Hook 摘除")), kResultText);
    }
}
