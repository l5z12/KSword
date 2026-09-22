#include "KernelCleanImageBaseline.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <winternl.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSet>
#include <QStringList>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr unsigned long kSystemModuleInformationClass = 11UL;

    QString baselineText(const QString& sourceText)
    {
        return ks::i18n::sourceText(sourceText);
    }

    struct KernelModuleRow
    {
        HANDLE section;
        PVOID mappedBase;
        PVOID imageBase;
        ULONG imageSize;
        ULONG flags;
        USHORT loadOrderIndex;
        USHORT initOrderIndex;
        USHORT loadCount;
        USHORT fileNameOffset;
        UCHAR fullPathName[256];
    };

    struct KernelModuleList
    {
        ULONG count;
        KernelModuleRow rows[1];
    };

    struct LoadedModule
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        QString ntPath;
        QString filePath;
        QString name;
    };

    using NtQuerySystemInformationFunction =
        NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    class ReadOnlyTrustFile final
    {
    public:
        explicit ReadOnlyTrustFile(const QString& path)
            : handle(::CreateFileW(
                  reinterpret_cast<LPCWSTR>(path.utf16()),
                  GENERIC_READ,
                  FILE_SHARE_READ,
                  nullptr,
                  OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                  nullptr))
        {
        }

        ~ReadOnlyTrustFile()
        {
            if (handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle);
            }
        }

        ReadOnlyTrustFile(const ReadOnlyTrustFile&) = delete;
        ReadOnlyTrustFile& operator=(const ReadOnlyTrustFile&) = delete;

        HANDLE handle = INVALID_HANDLE_VALUE;
    };

    class CatalogAdminContext final
    {
    public:
        ~CatalogAdminContext()
        {
            if (handle != nullptr)
            {
                ::CryptCATAdminReleaseContext(handle, 0);
            }
        }

        CatalogAdminContext(const CatalogAdminContext&) = delete;
        CatalogAdminContext& operator=(const CatalogAdminContext&) = delete;
        CatalogAdminContext() = default;

        HCATADMIN handle = nullptr;
    };

    void initializeStrictTrustData(WINTRUST_DATA& trustData)
    {
        trustData = WINTRUST_DATA{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwProvFlags =
            WTD_SAFER_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL |
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            WTD_DISABLE_MD2_MD4;
    }

    LONG runWinTrustAndClose(WINTRUST_DATA& trustData)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG kStatus =
            ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return kStatus;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& hashOut)
    {
        LARGE_INTEGER fileStart{};
        hashOut.clear();
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        DWORD hashBytes = 0U;
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                nullptr,
                0) ||
            hashBytes == 0U)
        {
            return false;
        }
        hashOut.resize(hashBytes);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                hashOut.data(),
                0))
        {
            hashOut.clear();
            return false;
        }
        hashOut.resize(hashBytes);
        return true;
    }

    bool verifyCatalogTrust(
        const QString& path,
        const HANDLE fileHandle)
    {
        CatalogAdminContext catalogAdmin;
        GUID driverActionVerify = DRIVER_ACTION_VERIFY;
        if (!::CryptCATAdminAcquireContext2(
                &catalogAdmin.handle,
                &driverActionVerify,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0))
        {
            return false;
        }

        std::vector<BYTE> hash;
        if (!calculateCatalogHash(
                catalogAdmin.handle,
                fileHandle,
                hash))
        {
            return false;
        }
        const QByteArray kFileHashBytes(
            reinterpret_cast<const char*>(hash.data()),
            static_cast<qsizetype>(hash.size()));
        const QByteArray kMemberTagBytes =
            kFileHashBytes.toHex().toUpper();
        const QString kMemberTag = QString::fromLatin1(
            kMemberTagBytes.constData(),
            kMemberTagBytes.size());

        HCATINFO previousCatalog = nullptr;
        for (;;)
        {
            HCATINFO currentCatalog =
                ::CryptCATAdminEnumCatalogFromHash(
                    catalogAdmin.handle,
                    hash.data(),
                    static_cast<DWORD>(hash.size()),
                    0,
                    &previousCatalog);
            if (currentCatalog == nullptr)
            {
                // Enum consumes/releases the previous context when advancing.
                // Natural exhaustion therefore leaves no caller-owned HCATINFO.
                return false;
            }
            previousCatalog = currentCatalog;

            CATALOG_INFO catalogInfo{};
            catalogInfo.cbStruct = sizeof(catalogInfo);
            if (!::CryptCATCatalogInfoFromContext(
                    currentCatalog,
                    &catalogInfo,
                    0))
            {
                continue;
            }

            WINTRUST_CATALOG_INFO trustCatalogInfo{};
            trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
            trustCatalogInfo.pcwszCatalogFilePath =
                catalogInfo.wszCatalogFile;
            trustCatalogInfo.pcwszMemberTag =
                reinterpret_cast<LPCWSTR>(kMemberTag.utf16());
            trustCatalogInfo.pcwszMemberFilePath =
                reinterpret_cast<LPCWSTR>(path.utf16());
            trustCatalogInfo.hMemberFile = fileHandle;
            trustCatalogInfo.pbCalculatedFileHash = hash.data();
            trustCatalogInfo.cbCalculatedFileHash =
                static_cast<DWORD>(hash.size());
            trustCatalogInfo.hCatAdmin = catalogAdmin.handle;

            LARGE_INTEGER fileStart{};
            ::SetFilePointerEx(
                fileHandle,
                fileStart,
                nullptr,
                FILE_BEGIN);
            WINTRUST_DATA trustData{};
            initializeStrictTrustData(trustData);
            trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
            trustData.pCatalog = &trustCatalogInfo;
            if (runWinTrustAndClose(trustData) == ERROR_SUCCESS)
            {
                ::CryptCATAdminReleaseCatalogContext(
                    catalogAdmin.handle,
                    currentCatalog,
                    0);
                previousCatalog = nullptr;
                return true;
            }
        }
    }

    bool readDiskImage(
        const HANDLE fileHandle,
        QByteArray& bytesOut)
    {
        bytesOut.clear();
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER fileSize{};
        constexpr LONGLONG kMaximumImageBytes =
            512LL * 1024LL * 1024LL;
        if (!::GetFileSizeEx(fileHandle, &fileSize) ||
            fileSize.QuadPart < 0 ||
            fileSize.QuadPart > kMaximumImageBytes ||
            fileSize.QuadPart >
                static_cast<LONGLONG>(
                    std::numeric_limits<qsizetype>::max()))
        {
            return false;
        }
        LARGE_INTEGER fileStart{};
        if (!::SetFilePointerEx(
                fileHandle,
                fileStart,
                nullptr,
                FILE_BEGIN))
        {
            return false;
        }

        bytesOut.resize(static_cast<qsizetype>(fileSize.QuadPart));
        qsizetype offset = 0;
        while (offset < bytesOut.size())
        {
            const qsizetype kRemaining = bytesOut.size() - offset;
            const DWORD kRequestBytes = static_cast<DWORD>(
                std::min<qsizetype>(kRemaining, MAXDWORD));
            DWORD bytesRead = 0U;
            if (!::ReadFile(
                    fileHandle,
                    bytesOut.data() + offset,
                    kRequestBytes,
                    &bytesRead,
                    nullptr) ||
                bytesRead == 0U)
            {
                bytesOut.clear();
                return false;
            }
            offset += static_cast<qsizetype>(bytesRead);
        }
        return true;
    }

    bool readTrustedDiskImage(
        const QString& path,
        const HANDLE fileHandle,
        QByteArray& bytesOut)
    {
        bytesOut.clear();
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath =
            reinterpret_cast<LPCWSTR>(path.utf16());
        fileInfo.hFile = fileHandle;

        WINTRUST_DATA trustData{};
        initializeStrictTrustData(trustData);
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        const bool kTrusted =
            runWinTrustAndClose(trustData) == ERROR_SUCCESS ||
            verifyCatalogTrust(path, fileHandle);
        return kTrusted &&
            readDiskImage(fileHandle, bytesOut);
    }

    QString normalizeKernelPath(const QString& input)
    {
        QString path = input.trimmed();
        if (path.isEmpty())
        {
            return {};
        }
        path.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (path.startsWith(QStringLiteral("\\SystemRoot\\"),
                Qt::CaseInsensitive))
        {
            wchar_t windowsDirectory[MAX_PATH] = {};
            const UINT kLength = ::GetWindowsDirectoryW(
                windowsDirectory,
                static_cast<UINT>(std::size(windowsDirectory)));
            if (kLength != 0U
                && kLength < static_cast<UINT>(std::size(windowsDirectory)))
            {
                return QDir::cleanPath(
                    QString::fromWCharArray(windowsDirectory)
                    + path.mid(11));
            }
        }
        if (path.startsWith(QStringLiteral("\\??\\")))
        {
            return QDir::cleanPath(path.mid(4));
        }
        if (path.size() >= 3
            && path.at(1) == QLatin1Char(':')
            && path.at(2) == QLatin1Char('\\'))
        {
            return QDir::cleanPath(path);
        }
        if (path.startsWith(QStringLiteral("\\Device\\"),
                Qt::CaseInsensitive))
        {
            for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
            {
                wchar_t driveName[3] = { drive, L':', L'\0' };
                std::vector<wchar_t> target(32768U, L'\0');
                const DWORD kChars = ::QueryDosDeviceW(
                    driveName,
                    target.data(),
                    static_cast<DWORD>(target.size()));
                if (kChars == 0U)
                {
                    continue;
                }
                const QString kDevicePrefix =
                    QString::fromWCharArray(target.data());
                if (path.startsWith(kDevicePrefix, Qt::CaseInsensitive))
                {
                    return QDir::cleanPath(
                        QString::fromWCharArray(driveName)
                        + path.mid(kDevicePrefix.size()));
                }
            }
        }
        return QDir::cleanPath(path);
    }

    bool enumerateLoadedModules(
        std::vector<LoadedModule>& modulesOut,
        QString& errorTextOut)
    {
        modulesOut.clear();
        errorTextOut.clear();
        const HMODULE kNtdll = ::GetModuleHandleW(L"ntdll.dll");
        if (kNtdll == nullptr)
        {
            errorTextOut = QStringLiteral("无法获取 ntdll 模块句柄。");
            return false;
        }
        const auto kQuery = reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(kNtdll, "NtQuerySystemInformation"));
        if (kQuery == nullptr)
        {
            errorTextOut =
                QStringLiteral("无法解析系统模块枚举入口。");
            return false;
        }

        ULONG required = 0U;
        NTSTATUS status = kQuery(
            kSystemModuleInformationClass,
            nullptr,
            0U,
            &required);
        if (required < sizeof(KernelModuleList))
        {
            required = 1024U * 1024U;
        }
        for (int attempt = 0; attempt < 4; ++attempt)
        {
            std::vector<std::uint8_t> buffer(
                static_cast<std::size_t>(required) + 64U * 1024U,
                0U);
            ULONG returned = 0U;
            status = kQuery(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &returned);
            if (status == static_cast<NTSTATUS>(0xC0000004L))
            {
                required = std::max<ULONG>(
                    returned,
                    static_cast<ULONG>(buffer.size() * 2U));
                continue;
            }
            if (status < 0)
            {
                errorTextOut = QStringLiteral(
                    "系统模块枚举失败，NTSTATUS=0x%1。")
                    .arg(static_cast<unsigned long>(status),
                        8,
                        16,
                        QChar('0'));
                return false;
            }

            const auto* list =
                reinterpret_cast<const KernelModuleList*>(buffer.data());
            const std::size_t kMaximumRows =
                (buffer.size() - offsetof(KernelModuleList, rows))
                / sizeof(KernelModuleRow);
            const std::size_t kRows = std::min<std::size_t>(
                list->count,
                kMaximumRows);
            modulesOut.reserve(kRows);
            for (std::size_t index = 0; index < kRows; ++index)
            {
                const KernelModuleRow& source = list->rows[index];
                LoadedModule module;
                module.base = reinterpret_cast<std::uintptr_t>(
                    source.imageBase);
                module.size = source.imageSize;
                module.ntPath = QString::fromLocal8Bit(
                    reinterpret_cast<const char*>(source.fullPathName),
                    static_cast<int>(strnlen_s(
                        reinterpret_cast<const char*>(
                            source.fullPathName),
                        sizeof(source.fullPathName))));
                module.filePath = normalizeKernelPath(module.ntPath);
                const int kNameOffset = std::min<int>(
                    source.fileNameOffset,
                    module.ntPath.size());
                module.name = module.ntPath.mid(kNameOffset);
                modulesOut.push_back(std::move(module));
            }
            return true;
        }
        errorTextOut = QStringLiteral("系统模块列表在重试后仍持续变化。");
        return false;
    }

    const LoadedModule* moduleForAddress(
        const std::vector<LoadedModule>& modules,
        const std::uint64_t address)
    {
        for (const LoadedModule& module : modules)
        {
            if (address >= module.base
                && address - module.base < module.size)
            {
                return &module;
            }
        }
        return nullptr;
    }

    template <typename T>
    bool copyStructure(
        const QByteArray& bytes,
        const std::uint64_t offset,
        T& valueOut)
    {
        if (offset > static_cast<std::uint64_t>(bytes.size())
            || sizeof(T)
                > static_cast<std::uint64_t>(bytes.size()) - offset)
        {
            return false;
        }
        std::memcpy(
            &valueOut,
            bytes.constData() + static_cast<qsizetype>(offset),
            sizeof(T));
        return true;
    }

    struct PeIdentity
    {
        bool valid = false;
        std::uint16_t machine = 0;
        std::uint32_t timestamp = 0;
        std::uint32_t sizeOfImage = 0;
        std::uint32_t checkSum = 0;
        std::uint32_t sizeOfHeaders = 0;
        std::uint32_t relocationRva = 0;
        std::uint32_t relocationSize = 0;
        std::uint64_t preferredImageBase = 0;
        std::uint64_t sectionTableOffset = 0;
        std::uint16_t sectionCount = 0;
    };

    bool parsePeIdentity(
        const QByteArray& bytes,
        PeIdentity& identityOut,
        QString& errorTextOut)
    {
        identityOut = {};
        IMAGE_DOS_HEADER dos = {};
        if (!copyStructure(bytes, 0U, dos)
            || dos.e_magic != IMAGE_DOS_SIGNATURE
            || dos.e_lfanew <= 0)
        {
            errorTextOut = QStringLiteral("映像 DOS 头无效。");
            return false;
        }

        const std::uint64_t kNtOffset =
            static_cast<std::uint32_t>(dos.e_lfanew);
        DWORD signature = 0U;
        IMAGE_FILE_HEADER fileHeader = {};
        if (!copyStructure(bytes, kNtOffset, signature)
            || signature != IMAGE_NT_SIGNATURE
            || !copyStructure(
                bytes,
                kNtOffset + sizeof(signature),
                fileHeader))
        {
            errorTextOut = QStringLiteral("映像 PE 头无效。");
            return false;
        }

        const std::uint64_t kOptionalOffset =
            kNtOffset + sizeof(signature) + sizeof(fileHeader);
        WORD magic = 0U;
        if (!copyStructure(bytes, kOptionalOffset, magic))
        {
            errorTextOut = QStringLiteral("映像可选头缺失。");
            return false;
        }
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 optional = {};
            if (!copyStructure(bytes, kOptionalOffset, optional))
            {
                errorTextOut = QStringLiteral("PE32+ 可选头不完整。");
                return false;
            }
            identityOut.sizeOfImage = optional.SizeOfImage;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
            identityOut.preferredImageBase = optional.ImageBase;
            if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
            {
                identityOut.relocationRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .VirtualAddress;
                identityOut.relocationSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .Size;
            }
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 optional = {};
            if (!copyStructure(bytes, kOptionalOffset, optional))
            {
                errorTextOut = QStringLiteral("PE32 可选头不完整。");
                return false;
            }
            identityOut.sizeOfImage = optional.SizeOfImage;
            identityOut.checkSum = optional.CheckSum;
            identityOut.sizeOfHeaders = optional.SizeOfHeaders;
            identityOut.preferredImageBase = optional.ImageBase;
            if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
            {
                identityOut.relocationRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .VirtualAddress;
                identityOut.relocationSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                        .Size;
            }
        }
        else
        {
            errorTextOut = QStringLiteral("映像可选头类型未知。");
            return false;
        }

        if (fileHeader.NumberOfSections == 0U
            || fileHeader.NumberOfSections > 128U)
        {
            errorTextOut = QStringLiteral("映像区段数量异常。");
            return false;
        }
        identityOut.timestamp = fileHeader.TimeDateStamp;
        identityOut.machine = fileHeader.Machine;
        identityOut.sectionCount = fileHeader.NumberOfSections;
        identityOut.sectionTableOffset =
            kOptionalOffset + fileHeader.SizeOfOptionalHeader;
        identityOut.valid = true;
        return true;
    }

    std::vector<std::uint8_t> loadedHeaderBytes(
        std::uint64_t moduleBase,
        QString& errorTextOut);

    bool mapPeImage(
        const QByteArray& diskImage,
        const PeIdentity& identity,
        const std::uint64_t loadedBase,
        std::vector<std::uint8_t>& mappedImageOut,
        bool& relocationAppliedOut,
        QString& errorTextOut)
    {
        constexpr std::uint32_t kMaximumMappedImageBytes =
            512U * 1024U * 1024U;
        mappedImageOut.clear();
        relocationAppliedOut = false;
        if (!identity.valid
            || identity.sizeOfImage == 0U
            || identity.sizeOfImage > kMaximumMappedImageBytes)
        {
            errorTextOut =
                baselineText(QStringLiteral("映像 SizeOfImage 无效或超过取证上限。"));
            return false;
        }

        mappedImageOut.assign(identity.sizeOfImage, 0U);
        const std::size_t kHeaderBytes = std::min<std::size_t>(
            {
                mappedImageOut.size(),
                static_cast<std::size_t>(diskImage.size()),
                static_cast<std::size_t>(identity.sizeOfHeaders)
            });
        if (kHeaderBytes == 0U)
        {
            errorTextOut = baselineText(QStringLiteral("映像头范围为空。"));
            return false;
        }
        std::memcpy(
            mappedImageOut.data(),
            diskImage.constData(),
            kHeaderBytes);

        for (std::uint16_t index = 0;
             index < identity.sectionCount;
             ++index)
        {
            IMAGE_SECTION_HEADER section = {};
            const std::uint64_t kSectionOffset =
                identity.sectionTableOffset
                + static_cast<std::uint64_t>(index)
                    * sizeof(IMAGE_SECTION_HEADER);
            if (!copyStructure(diskImage, kSectionOffset, section))
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段表读取失败。"));
                return false;
            }
            if (section.SizeOfRawData == 0U)
            {
                continue;
            }
            if (section.VirtualAddress >= mappedImageOut.size()
                || section.PointerToRawData
                    >= static_cast<std::uint32_t>(diskImage.size()))
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段范围越界。"));
                return false;
            }
            const std::size_t kMappedRemaining =
                mappedImageOut.size() - section.VirtualAddress;
            const std::size_t kFileRemaining =
                static_cast<std::size_t>(diskImage.size())
                - section.PointerToRawData;
            const std::size_t kCopyBytes = std::min<std::size_t>(
                {
                    static_cast<std::size_t>(section.SizeOfRawData),
                    kMappedRemaining,
                    kFileRemaining
                });
            if (kCopyBytes != section.SizeOfRawData)
            {
                errorTextOut =
                    baselineText(QStringLiteral("映像区段原始数据被截断。"));
                return false;
            }
            std::memcpy(
                mappedImageOut.data() + section.VirtualAddress,
                diskImage.constData() + section.PointerToRawData,
                kCopyBytes);
        }

        const std::uint64_t kRelocationDelta =
            loadedBase - identity.preferredImageBase;
        if (kRelocationDelta == 0U)
        {
            return true;
        }
        if (identity.relocationRva == 0U
            || identity.relocationSize < sizeof(IMAGE_BASE_RELOCATION)
            || identity.relocationRva >= mappedImageOut.size()
            || identity.relocationSize
                > mappedImageOut.size() - identity.relocationRva)
        {
            errorTextOut = baselineText(QStringLiteral("映像发生基址变化，但重定位目录不可用。"));
            return false;
        }

        std::uint32_t consumed = 0U;
        while (consumed < identity.relocationSize)
        {
            if (identity.relocationSize - consumed
                    < sizeof(IMAGE_BASE_RELOCATION))
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位块头被截断。"));
                return false;
            }
            const std::size_t kBlockOffset =
                static_cast<std::size_t>(identity.relocationRva)
                + consumed;
            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(
                &block,
                mappedImageOut.data() + kBlockOffset,
                sizeof(block));
            if (block.SizeOfBlock < sizeof(block)
                || block.SizeOfBlock
                    > identity.relocationSize - consumed)
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位块长度无效。"));
                return false;
            }
            const std::uint32_t kEntryBytes =
                block.SizeOfBlock - sizeof(block);
            if ((kEntryBytes % sizeof(WORD)) != 0U)
            {
                errorTextOut =
                    baselineText(QStringLiteral("PE 重定位项未按 WORD 对齐。"));
                return false;
            }
            const std::uint32_t kEntryCount =
                kEntryBytes / sizeof(WORD);
            for (std::uint32_t entryIndex = 0U;
                 entryIndex < kEntryCount;
                 ++entryIndex)
            {
                WORD entry = 0U;
                std::memcpy(
                    &entry,
                    mappedImageOut.data()
                        + kBlockOffset + sizeof(block)
                        + entryIndex * sizeof(WORD),
                    sizeof(entry));
                const WORD kType = static_cast<WORD>(entry >> 12);
                const std::uint64_t kTargetRva =
                    static_cast<std::uint64_t>(block.VirtualAddress)
                    + (entry & 0x0FFFU);
                if (kType == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                if (kType == IMAGE_REL_BASED_DIR64)
                {
                    if (kTargetRva > mappedImageOut.size()
                        || sizeof(std::uint64_t)
                            > mappedImageOut.size()
                                - static_cast<std::size_t>(kTargetRva))
                    {
                        errorTextOut =
                            baselineText(QStringLiteral("DIR64 重定位目标越界。"));
                        return false;
                    }
                    std::uint64_t value = 0U;
                    std::memcpy(
                        &value,
                        mappedImageOut.data()
                            + static_cast<std::size_t>(kTargetRva),
                        sizeof(value));
                    value += kRelocationDelta;
                    std::memcpy(
                        mappedImageOut.data()
                            + static_cast<std::size_t>(kTargetRva),
                        &value,
                        sizeof(value));
                    relocationAppliedOut = true;
                    continue;
                }
                if (kType == IMAGE_REL_BASED_HIGHLOW)
                {
                    if (kTargetRva > mappedImageOut.size()
                        || sizeof(std::uint32_t)
                            > mappedImageOut.size()
                                - static_cast<std::size_t>(kTargetRva))
                    {
                        errorTextOut =
                            baselineText(QStringLiteral("HIGHLOW 重定位目标越界。"));
                        return false;
                    }
                    std::uint32_t value = 0U;
                    std::memcpy(
                        &value,
                        mappedImageOut.data()
                            + static_cast<std::size_t>(kTargetRva),
                        sizeof(value));
                    value += static_cast<std::uint32_t>(
                        kRelocationDelta);
                    std::memcpy(
                        mappedImageOut.data()
                            + static_cast<std::size_t>(kTargetRva),
                        &value,
                        sizeof(value));
                    relocationAppliedOut = true;
                    continue;
                }
                errorTextOut = baselineText(QStringLiteral("PE 含有当前取证器不支持的重定位类型 %1。"))
                    .arg(kType);
                return false;
            }
            consumed += block.SizeOfBlock;
        }
        return true;
    }

    QString thumbprintText(
        const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE& response)
    {
        const std::uint32_t kByteCount = std::min<std::uint32_t>(
            response.thumbprintSize,
            KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES);
        return QString::fromLatin1(
            QByteArray(
                reinterpret_cast<const char*>(response.thumbprint),
                static_cast<qsizetype>(kByteCount))
                .toHex());
    }

    struct PreparedTrustedImage
    {
        LoadedModule module;
        PeIdentity identity;
        QByteArray diskImage;
        std::vector<std::uint8_t> mappedImage;
        QString sha256;
        QString signingThumbprint;
        std::uint32_t signingLevel = 0;
        bool diskTrustVerified = false;
        bool relocationApplied = false;
    };

    bool prepareTrustedImage(
        const LoadedModule& module,
        const bool requireTrustedDiskImage,
        PreparedTrustedImage& preparedOut,
        QString& errorTextOut)
    {
        preparedOut = {};
        preparedOut.module = module;
        if (module.filePath.isEmpty()
            || !QFileInfo::exists(module.filePath))
        {
            errorTextOut = baselineText(QStringLiteral("模块磁盘路径不可用：%1")).arg(module.ntPath);
            return false;
        }

        ReadOnlyTrustFile imageFile(module.filePath);
        if (imageFile.handle == INVALID_HANDLE_VALUE)
        {
            errorTextOut = baselineText(QStringLiteral("无法读取模块磁盘映像：%1"))
                .arg(QDir::toNativeSeparators(module.filePath));
            return false;
        }
        if (requireTrustedDiskImage)
        {
            if (!readTrustedDiskImage(
                    module.filePath,
                    imageFile.handle,
                    preparedOut.diskImage))
            {
                errorTextOut = baselineText(QStringLiteral(
                    "磁盘映像未通过 embedded/catalog 完整链信任验证，拒绝建立安全基线。"));
                return false;
            }
            preparedOut.diskTrustVerified = true;
        }
        else
        {
            if (!readDiskImage(
                    imageFile.handle,
                    preparedOut.diskImage))
            {
                errorTextOut = baselineText(QStringLiteral("无法读取模块磁盘映像：%1"))
                    .arg(QDir::toNativeSeparators(module.filePath));
                return false;
            }
        }
        if (preparedOut.diskImage.isEmpty())
        {
            errorTextOut = baselineText(QStringLiteral("模块磁盘映像为空。"));
            return false;
        }
        preparedOut.sha256 = QString::fromLatin1(
            QCryptographicHash::hash(
                preparedOut.diskImage,
                QCryptographicHash::Sha256)
                .toHex());
        if (!parsePeIdentity(
            preparedOut.diskImage,
            preparedOut.identity,
            errorTextOut))
        {
            return false;
        }

        const std::vector<std::uint8_t> kMemoryHeader =
            loadedHeaderBytes(module.base, errorTextOut);
        if (kMemoryHeader.empty())
        {
            return false;
        }
        const QByteArray kMemoryHeaderArray(
            reinterpret_cast<const char*>(kMemoryHeader.data()),
            static_cast<qsizetype>(kMemoryHeader.size()));
        PeIdentity memoryIdentity;
        if (!parsePeIdentity(
            kMemoryHeaderArray,
            memoryIdentity,
            errorTextOut))
        {
            errorTextOut = baselineText(QStringLiteral("已加载映像身份读取失败：%1")).arg(errorTextOut);
            return false;
        }
        if (preparedOut.identity.machine != memoryIdentity.machine
            || preparedOut.identity.timestamp != memoryIdentity.timestamp
            || preparedOut.identity.sizeOfImage != memoryIdentity.sizeOfImage
            || preparedOut.identity.checkSum != memoryIdentity.checkSum
            || preparedOut.identity.sizeOfImage != module.size)
        {
            errorTextOut = baselineText(QStringLiteral("磁盘映像与已加载模块的机器类型、时间戳、映像大小或校验和不一致。"));
            return false;
        }

        const ksword::ark::DriverClient kClient;
        const ksword::ark::ImageSignatureQueryResult kSignature =
            kClient.queryImageSignature(
                module.ntPath.toStdWString(),
                module.base,
                KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT
                    | KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE);
        const std::uint32_t kRequiredFields =
            KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL
            | KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE
            | KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH;
        if (!kSignature.io.ok
            || (kSignature.response.fieldFlags & kRequiredFields)
                != kRequiredFields
            || kSignature.response.signingLevelStatus < 0
            || kSignature.response.loadedModuleStatus < 0
            || kSignature.response.matchedModuleBase != module.base
            || kSignature.response.signingLevel
                < KSWORD_ARK_SIGNING_LEVEL_AUTHENTICODE
            || (kSignature.response.structuralFlags
                & KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH)
                != 0U)
        {
            errorTextOut = baselineText(QStringLiteral("内核 Code Integrity 签名级别或已加载模块身份证据不足，拒绝建立可信基线。"));
            return false;
        }
        preparedOut.signingLevel = kSignature.response.signingLevel;
        preparedOut.signingThumbprint =
            thumbprintText(kSignature.response);

        return mapPeImage(
            preparedOut.diskImage,
            preparedOut.identity,
            module.base,
            preparedOut.mappedImage,
            preparedOut.relocationApplied,
            errorTextOut);
    }

    const PreparedTrustedImage* cachedTrustedImage(
        const LoadedModule& module,
        QString& errorTextOut)
    {
        thread_local std::vector<PreparedTrustedImage> cache;
        const auto kExisting = std::find_if(
            cache.cbegin(),
            cache.cend(),
            [&module](const PreparedTrustedImage& candidate)
            {
                return candidate.module.base == module.base
                    && candidate.module.size == module.size
                    && candidate.module.filePath.compare(
                        module.filePath,
                        Qt::CaseInsensitive) == 0;
            });
        if (kExisting != cache.cend())
        {
            return &(*kExisting);
        }

        PreparedTrustedImage prepared;
        if (!prepareTrustedImage(
                module,
                false,
                prepared,
                errorTextOut))
        {
            return nullptr;
        }
        cache.push_back(std::move(prepared));
        return &cache.back();
    }

    struct IdtBaselineProfile
    {
        std::uint32_t tableRva = 0;
        std::array<std::vector<std::uint64_t>, 256>
            handlerAddresses;
        QString sourceSymbol;
        QString profilePath;
    };

    std::optional<std::uint32_t> jsonUInt32(
        const QJsonValue& value)
    {
        if (value.isDouble())
        {
            const double kNumber = value.toDouble(-1.0);
            if (kNumber < 0.0
                || kNumber
                    > static_cast<double>(
                        std::numeric_limits<std::uint32_t>::max())
                || kNumber != static_cast<double>(
                    static_cast<std::uint32_t>(kNumber)))
            {
                return std::nullopt;
            }
            return static_cast<std::uint32_t>(kNumber);
        }
        if (!value.isString())
        {
            return std::nullopt;
        }
        QString text = value.toString().trimmed();
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"),
                Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        bool converted = false;
        const qulonglong kParsed = text.toULongLong(
            &converted,
            base);
        if (!converted
            || kParsed
                > std::numeric_limits<std::uint32_t>::max())
        {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(kParsed);
    }

    QStringList idtProfileCandidatePaths()
    {
        QStringList paths;
        const QStringList kRoots = {
            QDir(QCoreApplication::applicationDirPath())
                .filePath(QStringLiteral("profiles")),
            QDir::current().filePath(QStringLiteral("profiles"))
        };
        QSet<QString> seen;
        for (const QString& root : kRoots)
        {
            const QDir kDirectory(root);
            const QString kPath =
                QFileInfo(kDirectory.filePath(QStringLiteral("ark_dyndata_pack_v4.json")))
                    .absoluteFilePath();
            const QString kKey =
                QDir::cleanPath(kPath).toLower();
            if (!seen.contains(kKey) && QFileInfo::exists(kPath))
            {
                seen.insert(kKey);
                paths.push_back(kPath);
            }
        }
        return paths;
    }

    bool idtProfileEntryMatches(
        const QJsonObject& profile,
        const PreparedTrustedImage& image,
        const bool compactPack)
    {
        const QJsonObject kIdentity = compactPack
            ? profile
            : profile.value(QStringLiteral("module")).toObject();
        const std::optional<std::uint32_t> kMachine =
            jsonUInt32(kIdentity.value(QStringLiteral("machine")));
        const std::optional<std::uint32_t> kTimestamp =
            jsonUInt32(kIdentity.value(QStringLiteral("timeDateStamp")));
        const std::optional<std::uint32_t> kSize =
            jsonUInt32(kIdentity.value(QStringLiteral("sizeOfImage")));
        return kMachine.has_value()
            && kTimestamp.has_value()
            && kSize.has_value()
            && kMachine.value() == image.identity.machine
            && kTimestamp.value() == image.identity.timestamp
            && kSize.value() == image.identity.sizeOfImage;
    }

    bool loadIdtBaselineProfile(
        const PreparedTrustedImage& image,
        IdtBaselineProfile& profileOut,
        QString& errorTextOut)
    {
        profileOut = {};
        bool identitySeen = false;
        bool hashSeen = false;
        bool invalidMetadataSeen = false;
        for (const QString& path : idtProfileCandidatePaths())
        {
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                continue;
            }
            QJsonParseError parseError = {};
            const QJsonDocument kDocument =
                QJsonDocument::fromJson(file.readAll(), &parseError);
            file.close();
            if (parseError.error != QJsonParseError::NoError
                || !kDocument.isObject())
            {
                continue;
            }

            const QJsonObject kRoot = kDocument.object();
            const bool kCompactPack =
                kRoot.value(QStringLiteral("profiles")).isArray();
            QJsonArray entries;
            if (kCompactPack)
            {
                entries =
                    kRoot.value(QStringLiteral("profiles")).toArray();
            }
            else
            {
                entries.append(kRoot);
            }
            for (const QJsonValue& entryValue : entries)
            {
                if (!entryValue.isObject())
                {
                    continue;
                }
                const QJsonObject kEntry = entryValue.toObject();
                if (!idtProfileEntryMatches(
                    kEntry,
                    image,
                    kCompactPack))
                {
                    continue;
                }
                identitySeen = true;
                const QJsonObject kIdentity = kCompactPack
                    ? kEntry
                    : kEntry.value(QStringLiteral("module")).toObject();
                const QString kProfileHash =
                    kIdentity.value(QStringLiteral("sha256"))
                        .toString()
                        .trimmed()
                        .toLower();
                if (kProfileHash.size() != 64
                    || kProfileHash != image.sha256.toLower())
                {
                    continue;
                }
                hashSeen = true;
                const QJsonObject kBaseline =
                    kEntry.value(QStringLiteral("idtBaseline"))
                        .toObject();
                const std::optional<std::uint32_t> kSchemaVersion =
                    jsonUInt32(
                        kBaseline.value(QStringLiteral("schemaVersion")));
                const std::optional<std::uint32_t> kTableRva =
                    jsonUInt32(
                        kBaseline.value(QStringLiteral("tableRva")));
                const QString kSourceSymbol =
                    kBaseline.value(QStringLiteral("sourceSymbol"))
                        .toString()
                        .trimmed();
                const QJsonArray kHandlers =
                    kBaseline.value(QStringLiteral("handlers")).toArray();
                if (!kSchemaVersion.has_value()
                    || kSchemaVersion.value() != 2U
                    || !kTableRva.has_value()
                    || kTableRva.value() == 0U
                    || kTableRva.value() >= image.mappedImage.size()
                    || kHandlers.isEmpty()
                    || kSourceSymbol
                        != QStringLiteral("KiInterruptInitTable"))
                {
                    invalidMetadataSeen = true;
                    continue;
                }
                IdtBaselineProfile parsedProfile;
                parsedProfile.tableRva = kTableRva.value();
                parsedProfile.sourceSymbol = kSourceSymbol;
                parsedProfile.profilePath = path;
                std::size_t acceptedHandlers = 0U;
                bool invalidHandlerSeen = false;
                for (const QJsonValue& handlerValue : kHandlers)
                {
                    const QJsonObject kHandler =
                        handlerValue.toObject();
                    const std::optional<std::uint32_t> kVector =
                        jsonUInt32(
                            kHandler.value(QStringLiteral("vector")));
                    const std::optional<std::uint32_t> kHandlerRva =
                        jsonUInt32(
                            kHandler.value(QStringLiteral("rva")));
                    const QString kHandlerSymbol =
                        kHandler.value(QStringLiteral("symbol"))
                            .toString()
                            .trimmed();
                    if (!kVector.has_value()
                        || kVector.value() > 0xFFU
                        || !kHandlerRva.has_value()
                        || kHandlerRva.value() == 0U
                        || kHandlerRva.value() >= image.module.size
                        || !kHandlerSymbol.startsWith(
                            QStringLiteral("Ki")))
                    {
                        invalidHandlerSeen = true;
                        break;
                    }
                    const std::uint64_t kHandlerAddress =
                        image.module.base + kHandlerRva.value();
                    std::vector<std::uint64_t>& candidates =
                        parsedProfile.handlerAddresses[kVector.value()];
                    if (std::find(
                        candidates.cbegin(),
                        candidates.cend(),
                        kHandlerAddress) == candidates.cend())
                    {
                        candidates.push_back(kHandlerAddress);
                        ++acceptedHandlers;
                    }
                }
                if (invalidHandlerSeen || acceptedHandlers == 0U)
                {
                    invalidMetadataSeen = true;
                    continue;
                }
                profileOut = std::move(parsedProfile);
                return true;
            }
        }

        if (hashSeen)
        {
            errorTextOut = invalidMetadataSeen
                ? QStringLiteral(
                    "精确 SHA256 profile 的 IDT 基线元数据缺失或无效，IDT 预期处理程序 unsupported。")
                : QStringLiteral(
                    "精确 SHA256 profile 未提供 KiInterruptInitTable，IDT 预期处理程序 unsupported。");
        }
        else if (identitySeen)
        {
            errorTextOut = QStringLiteral(
                "PDB profile 的 PE 身份匹配但 SHA256 不匹配，拒绝使用。");
        }
        else
        {
            errorTextOut = QStringLiteral(
                "没有与当前 ntoskrnl 机器类型、时间戳、SizeOfImage 和 SHA256 精确匹配的 IDT profile。");
        }
        return false;
    }

    std::vector<std::uint8_t> loadedHeaderBytes(
        const std::uint64_t moduleBase,
        QString& errorTextOut)
    {
        std::vector<std::uint8_t> bytes;
        if (!ks::kernel::KernelCleanImageBaseline::readKernelBytes(
            moduleBase,
            64U * 1024U,
            bytes,
            errorTextOut))
        {
            return {};
        }
        return bytes;
    }

    // ---- PE structure auxiliary for full-section executable comparison ----

#pragma pack(push, 1)
    // IMAGE_DYNAMIC_RELOCATION_TABLE: Dynamic relocation table header.
    struct DynamicRelocationTableHeader
    {
        std::uint32_t version;
        std::uint32_t size;
    };

    // IMAGE_DYNAMIC_RELOCATION64: One entry per symbol, followed by an IMAGE_BASE_RELOCATION block.
    struct DynamicRelocation64Header
    {
        std::uint64_t symbol;
        std::uint32_t baseRelocSize;
    };
#pragma pack(pop)

    // This tool can decode dynamic relocation symbols at offset sites. These are the specific types on x64 that
    // actually modify the .text section (import optimization and the two types of indirect control transfer rewrites).
    constexpr std::uint64_t kDynamicRelocImportControlTransfer = 3ULL;
    constexpr std::uint64_t kDynamicRelocIndirControlTransfer = 4ULL;
    constexpr std::uint64_t kDynamicRelocSwitchtableBranch = 5ULL;

    // Maximum number of bytes covered by a single dynamic relocation site. On x64, the overwritten
    // instruction is a call/jmp; 8 bytes are reserved to accommodate prefixes and ModRM overhead.
    constexpr std::uint32_t kDynamicRelocSiteSpan = 8U;

    // Describes the range of an executable section in the image.
    struct ExecutableSection
    {
        std::uint32_t rva = 0;
        std::uint32_t size = 0;
        QString name;
    };

    QString sectionNameText(const IMAGE_SECTION_HEADER& section)
    {
        char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        std::memcpy(buffer, section.Name, IMAGE_SIZEOF_SHORT_NAME);
        return QString::fromLatin1(buffer).trimmed();
    }

    // Collect all sections in the image with IMAGE_SCN_MEM_EXECUTE. The in-memory section
    // length is the larger of VirtualSize and SizeOfRawData, truncated to within SizeOfImage.
    std::vector<ExecutableSection> collectExecutableSections(
        const PreparedTrustedImage& prepared)
    {
        std::vector<ExecutableSection> sections;
        for (std::uint16_t index = 0;
             index < prepared.identity.sectionCount;
             ++index)
        {
            IMAGE_SECTION_HEADER header = {};
            const std::uint64_t kOffset =
                prepared.identity.sectionTableOffset
                + static_cast<std::uint64_t>(index)
                    * sizeof(IMAGE_SECTION_HEADER);
            if (!copyStructure(prepared.diskImage, kOffset, header))
            {
                break;
            }
            if ((header.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0U)
            {
                continue;
            }
            std::uint32_t length = std::max<std::uint32_t>(
                header.Misc.VirtualSize,
                header.SizeOfRawData);
            if (length == 0U
                || header.VirtualAddress >= prepared.mappedImage.size())
            {
                continue;
            }
            const std::uint32_t kAvailable =
                static_cast<std::uint32_t>(prepared.mappedImage.size())
                - header.VirtualAddress;
            length = std::min(length, kAvailable);
            sections.push_back(
                ExecutableSection{
                    header.VirtualAddress,
                    length,
                    sectionNameText(header) });
        }
        return sections;
    }

    // Locate the dynamic relocation table from the LoadConfig directory and collect decodable site RVAs into sitesOut.
    // Returns false if a symbol that this tool cannot resolve is encountered; the caller uses this to reduce the conclusion strength.
    bool collectDynamicRelocationSites(
        const PreparedTrustedImage& prepared,
        std::vector<std::uint32_t>& sitesOut)
    {
        sitesOut.clear();

        IMAGE_DOS_HEADER dos = {};
        if (!copyStructure(prepared.diskImage, 0U, dos)
            || dos.e_lfanew <= 0)
        {
            return true;
        }
        IMAGE_NT_HEADERS64 ntHeaders = {};
        if (!copyStructure(
                prepared.diskImage,
                static_cast<std::uint64_t>(dos.e_lfanew),
                ntHeaders)
            || ntHeaders.OptionalHeader.Magic
                != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            || ntHeaders.OptionalHeader.NumberOfRvaAndSizes
                <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        {
            return true;
        }

        const IMAGE_DATA_DIRECTORY kLoadConfigDirectory =
            ntHeaders.OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (kLoadConfigDirectory.VirtualAddress == 0U
            || kLoadConfigDirectory.Size < sizeof(std::uint32_t)
            || kLoadConfigDirectory.VirtualAddress
                >= prepared.mappedImage.size())
        {
            return true;
        }

        // The LoadConfig structure grows with versions; only the portion declared by the Size field is usable.
        IMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = {};
        const std::size_t kCopyBytes = std::min<std::size_t>(
            {
                sizeof(loadConfig),
                static_cast<std::size_t>(kLoadConfigDirectory.Size),
                prepared.mappedImage.size()
                    - kLoadConfigDirectory.VirtualAddress
            });
        std::memcpy(
            &loadConfig,
            prepared.mappedImage.data() + kLoadConfigDirectory.VirtualAddress,
            kCopyBytes);

        constexpr std::size_t kRequiredSize =
            offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64,
                DynamicValueRelocTableSection)
            + sizeof(loadConfig.DynamicValueRelocTableSection);
        if (loadConfig.Size < kRequiredSize
            || kCopyBytes < kRequiredSize
            || loadConfig.DynamicValueRelocTableOffset == 0U
            || loadConfig.DynamicValueRelocTableSection == 0U)
        {
            return true;
        }

        // DynamicValueRelocTableSection is a 1-based section index; offsets are relative to the start of that section.
        IMAGE_SECTION_HEADER hostSection = {};
        const std::uint16_t kSectionIndex =
            static_cast<std::uint16_t>(
                loadConfig.DynamicValueRelocTableSection - 1U);
        if (kSectionIndex >= prepared.identity.sectionCount
            || !copyStructure(
                prepared.diskImage,
                prepared.identity.sectionTableOffset
                    + static_cast<std::uint64_t>(kSectionIndex)
                        * sizeof(IMAGE_SECTION_HEADER),
                hostSection))
        {
            return true;
        }

        const std::uint64_t kTableRva =
            static_cast<std::uint64_t>(hostSection.VirtualAddress)
            + loadConfig.DynamicValueRelocTableOffset;
        if (kTableRva + sizeof(DynamicRelocationTableHeader)
            > prepared.mappedImage.size())
        {
            return true;
        }

        DynamicRelocationTableHeader tableHeader = {};
        std::memcpy(
            &tableHeader,
            prepared.mappedImage.data() + kTableRva,
            sizeof(tableHeader));
        if (tableHeader.version != 1U || tableHeader.size == 0U)
        {
            // If the version is unrecognized, perform no decoding and let the caller handle it conservatively.
            return tableHeader.size == 0U;
        }

        const std::uint64_t kEntriesRva =
            kTableRva + sizeof(DynamicRelocationTableHeader);
        if (kEntriesRva > prepared.mappedImage.size()
            || tableHeader.size
                > prepared.mappedImage.size() - kEntriesRva)
        {
            return true;
        }

        bool fullyParsed = true;
        std::uint32_t consumed = 0U;
        while (consumed + sizeof(DynamicRelocation64Header)
               <= tableHeader.size)
        {
            DynamicRelocation64Header entry = {};
            std::memcpy(
                &entry,
                prepared.mappedImage.data() + kEntriesRva + consumed,
                sizeof(entry));
            consumed += static_cast<std::uint32_t>(sizeof(entry));
            if (entry.baseRelocSize == 0U
                || entry.baseRelocSize > tableHeader.size - consumed)
            {
                fullyParsed = false;
                break;
            }

            const std::uint32_t kEntrySize =
                (entry.symbol == kDynamicRelocImportControlTransfer
                 || entry.symbol == kDynamicRelocSwitchtableBranch)
                    ? 4U
                    : (entry.symbol == kDynamicRelocIndirControlTransfer
                        ? 2U
                        : 0U);
            if (kEntrySize == 0U)
            {
                // Unknown or unimplemented symbol: skip its data but mark parsing as incomplete.
                fullyParsed = false;
                consumed += entry.baseRelocSize;
                continue;
            }

            std::uint32_t blockConsumed = 0U;
            while (blockConsumed + sizeof(IMAGE_BASE_RELOCATION)
                   <= entry.baseRelocSize)
            {
                IMAGE_BASE_RELOCATION block = {};
                std::memcpy(
                    &block,
                    prepared.mappedImage.data()
                        + kEntriesRva + consumed + blockConsumed,
                    sizeof(block));
                if (block.SizeOfBlock < sizeof(block)
                    || block.SizeOfBlock
                        > entry.baseRelocSize - blockConsumed)
                {
                    fullyParsed = false;
                    break;
                }
                const std::uint32_t kPayloadBytes =
                    block.SizeOfBlock
                    - static_cast<std::uint32_t>(sizeof(block));
                for (std::uint32_t offsetInPayload = 0U;
                     offsetInPayload + kEntrySize <= kPayloadBytes;
                     offsetInPayload += kEntrySize)
                {
                    std::uint32_t raw = 0U;
                    std::memcpy(
                        &raw,
                        prepared.mappedImage.data()
                            + kEntriesRva + consumed + blockConsumed
                            + sizeof(block) + offsetInPayload,
                        kEntrySize);
                    // The lower 12 bits of all three symbols represent the page offset.
                    const std::uint32_t kPageOffset = raw & 0x0FFFU;
                    sitesOut.push_back(
                        block.VirtualAddress + kPageOffset);
                }
                blockConsumed += block.SizeOfBlock;
            }
            consumed += entry.baseRelocSize;
        }

        std::sort(sitesOut.begin(), sitesOut.end());
        sitesOut.erase(
            std::unique(sitesOut.begin(), sitesOut.end()),
            sitesOut.end());
        return fullyParsed;
    }

    // Check whether [rva, rva+length) is fully covered by known dynamic relocation sites.
    bool rangeCoveredByDynamicRelocation(
        const std::vector<std::uint32_t>& sites,
        const std::uint32_t rva,
        const std::uint32_t length)
    {
        if (sites.empty() || length == 0U)
        {
            return false;
        }
        for (std::uint32_t offset = 0U; offset < length; ++offset)
        {
            const std::uint32_t kProbe = rva + offset;
            // Find the first start point greater than the probe; the point immediately preceding it is the only one that might cover the probe.
            const auto kUpper = std::upper_bound(
                sites.cbegin(),
                sites.cend(),
                kProbe);
            if (kUpper == sites.cbegin())
            {
                return false;
            }
            const std::uint32_t kSite = *std::prev(kUpper);
            if (kProbe - kSite >= kDynamicRelocSiteSpan)
            {
                return false;
            }
        }
        return true;
    }
}

namespace ks::kernel
{
    bool KernelCleanImageBaseline::readKernelBytes(
        const std::uint64_t kernelAddress,
        const std::uint32_t byteCount,
        std::vector<std::uint8_t>& bytesOut,
        QString& errorTextOut)
    {
        bytesOut.clear();
        errorTextOut.clear();
        if (kernelAddress == 0U
            || byteCount == 0U
            || byteCount > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
        {
            errorTextOut = QStringLiteral("内核读取参数无效。");
            return false;
        }

        const ksword::ark::DriverClient kClient;
        const ksword::ark::VirtualMemoryReadResult kRead =
            kClient.readVirtualMemory(
                0U,
                kernelAddress,
                byteCount,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
        if (!kRead.io.ok || kRead.bytesRead != byteCount)
        {
            errorTextOut = QStringLiteral(
                "R0 内核读取失败：Win32=%1，NT=0x%2，读取=%3/%4。")
                .arg(kRead.io.win32Error)
                .arg(static_cast<unsigned long>(kRead.copyStatus),
                    8,
                    16,
                    QChar('0'))
                .arg(kRead.bytesRead)
                .arg(byteCount);
            return false;
        }
        bytesOut = kRead.data;
        return bytesOut.size() == byteCount;
    }

    CleanImageBaselineResult KernelCleanImageBaseline::compareAddress(
        const std::uint64_t kernelAddress,
        const std::uint32_t byteCount,
        const std::vector<std::uint8_t>& observedBytes,
        const bool requireTrustedDiskImage)
    {
        CleanImageBaselineResult result;
        if (kernelAddress == 0U
            || byteCount == 0U
            || byteCount > 64U * 1024U)
        {
            result.statusText = QStringLiteral("基线请求范围无效。");
            return result;
        }

        std::vector<LoadedModule> modules;
        QString errorText;
        if (!enumerateLoadedModules(modules, errorText))
        {
            result.statusText = errorText;
            return result;
        }
        const LoadedModule* module =
            moduleForAddress(modules, kernelAddress);
        if (module == nullptr)
        {
            result.statusText =
                QStringLiteral("目标地址不属于已加载内核映像。");
            return result;
        }

        result.moduleBase = module->base;
        result.moduleSize = module->size;
        result.moduleName = module->name;
        result.imagePath = module->filePath;
        const std::uint64_t kRva64 = kernelAddress - module->base;
        if (kRva64 > std::numeric_limits<std::uint32_t>::max())
        {
            result.statusText = QStringLiteral("目标 RVA 超出 32 位范围。");
            return result;
        }
        result.relativeVirtualAddress =
            static_cast<std::uint32_t>(kRva64);
        PreparedTrustedImage trustedDiskImage;
        const PreparedTrustedImage* prepared = nullptr;
        if (requireTrustedDiskImage)
        {
            if (!prepareTrustedImage(
                    *module,
                    true,
                    trustedDiskImage,
                    errorText))
            {
                result.statusText = errorText;
                return result;
            }
            prepared = &trustedDiskImage;
        }
        else
        {
            prepared = cachedTrustedImage(
                *module,
                errorText);
        }
        if (prepared == nullptr)
        {
            result.statusText = errorText;
            return result;
        }
        result.identityMatched = true;
        result.diskTrustVerified = prepared->diskTrustVerified;
        result.codeIntegrityTrusted = true;
        result.relocationApplied = prepared->relocationApplied;
        result.preferredImageBase =
            prepared->identity.preferredImageBase;
        result.signingLevel = prepared->signingLevel;
        result.imageSha256 = prepared->sha256;
        result.signingThumbprint = prepared->signingThumbprint;
        if (result.relativeVirtualAddress > prepared->mappedImage.size()
            || byteCount > prepared->mappedImage.size()
                - result.relativeVirtualAddress)
        {
            result.statusText =
                baselineText(QStringLiteral("目标 RVA 在已重定位映像中越界。"));
            return result;
        }
        result.cleanBytes.assign(
            prepared->mappedImage.cbegin()
                + result.relativeVirtualAddress,
            prepared->mappedImage.cbegin()
                + result.relativeVirtualAddress + byteCount);
        if (observedBytes.empty())
        {
            if (!readKernelBytes(
                kernelAddress,
                byteCount,
                result.observedBytes,
                errorText))
            {
                result.statusText = errorText;
                return result;
            }
        }
        else if (observedBytes.size() == byteCount)
        {
            result.observedBytes = observedBytes;
        }
        else
        {
            result.statusText =
                QStringLiteral("调用方提供的观察字节长度与目标范围不一致。");
            return result;
        }

        result.available = true;
        result.differs = result.cleanBytes != result.observedBytes;
        result.statusText = result.differs
            ? baselineText(QStringLiteral("当前内存与身份、SHA256、Code Integrity 签名级别绑定的重定位映像基线不一致"))
            : baselineText(QStringLiteral("当前内存与身份、SHA256、Code Integrity 签名级别绑定的重定位映像基线一致"));
        return result;
    }

    std::vector<KernelTextIntegrityResult>
    KernelCleanImageBaseline::scanExecutableSections(
        const KernelTextScanOptions& options)
    {
        std::vector<KernelTextIntegrityResult> results;

        std::vector<LoadedModule> modules;
        QString errorText;
        if (!enumerateLoadedModules(modules, errorText))
        {
            KernelTextIntegrityResult failure;
            failure.statusText = errorText;
            results.push_back(std::move(failure));
            return results;
        }

        // The read chunk size must be constrained by both the protocol limit and the caller's setting.
        std::uint32_t chunkBytes = options.chunkBytes;
        if (chunkBytes == 0U
            || chunkBytes > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
        {
            chunkBytes = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
        }

        for (const LoadedModule& module : modules)
        {
            if (options.cancelFlag != nullptr
                && options.cancelFlag->load())
            {
                break;
            }
            if (!options.moduleFilter.isEmpty()
                && !module.name.contains(
                    options.moduleFilter,
                    Qt::CaseInsensitive))
            {
                continue;
            }

            KernelTextIntegrityResult result;
            result.moduleBase = module.base;
            result.moduleSize = module.size;
            result.moduleName = module.name;
            result.imagePath = module.filePath;

            QString prepareError;
            const PreparedTrustedImage* prepared =
                cachedTrustedImage(module, prepareError);
            if (prepared == nullptr)
            {
                result.statusText = prepareError;
                if (options.onModuleComplete)
                {
                    options.onModuleComplete(result);
                }
                results.push_back(std::move(result));
                continue;
            }

            result.identityMatched = true;
            result.diskTrustVerified = prepared->diskTrustVerified;
            result.relocationApplied = prepared->relocationApplied;
            result.imageSha256 = prepared->sha256;

            std::vector<std::uint32_t> dynamicSites;
            result.unparsedDynamicRelocations =
                !collectDynamicRelocationSites(*prepared, dynamicSites);

            const std::vector<ExecutableSection> kSections =
                collectExecutableSections(*prepared);
            result.executableSectionCount =
                static_cast<std::uint32_t>(kSections.size());
            if (kSections.empty())
            {
                result.statusText = baselineText(
                    QStringLiteral("该映像没有可执行节，未做比对。"));
                if (options.onModuleComplete)
                {
                    options.onModuleComplete(result);
                }
                results.push_back(std::move(result));
                continue;
            }

            bool cancelled = false;
            for (const ExecutableSection& section : kSections)
            {
                std::uint32_t sectionOffset = 0U;
                while (sectionOffset < section.size)
                {
                    if (options.cancelFlag != nullptr
                        && options.cancelFlag->load())
                    {
                        cancelled = true;
                        break;
                    }

                    const std::uint32_t kReadBytes = std::min(
                        chunkBytes,
                        section.size - sectionOffset);
                    const std::uint32_t kChunkRva =
                        section.rva + sectionOffset;
                    sectionOffset += kReadBytes;

                    std::vector<std::uint8_t> observed;
                    QString readError;
                    if (!readKernelBytes(
                            module.base + kChunkRva,
                            kReadBytes,
                            observed,
                            readError))
                    {
                        // Only count unreadable blocks as metrics, not as differences, to avoid misreporting page faults as tampering.
                        result.unreadableBytes += kReadBytes;
                        continue;
                    }
                    result.scannedBytes += kReadBytes;

                    const std::uint8_t* clean =
                        prepared->mappedImage.data() + kChunkRva;
                    std::uint32_t index = 0U;
                    while (index < kReadBytes)
                    {
                        if (clean[index] == observed[index])
                        {
                            ++index;
                            continue;
                        }
                        // Merge consecutive differing bytes into a single interval for classification.
                        const std::uint32_t kStart = index;
                        while (index < kReadBytes
                               && clean[index] != observed[index])
                        {
                            ++index;
                        }
                        const std::uint32_t kLength = index - kStart;
                        result.differingBytes += kLength;

                        const std::uint32_t kRangeRva = kChunkRva + kStart;
                        const bool kKnown = rangeCoveredByDynamicRelocation(
                            dynamicSites,
                            kRangeRva,
                            kLength);
                        if (kKnown)
                        {
                            result.knownRangeCount += 1U;
                        }
                        else
                        {
                            result.unexplainedRangeCount += 1U;
                        }

                        if (result.ranges.size()
                            >= options.maxRangesPerModule)
                        {
                            result.truncatedRangeCount += 1U;
                            continue;
                        }

                        KernelTextDiffRange range;
                        range.rva = kRangeRva;
                        range.length = kLength;
                        range.kernelAddress = module.base + kRangeRva;
                        range.origin = kKnown
                            ? KernelTextDiffRange::Origin::kKnownDynamicRelocation
                            : KernelTextDiffRange::Origin::kUnexplained;
                        range.sectionName = section.name;
                        const std::uint32_t kPreviewBytes = std::min(
                            kLength,
                            options.maxRangeBytes);
                        range.cleanBytes.assign(
                            clean + kStart,
                            clean + kStart + kPreviewBytes);
                        range.observedBytes.assign(
                            observed.cbegin() + kStart,
                            observed.cbegin() + kStart + kPreviewBytes);
                        result.ranges.push_back(std::move(range));
                    }
                }
                if (cancelled)
                {
                    break;
                }
            }

            result.available = true;
            if (cancelled)
            {
                result.statusText = baselineText(
                    QStringLiteral("扫描被取消，结果不完整。"));
            }
            else if (result.unexplainedRangeCount != 0U)
            {
                result.statusText = baselineText(
                    QStringLiteral("发现无法用动态重定位解释的代码改写。"));
            }
            else if (result.knownRangeCount != 0U)
            {
                result.statusText = baselineText(
                    QStringLiteral("仅存在动态重定位位点差异，未见异常改写。"));
            }
            else
            {
                result.statusText = baselineText(
                    QStringLiteral("可执行节与重定位后的磁盘净映像一致。"));
            }
            if (options.onModuleComplete)
            {
                options.onModuleComplete(result);
            }
            results.push_back(std::move(result));

            if (cancelled)
            {
                break;
            }
        }

        return results;
    }

    std::vector<TrustedIdtBaselineResult>
    KernelCleanImageBaseline::compareIdtHandlers(
        const std::vector<IdtHandlerObservation>& observations)
    {
        std::vector<TrustedIdtBaselineResult> results;
        results.reserve(observations.size());
        for (const IdtHandlerObservation& observation : observations)
        {
            TrustedIdtBaselineResult row;
            row.vector = observation.vector;
            row.observedHandler = observation.handler;
            results.push_back(std::move(row));
        }
        if (observations.empty())
        {
            return results;
        }

        auto failAll = [&results](const QString& message)
        {
            for (TrustedIdtBaselineResult& row : results)
            {
                row.statusText = message;
            }
        };

        std::vector<LoadedModule> modules;
        QString errorText;
        if (!enumerateLoadedModules(modules, errorText))
        {
            failAll(errorText);
            return results;
        }
        const auto kNtosIterator = std::find_if(
            modules.cbegin(),
            modules.cend(),
            [](const LoadedModule& module)
            {
                const QString kFileName =
                    QFileInfo(module.filePath).fileName().toLower();
                return kFileName == QStringLiteral("ntoskrnl.exe")
                    || kFileName == QStringLiteral("ntkrnlmp.exe")
                    || kFileName == QStringLiteral("ntkrla57.exe");
            });
        if (kNtosIterator == modules.cend())
        {
            failAll(QStringLiteral(
                "无法在已加载模块列表中定位 ntoskrnl，IDT 可信映像基线 unsupported。"));
            return results;
        }

        PreparedTrustedImage image;
        if (!prepareTrustedImage(*kNtosIterator, true, image, errorText))
        {
            failAll(errorText);
            return results;
        }
        IdtBaselineProfile profile;
        if (!loadIdtBaselineProfile(image, profile, errorText))
        {
            failAll(errorText);
            return results;
        }

        for (TrustedIdtBaselineResult& row : results)
        {
            row.identityMatched = true;
            row.diskTrustVerified = image.diskTrustVerified;
            row.codeIntegrityTrusted = true;
            row.profileHashMatched = true;
            row.imagePath = image.module.filePath;
            row.imageSha256 = image.sha256;
            row.profilePath = profile.profilePath;
            row.sourceSymbol = profile.sourceSymbol;
            if (row.vector > 0xFFU)
            {
                row.statusText = QStringLiteral(
                    "IDT 向量超出 x64 架构范围。");
                continue;
            }
            const std::vector<std::uint64_t>& candidates =
                profile.handlerAddresses[row.vector];
            row.expectedCandidateCount =
                static_cast<std::uint32_t>(candidates.size());
            if (candidates.empty())
            {
                row.statusText = QStringLiteral(
                    "精确 PDB 未公开该向量的静态 Handler；动态设备中断或默认 thunk 明确标记 unsupported。");
                continue;
            }
            const auto kMatched = std::find(
                candidates.cbegin(),
                candidates.cend(),
                row.observedHandler);
            row.handlerMatches = kMatched != candidates.cend();
            row.expectedHandler = row.handlerMatches
                ? row.observedHandler
                : candidates.front();
            row.available = true;
            row.statusText = row.handlerMatches
                ? QStringLiteral(
                    "当前 IDT Handler 与精确 PDB/SHA256 绑定的静态向量符号一致")
                : QStringLiteral(
                    "当前 IDT Handler 偏离精确 PDB/SHA256 绑定的静态向量符号");
        }
        return results;
    }

}
