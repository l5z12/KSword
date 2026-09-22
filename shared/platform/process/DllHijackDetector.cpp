#include "DllHijackDetector.h"

#include "Process.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <bcrypt.h>
#include <mscat.h>
#include <wincrypt.h>

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMap>
#include <QSet>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr std::uint32_t kMaxApplicationDllCount = 4096U;
    constexpr std::uint32_t kMaxPeHeaderOffset = 16U * 1024U * 1024U;

#ifndef IMAGE_FILE_MACHINE_ARM64EC
    constexpr std::uint16_t kImageFileMachineArm64Ec = 0xA641U;
#else
    constexpr std::uint16_t ImageFileMachineArm64Ec = IMAGE_FILE_MACHINE_ARM64EC;
#endif

#ifndef IMAGE_FILE_MACHINE_CHPE_X86
    constexpr std::uint16_t kImageFileMachineChpeX86 = 0x3A64U;
#else
    constexpr std::uint16_t ImageFileMachineChpeX86 = IMAGE_FILE_MACHINE_CHPE_X86;
#endif

    struct VersionEvidence
    {
        QString companyName;
        QString originalFilename;
        QString fileVersion;
    };

    struct CatalogTrustResult
    {
        QString signer;
        QString catalogPath;
        QString fileIdentifier;
        LONG trustStatus = 0;
        DWORD lookupError = ERROR_SUCCESS;
        bool trustStatusAvailable = false;
        bool trusted = false;
    };

    struct CandidateDll
    {
        QString path;
        bool loaded = false;
    };

    class ScopedFileHandle final
    {
    public:
        explicit ScopedFileHandle(const QString& filePath)
            : value(::CreateFileW(
                reinterpret_cast<LPCWSTR>(filePath.utf16()),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr))
        {
        }

        ~ScopedFileHandle()
        {
            if (value != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(value);
            }
        }

        ScopedFileHandle(const ScopedFileHandle&) = delete;
        ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;

        HANDLE value = INVALID_HANDLE_VALUE;
    };

    class ScopedCatalogAdmin final
    {
    public:
        ~ScopedCatalogAdmin()
        {
            if (value != nullptr)
            {
                ::CryptCATAdminReleaseContext(value, 0);
            }
        }

        ScopedCatalogAdmin(const ScopedCatalogAdmin&) = delete;
        ScopedCatalogAdmin& operator=(const ScopedCatalogAdmin&) = delete;
        ScopedCatalogAdmin() = default;

        HCATADMIN value = nullptr;
    };

    std::uint16_t readLe16(const char* const bytes)
    {
        const auto* const kData = reinterpret_cast<const unsigned char*>(bytes);
        return static_cast<std::uint16_t>(kData[0]) |
            (static_cast<std::uint16_t>(kData[1]) << 8U);
    }

    std::uint32_t readLe32(const char* const bytes)
    {
        const auto* const kData = reinterpret_cast<const unsigned char*>(bytes);
        return static_cast<std::uint32_t>(kData[0]) |
            (static_cast<std::uint32_t>(kData[1]) << 8U) |
            (static_cast<std::uint32_t>(kData[2]) << 16U) |
            (static_cast<std::uint32_t>(kData[3]) << 24U);
    }

    QString normalizedAbsolutePath(const QString& rawPath)
    {
        const QString kTrimmedPath = QDir::fromNativeSeparators(rawPath.trimmed());
        if (kTrimmedPath.isEmpty())
        {
            return QString();
        }
        return QDir::toNativeSeparators(
            QDir::cleanPath(QFileInfo(kTrimmedPath).absoluteFilePath()));
    }

    QString pathKey(const QString& rawPath)
    {
        return QDir::fromNativeSeparators(normalizedAbsolutePath(rawPath)).toCaseFolded();
    }

    bool pathIsInsideDirectory(const QString& filePath, const QString& directoryPath)
    {
        QString directoryKey = pathKey(directoryPath);
        const QString kFileKey = pathKey(filePath);
        if (directoryKey.isEmpty() || kFileKey.isEmpty())
        {
            return false;
        }
        if (!directoryKey.endsWith(QChar('/')))
        {
            directoryKey += QChar('/');
        }
        return kFileKey.startsWith(directoryKey);
    }

    QString queryNativeSystemDirectory()
    {
        std::array<wchar_t, MAX_PATH + 1U> buffer{};
        const UINT kLength = ::GetSystemDirectoryW(
            buffer.data(),
            static_cast<UINT>(buffer.size()));
        if (kLength == 0U || kLength >= buffer.size())
        {
            return QString();
        }
        return normalizedAbsolutePath(
            QString::fromWCharArray(buffer.data(), static_cast<int>(kLength)));
    }

    QString queryWow64SystemDirectory()
    {
        std::array<wchar_t, MAX_PATH + 1U> buffer{};
        const UINT kLength = ::GetSystemWow64DirectoryW(
            buffer.data(),
            static_cast<UINT>(buffer.size()));
        if (kLength == 0U || kLength >= buffer.size())
        {
            return QString();
        }
        return normalizedAbsolutePath(
            QString::fromWCharArray(buffer.data(), static_cast<int>(kLength)));
    }

    std::uint16_t readPeMachine(const QString& filePath)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            return 0U;
        }

        const QByteArray kDosHeader = file.read(64);
        if (kDosHeader.size() < 64 ||
            static_cast<unsigned char>(kDosHeader[0]) != 'M' ||
            static_cast<unsigned char>(kDosHeader[1]) != 'Z')
        {
            return 0U;
        }

        const std::uint32_t kNtOffset = readLe32(kDosHeader.constData() + 0x3c);
        if (kNtOffset > kMaxPeHeaderOffset ||
            !file.seek(static_cast<qint64>(kNtOffset)))
        {
            return 0U;
        }

        const QByteArray kNtHeaderPrefix = file.read(6);
        if (kNtHeaderPrefix.size() != 6 ||
            static_cast<unsigned char>(kNtHeaderPrefix[0]) != 'P' ||
            static_cast<unsigned char>(kNtHeaderPrefix[1]) != 'E' ||
            kNtHeaderPrefix[2] != '\0' ||
            kNtHeaderPrefix[3] != '\0')
        {
            return 0U;
        }
        return readLe16(kNtHeaderPrefix.constData() + 4);
    }

    bool machinesCompatible(
        const std::uint16_t processMachine,
        const std::uint16_t imageMachine)
    {
        if (processMachine == 0U || imageMachine == 0U ||
            processMachine == imageMachine)
        {
            return true;
        }
        if (processMachine == IMAGE_FILE_MACHINE_I386 &&
            imageMachine == kImageFileMachineChpeX86)
        {
            return true;
        }
        if ((processMachine == IMAGE_FILE_MACHINE_AMD64 ||
                processMachine == IMAGE_FILE_MACHINE_ARM64) &&
            imageMachine == kImageFileMachineArm64Ec)
        {
            return true;
        }
        return false;
    }

    QString queryVersionString(
        const std::vector<BYTE>& versionBytes,
        const WORD language,
        const WORD codePage,
        const wchar_t* const fieldName)
    {
        std::array<wchar_t, 160> queryPath{};
        const int kFormatLength = _snwprintf_s(
            queryPath.data(),
            queryPath.size(),
            _TRUNCATE,
            L"\\StringFileInfo\\%04x%04x\\%ls",
            language,
            codePage,
            fieldName);
        if (kFormatLength <= 0)
        {
            return QString();
        }

        LPWSTR value = nullptr;
        UINT valueLength = 0U;
        if (!::VerQueryValueW(
                versionBytes.data(),
                queryPath.data(),
                reinterpret_cast<void**>(&value),
                &valueLength) ||
            value == nullptr || valueLength <= 1U)
        {
            return QString();
        }
        return QString::fromWCharArray(
            value,
            static_cast<int>(valueLength - 1U)).trimmed();
    }

    VersionEvidence readVersionEvidence(const QString& filePath)
    {
        VersionEvidence evidence;
        DWORD ignoredHandle = 0U;
        const DWORD kByteCount = ::GetFileVersionInfoSizeW(
            reinterpret_cast<LPCWSTR>(filePath.utf16()),
            &ignoredHandle);
        if (kByteCount == 0U)
        {
            return evidence;
        }

        std::vector<BYTE> versionBytes(kByteCount);
        if (!::GetFileVersionInfoW(
                reinterpret_cast<LPCWSTR>(filePath.utf16()),
                0,
                kByteCount,
                versionBytes.data()))
        {
            return evidence;
        }

        struct LanguageAndCodePage
        {
            WORD language = 0U;
            WORD codePage = 0U;
        };

        LanguageAndCodePage* translations = nullptr;
        UINT translationBytes = 0U;
        std::vector<LanguageAndCodePage> candidates;
        if (::VerQueryValueW(
                versionBytes.data(),
                L"\\VarFileInfo\\Translation",
                reinterpret_cast<void**>(&translations),
                &translationBytes) &&
            translations != nullptr)
        {
            const std::size_t kTranslationCount =
                translationBytes / sizeof(LanguageAndCodePage);
            candidates.assign(translations, translations + kTranslationCount);
        }
        candidates.push_back(LanguageAndCodePage{0x0409U, 0x04B0U});
        candidates.push_back(LanguageAndCodePage{0x0409U, 0x04E4U});

        for (const LanguageAndCodePage& candidate : candidates)
        {
            if (evidence.companyName.isEmpty())
            {
                evidence.companyName = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"CompanyName");
            }
            if (evidence.originalFilename.isEmpty())
            {
                evidence.originalFilename = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"OriginalFilename");
            }
            if (evidence.fileVersion.isEmpty())
            {
                evidence.fileVersion = queryVersionString(
                    versionBytes,
                    candidate.language,
                    candidate.codePage,
                    L"FileVersion");
            }
            if (!evidence.companyName.isEmpty() &&
                !evidence.originalFilename.isEmpty() &&
                !evidence.fileVersion.isEmpty())
            {
                break;
            }
        }

        if (evidence.fileVersion.isEmpty())
        {
            VS_FIXEDFILEINFO* fixedInfo = nullptr;
            UINT fixedInfoBytes = 0U;
            if (::VerQueryValueW(
                    versionBytes.data(),
                    L"\\",
                    reinterpret_cast<void**>(&fixedInfo),
                    &fixedInfoBytes) &&
                fixedInfo != nullptr &&
                fixedInfoBytes >= sizeof(VS_FIXEDFILEINFO) &&
                fixedInfo->dwSignature == 0xFEEF04BDU)
            {
                evidence.fileVersion = QStringLiteral("%1.%2.%3.%4")
                    .arg(HIWORD(fixedInfo->dwFileVersionMS))
                    .arg(LOWORD(fixedInfo->dwFileVersionMS))
                    .arg(HIWORD(fixedInfo->dwFileVersionLS))
                    .arg(LOWORD(fixedInfo->dwFileVersionLS));
            }
        }
        return evidence;
    }

    QString calculateSha256(const QString& filePath)
    {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly))
        {
            return QString();
        }

        QCryptographicHash hasher(QCryptographicHash::Sha256);
        while (!file.atEnd())
        {
            const QByteArray kBlock = file.read(1024 * 1024);
            if (kBlock.isEmpty() && file.error() != QFile::NoError)
            {
                return QString();
            }
            hasher.addData(kBlock);
        }
        return QString::fromLatin1(hasher.result().toHex());
    }

    void initializeOfflineTrustData(WINTRUST_DATA& trustData)
    {
        trustData = WINTRUST_DATA{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwProvFlags =
            WTD_SAFER_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL |
            WTD_DISABLE_MD2_MD4;
    }

    QString extractSigner(const WINTRUST_DATA& trustData)
    {
        if (trustData.hWVTStateData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_DATA* const kProviderData =
            ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (kProviderData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_SGNR* const kSigner =
            ::WTHelperGetProvSignerFromChain(kProviderData, 0, FALSE, 0);
        if (kSigner == nullptr || kSigner->csCertChain == 0U ||
            kSigner->pasCertChain == nullptr ||
            kSigner->pasCertChain[0].pCert == nullptr)
        {
            return QString();
        }

        const CERT_CONTEXT* const kCertificate = kSigner->pasCertChain[0].pCert;
        const DWORD kRequiredChars = ::CertGetNameStringW(
            kCertificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nullptr,
            0);
        if (kRequiredChars <= 1U)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(kRequiredChars, L'\0');
        const DWORD kWrittenChars = ::CertGetNameStringW(
            kCertificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nameBuffer.data(),
            kRequiredChars);
        if (kWrittenChars <= 1U)
        {
            return QString();
        }
        return QString::fromWCharArray(
            nameBuffer.data(),
            static_cast<int>(kWrittenChars - 1U)).trimmed();
    }

    LONG runWinTrustAndClose(
        WINTRUST_DATA& trustData,
        QString* const signerOut)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG kStatus = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        if (signerOut != nullptr)
        {
            *signerOut = extractSigner(trustData);
        }
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return kStatus;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& fileHash)
    {
        LARGE_INTEGER fileStart{};
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

        fileHash.resize(hashBytes);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        if (!::CryptCATAdminCalcHashFromFileHandle2(
                catalogAdmin,
                fileHandle,
                &hashBytes,
                fileHash.data(),
                0))
        {
            return false;
        }
        fileHash.resize(hashBytes);
        return true;
    }

    CatalogTrustResult verifyCatalogTrust(
        const QString& filePath,
        const HANDLE fileHandle)
    {
        CatalogTrustResult finalResult;
        const std::array<LPCWSTR, 3> kAlgorithms{
            nullptr,
            BCRYPT_SHA256_ALGORITHM,
            BCRYPT_SHA1_ALGORITHM
        };
        QSet<QString> attemptedIdentifiers;

        for (const LPCWSTR kAlgorithm : kAlgorithms)
        {
            ScopedCatalogAdmin catalogAdmin;
            GUID subsystem = DRIVER_ACTION_VERIFY;
            if (!::CryptCATAdminAcquireContext2(
                    &catalogAdmin.value,
                    &subsystem,
                    kAlgorithm,
                    nullptr,
                    0))
            {
                finalResult.lookupError = ::GetLastError();
                continue;
            }

            std::vector<BYTE> fileHash;
            if (!calculateCatalogHash(
                    catalogAdmin.value,
                    fileHandle,
                    fileHash))
            {
                finalResult.lookupError = ::GetLastError();
                continue;
            }

            const QString kIdentifier = QString::fromLatin1(
                QByteArray(
                    reinterpret_cast<const char*>(fileHash.data()),
                    static_cast<qsizetype>(fileHash.size()))
                    .toHex().toUpper());
            if (attemptedIdentifiers.contains(kIdentifier))
            {
                continue;
            }
            attemptedIdentifiers.insert(kIdentifier);
            finalResult.fileIdentifier = kIdentifier;

            HCATINFO previousCatalog = nullptr;
            for (;;)
            {
                HCATINFO currentCatalog = ::CryptCATAdminEnumCatalogFromHash(
                    catalogAdmin.value,
                    fileHash.data(),
                    static_cast<DWORD>(fileHash.size()),
                    0,
                    &previousCatalog);
                if (currentCatalog == nullptr)
                {
                    const DWORD kEnumerationError = ::GetLastError();
                    finalResult.lookupError = kEnumerationError == ERROR_SUCCESS
                        ? ERROR_NOT_FOUND
                        : kEnumerationError;
                    previousCatalog = nullptr;
                    break;
                }
                previousCatalog = currentCatalog;

                CATALOG_INFO catalogInfo{};
                catalogInfo.cbStruct = sizeof(catalogInfo);
                if (!::CryptCATCatalogInfoFromContext(
                        currentCatalog,
                        &catalogInfo,
                        0))
                {
                    finalResult.lookupError = ::GetLastError();
                    continue;
                }

                const QString kCatalogPath = QString::fromWCharArray(
                    catalogInfo.wszCatalogFile);
                WINTRUST_CATALOG_INFO trustCatalogInfo{};
                trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
                trustCatalogInfo.pcwszCatalogFilePath =
                    reinterpret_cast<LPCWSTR>(kCatalogPath.utf16());
                trustCatalogInfo.pcwszMemberTag =
                    reinterpret_cast<LPCWSTR>(kIdentifier.utf16());
                trustCatalogInfo.pcwszMemberFilePath =
                    reinterpret_cast<LPCWSTR>(filePath.utf16());
                trustCatalogInfo.hMemberFile = fileHandle;
                trustCatalogInfo.pbCalculatedFileHash = fileHash.data();
                trustCatalogInfo.cbCalculatedFileHash =
                    static_cast<DWORD>(fileHash.size());
                trustCatalogInfo.hCatAdmin = catalogAdmin.value;

                WINTRUST_DATA trustData{};
                initializeOfflineTrustData(trustData);
                trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
                trustData.pCatalog = &trustCatalogInfo;
                LARGE_INTEGER fileStart{};
                ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);

                QString catalogSigner;
                const LONG kTrustStatus = runWinTrustAndClose(
                    trustData,
                    &catalogSigner);
                finalResult.catalogPath = kCatalogPath;
                finalResult.trustStatus = kTrustStatus;
                finalResult.trustStatusAvailable = true;
                if (!catalogSigner.isEmpty())
                {
                    finalResult.signer = catalogSigner;
                }
                if (kTrustStatus == ERROR_SUCCESS)
                {
                    finalResult.trusted = true;
                    finalResult.lookupError = ERROR_SUCCESS;
                    ::CryptCATAdminReleaseCatalogContext(
                        catalogAdmin.value,
                        currentCatalog,
                        0);
                    previousCatalog = nullptr;
                    return finalResult;
                }
            }
        }
        return finalResult;
    }

    void verifyAuthenticode(ks::process::DllFileEvidence& evidence)
    {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath =
            reinterpret_cast<LPCWSTR>(evidence.path.utf16());

        WINTRUST_DATA embeddedTrustData{};
        initializeOfflineTrustData(embeddedTrustData);
        embeddedTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        embeddedTrustData.pFile = &fileInfo;
        evidence.embeddedTrustStatus = static_cast<std::int32_t>(
            runWinTrustAndClose(embeddedTrustData, &evidence.signer));
        if (evidence.embeddedTrustStatus == ERROR_SUCCESS)
        {
            evidence.trusted = true;
            evidence.trustSource = ks::process::DllHijackTrustSource::kEmbedded;
            return;
        }

        evidence.catalogAttempted = true;
        ScopedFileHandle fileHandle(evidence.path);
        if (fileHandle.value == INVALID_HANDLE_VALUE)
        {
            evidence.catalogLookupError = ::GetLastError();
            return;
        }

        const CatalogTrustResult kCatalogTrust = verifyCatalogTrust(
            evidence.path,
            fileHandle.value);
        evidence.catalogTrustStatus =
            static_cast<std::int32_t>(kCatalogTrust.trustStatus);
        evidence.catalogLookupError = kCatalogTrust.lookupError;
        evidence.catalogTrustStatusAvailable =
            kCatalogTrust.trustStatusAvailable;
        if (!kCatalogTrust.signer.isEmpty())
        {
            evidence.signer = kCatalogTrust.signer;
        }
        if (kCatalogTrust.trusted)
        {
            evidence.trusted = true;
            evidence.trustSource = ks::process::DllHijackTrustSource::kCatalog;
        }
    }

    ks::process::DllFileEvidence readFileEvidence(const QString& rawPath)
    {
        ks::process::DllFileEvidence evidence;
        evidence.path = normalizedAbsolutePath(rawPath);
        const QFileInfo kFileInfo(evidence.path);
        evidence.readable = kFileInfo.exists() && kFileInfo.isFile() && kFileInfo.isReadable();
        if (!kFileInfo.exists() || !kFileInfo.isFile())
        {
            return evidence;
        }

        evidence.sizeBytes = kFileInfo.size() > 0
            ? static_cast<std::uint64_t>(kFileInfo.size())
            : 0U;
        const DWORD kAttributes = ::GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(evidence.path.utf16()));
        evidence.reparsePoint = kAttributes != INVALID_FILE_ATTRIBUTES &&
            (kAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
        evidence.machine = readPeMachine(evidence.path);

        const VersionEvidence kVersionEvidence = readVersionEvidence(evidence.path);
        evidence.companyName = kVersionEvidence.companyName;
        evidence.originalFilename = kVersionEvidence.originalFilename;
        evidence.fileVersion = kVersionEvidence.fileVersion;
        evidence.sha256 = calculateSha256(evidence.path);
        verifyAuthenticode(evidence);
        return evidence;
    }

    QSet<QString> queryKnownDllNames()
    {
        QSet<QString> names;
        HKEY knownDllKey = nullptr;
        LONG openStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &knownDllKey);
        if (openStatus != ERROR_SUCCESS)
        {
            openStatus = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
                0,
                KEY_READ,
                &knownDllKey);
        }
        if (openStatus != ERROR_SUCCESS || knownDllKey == nullptr)
        {
            return names;
        }

        DWORD valueCount = 0U;
        DWORD maxValueNameChars = 0U;
        DWORD maxValueDataBytes = 0U;
        if (::RegQueryInfoKeyW(
                knownDllKey,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                &valueCount,
                &maxValueNameChars,
                &maxValueDataBytes,
                nullptr,
                nullptr) == ERROR_SUCCESS)
        {
            std::vector<wchar_t> valueName(maxValueNameChars + 2U, L'\0');
            std::vector<BYTE> valueData(maxValueDataBytes + sizeof(wchar_t), 0U);
            for (DWORD valueIndex = 0U; valueIndex < valueCount; ++valueIndex)
            {
                DWORD valueNameChars = static_cast<DWORD>(valueName.size());
                DWORD valueDataBytes = static_cast<DWORD>(valueData.size());
                DWORD valueType = 0U;
                const LONG kEnumerateStatus = ::RegEnumValueW(
                    knownDllKey,
                    valueIndex,
                    valueName.data(),
                    &valueNameChars,
                    nullptr,
                    &valueType,
                    valueData.data(),
                    &valueDataBytes);
                if (kEnumerateStatus != ERROR_SUCCESS ||
                    (valueType != REG_SZ && valueType != REG_EXPAND_SZ) ||
                    valueDataBytes < sizeof(wchar_t))
                {
                    continue;
                }

                const auto* const kValueText =
                    reinterpret_cast<const wchar_t*>(valueData.data());
                int valueChars = static_cast<int>(
                    valueDataBytes / sizeof(wchar_t));
                while (valueChars > 0 && kValueText[valueChars - 1] == L'\0')
                {
                    --valueChars;
                }
                if (valueChars == 0)
                {
                    continue;
                }
                const QString kDllName = QFileInfo(
                    QString::fromWCharArray(kValueText, valueChars)
                        .trimmed())
                    .fileName()
                    .toCaseFolded();
                if (!kDllName.isEmpty())
                {
                    names.insert(kDllName);
                }
            }
        }
        ::RegCloseKey(knownDllKey);
        return names;
    }

    bool sameText(const QString& left, const QString& right)
    {
        return left.trimmed().compare(right.trimmed(), Qt::CaseInsensitive) == 0;
    }

    ks::process::DllHijackRisk classifyRisk(
        const ks::process::DllHijackFinding& finding)
    {
        if (finding.hashComparable && finding.hashesMatch)
        {
            return ks::process::DllHijackRisk::kSafe;
        }
        if (!finding.machineCompatible)
        {
            return finding.presence == ks::process::DllHijackPresence::kLoaded
                ? ks::process::DllHijackRisk::kHigh
                : ks::process::DllHijackRisk::kInformational;
        }

        const bool kSignerMismatch =
            finding.signerComparable && !finding.signersMatch;
        const bool kOriginalNameMismatch =
            finding.originalFilenameComparable &&
            !finding.originalFilenamesMatch;
        const bool kStrongReplacementEvidence =
            !finding.localFile.trusted ||
            kSignerMismatch ||
            kOriginalNameMismatch ||
            finding.localFile.reparsePoint;

        if (finding.presence == ks::process::DllHijackPresence::kLoaded)
        {
            return kStrongReplacementEvidence
                ? ks::process::DllHijackRisk::kHigh
                : ks::process::DllHijackRisk::kSuspicious;
        }
        if (finding.knownDll && !finding.dllRedirectionPresent)
        {
            return ks::process::DllHijackRisk::kInformational;
        }
        return kStrongReplacementEvidence
            ? ks::process::DllHijackRisk::kSuspicious
            : ks::process::DllHijackRisk::kInformational;
    }

    int riskSortValue(const ks::process::DllHijackRisk risk)
    {
        switch (risk)
        {
        case ks::process::DllHijackRisk::kHigh:
            return 3;
        case ks::process::DllHijackRisk::kSuspicious:
            return 2;
        case ks::process::DllHijackRisk::kInformational:
            return 1;
        case ks::process::DllHijackRisk::kSafe:
        default:
            return 0;
        }
    }
}

namespace ks::process
{
    DllHijackScanResult scanProcessDllHijacking(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const QString& fallbackImagePath)
    {
        DllHijackScanResult result;

        std::uint64_t currentCreationTime100ns = 0U;
        std::string identityDiagnostic;
        if (!queryProcessCreationTimeByPid(
                pid,
                &currentCreationTime100ns,
                &identityDiagnostic))
        {
            result.status = DllHijackScanStatus::kProcessIdentityUnavailable;
            result.diagnosticText = QString::fromStdString(identityDiagnostic);
            return result;
        }
        if (expectedCreationTime100ns != 0U &&
            expectedCreationTime100ns != currentCreationTime100ns)
        {
            result.status = DllHijackScanStatus::kProcessIdentityMismatch;
            result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
                .arg(expectedCreationTime100ns)
                .arg(currentCreationTime100ns);
            return result;
        }

        const std::uint64_t kVerifiedCreationTime100ns =
            expectedCreationTime100ns != 0U
                ? expectedCreationTime100ns
                : currentCreationTime100ns;
        const ProcessModuleSnapshot kModuleSnapshot =
            enumerateProcessModulesAndThreadsIfIdentityMatches(
                pid,
                kVerifiedCreationTime100ns,
                false);
        result.loadedModuleEvidenceAvailable = !kModuleSnapshot.modules.empty();

        const std::string kQueriedImagePath = queryProcessPathByPid(pid);
        result.processImagePath = normalizedAbsolutePath(
            kQueriedImagePath.empty()
                ? fallbackImagePath
                : QString::fromStdString(kQueriedImagePath));
        if (result.processImagePath.isEmpty() ||
            !QFileInfo(result.processImagePath).isFile())
        {
            for (const ProcessModuleRecord& module : kModuleSnapshot.modules)
            {
                const QString kModulePath = normalizedAbsolutePath(
                    QString::fromStdString(module.modulePath));
                if (QFileInfo(kModulePath).suffix().compare(
                        QStringLiteral("exe"),
                        Qt::CaseInsensitive) == 0)
                {
                    result.processImagePath = kModulePath;
                    break;
                }
            }
        }
        if (result.processImagePath.isEmpty() ||
            !QFileInfo(result.processImagePath).isFile())
        {
            result.status = DllHijackScanStatus::kImagePathUnavailable;
            result.diagnosticText = QString::fromStdString(
                kModuleSnapshot.diagnosticText);
            return result;
        }

        result.applicationDirectory = normalizedAbsolutePath(
            QFileInfo(result.processImagePath).absolutePath());
        if (result.applicationDirectory.isEmpty() ||
            !QFileInfo(result.applicationDirectory).isDir())
        {
            result.status = DllHijackScanStatus::kApplicationDirectoryUnavailable;
            return result;
        }

        const std::uint16_t kProcessMachine = readPeMachine(
            result.processImagePath);
        const QString kNativeSystemDirectory = queryNativeSystemDirectory();
        const QString kWow64SystemDirectory = queryWow64SystemDirectory();
        result.systemDirectory = kProcessMachine == IMAGE_FILE_MACHINE_I386 &&
                !kWow64SystemDirectory.isEmpty()
            ? kWow64SystemDirectory
            : kNativeSystemDirectory;
        if (result.systemDirectory.isEmpty() ||
            !QFileInfo(result.systemDirectory).isDir())
        {
            result.status = DllHijackScanStatus::kSystemDirectoryUnavailable;
            return result;
        }

        const QString kApplicationDirectoryKey = pathKey(
            result.applicationDirectory);
        if (kApplicationDirectoryKey == pathKey(kNativeSystemDirectory) ||
            (!kWow64SystemDirectory.isEmpty() &&
                kApplicationDirectoryKey == pathKey(kWow64SystemDirectory)))
        {
            result.diagnosticText = QStringLiteral(
                "application directory is an architecture system directory");
            return result;
        }

        const QFileInfo kRedirectionInfo(result.processImagePath + QStringLiteral(".local"));
        result.dllRedirectionPresent = kRedirectionInfo.exists();

        QMap<QString, CandidateDll> candidates;
        auto addCandidate = [&candidates, &result](
            const QString& rawPath,
            const bool loaded)
        {
            const QString kNormalizedPath = normalizedAbsolutePath(rawPath);
            if (kNormalizedPath.isEmpty() ||
                QFileInfo(kNormalizedPath).suffix().compare(
                    QStringLiteral("dll"),
                    Qt::CaseInsensitive) != 0 ||
                !pathIsInsideDirectory(
                    kNormalizedPath,
                    result.applicationDirectory))
            {
                return;
            }

            const QString kKey = pathKey(kNormalizedPath);
            auto existing = candidates.find(kKey);
            if (existing == candidates.end())
            {
                CandidateDll candidate;
                candidate.path = kNormalizedPath;
                candidate.loaded = loaded;
                candidates.insert(kKey, candidate);
            }
            else if (loaded)
            {
                existing->loaded = true;
            }
        };

        QDirIterator directoryIterator(
            result.applicationDirectory,
            QStringList{QStringLiteral("*.dll")},
            QDir::Files | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
            QDirIterator::NoIteratorFlags);
        while (directoryIterator.hasNext())
        {
            if (result.scannedApplicationDllCount >= kMaxApplicationDllCount)
            {
                result.directoryEnumerationTruncated = true;
                break;
            }
            const QString kDllPath = directoryIterator.next();
            ++result.scannedApplicationDllCount;
            addCandidate(kDllPath, false);
        }

        for (const ProcessModuleRecord& module : kModuleSnapshot.modules)
        {
            addCandidate(QString::fromStdString(module.modulePath), true);
        }

        const QSet<QString> kKnownDllNames = queryKnownDllNames();
        QHash<QString, DllFileEvidence> systemEvidenceCache;
        for (auto candidateIterator = candidates.cbegin();
             candidateIterator != candidates.cend();
             ++candidateIterator)
        {
            const CandidateDll& candidate = candidateIterator.value();
            const QString kDllName = QFileInfo(candidate.path).fileName();
            const QString kSystemPath = normalizedAbsolutePath(
                QDir(result.systemDirectory).filePath(kDllName));
            if (!QFileInfo(kSystemPath).isFile() ||
                pathKey(kSystemPath) == pathKey(candidate.path))
            {
                continue;
            }
            ++result.systemNameCollisionCount;

            const QString kSystemKey = pathKey(kSystemPath);
            auto systemEvidenceIterator = systemEvidenceCache.find(kSystemKey);
            if (systemEvidenceIterator == systemEvidenceCache.end())
            {
                systemEvidenceIterator = systemEvidenceCache.insert(
                    kSystemKey,
                    readFileEvidence(kSystemPath));
            }
            const DllFileEvidence& systemEvidence = systemEvidenceIterator.value();
            if (!systemEvidence.trusted)
            {
                continue;
            }
            ++result.signedSystemBaselineCount;
            if (!machinesCompatible(kProcessMachine, systemEvidence.machine))
            {
                ++result.skippedArchitectureMismatchCount;
                continue;
            }

            DllHijackFinding finding;
            finding.localFile = readFileEvidence(candidate.path);
            finding.systemFile = systemEvidence;
            finding.presence = candidate.loaded
                ? DllHijackPresence::kLoaded
                : DllHijackPresence::kPresentOnly;
            finding.knownDll = kKnownDllNames.contains(kDllName.toCaseFolded());
            finding.dllRedirectionPresent = result.dllRedirectionPresent;
            finding.hashComparable = !finding.localFile.sha256.isEmpty() &&
                !finding.systemFile.sha256.isEmpty();
            finding.hashesMatch = finding.hashComparable &&
                sameText(finding.localFile.sha256, finding.systemFile.sha256);
            finding.signerComparable = !finding.localFile.signer.isEmpty() &&
                !finding.systemFile.signer.isEmpty();
            finding.signersMatch = finding.signerComparable &&
                sameText(finding.localFile.signer, finding.systemFile.signer);
            finding.companyComparable = !finding.localFile.companyName.isEmpty() &&
                !finding.systemFile.companyName.isEmpty();
            finding.companiesMatch = finding.companyComparable &&
                sameText(
                    finding.localFile.companyName,
                    finding.systemFile.companyName);
            finding.originalFilenameComparable =
                !finding.localFile.originalFilename.isEmpty() &&
                !finding.systemFile.originalFilename.isEmpty();
            finding.originalFilenamesMatch =
                finding.originalFilenameComparable &&
                sameText(
                    finding.localFile.originalFilename,
                    finding.systemFile.originalFilename);
            finding.versionComparable = !finding.localFile.fileVersion.isEmpty() &&
                !finding.systemFile.fileVersion.isEmpty();
            finding.versionsMatch = finding.versionComparable &&
                sameText(
                    finding.localFile.fileVersion,
                    finding.systemFile.fileVersion);
            finding.machineCompatible = machinesCompatible(
                kProcessMachine,
                finding.localFile.machine);
            finding.risk = classifyRisk(finding);
            result.findings.push_back(std::move(finding));
        }

        std::uint64_t finalCreationTime100ns = 0U;
        std::string finalIdentityDiagnostic;
        if (!queryProcessCreationTimeByPid(
                pid,
                &finalCreationTime100ns,
                &finalIdentityDiagnostic))
        {
            result.status = DllHijackScanStatus::kProcessIdentityUnavailable;
            result.diagnosticText =
                QString::fromStdString(finalIdentityDiagnostic);
            result.findings.clear();
            return result;
        }
        if (finalCreationTime100ns != kVerifiedCreationTime100ns)
        {
            result.status = DllHijackScanStatus::kProcessIdentityMismatch;
            result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
                .arg(kVerifiedCreationTime100ns)
                .arg(finalCreationTime100ns);
            result.findings.clear();
            return result;
        }

        std::sort(
            result.findings.begin(),
            result.findings.end(),
            [](const DllHijackFinding& left, const DllHijackFinding& right)
            {
                const int kLeftRisk = riskSortValue(left.risk);
                const int kRightRisk = riskSortValue(right.risk);
                if (kLeftRisk != kRightRisk)
                {
                    return kLeftRisk > kRightRisk;
                }
                if (left.presence != right.presence)
                {
                    return left.presence == DllHijackPresence::kLoaded;
                }
                return QFileInfo(left.localFile.path).fileName().compare(
                    QFileInfo(right.localFile.path).fileName(),
                    Qt::CaseInsensitive) < 0;
            });
        return result;
    }
}
