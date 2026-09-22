#include "DriverDock.Internal.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/TableInteractionSupport.h"

#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <Softpub.h>
#include <WinTrust.h>

#include <QByteArray>

#pragma comment(lib, "Wintrust.lib")

using namespace ksword::driver_dock_internal;

namespace
{
    class DriverEvidenceSourceTextScope final
    {
    public:
        DriverEvidenceSourceTextScope()
            : previousMode_(swapDriverEvidenceSourceTextMode(true))
        {
        }

        ~DriverEvidenceSourceTextScope()
        {
            swapDriverEvidenceSourceTextMode(previousMode_);
        }

        DriverEvidenceSourceTextScope(const DriverEvidenceSourceTextScope&) = delete;
        DriverEvidenceSourceTextScope& operator=(const DriverEvidenceSourceTextScope&) = delete;

    private:
        bool previousMode_ = false;
    };

    // EvidenceModuleKey: lowercase module name key used for module evidence aggregation.
    // Input: Module name or path leaf; Processing: trim whitespace, extract filename, lowercase; Return: stable comparison key.
    QString evidenceModuleKey(QString moduleNameText)
    {
        moduleNameText = moduleNameText.trimmed();
        const int kSlashIndex = std::max(moduleNameText.lastIndexOf(QLatin1Char('\\')), moduleNameText.lastIndexOf(QLatin1Char('/')));
        if (kSlashIndex >= 0 && kSlashIndex + 1 < moduleNameText.size())
        {
            moduleNameText = moduleNameText.mid(kSlashIndex + 1);
        }
        return moduleNameText.toLower();
    }

    // evidenceModuleStem: Generate 'xxx' from 'xxx.sys' to use as a DriverObject name candidate.
    // Input: Module filename; Processing: extract leaf name and strip .sys suffix; Return: candidate object leaf name.
    QString evidenceModuleStem(const QString& moduleNameText)
    {
        QString stemText = evidenceModuleKey(moduleNameText);
        if (stemText.endsWith(QStringLiteral(".sys"), Qt::CaseInsensitive))
        {
            stemText.chop(4);
        }
        return stemText.trimmed();
    }

    // evidenceYesNo: Converts the evidence boolean to short Chinese text.
    // Input: flag indicates a hit or miss; Processing: select two Chinese phrases; Return: cell display text.
    QString evidenceYesNo(const bool flag, const QString& yesText, const QString& noText)
    {
        return flag ? yesText : noText;
    }

    // evidenceHookStatusText: Convert kernel Hook status to DriverDock evidence text.
    // Input: R0 shared protocol status; Processing: map according to shared constants; Return: Chinese status text.
    QString evidenceHookStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN:
            return driverText("driver.evidence.hook.clean", QStringLiteral("干净"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS:
            return driverText("driver.evidence.hook.suspicious_external", QStringLiteral("可疑外跳"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH:
            return driverText("driver.evidence.hook.internal_branch", QStringLiteral("模块内跳转"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED:
            return driverText("driver.evidence.hook.read_failed", QStringLiteral("读取失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED:
            return driverText("driver.evidence.hook.parse_failed", QStringLiteral("解析失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED:
            return driverText("driver.evidence.hook.force_required", QStringLiteral("需要强制确认"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED:
            return driverText("driver.evidence.hook.patched", QStringLiteral("已修复/摘除"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED:
            return driverText("driver.evidence.hook.patch_failed", QStringLiteral("修复失败"));
        default:
            return driverText("driver.evidence.hook.unknown", QStringLiteral("未知(%1)")).arg(statusValue);
        }
    }

    // evidenceInlineHookTypeText: Converts Inline Hook types to short text.
    // Input: shared protocol hookType; Processing: map common jump/patch forms; Return: Chinese/assembly text.
    QString evidenceInlineHookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case KSWORD_ARK_INLINE_HOOK_TYPE_NONE:
            return driverText("driver.evidence.inline.none", QStringLiteral("无明显补丁"));
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
            return driverText("driver.evidence.inline.ret_patch", QStringLiteral("RET 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
            return driverText("driver.evidence.inline.int3_patch", QStringLiteral("INT3 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_UNKNOWN_PATCH:
            return driverText("driver.evidence.inline.unknown_patch", QStringLiteral("未知补丁"));
        default:
            return driverText("driver.evidence.inline.unknown", QStringLiteral("未知(%1)")).arg(hookType);
        }
    }

    // evidenceIatEatClassText: Convert IAT/EAT type to detailed text.
    // Input: shared protocol hookClass; Processing: map IAT or EAT; Return: Chinese category text.
    QString evidenceIatEatClassText(const std::uint32_t hookClass)
    {
        switch (hookClass)
        {
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT:
            return QStringLiteral("IAT");
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT:
            return QStringLiteral("EAT");
        default:
            return driverText("driver.evidence.iat_eat.unknown", QStringLiteral("未知(%1)")).arg(hookClass);
        }
    }

    // evidenceCallbackClassText: Converts the Callback class into detailed text.
    // Input: shared protocol callbackClass; Processing: map known callback types; Return: Chinese category text.
    QString evidenceCallbackClassText(const std::uint32_t callbackClass)
    {
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return driverText("driver.evidence.callback.class.registry", QStringLiteral("注册表 CmCallback"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return driverText("driver.evidence.callback.class.process", QStringLiteral("进程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return driverText("driver.evidence.callback.class.thread", QStringLiteral("线程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return driverText("driver.evidence.callback.class.image", QStringLiteral("镜像加载 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return QStringLiteral("Object Callback");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return QStringLiteral("WFP Callout");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return QStringLiteral("ETW Provider/Consumer");
        default:
            return driverText("driver.evidence.callback.class.unknown", QStringLiteral("未知(%1)")).arg(callbackClass);
        }
    }

    // evidenceCallbackStatusText: Converts Callback enum status to detailed text.
    // Input: shared protocol status and NTSTATUS; Processing: preserve failure codes; Output: Chinese status text.
    QString evidenceCallbackStatusText(const std::uint32_t statusValue, const long lastStatus)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK:
            return driverText("driver.evidence.callback.status.ok", QStringLiteral("可见/成功"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED:
            return driverText("driver.evidence.callback.status.not_registered", QStringLiteral("未注册"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED:
            return driverText("driver.evidence.callback.status.unsupported", QStringLiteral("当前不支持"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED:
            return driverText("driver.evidence.callback.status.query_failed", QStringLiteral("查询失败(%1)"))
                .arg(formatNtStatusText(lastStatus));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED:
            return driverText("driver.evidence.callback.status.truncated", QStringLiteral("缓冲截断"));
        default:
            return driverText("driver.evidence.callback.status.unknown", QStringLiteral("未知(%1)"))
                .arg(statusValue);
        }
    }

    // evidenceAppendIoSummary: Unified recording of ArkDriverClient call summaries.
    // Input: Title, IoResult, output list; Processing: Append a copyable diagnostic line; Return: None.
    void evidenceAppendIoSummary(
        QStringList& detailLines,
        const QString& titleText,
        const ksword::ark::IoResult& ioResult)
    {
        detailLines << QStringLiteral("[%1]").arg(titleText);
        detailLines << driverText("driver.evidence.io_summary", QStringLiteral("ok=%1 win32=%2 nt=%3 bytes=%4 说明=%5"))
            .arg(ioResult.ok ? QStringLiteral("true") : QStringLiteral("false"))
            .arg(ioResult.win32Error)
            .arg(formatNtStatusText(ioResult.ntStatus))
            .arg(ioResult.bytesReturned)
            .arg(describeDriverCollection(ioResult));
    }

    // evidenceModuleNameMatches: Determine if the R0 module name matches the target module.
    // Inputs: R0 module name and target module name; Processing: compare lowercase leaf names; Return: true if they match.
    bool evidenceModuleNameMatches(const QString& leftText, const QString& rightText)
    {
        const QString kLeftKey = evidenceModuleKey(leftText);
        const QString kRightKey = evidenceModuleKey(rightText);
        return !kLeftKey.isEmpty() && !kRightKey.isEmpty() && kLeftKey == kRightKey;
    }

    // evidenceAddressLooksInsideModule: Use base address and size as fallback to determine if an address falls within a module.
    // Input: address, module base, and module size; Processing: open interval range check; Output: true if within module range.
    bool evidenceAddressLooksInsideModule(
        const std::uint64_t addressValue,
        const std::uint64_t moduleBase,
        const std::uint32_t moduleSize)
    {
        if (addressValue == 0U || moduleBase == 0U || moduleSize == 0U)
        {
            return false;
        }
        return addressValue >= moduleBase && addressValue < (moduleBase + moduleSize);
    }

    // evidenceCommunicationMaskForMajor: Maps WDK MajorFunction indices to the 5-bit protocol mask for Issue #47.
    // Input: MajorFunction value; Processing: Only recognize the five fixed communication slots managed by this function; Return: Corresponding mask or 0.
    std::uint32_t evidenceCommunicationMaskForMajor(const std::uint32_t majorFunction)
    {
        switch (majorFunction)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_CREATE:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_CREATE;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_READ:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_READ;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_WRITE:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_WRITE;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_DEVICE_CONTROL:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_DEVICE_CONTROL;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_INTERNAL_DEVICE_CONTROL:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_INTERNAL_DEVICE_CONTROL;
        default:
            return 0U;
        }
    }

    // evidenceCommunicationMaskCount: Count the set bits in the five-tuple communication slot mask.
    // Input: shared protocol mask; Processing: clear the lowest set bit iteratively; Return: number of set bits.
    std::uint32_t evidenceCommunicationMaskCount(std::uint32_t maskValue)
    {
        std::uint32_t bitCount = 0U;
        while (maskValue != 0U)
        {
            maskValue &= (maskValue - 1U);
            ++bitCount;
        }
        return bitCount;
    }

    struct CatalogSignatureVerification
    {
        QString fileIdentifier;
        QString catalogPath;
        QString signerCertificateName;
        LONG trustStatus = 0;
        DWORD lookupError = ERROR_SUCCESS;
        bool trustStatusAvailable = false;
        bool trusted = false;
    };

    class CatalogAdminHandle final
    {
    public:
        CatalogAdminHandle() = default;

        ~CatalogAdminHandle()
        {
            if (value != nullptr)
            {
                ::CryptCATAdminReleaseContext(value, 0);
            }
        }

        CatalogAdminHandle(const CatalogAdminHandle&) = delete;
        CatalogAdminHandle& operator=(const CatalogAdminHandle&) = delete;

        HCATADMIN value = nullptr;
    };

    class ReadOnlyFileHandle final
    {
    public:
        explicit ReadOnlyFileHandle(const QString& filePath)
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

        ~ReadOnlyFileHandle()
        {
            if (value != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(value);
            }
        }

        ReadOnlyFileHandle(const ReadOnlyFileHandle&) = delete;
        ReadOnlyFileHandle& operator=(const ReadOnlyFileHandle&) = delete;

        HANDLE value = INVALID_HANDLE_VALUE;
    };

    // initializeStrictTrustData：
    // - whole-chain revocation check covers the full certificate chain (excluding the root certificate);
    // - Uses only local cache; WinVerifyTrust must fail when offline, unknown, or the chain is incomplete.
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

    // extractSignerCertificateName：
    // - Input: Provider state retained by WinVerifyTrust during the VERIFY phase;
    // - Processing: Read the simple display name of the leaf certificate from the first signer chain.
    // - Return: The final signer certificate name; empty if the chain status is unreadable.
    QString extractSignerCertificateName(const WINTRUST_DATA& trustData)
    {
        if (trustData.hWVTStateData == nullptr)
        {
            return QString();
        }

        CRYPT_PROVIDER_DATA* providerData =
            ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (providerData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_SGNR* signer =
            ::WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
        if (signer == nullptr ||
            signer->csCertChain == 0 ||
            signer->pasCertChain == nullptr ||
            signer->pasCertChain[0].pCert == nullptr)
        {
            return QString();
        }

        const CERT_CONTEXT* certificateContext =
            signer->pasCertChain[0].pCert;
        const DWORD kRequiredChars = ::CertGetNameStringW(
            certificateContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nullptr,
            0);
        if (kRequiredChars <= 1)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(kRequiredChars, L'\0');
        const DWORD kWrittenChars = ::CertGetNameStringW(
            certificateContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nameBuffer.data(),
            kRequiredChars);
        if (kWrittenChars <= 1)
        {
            return QString();
        }
        return QString::fromWCharArray(
            nameBuffer.data(),
            static_cast<int>(kWrittenChars - 1)).trimmed();
    }

    // runWinTrustAndClose: All VERIFY paths must first extract the leaf certificate name before executing STATEACTION_CLOSE.
    LONG runWinTrustAndClose(
        WINTRUST_DATA& trustData,
        QString* const signerCertificateNameOut = nullptr)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG kTrustStatus = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        if (signerCertificateNameOut != nullptr)
        {
            *signerCertificateNameOut =
                extractSignerCertificateName(trustData);
        }
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return kTrustStatus;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& fileHash)
    {
        LARGE_INTEGER fileStart{};
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        DWORD hashSize = 0U;
        if (!::CryptCATAdminCalcHashFromFileHandle2(
            catalogAdmin,
            fileHandle,
            &hashSize,
            nullptr,
            0) ||
            hashSize == 0U)
        {
            return false;
        }

        fileHash.resize(hashSize);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        const BOOL kHashResult = ::CryptCATAdminCalcHashFromFileHandle2(
            catalogAdmin,
            fileHandle,
            &hashSize,
            fileHash.data(),
            0);
        if (kHashResult == FALSE)
        {
            return false;
        }
        fileHash.resize(hashSize);
        return true;
    }

    CatalogSignatureVerification verifyCatalogSignature(
        const QString& normalizedPath,
        const HANDLE fileHandle)
    {
        CatalogSignatureVerification verification;
        CatalogAdminHandle catalogAdmin;
        GUID driverActionVerify = DRIVER_ACTION_VERIFY;
        if (!::CryptCATAdminAcquireContext2(
            &catalogAdmin.value,
            &driverActionVerify,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0))
        {
            verification.lookupError = ::GetLastError();
            return verification;
        }

        std::vector<BYTE> fileHash;
        if (!calculateCatalogHash(catalogAdmin.value, fileHandle, fileHash))
        {
            verification.lookupError = ::GetLastError();
            return verification;
        }

        const QByteArray kFileIdentifierBytes = QByteArray(
            reinterpret_cast<const char*>(fileHash.data()),
            static_cast<qsizetype>(fileHash.size()))
            .toHex()
            .toUpper();
        verification.fileIdentifier = QString::fromLatin1(
            kFileIdentifierBytes.constData(),
            kFileIdentifierBytes.size());

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
                verification.lookupError = kEnumerationError == ERROR_SUCCESS
                    ? ERROR_NOT_FOUND
                    : kEnumerationError;
                // Pass previous to the next enumeration; the API takes over and releases this context.
                // After natural exhaustion returns nullptr, the caller no longer owns HCATINFO.
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
                verification.lookupError = ::GetLastError();
                continue;
            }

            verification.catalogPath = QString::fromWCharArray(
                catalogInfo.wszCatalogFile);
            WINTRUST_CATALOG_INFO trustCatalogInfo{};
            trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
            trustCatalogInfo.pcwszCatalogFilePath =
                reinterpret_cast<LPCWSTR>(verification.catalogPath.utf16());
            trustCatalogInfo.pcwszMemberTag =
                reinterpret_cast<LPCWSTR>(verification.fileIdentifier.utf16());
            trustCatalogInfo.pcwszMemberFilePath =
                reinterpret_cast<LPCWSTR>(normalizedPath.utf16());
            trustCatalogInfo.hMemberFile = fileHandle;
            trustCatalogInfo.pbCalculatedFileHash = fileHash.data();
            trustCatalogInfo.cbCalculatedFileHash =
                static_cast<DWORD>(fileHash.size());
            trustCatalogInfo.hCatAdmin = catalogAdmin.value;

            WINTRUST_DATA trustData{};
            initializeStrictTrustData(trustData);
            trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
            trustData.pCatalog = &trustCatalogInfo;
            // The catalog provider returns to the file start before reading the same read-only handle, without relying on the cursor left by the hash API.
            LARGE_INTEGER fileStart{};
            ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
            verification.trustStatus = runWinTrustAndClose(
                trustData,
                &verification.signerCertificateName);
            verification.trustStatusAvailable = true;
            verification.trusted =
                verification.trustStatus == ERROR_SUCCESS;
            if (verification.trusted)
            {
                // On success, terminate enumeration early and explicitly release the last context per the mscat contract.
                ::CryptCATAdminReleaseCatalogContext(
                    catalogAdmin.value,
                    currentCatalog,
                    0);
                previousCatalog = nullptr;
                verification.lookupError = ERROR_SUCCESS;
                break;
            }
        }
        return verification;
    }
}

DriverDock::LoadedModuleSignatureEvidence DriverDock::verifyLoadedModuleSignature(
    const QString& rawImagePath)
{
    LoadedModuleSignatureEvidence evidence;
    const QString kNormalizedPath =
        ks::online_scan::normalizeKernelImagePathForUpload(rawImagePath).trimmed();
    evidence.verificationPath =
        kNormalizedPath.isEmpty() ? rawImagePath : kNormalizedPath;
    if (kNormalizedPath.isEmpty() || !QFileInfo::exists(kNormalizedPath))
    {
        evidence.state = LoadedModuleSignatureState::kPathUnavailable;
        return evidence;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath =
        reinterpret_cast<LPCWSTR>(kNormalizedPath.utf16());

    WINTRUST_DATA embeddedTrustData{};
    initializeStrictTrustData(embeddedTrustData);
    embeddedTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    embeddedTrustData.pFile = &fileInfo;
    const LONG kEmbeddedTrustStatus = runWinTrustAndClose(
        embeddedTrustData,
        &evidence.signerCertificateName);
    evidence.embeddedTrustStatus =
        static_cast<std::int32_t>(kEmbeddedTrustStatus);
    if (kEmbeddedTrustStatus == ERROR_SUCCESS)
    {
        evidence.state = LoadedModuleSignatureState::kTrustedEmbedded;
        return evidence;
    }

    // If embedded fails, continue checking the system Catalog to support catalog-only drivers without a PE certificate table.
    evidence.catalogAttempted = true;
    ReadOnlyFileHandle fileHandle(kNormalizedPath);
    if (fileHandle.value == INVALID_HANDLE_VALUE)
    {
        evidence.catalogLookupError = ::GetLastError();
        evidence.state = LoadedModuleSignatureState::kInvalidTrust;
        return evidence;
    }

    const CatalogSignatureVerification kCatalogVerification =
        verifyCatalogSignature(kNormalizedPath, fileHandle.value);
    evidence.fileIdentifier = kCatalogVerification.fileIdentifier;
    evidence.catalogPath = kCatalogVerification.catalogPath;
    evidence.signerCertificateName =
        kCatalogVerification.signerCertificateName;
    evidence.catalogTrustStatus =
        static_cast<std::int32_t>(kCatalogVerification.trustStatus);
    evidence.catalogLookupError = kCatalogVerification.lookupError;
    evidence.catalogTrustStatusAvailable =
        kCatalogVerification.trustStatusAvailable;
    evidence.state = kCatalogVerification.trusted
        ? LoadedModuleSignatureState::kTrustedCatalog
        : LoadedModuleSignatureState::kInvalidTrust;
    return evidence;
}

DriverDock::LoadedModuleEvidenceRecord DriverDock::buildPendingModuleEvidenceRecord(
    const LoadedKernelModuleRecord& moduleRecord)
{
    // Input: module record; Processing: populate column wait text; Return: placeholder evidence record.
    LoadedModuleEvidenceRecord evidence;
    evidence.moduleName = moduleRecord.moduleName;
    const QString kPendingScanText = QStringLiteral("待扫描");
    evidence.driverObjectStatusText = kPendingScanText;
    evidence.driverStartMatchText = kPendingScanText;
    evidence.majorFunctionStatusText = kPendingScanText;
    evidence.iatEatStatusText = kPendingScanText;
    evidence.inlineHookStatusText = kPendingScanText;
    evidence.callbackStatusText = kPendingScanText;
    evidence.detailText = QStringLiteral(
        "模块 %1 尚未执行证据聚合。\n点击工具栏证据刷新按钮后，后台线程会只读查询 DriverObject / Hook / Callback。")
        .arg(moduleRecord.moduleName);
    return evidence;
}

QColor DriverDock::moduleEvidenceStatusColor(const LoadedModuleEvidenceRecord& evidence)
{
    // Input: Evidence row; Processing: Error/Suspicious/Normal three-tier colors; Return: QColor foreground color.
    if (!evidence.queryAttempted)
    {
        return ksword_theme::textSecondaryColor();
    }
    if ((moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence)) ||
        evidence.hasMajorFunctionExternalJump ||
        evidence.hasIatEatSuspicious ||
        evidence.hasInlineHookSuspicious ||
        evidence.communicationConflict)
    {
        return ksword_theme::errorColor();
    }
    if (evidence.hasScanError ||
        !evidence.driverObjectResolved ||
        (evidence.driverStartKnown && !evidence.driverStartMatchesBase) ||
        evidence.hasCallbackReference ||
        evidence.communicationActive)
    {
        return ksword_theme::warningColor();
    }
    return ksword_theme::successColor();
}

bool DriverDock::moduleSignatureCheckAttempted(
    const LoadedModuleEvidenceRecord& evidence)
{
    return evidence.signatureEvidence.state !=
        LoadedModuleSignatureState::kPending;
}

bool DriverDock::moduleSignatureTrusted(
    const LoadedModuleEvidenceRecord& evidence)
{
    return evidence.signatureEvidence.state ==
            LoadedModuleSignatureState::kTrustedEmbedded ||
        evidence.signatureEvidence.state ==
            LoadedModuleSignatureState::kTrustedCatalog;
}

QString DriverDock::moduleSignatureStatusText(
    const LoadedModuleEvidenceRecord& evidence)
{
    if (!moduleSignatureCheckAttempted(evidence))
    {
        return driverText(
            "driver.evidence.pending",
            QStringLiteral("待扫描"));
    }
    if (!moduleSignatureTrusted(evidence))
    {
        return driverText(
            "driver.signature.invalid",
            QStringLiteral("无效"));
    }
    if (!evidence.signatureEvidence.signerCertificateName.isEmpty())
    {
        return evidence.signatureEvidence.signerCertificateName;
    }
    return driverText(
        "driver.signature.valid_signer_unknown",
        QStringLiteral("有效（签名者未知）"));
}

QString DriverDock::moduleSignatureDetailText(
    const LoadedModuleEvidenceRecord& evidence)
{
    const LoadedModuleSignatureEvidence& signature =
        evidence.signatureEvidence;
    const auto kTrustStatusHex = [](const std::int32_t statusValue)
    {
        return QString::number(
            static_cast<std::uint32_t>(statusValue),
            16)
            .rightJustified(8, QLatin1Char('0'))
            .toUpper();
    };
    const QString kUnavailableText = driverText(
        "driver.signature.not_available",
        QStringLiteral("<不可用>"));
    const QString kVerificationPath = signature.verificationPath.isEmpty()
        ? kUnavailableText
        : signature.verificationPath;
    const QString kSignerCertificateName =
        signature.signerCertificateName.isEmpty()
        ? kUnavailableText
        : signature.signerCertificateName;

    switch (signature.state)
    {
    case LoadedModuleSignatureState::kPending:
        return driverText(
            "driver.signature.pending.detail",
            QStringLiteral("数字签名信任链等待后台验证。"));
    case LoadedModuleSignatureState::kPathUnavailable:
        return driverText(
            "driver.signature.path_unavailable",
            QStringLiteral("签名无效：模块映像路径不可访问。\n路径：%1"))
            .arg(kVerificationPath);
    case LoadedModuleSignatureState::kTrustedEmbedded:
        return driverText(
            "driver.signature.valid.embedded.detail",
            QStringLiteral(
                "数字签名有效：Windows 已验证嵌入式 Authenticode 完整信任链。\n"
                "签名者：%1\n路径：%2\n验证方式：嵌入签名"))
            .arg(kSignerCertificateName)
            .arg(kVerificationPath);
    case LoadedModuleSignatureState::kTrustedCatalog:
        return driverText(
            "driver.signature.valid.catalog.detail",
            QStringLiteral(
                "数字签名有效：Windows 已通过系统目录验证完整信任链。\n"
                "签名者：%1\n路径：%2\n验证方式：目录签名\n文件标识：%3\n目录：%4"))
            .arg(kSignerCertificateName)
            .arg(kVerificationPath)
            .arg(signature.fileIdentifier.isEmpty()
                ? kUnavailableText
                : signature.fileIdentifier)
            .arg(signature.catalogPath.isEmpty()
                ? kUnavailableText
                : signature.catalogPath);
    case LoadedModuleSignatureState::kInvalidTrust:
    default:
        break;
    }

    const QString kCatalogTrustText =
        signature.catalogTrustStatusAvailable
        ? QStringLiteral("0x%1").arg(
            kTrustStatusHex(signature.catalogTrustStatus))
        : driverText(
            "driver.signature.not_performed",
            QStringLiteral("未执行"));
    const QString kCatalogLookupText = QStringLiteral("%1 (0x%2)")
        .arg(signature.catalogLookupError)
        .arg(
            QString::number(signature.catalogLookupError, 16)
                .rightJustified(8, QLatin1Char('0'))
                .toUpper());
    return driverText(
        "driver.signature.invalid.strict.detail",
        QStringLiteral(
            "数字签名无效或完整信任链无法验证。\n"
            "路径：%1\n"
            "嵌入式 WinVerifyTrust：0x%2\n"
            "目录 WinVerifyTrust：%3\n"
            "目录查询错误：%4\n"
            "文件标识：%5\n"
            "说明：吊销状态离线、未知或链不完整均按无效处理。"))
        .arg(kVerificationPath)
        .arg(kTrustStatusHex(signature.embeddedTrustStatus))
        .arg(kCatalogTrustText)
        .arg(kCatalogLookupText)
        .arg(signature.fileIdentifier.isEmpty()
            ? kUnavailableText
            : signature.fileIdentifier);
}

QString DriverDock::localizedModuleEvidenceText(const QString& sourceText)
{
    QStringList localizedLines;
    const QStringList kSourceLines =
        sourceText.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    localizedLines.reserve(kSourceLines.size());
    for (const QString& sourceLine : kSourceLines)
    {
        localizedLines.push_back(ks::i18n::displayText(sourceLine));
    }
    return localizedLines.join(QLatin1Char('\n'));
}

bool DriverDock::queryDriverObjectForModuleEvidence(
    const LoadedKernelModuleRecord& moduleRecord,
    ksword::ark::DriverObjectQueryResult& resultOut,
    QString& attemptedNamesTextOut)
{
    // Input: Loaded module row; Processing: Attempt queries sequentially by common DriverObject namespace; Return: Whether parsing succeeded.
    resultOut = ksword::ark::DriverObjectQueryResult{};
    attemptedNamesTextOut.clear();

    const QString kStemText = evidenceModuleStem(moduleRecord.moduleName);
    if (kStemText.isEmpty())
    {
        attemptedNamesTextOut = driverText("driver.evidence.module_name.empty", QStringLiteral("<模块名为空>"));
        return false;
    }

    const QStringList kCandidateNames = {
        QStringLiteral("\\Driver\\%1").arg(kStemText),
        QStringLiteral("\\FileSystem\\%1").arg(kStemText),
        QStringLiteral("\\FileSystem\\Filters\\%1").arg(kStemText),
        kStemText
    };

    QStringList attemptedNames;
    const ksword::ark::DriverClient kDriverClient;
    for (const QString& candidateName : kCandidateNames)
    {
        if (attemptedNames.contains(candidateName, Qt::CaseInsensitive))
        {
            continue;
        }
        attemptedNames << candidateName;

        const ksword::ark::DriverObjectQueryResult kQueryResult = kDriverClient.queryDriverObject(
            candidateName.toStdWString(),
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_MAJOR_FUNCTIONS |
                KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_NAMES,
            1UL,
            1UL);

        resultOut = kQueryResult;
        if (kQueryResult.io.ok &&
            (kQueryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
                kQueryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL) &&
            kQueryResult.driverObjectAddress != 0U)
        {
            attemptedNamesTextOut = attemptedNames.join(QStringLiteral(", "));
            return true;
        }
    }

    attemptedNamesTextOut = attemptedNames.join(QStringLiteral(", "));
    return false;
}

std::vector<DriverDock::LoadedModuleEvidenceRecord> DriverDock::collectEvidenceForLoadedModules(
    const std::vector<LoadedKernelModuleRecord>& moduleRecords)
{
    // Input: current module snapshot; Processing: aggregate evidence using existing DriverClient capabilities; Output: evidence array with the same length as input.
    // Background threads only cache source text and semantic fields; LanguageManager allows access only during the GUI rendering phase.
    const DriverEvidenceSourceTextScope kSourceTextScope;
    std::vector<LoadedModuleEvidenceRecord> evidenceRecords;
    evidenceRecords.reserve(moduleRecords.size());

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::KernelInlineHookScanResult kInlineResult = kDriverClient.scanInlineHooks(
        0UL,
        KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
        std::wstring());
    const ksword::ark::KernelIatEatHookScanResult kIatEatResult = kDriverClient.enumerateIatEatHooks(
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS,
        KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
        std::wstring());
    const ksword::ark::CallbackEnumResult kCallbackResult = kDriverClient.enumerateCallbacks(
        KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);

    for (const LoadedKernelModuleRecord& moduleRecord : moduleRecords)
    {
        LoadedModuleEvidenceRecord evidence = buildPendingModuleEvidenceRecord(moduleRecord);
        evidence.queryAttempted = true;
        // Note: signatureVerification purpose: Incorporate the Windows trust chain conclusion of the module file into the same background evidence snapshot.
        evidence.signatureEvidence =
            verifyLoadedModuleSignature(moduleRecord.imagePath);

        QStringList detailLines;

        ksword::ark::DriverObjectQueryResult objectResult;
        QString attemptedNamesText;
        evidence.driverObjectResolved = queryDriverObjectForModuleEvidence(
            moduleRecord,
            objectResult,
            attemptedNamesText);
        evidenceAppendIoSummary(
            detailLines,
            driverText("driver.evidence.detail.driver_object_query", QStringLiteral("DriverObject 查询")),
            objectResult.io);
        detailLines << driverText("driver.evidence.detail.candidate_names", QStringLiteral("候选名称: %1"))
            .arg(attemptedNamesText);
        detailLines << QStringLiteral("QueryStatus: %1").arg(driverObjectQueryStatusText(objectResult.queryStatus));
        detailLines << QStringLiteral("DriverName: %1").arg(QString::fromStdWString(objectResult.driverName));
        detailLines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(objectResult.driverObjectAddress));
        detailLines << QStringLiteral("DriverStart: %1").arg(formatCompactAddress(objectResult.driverStart));
        detailLines << QStringLiteral("DriverSize: 0x%1").arg(static_cast<qulonglong>(objectResult.driverSize), 8, 16, QChar('0')).toUpper();
        detailLines << QStringLiteral("ImagePath: %1").arg(QString::fromStdWString(objectResult.imagePath));
        detailLines << QString();

        evidence.driverObjectName = QString::fromStdWString(objectResult.driverName);
        evidence.driverObjectAddress = objectResult.driverObjectAddress;
        evidence.driverObjectStatusText = evidence.driverObjectResolved
            ? driverText("driver.evidence.status.resolved", QStringLiteral("已解析"))
            : driverText("driver.evidence.status.unresolved", QStringLiteral("未解析"));
        evidence.driverStartKnown = objectResult.driverStart != 0U;
        evidence.driverStartMatchesBase = evidence.driverStartKnown &&
            objectResult.driverStart == moduleRecord.baseAddress;
        evidence.driverStartMatchText = !evidence.driverStartKnown
            ? driverText("driver.evidence.status.unknown", QStringLiteral("未知"))
            : evidenceYesNo(
                evidence.driverStartMatchesBase,
                driverText("driver.evidence.status.match", QStringLiteral("匹配")),
                driverText("driver.evidence.status.mismatch", QStringLiteral("不匹配")));
        if (!objectResult.io.ok)
        {
            evidence.hasScanError = true;
        }

        ksword::ark::DriverCommunicationControlResult communicationResult;
        const bool kCommunicationQueryEligible =
            evidence.driverObjectResolved &&
            evidence.driverStartMatchesBase &&
            evidence.driverObjectAddress != 0U &&
            !evidence.driverObjectName.trimmed().isEmpty();
        detailLines << driverText(
            "driver.evidence.communication.title",
            QStringLiteral("[IRP 通信控制]"));
        if (kCommunicationQueryEligible)
        {
            communicationResult = kDriverClient.queryDriverCommunication(
                moduleRecord.baseAddress,
                evidence.driverObjectName.toStdWString());
            const bool kOperationSucceeded =
                communicationResult.io.ok &&
                communicationResult.lastStatus >= 0;
            const bool kResponseIdentityMatches =
                communicationResult.state ==
                    KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE ||
                (communicationResult.driverStart == moduleRecord.baseAddress &&
                    communicationResult.driverObjectAddress ==
                        evidence.driverObjectAddress);
            evidence.communicationStateKnown =
                kOperationSucceeded &&
                kResponseIdentityMatches;
            evidence.communicationActiveMask =
                evidence.communicationStateKnown
                ? communicationResult.activeMask
                : 0U;
            evidence.communicationOwnedMask =
                evidence.communicationStateKnown
                ? communicationResult.ownedMask
                : 0U;
            evidence.communicationConflictMask =
                evidence.communicationStateKnown
                ? communicationResult.conflictMask
                : 0U;
            evidence.communicationGeneration =
                evidence.communicationStateKnown
                ? communicationResult.generation
                : 0U;
            evidence.communicationRejectDispatchAddress =
                evidence.communicationStateKnown
                ? communicationResult.rejectDispatchAddress
                : 0U;
            evidence.communicationActive =
                evidence.communicationOwnedMask != 0U;
            evidence.communicationConflict =
                evidence.communicationConflictMask != 0U ||
                (evidence.communicationStateKnown &&
                    communicationResult.state ==
                        KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT);

            detailLines << driverText(
                "driver.evidence.communication.io",
                QStringLiteral("查询: ok=%1 Last=%2 说明=%3"))
                .arg(communicationResult.io.ok
                    ? QStringLiteral("true")
                    : QStringLiteral("false"))
                .arg(communicationResult.io.ok
                    ? formatNtStatusText(communicationResult.lastStatus)
                    : QStringLiteral("<不可用>"))
                .arg(describeDriverCollection(communicationResult.io));
            detailLines << driverText(
                "driver.evidence.communication.state",
                QStringLiteral(
                    "状态: known=%1 state=%2 active=%3 owned=%4 conflict=%5 generation=%6"))
                .arg(evidence.communicationStateKnown
                    ? QStringLiteral("true")
                    : QStringLiteral("false"))
                .arg(communicationResult.state)
                .arg(formatHex32(communicationResult.activeMask))
                .arg(formatHex32(communicationResult.ownedMask))
                .arg(formatHex32(communicationResult.conflictMask))
                .arg(communicationResult.generation);
            detailLines << driverText(
                "driver.evidence.communication.identity",
                QStringLiteral("身份: DriverObject=%1 DriverStart=%2 Reject=%3"))
                .arg(formatCompactAddress(
                    communicationResult.driverObjectAddress))
                .arg(formatCompactAddress(communicationResult.driverStart))
                .arg(formatCompactAddress(
                    communicationResult.rejectDispatchAddress));
            if (kOperationSucceeded && !kResponseIdentityMatches)
            {
                evidence.hasScanError = true;
                detailLines << driverText(
                    "driver.evidence.communication.identity_mismatch",
                    QStringLiteral(
                        "通信控制记录与当前 DriverObject 证据不一致，已拒绝把该记录视为可信状态。"));
            }
        }
        else
        {
            detailLines << driverText(
                "driver.evidence.communication.not_eligible",
                QStringLiteral(
                    "未查询：需要已解析的 canonical DriverObject、对象地址及匹配的 DriverStart。"));
        }
        detailLines << QString();

        detailLines << QStringLiteral("[MajorFunction]");
        if (objectResult.majorFunctions.empty())
        {
            detailLines << driverText(
                "driver.evidence.detail.major_function_missing",
                QStringLiteral("未返回 MajorFunction 表。")) << QString();
        }
        else
        {
            for (const ksword::ark::DriverMajorFunctionEntry& entry : objectResult.majorFunctions)
            {
                const bool kOutsideOwnImage = (entry.flags & 0x00000002U) == 0U;
                const std::uint32_t kCommunicationMask =
                    evidenceCommunicationMaskForMajor(entry.majorFunction);
                const bool kIntentionalCommunicationBlind =
                    kOutsideOwnImage &&
                    evidence.communicationStateKnown &&
                    evidence.communicationRejectDispatchAddress != 0U &&
                    kCommunicationMask != 0U &&
                    (evidence.communicationActiveMask & kCommunicationMask) != 0U &&
                    (evidence.communicationOwnedMask & kCommunicationMask) != 0U &&
                    entry.dispatchAddress ==
                        evidence.communicationRejectDispatchAddress;
                if (kIntentionalCommunicationBlind)
                {
                    ++evidence.majorFunctionIntentionalBlindCount;
                    detailLines << driverText(
                        "driver.evidence.detail.major_function_intentional_blind",
                        QStringLiteral(
                            "主动致盲: %1 dispatch=%2 系统拒绝入口，由 Issue #47 通信控制持有"))
                        .arg(driverMajorFunctionName(entry.majorFunction))
                        .arg(formatCompactAddress(entry.dispatchAddress));
                }
                else if (kOutsideOwnImage)
                {
                    ++evidence.majorFunctionExternalCount;
                    detailLines << driverText(
                        "driver.evidence.detail.major_function_external",
                        QStringLiteral("外跳: %1 dispatch=%2 module=%3 moduleBase=%4 location=%5"))
                        .arg(driverMajorFunctionName(entry.majorFunction))
                        .arg(formatCompactAddress(entry.dispatchAddress))
                        .arg(QString::fromStdWString(entry.moduleName))
                        .arg(formatCompactAddress(entry.moduleBase))
                        .arg(driverDispatchLocationText(entry.flags));
                }
            }
            if (evidence.majorFunctionExternalCount == 0U &&
                evidence.majorFunctionIntentionalBlindCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.major_function_clean",
                    QStringLiteral("未发现 MajorFunction 外跳。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasMajorFunctionExternalJump = evidence.majorFunctionExternalCount != 0U;
        const std::uint32_t kCommunicationConflictCount =
            evidenceCommunicationMaskCount(evidence.communicationConflictMask);
        if (evidence.communicationConflict)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_conflict",
                QStringLiteral("主动致盲 %1/5 · 冲突 %2"))
                .arg(evidence.majorFunctionIntentionalBlindCount)
                .arg(kCommunicationConflictCount);
        }
        else if (evidence.majorFunctionIntentionalBlindCount != 0U &&
            evidence.hasMajorFunctionExternalJump)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_and_external",
                QStringLiteral("主动致盲 %1/5 · 未知外跳 %2"))
                .arg(evidence.majorFunctionIntentionalBlindCount)
                .arg(evidence.majorFunctionExternalCount);
        }
        else if (evidence.majorFunctionIntentionalBlindCount != 0U)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_active",
                QStringLiteral("主动致盲 %1/5"))
                .arg(evidence.majorFunctionIntentionalBlindCount);
        }
        else
        {
            evidence.majorFunctionStatusText = evidence.hasMajorFunctionExternalJump
                ? driverText("driver.evidence.status.external_count", QStringLiteral("外跳 %1"))
                    .arg(evidence.majorFunctionExternalCount)
                : driverText("driver.evidence.status.no_external", QStringLiteral("未见外跳"));
        }

        detailLines << QStringLiteral("[IAT/EAT]");
        if (!kIatEatResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.scan_failed", QStringLiteral("扫描失败: %1"))
                .arg(describeDriverCollection(kIatEatResult.io));
        }
        else
        {
            for (const ksword::ark::KernelIatEatHookEntry& entry : kIatEatResult.entries)
            {
                const bool kSameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.moduleName), moduleRecord.moduleName);
                if (!kSameModule || entry.status != KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    continue;
                }
                ++evidence.iatEatSuspiciousCount;
                detailLines << driverText(
                    "driver.evidence.detail.iat_eat_suspicious",
                    QStringLiteral("可疑: %1 module=%2 import=%3 func=%4 thunk=%5 current=%6 expected=%7 targetModule=%8 status=%9"))
                    .arg(evidenceIatEatClassText(entry.hookClass))
                    .arg(QString::fromStdWString(entry.moduleName))
                    .arg(QString::fromStdWString(entry.importModuleName))
                    .arg(QString::fromLocal8Bit(entry.functionName.data(), static_cast<int>(entry.functionName.size())))
                    .arg(formatCompactAddress(entry.thunkAddress))
                    .arg(formatCompactAddress(entry.currentTarget))
                    .arg(formatCompactAddress(entry.expectedTarget))
                    .arg(QString::fromStdWString(entry.targetModuleName))
                    .arg(evidenceHookStatusText(entry.status));
            }
            if (evidence.iatEatSuspiciousCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.iat_eat_clean",
                    QStringLiteral("未发现该模块 IAT/EAT 可疑项。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasIatEatSuspicious = evidence.iatEatSuspiciousCount != 0U;
        evidence.iatEatStatusText = evidence.hasIatEatSuspicious
            ? driverText("driver.evidence.status.suspicious_count", QStringLiteral("可疑 %1"))
                .arg(evidence.iatEatSuspiciousCount)
            : (kIatEatResult.io.ok
                ? driverText("driver.evidence.status.no_suspicious", QStringLiteral("未见可疑"))
                : driverText("driver.evidence.status.scan_failed", QStringLiteral("扫描失败")));

        detailLines << QStringLiteral("[Inline Hook]");
        if (!kInlineResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.scan_failed", QStringLiteral("扫描失败: %1"))
                .arg(describeDriverCollection(kInlineResult.io));
        }
        else
        {
            for (const ksword::ark::KernelInlineHookEntry& entry : kInlineResult.entries)
            {
                const bool kSameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.moduleName), moduleRecord.moduleName);
                if (!kSameModule || entry.status != KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    continue;
                }
                ++evidence.inlineHookSuspiciousCount;
                detailLines << driverText(
                    "driver.evidence.detail.inline_suspicious",
                    QStringLiteral("可疑: module=%1 function=%2 address=%3 type=%4 target=%5 targetModule=%6 status=%7"))
                    .arg(QString::fromStdWString(entry.moduleName))
                    .arg(QString::fromLocal8Bit(entry.functionName.data(), static_cast<int>(entry.functionName.size())))
                    .arg(formatCompactAddress(entry.functionAddress))
                    .arg(evidenceInlineHookTypeText(entry.hookType))
                    .arg(formatCompactAddress(entry.targetAddress))
                    .arg(QString::fromStdWString(entry.targetModuleName))
                    .arg(evidenceHookStatusText(entry.status));
            }
            if (evidence.inlineHookSuspiciousCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.inline_clean",
                    QStringLiteral("未发现该模块 Inline Hook 可疑项。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasInlineHookSuspicious = evidence.inlineHookSuspiciousCount != 0U;
        evidence.inlineHookStatusText = evidence.hasInlineHookSuspicious
            ? driverText("driver.evidence.status.suspicious_count", QStringLiteral("可疑 %1"))
                .arg(evidence.inlineHookSuspiciousCount)
            : (kInlineResult.io.ok
                ? driverText("driver.evidence.status.no_suspicious", QStringLiteral("未见可疑"))
                : driverText("driver.evidence.status.scan_failed", QStringLiteral("扫描失败")));

        detailLines << QStringLiteral("[Callback]");
        if (!kCallbackResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.enumeration_failed", QStringLiteral("枚举失败: %1"))
                .arg(describeDriverCollection(kCallbackResult.io));
        }
        else
        {
            for (const ksword::ark::CallbackEnumEntry& entry : kCallbackResult.entries)
            {
                const bool kSameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceAddressLooksInsideModule(entry.callbackAddress, moduleRecord.baseAddress, entry.moduleSize) ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.modulePath), moduleRecord.moduleName) ||
                    QString::fromStdWString(entry.modulePath).contains(moduleRecord.moduleName, Qt::CaseInsensitive);
                if (!kSameModule)
                {
                    continue;
                }
                ++evidence.callbackReferenceCount;
                detailLines << driverText(
                    "driver.evidence.detail.callback_reference",
                    QStringLiteral("引用: class=%1 status=%2 callback=%3 context=%4 registration=%5 moduleBase=%6 modulePath=%7 name=%8 altitude=%9 detail=%10"))
                    .arg(evidenceCallbackClassText(entry.callbackClass))
                    .arg(evidenceCallbackStatusText(entry.status, entry.lastStatus))
                    .arg(formatCompactAddress(entry.callbackAddress))
                    .arg(formatCompactAddress(entry.contextAddress))
                    .arg(formatCompactAddress(entry.registrationAddress))
                    .arg(formatCompactAddress(entry.moduleBase))
                    .arg(QString::fromStdWString(entry.modulePath))
                    .arg(QString::fromStdWString(entry.name))
                    .arg(QString::fromStdWString(entry.altitude))
                    .arg(QString::fromStdWString(entry.detail));
            }
            if (evidence.callbackReferenceCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.callback_clean",
                    QStringLiteral("未发现 Callback 引用该模块。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasCallbackReference = evidence.callbackReferenceCount != 0U;
        evidence.callbackStatusText = evidence.hasCallbackReference
            ? driverText("driver.evidence.status.reference_count", QStringLiteral("引用 %1"))
                .arg(evidence.callbackReferenceCount)
            : (kCallbackResult.io.ok
                ? driverText("driver.evidence.status.no_reference", QStringLiteral("未见引用"))
                : driverText("driver.evidence.status.enumeration_failed", QStringLiteral("枚举失败")));

        detailLines << driverText("driver.evidence.detail.global_summary", QStringLiteral("[全局扫描摘要]"));
        evidenceAppendIoSummary(detailLines, QStringLiteral("Inline Hook"), kInlineResult.io);
        detailLines << driverText(
            "driver.evidence.detail.inline_summary",
            QStringLiteral("Inline returned=%1 total=%2 modules=%3 last=%4"))
            .arg(kInlineResult.entries.size())
            .arg(kInlineResult.totalCount)
            .arg(kInlineResult.moduleCount)
            .arg(formatNtStatusText(kInlineResult.lastStatus));
        evidenceAppendIoSummary(detailLines, QStringLiteral("IAT/EAT"), kIatEatResult.io);
        detailLines << driverText(
            "driver.evidence.detail.iat_eat_summary",
            QStringLiteral("IAT/EAT returned=%1 total=%2 modules=%3 last=%4"))
            .arg(kIatEatResult.entries.size())
            .arg(kIatEatResult.totalCount)
            .arg(kIatEatResult.moduleCount)
            .arg(formatNtStatusText(kIatEatResult.lastStatus));
        evidenceAppendIoSummary(detailLines, QStringLiteral("Callback"), kCallbackResult.io);
        detailLines << driverText(
            "driver.evidence.detail.callback_summary",
            QStringLiteral("Callback returned=%1 total=%2 last=%3"))
            .arg(kCallbackResult.entries.size())
            .arg(kCallbackResult.totalCount)
            .arg(formatNtStatusText(kCallbackResult.lastStatus));

        evidence.detailText = detailLines.join('\n');
        evidenceRecords.push_back(std::move(evidence));
    }

    return evidenceRecords;
}

void DriverDock::refreshLoadedModuleEvidenceAsync()
{
    // Input: Currently loaded module cache; Processing: Aggregate R0 evidence in the background and push to UI; Return: None.
    if (moduleEvidenceQuerying_)
    {
        return;
    }
    if (loadedModuleCache_.empty())
    {
        // If the user manually clicks 'Refresh Evidence' but no module snapshot exists, only prompt the user to refresh modules first:
        // - Input: Null m_loadedModuleCache;
        // - Processing: Do not call refreshLoadedKernelModuleRecords in reverse here.
        // - Return: None. Prevents recursive module refresh and evidence refresh in an empty list environment.
        if (moduleEvidenceStatusLabel_ != nullptr)
        {
            moduleEvidenceStatusLabel_->setText(driverText(
                "driver.evidence.status.no_modules",
                QStringLiteral("证据：没有可聚合的模块，请先刷新已加载模块。")));
        }
        return;
    }

    moduleEvidenceQuerying_ = true;
    const std::uint64_t kTicketValue = ++moduleEvidenceQueryTicket_;
    if (refreshModuleEvidenceButton_ != nullptr)
    {
        refreshModuleEvidenceButton_->setEnabled(false);
    }
    if (moduleEvidenceStatusLabel_ != nullptr)
    {
        moduleEvidenceStatusLabel_->setText(driverText(
            "driver.evidence.status.aggregating",
            QStringLiteral("证据：正在刷新...")));
    }

    const std::vector<LoadedKernelModuleRecord> kModuleSnapshot = loadedModuleCache_;
    QObject* const kApplicationContext = QCoreApplication::instance();
    if (kApplicationContext == nullptr)
    {
        moduleEvidenceQuerying_ = false;
        if (refreshModuleEvidenceButton_ != nullptr)
        {
            refreshModuleEvidenceButton_->setEnabled(true);
        }
        return;
    }

    QPointer<DriverDock> guardThis(this);
    auto* evidenceTask = QRunnable::create(
        [kApplicationContext, guardThis, kTicketValue, kModuleSnapshot]()
        {
            auto resultRecords = DriverDock::collectEvidenceForLoadedModules(kModuleSnapshot);

            // The application object is a stable dispatch context; QPointer is only checked and dereferenced within the GUI lambda.
            QMetaObject::invokeMethod(
                kApplicationContext,
                [guardThis, kTicketValue, resultRecords = std::move(resultRecords)]() mutable
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const auto kDeferredRecords =
                        std::make_shared<std::vector<LoadedModuleEvidenceRecord>>(
                            std::move(resultRecords));
                    const auto kCommitEvidence = [guardThis, kTicketValue, kDeferredRecords]()
                    {
                        if (guardThis == nullptr ||
                            guardThis->moduleEvidenceQueryTicket_ != kTicketValue)
                        {
                            return;
                        }

                        guardThis->moduleEvidenceQuerying_ = false;
                        if (guardThis->refreshModuleEvidenceButton_ != nullptr)
                        {
                            guardThis->refreshModuleEvidenceButton_->setEnabled(true);
                        }

                        guardThis->loadedModuleEvidenceCache_ = std::move(*kDeferredRecords);
                        // Since the signature status is itself a search field, the shared filter must be reapplied after background completion.
                        guardThis->rebuildLoadedModuleTable();
                        guardThis->updateLoadedModuleEvidenceStatusText();
                    };

                    if (guardThis == nullptr ||
                        guardThis->moduleEvidenceQueryTicket_ != kTicketValue)
                    {
                        return;
                    }
                    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("driver-loaded-module-evidence-apply"),
                        { guardThis->moduleTable_ },
                        kCommitEvidence))
                    {
                        return;
                    }
                    kCommitEvidence();
                },
                Qt::QueuedConnection);
        });
    evidenceTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(evidenceTask);
}

void DriverDock::updateLoadedModuleEvidenceStatusText()
{
    if (moduleEvidenceStatusLabel_ == nullptr)
    {
        return;
    }
    if (moduleEvidenceQuerying_)
    {
        moduleEvidenceStatusLabel_->setText(driverText(
            "driver.evidence.status.aggregating",
            QStringLiteral("证据：正在刷新...")));
        return;
    }
    if (loadedModuleEvidenceCache_.empty())
    {
        moduleEvidenceStatusLabel_->setText(driverText(
            "driver.evidence.status.no_modules_short",
            QStringLiteral("证据：没有可聚合的模块。")));
        return;
    }

    const bool kHasCompletedEvidence = std::any_of(
        loadedModuleEvidenceCache_.cbegin(),
        loadedModuleEvidenceCache_.cend(),
        [](const LoadedModuleEvidenceRecord& evidence)
        {
            return evidence.queryAttempted;
        });
    if (!kHasCompletedEvidence)
    {
        moduleEvidenceStatusLabel_->setText(driverText(
            "driver.evidence.status.modules_refreshed",
            QStringLiteral("证据：模块列表已刷新。")));
        return;
    }

    std::size_t suspiciousCount = 0U;
    std::size_t callbackCount = 0U;
    std::size_t errorCount = 0U;
    std::size_t invalidSignatureCount = 0U;
    for (const LoadedModuleEvidenceRecord& evidence :
        loadedModuleEvidenceCache_)
    {
        if (evidence.hasMajorFunctionExternalJump ||
            evidence.hasIatEatSuspicious ||
            evidence.hasInlineHookSuspicious ||
            evidence.communicationConflict)
        {
            ++suspiciousCount;
        }
        if (evidence.hasCallbackReference)
        {
            ++callbackCount;
        }
        if (evidence.hasScanError)
        {
            ++errorCount;
        }
        if (moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence))
        {
            ++invalidSignatureCount;
        }
    }

    moduleEvidenceStatusLabel_->setText(
        driverText(
            "driver.evidence.status.completed",
            QStringLiteral(
                "证据：已聚合 %1 个模块，可疑=%2，Callback引用=%3，错误=%4，签名无效=%5"))
        .arg(loadedModuleEvidenceCache_.size())
        .arg(suspiciousCount)
        .arg(callbackCount)
        .arg(errorCount)
        .arg(invalidSignatureCount));
}

void DriverDock::rebuildLoadedModuleEvidenceViews()
{
    // Input: current module table and evidence cache; Processing: fill evidence column colors/text row by row; Return: none.
    if (moduleTable_ == nullptr)
    {
        return;
    }

    for (int rowIndex = 0; rowIndex < moduleTable_->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* moduleItem = moduleTable_->item(rowIndex, 0);
        if (moduleItem == nullptr)
        {
            continue;
        }

        const std::size_t kSourceIndex = static_cast<std::size_t>(
            moduleItem->data(kModuleRecordIndexRole).toULongLong());
        if (kSourceIndex >= loadedModuleEvidenceCache_.size())
        {
            continue;
        }

        const LoadedModuleEvidenceRecord& evidence = loadedModuleEvidenceCache_[kSourceIndex];
        // invalidSignature usage: Only mark the entire line red if the background check was completed and the trust chain failed.
        const bool kInvalidSignature =
            moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence);
        QColor invalidSignatureBackgroundColor = ksword_theme::errorColor();
        invalidSignatureBackgroundColor.setAlpha(48);
        for (int columnIndex = 0;
            columnIndex < moduleTable_->columnCount();
            ++columnIndex)
        {
            QTableWidgetItem* rowItem = moduleTable_->item(rowIndex, columnIndex);
            if (rowItem != nullptr)
            {
                rowItem->setBackground(
                    kInvalidSignature
                    ? QBrush(invalidSignatureBackgroundColor)
                    : QBrush());
            }
        }

        QTableWidgetItem* signatureItem =
            moduleTable_->item(rowIndex, kModuleSignatureColumn);
        const QString kSignatureStatusText =
            moduleSignatureStatusText(evidence);
        const QString kSignatureDetailText =
            moduleSignatureDetailText(evidence);
        if (signatureItem == nullptr)
        {
            signatureItem = createReadOnlyItem(kSignatureStatusText);
            moduleTable_->setItem(rowIndex, kModuleSignatureColumn, signatureItem);
        }
        else
        {
            signatureItem->setText(kSignatureStatusText);
        }
        const QColor kSignatureColor = !moduleSignatureCheckAttempted(evidence)
            ? ksword_theme::textSecondaryColor()
            : (moduleSignatureTrusted(evidence)
                ? ksword_theme::successColor()
                : ksword_theme::errorColor());
        signatureItem->setForeground(QBrush(kSignatureColor));
        signatureItem->setToolTip(kSignatureDetailText.left(4000));

        const QString kPendingText = driverText(
            "driver.evidence.pending",
            QStringLiteral("待扫描"));
        const QString kDriverObjectStatusText = !evidence.queryAttempted
            ? kPendingText
            : (evidence.driverObjectResolved
                ? driverText(
                    "driver.evidence.status.resolved",
                    QStringLiteral("已解析"))
                : driverText(
                    "driver.evidence.status.unresolved",
                    QStringLiteral("未解析")));
        const QString kDriverStartStatusText = !evidence.queryAttempted
            ? kPendingText
            : (!evidence.driverStartKnown
                ? driverText(
                    "driver.evidence.status.unknown",
                    QStringLiteral("未知"))
                : (evidence.driverStartMatchesBase
                    ? driverText(
                        "driver.evidence.status.match",
                        QStringLiteral("匹配"))
                    : driverText(
                        "driver.evidence.status.mismatch",
                        QStringLiteral("不匹配"))));

        QString majorFunctionStatusText = kPendingText;
        if (evidence.queryAttempted)
        {
            const std::uint32_t kCommunicationConflictCount =
                evidenceCommunicationMaskCount(
                    evidence.communicationConflictMask);
            if (evidence.communicationConflict)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_conflict",
                    QStringLiteral("主动致盲 %1/5 · 冲突 %2"))
                    .arg(evidence.majorFunctionIntentionalBlindCount)
                    .arg(kCommunicationConflictCount);
            }
            else if (evidence.majorFunctionIntentionalBlindCount != 0U &&
                evidence.hasMajorFunctionExternalJump)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_and_external",
                    QStringLiteral("主动致盲 %1/5 · 未知外跳 %2"))
                    .arg(evidence.majorFunctionIntentionalBlindCount)
                    .arg(evidence.majorFunctionExternalCount);
            }
            else if (evidence.majorFunctionIntentionalBlindCount != 0U)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_active",
                    QStringLiteral("主动致盲 %1/5"))
                    .arg(evidence.majorFunctionIntentionalBlindCount);
            }
            else
            {
                majorFunctionStatusText =
                    evidence.hasMajorFunctionExternalJump
                    ? driverText(
                        "driver.evidence.status.external_count",
                        QStringLiteral("外跳 %1"))
                        .arg(evidence.majorFunctionExternalCount)
                    : driverText(
                        "driver.evidence.status.no_external",
                        QStringLiteral("未见外跳"));
            }
        }

        const QString kIatEatStatusText =
            evidence.queryAttempted && evidence.hasIatEatSuspicious
            ? driverText(
                "driver.evidence.status.suspicious_count",
                QStringLiteral("可疑 %1"))
                .arg(evidence.iatEatSuspiciousCount)
            : localizedModuleEvidenceText(evidence.iatEatStatusText);
        const QString kInlineHookStatusText =
            evidence.queryAttempted && evidence.hasInlineHookSuspicious
            ? driverText(
                "driver.evidence.status.suspicious_count",
                QStringLiteral("可疑 %1"))
                .arg(evidence.inlineHookSuspiciousCount)
            : localizedModuleEvidenceText(evidence.inlineHookStatusText);
        const QString kCallbackStatusText =
            evidence.queryAttempted && evidence.hasCallbackReference
            ? driverText(
                "driver.evidence.status.reference_count",
                QStringLiteral("引用 %1"))
                .arg(evidence.callbackReferenceCount)
            : localizedModuleEvidenceText(evidence.callbackStatusText);
        const QStringList kColumnTexts = {
            kDriverObjectStatusText,
            kDriverStartStatusText,
            majorFunctionStatusText,
            kIatEatStatusText,
            kInlineHookStatusText,
            kCallbackStatusText
        };
        const QColor kForegroundColor = moduleEvidenceStatusColor(evidence);
        for (int columnOffset = 0; columnOffset < kColumnTexts.size(); ++columnOffset)
        {
            const int kColumnIndex = kModuleEvidenceFirstColumn + columnOffset;
            QTableWidgetItem* cellItem = moduleTable_->item(rowIndex, kColumnIndex);
            if (cellItem == nullptr)
            {
                cellItem = createReadOnlyItem(kColumnTexts[columnOffset]);
                moduleTable_->setItem(rowIndex, kColumnIndex, cellItem);
            }
            else
            {
                cellItem->setText(kColumnTexts[columnOffset]);
            }
            cellItem->setForeground(QBrush(kForegroundColor));
            // Full evidence is already displayed in the detail area below the table; the evidence column no longer
            // attaches hover text up to 4000 characters to avoid the tooltip obscuring the entire main window.
            cellItem->setToolTip(QString());
        }
    }

    showSelectedModuleEvidenceDetail();
}

void DriverDock::showSelectedModuleEvidenceDetail()
{
    // Input: current module table selection; Processing: read cache and display details; Output: none.
    if (moduleEvidenceDetailEditor_ == nullptr)
    {
        return;
    }
    if (moduleTable_ == nullptr || moduleTable_->selectionModel() == nullptr)
    {
        moduleEvidenceDetailEditor_->setLocalizedText(
            driverText("driver.evidence.detail.table_unavailable", QStringLiteral("模块表不可用。")));
        return;
    }

    const QModelIndexList kSelectedRows = moduleTable_->selectionModel()->selectedRows(0);
    if (kSelectedRows.isEmpty())
    {
        moduleEvidenceDetailEditor_->setLocalizedText(driverText(
            "driver.evidence.detail.select_module",
            QStringLiteral("请选择一条已加载模块查看聚合证据。")));
        return;
    }

    const int kRowIndex = kSelectedRows.front().row();
    QTableWidgetItem* moduleItem = moduleTable_->item(kRowIndex, 0);
    if (moduleItem == nullptr)
    {
        moduleEvidenceDetailEditor_->setLocalizedText(
            driverText("driver.evidence.detail.module_name_missing", QStringLiteral("当前行没有模块名。")));
        return;
    }

    const std::size_t kSourceIndex = static_cast<std::size_t>(
        moduleItem->data(kModuleRecordIndexRole).toULongLong());
    if (kSourceIndex >= loadedModuleEvidenceCache_.size())
    {
        moduleEvidenceDetailEditor_->setLocalizedText(
            driverText("driver.evidence.detail.not_generated", QStringLiteral("模块 %1 尚未生成证据详情。"))
            .arg(moduleItem->text()));
        return;
    }

    const LoadedModuleEvidenceRecord& evidence =
        loadedModuleEvidenceCache_[kSourceIndex];
    const LoadedKernelModuleRecord* moduleRecord =
        kSourceIndex < loadedModuleCache_.size()
        ? &loadedModuleCache_[kSourceIndex]
        : nullptr;
    const QString kSignatureSummary = driverText(
        "driver.evidence.detail.signature",
        QStringLiteral("数字签名: %1"))
        .arg(moduleSignatureStatusText(evidence));
    QString evidenceBody;
    if (!evidence.queryAttempted)
    {
        evidenceBody = driverText(
            "driver.evidence.pending.detail",
            QStringLiteral(
                "模块 %1 尚未执行证据聚合。\n"
                "点击工具栏证据刷新按钮后，后台线程会只读查询 DriverObject / Hook / Callback。"))
            .arg(evidence.moduleName);
    }
    else
    {
        evidenceBody = localizedModuleEvidenceText(evidence.detailText);
    }

    QStringList localizedDetailLines;
    localizedDetailLines
        << driverText(
            "driver.evidence.detail.title",
            QStringLiteral("模块证据聚合"))
        << driverText(
            "driver.evidence.detail.module",
            QStringLiteral("模块: %1"))
            .arg(evidence.moduleName);
    if (moduleRecord != nullptr)
    {
        localizedDetailLines
            << driverText(
                "driver.evidence.detail.base",
                QStringLiteral("基址: %1"))
                .arg(formatCompactAddress(moduleRecord->baseAddress))
            << driverText(
                "driver.evidence.detail.image_path",
                QStringLiteral("映像路径: %1"))
                .arg(moduleRecord->imagePath);
    }
    localizedDetailLines
        << kSignatureSummary
        << moduleSignatureDetailText(evidence)
        << driverText(
            "driver.evidence.detail.read_only_note",
            QStringLiteral("说明: 本结果仅聚合证据，不执行卸载、移除或修复。"))
        << QString()
        << evidenceBody;
    moduleEvidenceDetailEditor_->setRawText(
        localizedDetailLines.join(QLatin1Char('\n')));
}
