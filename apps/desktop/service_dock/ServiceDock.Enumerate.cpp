#include "ServiceDock.Internal.h"

#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>

#include <Softpub.h>
#include <wintrust.h>

using namespace service_dock_detail;

#pragma comment(lib, "Wintrust.lib")

namespace
{
    // kSignatureCacheEntryLimit:
    // - Limit the maximum number of signature result cache entries;
    // - Upon reaching the limit, clear the entire cache to prevent unbounded growth after the process runs for a long time.
    constexpr int kSignatureCacheEntryLimit = 4096;

    // signatureCacheMutex purpose: Protects the signature result cache.
    // Input: None.
    // Returns: a process-level unique mutex reference; full enumeration threads and single-refresh tasks access the cache concurrently.
    QMutex& signatureCacheMutex()
    {
        static QMutex mutexInstance;
        return mutexInstance;
    }

    // signatureCacheMap purpose: Caches the verdicts from WinVerifyTrust.
    // Input: None.
    // Returns: A reference to the result table keyed by 'lowercase path|last write milliseconds|file byte count'.
    QHash<QString, bool>& signatureCacheMap()
    {
        static QHash<QString, bool> cacheInstance;
        return cacheInstance;
    }

    // verifyFileTrustByWinTrust purpose: Actually performs a WinVerifyTrust signature verification.
    // Parameter: filePathText is the file path with leading and trailing whitespace removed.
    // Return: true if Windows trusts the file.
    bool verifyFileTrustByWinTrust(const QString& filePathText)
    {
        const std::wstring kUtf16Path = filePathText.toStdWString();
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = kUtf16Path.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.pFile = &fileInfo;

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG kVerifyResult = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        return kVerifyResult == ERROR_SUCCESS;
    }

    // isFileTrustedByWindows: Cached signature verification entry point.
    // Input: filePathText is the file path text held by the UI side.
    // Return: true if Windows trusts the file.
    // Note: Directory signatures (catalogs) still require searching the CatRoot database and hashing the file, typically
    //       taking tens to hundreds of milliseconds per file. Here, we cache the result based on 'path + last write time + size'
    //       to avoid repeatedly verifying the signature for the same executable between list refreshes and individual refreshes.
    bool isFileTrustedByWindows(const QString& filePathText)
    {
        const QString kNormalizedPathText = filePathText.trimmed();
        if (kNormalizedPathText.isEmpty())
        {
            return false;
        }

        const QFileInfo kTargetFileInfo(kNormalizedPathText);
        if (!kTargetFileInfo.exists() || !kTargetFileInfo.isFile())
        {
            return false;
        }

        const QString kCacheKeyText = QStringLiteral("%1|%2|%3")
            .arg(QDir::toNativeSeparators(kNormalizedPathText).toLower())
            .arg(kTargetFileInfo.lastModified().toMSecsSinceEpoch())
            .arg(kTargetFileInfo.size());

        {
            QMutexLocker cacheLocker(&signatureCacheMutex());
            const QHash<QString, bool>::const_iterator kCachedIterator =
                signatureCacheMap().constFind(kCacheKeyText);
            if (kCachedIterator != signatureCacheMap().constEnd())
            {
                return kCachedIterator.value();
            }
        }

        const bool kTrustedByWindows = verifyFileTrustByWinTrust(kNormalizedPathText);

        {
            QMutexLocker cacheLocker(&signatureCacheMutex());
            if (signatureCacheMap().size() >= kSignatureCacheEntryLimit)
            {
                signatureCacheMap().clear();
            }
            signatureCacheMap().insert(kCacheKeyText, kTrustedByWindows);
        }
        return kTrustedByWindows;
    }

    // queryFailureCommandTextByServiceName reads failure-action command via ks::service.
    // Input: serviceNameText is the SCM short name from the UI cache.
    // Processing: the reusable layer owns QueryServiceConfig2W and string ownership.
    // Return: command text, or empty when missing/unreadable.
    QString queryFailureCommandTextByServiceName(const QString& serviceNameText)
    {
        ks::service::FailureSettings settings;
        if (!ks::service::queryServiceFailureSettings(serviceNameText.toStdWString(), &settings))
        {
            return QString();
        }
        return QString::fromStdWString(settings.command).trimmed();
    }

    // queryServiceDllPathFromRegistry reads Parameters\ServiceDll.
    // Input: serviceNameText is the SCM short name.
    // Processing: this remains registry access, not SCM access, so it stays in UI helper scope.
    // Return: expanded native path or an empty string when absent.
    QString queryServiceDllPathFromRegistry(const QString& serviceNameText)
    {
        const QString kRegistryPathText = QStringLiteral(
            "SYSTEM\\CurrentControlSet\\Services\\%1\\Parameters").arg(serviceNameText.trimmed());
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            reinterpret_cast<LPCWSTR>(kRegistryPathText.utf16()),
            0,
            KEY_READ,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return QString();
        }

        DWORD valueType = 0;
        DWORD requiredBytes = 0;
        LONG queryResult = ::RegQueryValueExW(openedKey, L"ServiceDll", nullptr, &valueType, nullptr, &requiredBytes);
        if (queryResult != ERROR_SUCCESS || requiredBytes == 0 || (valueType != REG_EXPAND_SZ && valueType != REG_SZ))
        {
            ::RegCloseKey(openedKey);
            return QString();
        }

        std::vector<wchar_t> valueBuffer((requiredBytes / sizeof(wchar_t)) + 2, L'\0');
        queryResult = ::RegQueryValueExW(
            openedKey,
            L"ServiceDll",
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer.data()),
            &requiredBytes);
        ::RegCloseKey(openedKey);
        if (queryResult != ERROR_SUCCESS)
        {
            return QString();
        }

        QString rawPathText = QString::fromWCharArray(valueBuffer.data()).trimmed();
        if (rawPathText.isEmpty())
        {
            return QString();
        }

        wchar_t expandedPathBuffer[MAX_PATH * 4] = {};
        const DWORD kExpandedPathBufferCount =
            static_cast<DWORD>(sizeof(expandedPathBuffer) / sizeof(expandedPathBuffer[0]));
        const DWORD kExpandedLength = ::ExpandEnvironmentStringsW(
            reinterpret_cast<LPCWSTR>(rawPathText.utf16()),
            expandedPathBuffer,
            kExpandedPathBufferCount);
        if (kExpandedLength > 0 && kExpandedLength < kExpandedPathBufferCount)
        {
            rawPathText = QString::fromWCharArray(expandedPathBuffer).trimmed();
        }

        return QDir::toNativeSeparators(rawPathText);
    }

    // evaluateRiskTagList generates UI risk tags from an already-built ServiceEntry.
    // Input: entry contains normalized path/account/config fields.
    // Processing: combines file signature, ServiceDll, account, autostart, description and failure command checks.
    // Return: de-duplicated risk labels for the table and detail panes.
    QStringList evaluateRiskTagList(const ServiceDock::ServiceEntry& entry)
    {
        QStringList riskTagList;

        // Abnormal sources enter the risk path with highest priority to ensure both the main list and audit page can directly present cross-verification conclusions.
        if (entry.registryScanCompleted
            && !entry.scmRecordPresent
            && entry.registryKeyPresent)
        {
            riskTagList.push_back(QStringLiteral("被 SCM 隐藏的幽灵服务"));
        }
        else if (entry.registryScanCompleted
            && entry.scmRecordPresent
            && !entry.registryKeyPresent)
        {
            riskTagList.push_back(QStringLiteral("仅 SCM 存在的异常服务"));
        }

        const QFileInfo kImageFileInfo(entry.imagePathText);
        if (entry.imagePathText.trimmed().isEmpty() || !kImageFileInfo.exists())
        {
            riskTagList.push_back(QStringLiteral("文件不存在"));
        }
        else if (!isFileTrustedByWindows(entry.imagePathText))
        {
            riskTagList.push_back(QStringLiteral("无签名"));
        }

        if ((entry.serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            if (entry.serviceDllPathText.trimmed().isEmpty())
            {
                riskTagList.push_back(QStringLiteral("ServiceDll缺失"));
            }
            else if (!QFileInfo::exists(entry.serviceDllPathText))
            {
                riskTagList.push_back(QStringLiteral("ServiceDll不存在"));
            }
        }

        const QString kAccountLowerText = entry.accountText.trimmed().toLower();
        if (!kAccountLowerText.isEmpty()
            && kAccountLowerText != QStringLiteral("localsystem")
            && kAccountLowerText != QStringLiteral("nt authority\\localsystem")
            && kAccountLowerText != QStringLiteral("nt authority\\localservice")
            && kAccountLowerText != QStringLiteral("localservice")
            && kAccountLowerText != QStringLiteral("nt authority\\networkservice")
            && kAccountLowerText != QStringLiteral("networkservice")
            && kAccountLowerText != QStringLiteral("n/a"))
        {
            riskTagList.push_back(QStringLiteral("异常账户"));
        }

        if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            const QString kImagePathLowerText = QDir::toNativeSeparators(entry.imagePathText).toLower();
            const bool kUnderWindowsDirectory =
                kImagePathLowerText.startsWith(QStringLiteral("c:\\windows\\"))
                || kImagePathLowerText.startsWith(QStringLiteral("\\windows\\"));
            if (!kUnderWindowsDirectory)
            {
                riskTagList.push_back(QStringLiteral("非微软自动启动"));
            }
        }

        if (entry.descriptionText.trimmed().isEmpty())
        {
            riskTagList.push_back(QStringLiteral("配置缺失"));
        }

        // Registry-only entries may fail to OpenService entirely; query failure commands only for entries visible to SCM.
        const QString kFailureCommandText = entry.scmRecordPresent
            ? queryFailureCommandTextByServiceName(entry.serviceNameText).toLower()
            : QString();
        if (kFailureCommandText.contains(QStringLiteral("powershell"))
            || kFailureCommandText.contains(QStringLiteral("cmd.exe"))
            || kFailureCommandText.contains(QStringLiteral("wscript"))
            || kFailureCommandText.contains(QStringLiteral("cscript"))
            || kFailureCommandText.contains(QStringLiteral("rundll32")))
        {
            riskTagList.push_back(QStringLiteral("可疑失败命令"));
        }

        riskTagList.removeDuplicates();
        return riskTagList;
    }

    // finalizeServiceSourceAndRisk: Unify generation of source text, risk labels, and list summary.
    // Input: entryOut already contains SCM/registry presence flags and basic configuration.
    // Returns: None; the function updates derived fields used for the UI in place.
    void finalizeServiceSourceAndRisk(ServiceDock::ServiceEntry* entryOut)
    {
        if (entryOut == nullptr)
        {
            return;
        }

        if (!entryOut->registryScanCompleted)
        {
            entryOut->sourceStatusText = QStringLiteral("注册表扫描失败（未交叉验证）");
        }
        else if (entryOut->scmRecordPresent && entryOut->registryKeyPresent)
        {
            entryOut->sourceStatusText = QStringLiteral("SCM + 注册表");
        }
        else if (!entryOut->scmRecordPresent && entryOut->registryKeyPresent)
        {
            entryOut->sourceStatusText = QStringLiteral("仅注册表（被 SCM 隐藏的幽灵服务）");
        }
        else if (entryOut->scmRecordPresent && !entryOut->registryKeyPresent)
        {
            entryOut->sourceStatusText = QStringLiteral("仅 SCM（异常服务）");
        }
        else
        {
            entryOut->sourceStatusText = QStringLiteral("来源不可用");
        }

        entryOut->riskTagList = evaluateRiskTagList(*entryOut);
        entryOut->riskSummaryText = entryOut->riskTagList.isEmpty()
            ? QStringLiteral("低")
            : entryOut->riskTagList.join(QStringLiteral(" | "));
        entryOut->hasRisk = !entryOut->riskTagList.isEmpty();
    }

    // buildServiceEntryFromRecord converts a Qt-free ks::service record into the UI cache row.
    // Input: serviceRecord is produced by ks::service enumeration/query.
    // Processing: this function only formats text and derives UI-only risk fields.
    // Return: true when a usable row is produced; strict mode fails if config is missing.
    bool buildServiceEntryFromRecord(
        const ks::service::ServiceRecord& serviceRecord,
        ServiceDock::ServiceEntry* entryOut,
        QString* errorTextOut,
        const bool strictConfig)
    {
        if (entryOut == nullptr || serviceRecord.serviceName.empty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("服务记录参数无效");
            }
            return false;
        }

        ServiceDock::ServiceEntry entry;
        entry.serviceNameText = QString::fromStdWString(serviceRecord.serviceName).trimmed();
        entry.scmRecordPresent = true;
        entry.displayNameText = QString::fromStdWString(serviceRecord.displayName).trimmed();
        if (entry.displayNameText.isEmpty())
        {
            entry.displayNameText = entry.serviceNameText;
        }

        entry.currentState = serviceRecord.status.currentState;
        entry.stateText = serviceStateToText(entry.currentState);
        entry.controlsAccepted = serviceRecord.status.controlsAccepted;
        entry.processId = serviceRecord.status.processId;
        entry.serviceTypeValue = serviceRecord.status.serviceType;
        entry.serviceTypeText = serviceTypeToText(entry.serviceTypeValue);
        entry.accountText = QStringLiteral("N/A");
        entry.errorControlText = QStringLiteral("未知");
        entry.startTypeText = QStringLiteral("未知");

        if (!serviceRecord.hasConfig)
        {
            const QString kErrorText = QString::fromUtf8(serviceRecord.configErrorText.c_str());
            if (strictConfig)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kErrorText.isEmpty() ? QStringLiteral("读取服务配置失败") : kErrorText;
                }
                return false;
            }

            entry.descriptionText = QStringLiteral("读取服务配置失败：%1")
                .arg(kErrorText.isEmpty() ? QStringLiteral("未知错误") : kErrorText);
            entry.serviceDllPathText = queryServiceDllPathFromRegistry(entry.serviceNameText);
            *entryOut = std::move(entry);
            return true;
        }

        entry.descriptionText = QString::fromStdWString(serviceRecord.description).trimmed();
        entry.commandLineText = QString::fromStdWString(serviceRecord.config.binaryPath).trimmed();
        entry.imagePathText = normalizeServiceImagePath(entry.commandLineText);
        entry.accountText = serviceRecord.config.accountName.empty()
            ? QStringLiteral("N/A")
            : QString::fromStdWString(serviceRecord.config.accountName).trimmed();
        entry.startTypeValue = serviceRecord.config.startType;
        entry.serviceTypeValue = serviceRecord.config.serviceType;
        entry.errorControlValue = serviceRecord.config.errorControl;
        entry.serviceTypeText = serviceTypeToText(entry.serviceTypeValue);
        entry.errorControlText = errorControlToText(entry.errorControlValue);
        entry.serviceDllPathText = queryServiceDllPathFromRegistry(entry.serviceNameText);
        entry.delayedAutoStart = (entry.startTypeValue == SERVICE_AUTO_START) && serviceRecord.config.delayedAutoStart;
        entry.startTypeText = startTypeToText(entry.startTypeValue, entry.delayedAutoStart);

        *entryOut = std::move(entry);
        return true;
    }

    // isRegistryOnlyServiceCandidate purpose: Filter out performance provider keys and uninstantiated user service templates.
    // Input: snapshot is the registry-only scan result.
    // Return: true only for configurations with a valid Type that should appear in the full SCM enumeration.
    bool isRegistryOnlyServiceCandidate(
        const service_dock_detail::RegistryServiceSnapshot& snapshot)
    {
        if (!snapshot.keyReadable
            || !snapshot.hasServiceType
            || (snapshot.serviceTypeValue & SERVICE_TYPE_ALL) == 0)
        {
            return false;
        }

        const bool kUserServiceTemplate =
            (snapshot.serviceTypeValue & SERVICE_USER_SERVICE) != 0
            && (snapshot.serviceTypeValue & SERVICE_USERSERVICE_INSTANCE) == 0;
        return !kUserServiceTemplate;
    }

    // buildServiceEntryFromRegistrySnapshot purpose: Construct phantom service entries missing from SCM enumeration.
    // Input: snapshot comes from an independent registry scan; entryOut receives data ready for direct rendering.
    // Return: true if the configuration satisfies the service candidate rules and construction succeeds.
    bool buildServiceEntryFromRegistrySnapshot(
        const service_dock_detail::RegistryServiceSnapshot& snapshot,
        ServiceDock::ServiceEntry* entryOut)
    {
        if (entryOut == nullptr || !isRegistryOnlyServiceCandidate(snapshot))
        {
            return false;
        }

        ServiceDock::ServiceEntry entry;
        entry.serviceNameText = snapshot.serviceNameText.trimmed();
        entry.displayNameText = snapshot.displayNameText.trimmed().isEmpty()
            ? entry.serviceNameText
            : snapshot.displayNameText.trimmed();
        entry.descriptionText = snapshot.descriptionText.trimmed();
        entry.commandLineText = snapshot.binaryPathText.trimmed();
        entry.imagePathText = normalizeServiceImagePath(entry.commandLineText);
        entry.accountText = snapshot.accountText.trimmed().isEmpty()
            ? QStringLiteral("N/A")
            : snapshot.accountText.trimmed();
        entry.currentState = 0;
        entry.stateText = QStringLiteral("SCM 不可见");
        entry.controlsAccepted = 0;
        entry.processId = 0;
        entry.startTypeValue = snapshot.hasStartType ? snapshot.startTypeValue : 0;
        entry.serviceTypeValue = snapshot.serviceTypeValue;
        entry.errorControlValue = snapshot.hasErrorControl ? snapshot.errorControlValue : 0;
        entry.delayedAutoStart = snapshot.delayedAutoStart
            && entry.startTypeValue == SERVICE_AUTO_START;
        entry.startTypeText = snapshot.hasStartType
            ? startTypeToText(entry.startTypeValue, entry.delayedAutoStart)
            : QStringLiteral("未知");
        entry.serviceTypeText = serviceTypeToText(entry.serviceTypeValue);
        entry.errorControlText = snapshot.hasErrorControl
            ? errorControlToText(entry.errorControlValue)
            : QStringLiteral("未知");
        entry.serviceDllPathText = normalizeServiceImagePath(snapshot.serviceDllPathText);
        entry.scmRecordPresent = false;
        entry.registryKeyPresent = true;
        entry.registryScanCompleted = true;
        finalizeServiceSourceAndRisk(&entry);

        *entryOut = std::move(entry);
        return true;
    }
}

void ServiceDock::enumerateServiceList(
    std::vector<ServiceEntry>* serviceListOut,
    QString* errorTextOut) const
{
    if (serviceListOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("输出容器为空");
        }
        return;
    }

    serviceListOut->clear();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::vector<ks::service::ServiceRecord> serviceRecordList;
    std::string errorText;
    if (!ks::service::enumerateServiceRecords(
        SERVICE_TYPE_ALL,
        SERVICE_STATE_ALL,
        &serviceRecordList,
        &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("枚举服务失败：%1").arg(QString::fromUtf8(errorText.c_str()));
        }
        return;
    }

    // Scan the registry as a single independent source; if the scan fails, retain the SCM list without generating spurious source discrepancies.
    std::vector<service_dock_detail::RegistryServiceSnapshot> registrySnapshotList;
    QString registryErrorText;
    const bool kRegistryScanCompleted =
        service_dock_detail::enumerateRegistryServiceSnapshots(
            &registrySnapshotList,
            &registryErrorText);

    QHash<QString, int> registryIndexByLowerName;
    if (kRegistryScanCompleted)
    {
        registryIndexByLowerName.reserve(static_cast<qsizetype>(registrySnapshotList.size()));
        for (int registryIndex = 0;
            registryIndex < static_cast<int>(registrySnapshotList.size());
            ++registryIndex)
        {
            const QString kLowerNameText = registrySnapshotList[
                static_cast<std::size_t>(registryIndex)].serviceNameText.toLower();
            if (!kLowerNameText.isEmpty())
            {
                registryIndexByLowerName.insert(kLowerNameText, registryIndex);
            }
        }
    }

    QHash<QString, bool> scmNameSet;
    scmNameSet.reserve(static_cast<qsizetype>(serviceRecordList.size()));
    serviceListOut->reserve(serviceRecordList.size() + registrySnapshotList.size());
    for (const ks::service::ServiceRecord& serviceRecord : serviceRecordList)
    {
        ServiceEntry serviceEntry;
        QString buildErrorText;
        if (buildServiceEntryFromRecord(serviceRecord, &serviceEntry, &buildErrorText, false))
        {
            const QString kLowerNameText = serviceEntry.serviceNameText.toLower();
            serviceEntry.registryScanCompleted = kRegistryScanCompleted;
            serviceEntry.registryKeyPresent = kRegistryScanCompleted
                && registryIndexByLowerName.contains(kLowerNameText);
            finalizeServiceSourceAndRisk(&serviceEntry);
            scmNameSet.insert(kLowerNameText, true);
            serviceListOut->push_back(std::move(serviceEntry));
        }
    }

    if (kRegistryScanCompleted)
    {
        // Only add registry-only entries with a valid Type that do not belong to user service templates to the list,
        // to avoid false positives for .NET performance provider keys and per-user service templates as rootkits.
        for (const service_dock_detail::RegistryServiceSnapshot& registrySnapshot : registrySnapshotList)
        {
            const QString kLowerNameText = registrySnapshot.serviceNameText.toLower();
            if (kLowerNameText.isEmpty() || scmNameSet.contains(kLowerNameText))
            {
                continue;
            }

            ServiceEntry registryOnlyEntry;
            if (buildServiceEntryFromRegistrySnapshot(registrySnapshot, &registryOnlyEntry))
            {
                serviceListOut->push_back(std::move(registryOnlyEntry));
            }
        }
    }
    else if (errorTextOut != nullptr)
    {
        *errorTextOut = QStringLiteral("SCM 枚举成功，但注册表独立扫描失败：%1")
            .arg(registryErrorText);
    }
}

namespace service_dock_detail
{
    bool querySingleServiceSnapshot(
        const QString& serviceNameText,
        const bool sourceScmRecordPresent,
        const bool sourceRegistryScanCompleted,
        ServiceDock::ServiceEntry* entryOut,
        QString* errorTextOut)
    {
        if (entryOut == nullptr || serviceNameText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("querySingleServiceByName 参数无效");
            }
            return false;
        }

        RegistryServiceSnapshot registrySnapshot;
        QString registryErrorText;
        DWORD registryErrorCode = ERROR_SUCCESS;
        const bool kRegistryQuerySucceeded = queryRegistryServiceSnapshot(
            serviceNameText,
            &registrySnapshot,
            &registryErrorText,
            &registryErrorCode);

        ks::service::ServiceRecord serviceRecord;
        std::string scmErrorText;
        const bool kScmQuerySucceeded = ks::service::queryServiceRecord(
            serviceNameText.trimmed().toStdWString(),
            &serviceRecord,
            &scmErrorText);

        ServiceDock::ServiceEntry updatedEntry;
        if (kScmQuerySucceeded)
        {
            if (!buildServiceEntryFromRecord(
                serviceRecord,
                &updatedEntry,
                errorTextOut,
                true))
            {
                return false;
            }
        }
        else if (!sourceScmRecordPresent
            && kRegistryQuerySucceeded
            && buildServiceEntryFromRegistrySnapshot(registrySnapshot, &updatedEntry))
        {
            // If the entry was already invisible to SCM enumeration, allow continued use of the independent registry snapshot.
        }
        else
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("查询服务失败：%1")
                    .arg(QString::fromUtf8(scmErrorText.c_str()));
            }
            return false;
        }

        // A single refresh preserves the full EnumServicesStatusEx source conclusion; a successful OpenService alone only
        // enriches configuration and cannot overwrite the detection evidence that the service was invisible during enumeration.
        updatedEntry.scmRecordPresent = sourceScmRecordPresent;
        const bool kRegistryAbsenceConfirmed =
            registryErrorCode == ERROR_FILE_NOT_FOUND
            || registryErrorCode == ERROR_PATH_NOT_FOUND;
        updatedEntry.registryScanCompleted = sourceRegistryScanCompleted
            && (kRegistryQuerySucceeded || kRegistryAbsenceConfirmed);
        updatedEntry.registryKeyPresent = kRegistryQuerySucceeded;
        finalizeServiceSourceAndRisk(&updatedEntry);

        *entryOut = std::move(updatedEntry);
        return true;
    }
}

bool ServiceDock::querySingleServiceByName(
    const QString& serviceNameText,
    ServiceEntry* entryOut,
    QString* errorTextOut) const
{
    bool sourceScmRecordPresent = true;
    bool sourceRegistryScanCompleted = true;
    const int kExistingIndex = findServiceIndexByName(serviceNameText);
    if (kExistingIndex >= 0 && kExistingIndex < static_cast<int>(serviceList_.size()))
    {
        const ServiceEntry& existingEntry = serviceList_[static_cast<std::size_t>(kExistingIndex)];
        sourceScmRecordPresent = existingEntry.scmRecordPresent;
        sourceRegistryScanCompleted = existingEntry.registryScanCompleted;
    }

    return service_dock_detail::querySingleServiceSnapshot(
        serviceNameText,
        sourceScmRecordPresent,
        sourceRegistryScanCompleted,
        entryOut,
        errorTextOut);
}
