#include "ServiceDock.Internal.h"
#include "../framework/PrivilegeElevationPrompt.h"

#include <QCoreApplication>
#include <QRunnable>
#include <QSet>
#include <QThreadPool>

using namespace service_dock_detail;

namespace
{
    // kDeleteStopTimeoutMs purpose: The maximum time to wait for the service to actually stop during a combined delete operation.
    constexpr std::uint32_t kDeleteStopTimeoutMs = 10000;

    // LiveDeleteTarget purpose: preserves the real-time target identity re-read after a destructive operation begins.
    struct LiveDeleteTarget
    {
        QString serviceNameText;      // serviceNameText: Normalized short service name.
        QString serviceFilePathText; // serviceFilePathText: the actual exe/sys/ServiceDll to be deleted.
        DWORD serviceTypeValue = 0;  // serviceTypeValue: real-time service type.
        DWORD currentState = 0;      // currentState: Real-time SCM state; registry-only entries are 0.
        bool scmQueryable = false;   // scmQueryable: Whether the target can be queried via OpenService.
    };

    // ServiceDeleteResult purpose: return the full/partial/failure status of the background deletion to the UI thread.
    struct ServiceDeleteResult
    {
        bool success = false;             // success: Whether all stages of the request have completed.
        bool partialSuccess = false;      // partialSuccess: Service deleted but file deletion failed.
        bool registrationDeleted = false; // registrationDeleted: Service registration has been deleted or marked for deletion.
        bool fileDeleted = false;         // fileDeleted: Target file was deleted or did not originally exist.
        DWORD errorCode = ERROR_SUCCESS;  // errorCode: Win32 error code during the failure phase.
        QString serviceFilePathText;      // serviceFilePathText: File path after actual verification.
        QString detailText;               // detailText: user-readable failure/success details.
    };

    // pendingDeleteServiceNameSet: Prevents the same service from being dispatched deletion tasks repeatedly.
    // Input: None.
    // Returns: A case-normalized set of service names read/written only on the UI thread.
    QSet<QString>& pendingDeleteServiceNameSet()
    {
        static QSet<QString> pendingNameSet;
        return pendingNameSet;
    }

    // normalizedServiceFilePath purpose: Select the file truly belonging to the service based on service type.
    // Input parameters: for shared process services, prefer ServiceDll; for others, select the BinaryPath image.
    // Return: Normalized path suitable for file identity comparison; returns empty if it cannot be safely determined.
    QString normalizedServiceFilePath(
        const DWORD serviceTypeValue,
        const QString& binaryPathText,
        const QString& serviceDllPathText)
    {
        if ((serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            return normalizeServiceImagePath(serviceDllPathText);
        }
        return normalizeServiceImagePath(binaryPathText);
    }

    // selectedServiceFilePath: retrieves the file path to display in the confirmation dialog from the list cache.
    // Input parameter: entry is the cached row selected by the user via right-click.
    // Returns: ServiceDll for shared-process services, or image path for standalone services/drivers.
    QString selectedServiceFilePath(const ServiceDock::ServiceEntry& entry)
    {
        if ((entry.serviceTypeValue & SERVICE_WIN32_SHARE_PROCESS) != 0)
        {
            return normalizeServiceImagePath(entry.serviceDllPathText);
        }
        return normalizeServiceImagePath(entry.imagePathText);
    }

    // comparablePathKey: Generates a case-insensitive comparison key for Windows paths.
    // Input: filePathText is the extracted service file path.
    // Returns: the lowercase path with separators and dot segments cleaned.
    QString comparablePathKey(const QString& filePathText)
    {
        return QDir::cleanPath(QDir::toNativeSeparators(filePathText.trimmed())).toLower();
    }

    // setDeleteFailure purpose: Uniformly populate the background deletion failure result.
    // Input: resultOut is the result; errorCode/detailText describe the failure phase.
    // Returns: Always false to allow the call chain to exit directly.
    bool setDeleteFailure(
        ServiceDeleteResult* resultOut,
        const DWORD errorCode,
        const QString& detailText)
    {
        if (resultOut != nullptr)
        {
            resultOut->errorCode = errorCode;
            resultOut->detailText = detailText;
        }
        return false;
    }

    // queryLiveDeleteTarget: Re-establishes the target identity from SCM/Registry before deletion.
    // Input parameters: cachedEntry provides the expected source; targetOut receives the real-time status and file path.
    // Returns: true if the SCM can query it, or if it is confirmed to be a registry-only service.
    bool queryLiveDeleteTarget(
        const ServiceDock::ServiceEntry& cachedEntry,
        LiveDeleteTarget* targetOut,
        ServiceDeleteResult* resultOut)
    {
        if (targetOut == nullptr || resultOut == nullptr)
        {
            return false;
        }

        const QString kServiceNameText = cachedEntry.serviceNameText.trimmed();
        ks::service::ServiceRecord scmRecord;
        std::string scmErrorText;
        std::uint32_t scmErrorCode = ERROR_SUCCESS;
        const bool kScmQuerySucceeded = ks::service::queryServiceRecord(
            kServiceNameText.toStdWString(),
            &scmRecord,
            &scmErrorText,
            &scmErrorCode);

        RegistryServiceSnapshot registrySnapshot;
        QString registryErrorText;
        DWORD registryErrorCode = ERROR_SUCCESS;
        const bool kRegistryQuerySucceeded = queryRegistryServiceSnapshot(
            kServiceNameText,
            &registrySnapshot,
            &registryErrorText,
            &registryErrorCode);

        LiveDeleteTarget target;
        target.serviceNameText = kServiceNameText;
        if (kScmQuerySucceeded)
        {
            target.scmQueryable = true;
            target.serviceTypeValue = static_cast<DWORD>(scmRecord.config.serviceType);
            target.currentState = static_cast<DWORD>(scmRecord.status.currentState);
            const QString kBinaryPathText = QString::fromStdWString(
                scmRecord.config.binaryPath).trimmed();
            const QString kServiceDllPathText = kRegistryQuerySucceeded
                ? registrySnapshot.serviceDllPathText
                : cachedEntry.serviceDllPathText;
            target.serviceFilePathText = normalizedServiceFilePath(
                target.serviceTypeValue,
                kBinaryPathText,
                kServiceDllPathText);
        }
        else if (!cachedEntry.scmRecordPresent && kRegistryQuerySucceeded)
        {
            target.scmQueryable = false;
            target.serviceTypeValue = registrySnapshot.serviceTypeValue;
            target.currentState = 0;
            target.serviceFilePathText = normalizedServiceFilePath(
                target.serviceTypeValue,
                registrySnapshot.binaryPathText,
                registrySnapshot.serviceDllPathText);
        }
        else
        {
            const QString kScmDetailText = QString::fromUtf8(scmErrorText.c_str());
            return setDeleteFailure(
                resultOut,
                static_cast<DWORD>(scmErrorCode),
                QStringLiteral("删除前无法重新查询 SCM 服务：%1").arg(kScmDetailText));
        }

        const QString kCachedFilePathText = selectedServiceFilePath(cachedEntry);
        if (!kCachedFilePathText.isEmpty()
            && !target.serviceFilePathText.isEmpty()
            && comparablePathKey(kCachedFilePathText)
                != comparablePathKey(target.serviceFilePathText))
        {
            return setDeleteFailure(
                resultOut,
                ERROR_RETRY,
                QStringLiteral("服务文件路径在枚举后发生变化，已拒绝删除陈旧目标。\n原路径：%1\n当前路径：%2")
                    .arg(kCachedFilePathText, target.serviceFilePathText));
        }

        *targetOut = std::move(target);
        return true;
    }

    // collectOtherFileReferences: Verifies other references to the same file from both SCM and registry sources.
    // Input parameters: targetNameText/targetFilePathText specify the target; referenceListOut receives other service names.
    // Returns: true if both source scans are complete; fails safely if any scan is incomplete.
    bool collectOtherFileReferences(
        const QString& targetNameText,
        const QString& targetFilePathText,
        QStringList* referenceListOut,
        ServiceDeleteResult* resultOut)
    {
        if (referenceListOut == nullptr || resultOut == nullptr)
        {
            return false;
        }
        referenceListOut->clear();

        const QString kTargetPathKeyText = comparablePathKey(targetFilePathText);
        const QString kTargetNameKeyText = targetNameText.trimmed().toLower();
        QSet<QString> referenceNameKeySet;
        QHash<QString, QString> displayNameByKey;

        std::vector<RegistryServiceSnapshot> registrySnapshotList;
        QString registryErrorText;
        DWORD registryErrorCode = ERROR_SUCCESS;
        if (!enumerateRegistryServiceSnapshots(
            &registrySnapshotList,
            &registryErrorText,
            &registryErrorCode))
        {
            return setDeleteFailure(
                resultOut,
                registryErrorCode,
                QStringLiteral("无法完成服务文件共享引用的注册表复核：%1")
                    .arg(registryErrorText));
        }

        for (const RegistryServiceSnapshot& snapshot : registrySnapshotList)
        {
            if (!snapshot.keyReadable)
            {
                return setDeleteFailure(
                    resultOut,
                    ERROR_ACCESS_DENIED,
                    QStringLiteral("存在不可读的服务注册表键，无法安全证明目标文件为独占引用：%1")
                        .arg(snapshot.serviceNameText));
            }

            const QString kServiceFilePathText = normalizedServiceFilePath(
                snapshot.serviceTypeValue,
                snapshot.binaryPathText,
                snapshot.serviceDllPathText);
            const QString kServiceNameKeyText = snapshot.serviceNameText.toLower();
            if (!kServiceFilePathText.isEmpty()
                && kServiceNameKeyText != kTargetNameKeyText
                && comparablePathKey(kServiceFilePathText) == kTargetPathKeyText)
            {
                referenceNameKeySet.insert(kServiceNameKeyText);
                displayNameByKey.insert(kServiceNameKeyText, snapshot.serviceNameText);
            }
        }

        std::vector<ks::service::ServiceRecord> scmRecordList;
        std::string scmErrorText;
        std::uint32_t scmErrorCode = ERROR_SUCCESS;
        if (!ks::service::enumerateServiceRecords(
            SERVICE_TYPE_ALL,
            SERVICE_STATE_ALL,
            &scmRecordList,
            &scmErrorText,
            &scmErrorCode))
        {
            return setDeleteFailure(
                resultOut,
                static_cast<DWORD>(scmErrorCode),
                QStringLiteral("无法完成服务文件共享引用的 SCM 复核：%1")
                    .arg(QString::fromUtf8(scmErrorText.c_str())));
        }

        for (const ks::service::ServiceRecord& scmRecord : scmRecordList)
        {
            if (!scmRecord.hasConfig)
            {
                continue;
            }
            const QString kServiceNameText = QString::fromStdWString(
                scmRecord.serviceName).trimmed();
            const QString kServiceNameKeyText = kServiceNameText.toLower();
            const QString kServiceFilePathText = normalizeServiceImagePath(
                QString::fromStdWString(scmRecord.config.binaryPath));
            const bool kSharedProcessService =
                (scmRecord.config.serviceType & SERVICE_WIN32_SHARE_PROCESS) != 0;
            if (!kSharedProcessService
                && !kServiceFilePathText.isEmpty()
                && kServiceNameKeyText != kTargetNameKeyText
                && comparablePathKey(kServiceFilePathText) == kTargetPathKeyText)
            {
                referenceNameKeySet.insert(kServiceNameKeyText);
                displayNameByKey.insert(kServiceNameKeyText, kServiceNameText);
            }
        }

        for (const QString& referenceNameKeyText : referenceNameKeySet)
        {
            referenceListOut->push_back(displayNameByKey.value(referenceNameKeyText));
        }
        referenceListOut->sort(Qt::CaseInsensitive);
        return true;
    }

    // Purpose of stopAndRevalidateScmTarget: Strictly wait for stop and verify path identity before deletion.
    // Input: cachedEntry is the old snapshot; targetInOut receives the new state after stopping.
    // Returns: true if SERVICE_STOPPED, the path remains unchanged, and shared references are still zero.
    bool stopAndRevalidateScmTarget(
        const ServiceDock::ServiceEntry& cachedEntry,
        LiveDeleteTarget* targetInOut,
        ServiceDeleteResult* resultOut)
    {
        if (targetInOut == nullptr || resultOut == nullptr)
        {
            return false;
        }

        if (targetInOut->currentState != SERVICE_STOPPED)
        {
            ks::service::ServiceStatus finalStatus;
            std::string stopErrorText;
            std::uint32_t stopErrorCode = ERROR_SUCCESS;
            const bool kStopSucceeded = ks::service::stopServiceByName(
                targetInOut->serviceNameText.toStdWString(),
                kDeleteStopTimeoutMs,
                SERVICE_STOPPED,
                &finalStatus,
                &stopErrorText,
                &stopErrorCode);
            if (!kStopSucceeded
                || finalStatus.currentState != SERVICE_STOPPED)
            {
                const DWORD kFinalErrorCode = kStopSucceeded
                    ? ERROR_TIMEOUT
                    : static_cast<DWORD>(stopErrorCode);
                const QString kStopDetailText = kStopSucceeded
                    ? QStringLiteral("服务未在超时内到达 SERVICE_STOPPED，未删除服务注册或文件。")
                    : QString::fromUtf8(stopErrorText.c_str());
                return setDeleteFailure(resultOut, kFinalErrorCode, kStopDetailText);
            }
        }

        LiveDeleteTarget revalidatedTarget;
        if (!queryLiveDeleteTarget(cachedEntry, &revalidatedTarget, resultOut))
        {
            return false;
        }
        if (!revalidatedTarget.scmQueryable
            || revalidatedTarget.currentState != SERVICE_STOPPED)
        {
            return setDeleteFailure(
                resultOut,
                ERROR_BUSY,
                QStringLiteral("停止后复核未确认 SERVICE_STOPPED，未删除服务注册或文件。"));
        }
        if (comparablePathKey(revalidatedTarget.serviceFilePathText)
            != comparablePathKey(targetInOut->serviceFilePathText))
        {
            return setDeleteFailure(
                resultOut,
                ERROR_RETRY,
                QStringLiteral("停止后服务文件路径发生变化，未删除服务注册或文件。"));
        }

        *targetInOut = std::move(revalidatedTarget);
        return true;
    }

    // performServiceDeletion: Executes a full background transaction for 'service only' or 'service + file'.
    // Input parameters: cachedEntry is the snapshot taken at confirmation; deleteBinaryFile determines whether to execute the file phase.
    // Return value: Result value type containing partial success semantics.
    ServiceDeleteResult performServiceDeletion(
        const ServiceDock::ServiceEntry& cachedEntry,
        const bool deleteBinaryFile)
    {
        ServiceDeleteResult result;
        LiveDeleteTarget liveTarget;
        if (!queryLiveDeleteTarget(cachedEntry, &liveTarget, &result))
        {
            return result;
        }
        result.serviceFilePathText = liveTarget.serviceFilePathText;

        QStringList sharedReferenceList;
        if (deleteBinaryFile)
        {
            const QFileInfo kServiceFileInfo(liveTarget.serviceFilePathText);
            if (liveTarget.serviceFilePathText.isEmpty()
                || !kServiceFileInfo.isAbsolute()
                || !kServiceFileInfo.exists()
                || kServiceFileInfo.isDir())
            {
                setDeleteFailure(
                    &result,
                    ERROR_FILE_NOT_FOUND,
                    QStringLiteral("无法把服务文件复核为存在的绝对文件，未执行删除：%1")
                        .arg(liveTarget.serviceFilePathText));
                return result;
            }

            if (!collectOtherFileReferences(
                liveTarget.serviceNameText,
                liveTarget.serviceFilePathText,
                &sharedReferenceList,
                &result))
            {
                return result;
            }
            if (!sharedReferenceList.isEmpty())
            {
                setDeleteFailure(
                    &result,
                    ERROR_SHARING_VIOLATION,
                    QStringLiteral("目标文件仍被其它服务引用，未删除任何内容：%1")
                        .arg(sharedReferenceList.join(QStringLiteral(", "))));
                return result;
            }
        }

        if (liveTarget.scmQueryable)
        {
            if (deleteBinaryFile
                && !stopAndRevalidateScmTarget(cachedEntry, &liveTarget, &result))
            {
                return result;
            }

            if (deleteBinaryFile)
            {
                sharedReferenceList.clear();
                if (!collectOtherFileReferences(
                    liveTarget.serviceNameText,
                    liveTarget.serviceFilePathText,
                    &sharedReferenceList,
                    &result))
                {
                    return result;
                }
                if (!sharedReferenceList.isEmpty())
                {
                    setDeleteFailure(
                        &result,
                        ERROR_SHARING_VIOLATION,
                        QStringLiteral("停止后发现目标文件新增共享引用，未删除任何内容：%1")
                            .arg(sharedReferenceList.join(QStringLiteral(", "))));
                    return result;
                }
            }

            std::string deleteErrorText;
            std::uint32_t deleteErrorCode = ERROR_SUCCESS;
            const bool kDeleteServiceSucceeded = ks::service::deleteServiceByName(
                liveTarget.serviceNameText.toStdWString(),
                !deleteBinaryFile,
                kDeleteStopTimeoutMs,
                &deleteErrorText,
                &deleteErrorCode);
            if (!kDeleteServiceSucceeded)
            {
                setDeleteFailure(
                    &result,
                    static_cast<DWORD>(deleteErrorCode),
                    QStringLiteral("DeleteService 失败：%1")
                        .arg(QString::fromUtf8(deleteErrorText.c_str())));
                return result;
            }
        }
        else
        {
            RegistryServiceSnapshot currentRegistrySnapshot;
            QString registryQueryErrorText;
            DWORD registryQueryErrorCode = ERROR_SUCCESS;
            if (!queryRegistryServiceSnapshot(
                liveTarget.serviceNameText,
                &currentRegistrySnapshot,
                &registryQueryErrorText,
                &registryQueryErrorCode))
            {
                setDeleteFailure(
                    &result,
                    registryQueryErrorCode,
                    QStringLiteral("删除前无法复核幽灵服务注册表键：%1")
                        .arg(registryQueryErrorText));
                return result;
            }

            const QString kCurrentFilePathText = normalizedServiceFilePath(
                currentRegistrySnapshot.serviceTypeValue,
                currentRegistrySnapshot.binaryPathText,
                currentRegistrySnapshot.serviceDllPathText);
            if (deleteBinaryFile
                && comparablePathKey(kCurrentFilePathText)
                    != comparablePathKey(liveTarget.serviceFilePathText))
            {
                setDeleteFailure(
                    &result,
                    ERROR_RETRY,
                    QStringLiteral("幽灵服务文件路径在确认后发生变化，未删除任何内容。"));
                return result;
            }

            QString registryDeleteErrorText;
            DWORD registryDeleteErrorCode = ERROR_SUCCESS;
            if (!deleteRegistryServiceKey(
                liveTarget.serviceNameText,
                &registryDeleteErrorText,
                &registryDeleteErrorCode))
            {
                setDeleteFailure(
                    &result,
                    registryDeleteErrorCode,
                    registryDeleteErrorText);
                return result;
            }
        }
        result.registrationDeleted = true;

        if (!deleteBinaryFile)
        {
            result.success = true;
            result.detailText = QStringLiteral("服务注册已删除或已标记删除。文件未被修改。");
            return result;
        }

        const std::wstring kFilePathWide = liveTarget.serviceFilePathText.toStdWString();
        if (::DeleteFileW(kFilePathWide.c_str()) == FALSE)
        {
            const DWORD kDeleteFileErrorCode = ::GetLastError();
            if (kDeleteFileErrorCode != ERROR_FILE_NOT_FOUND)
            {
                result.partialSuccess = true;
                result.errorCode = kDeleteFileErrorCode;
                result.detailText = QStringLiteral("服务注册已删除，但 DeleteFileW 失败：%1")
                    .arg(QString::fromUtf8(
                        ks::service::formatWin32ErrorText(kDeleteFileErrorCode).c_str()));
                return result;
            }
        }

        result.fileDeleted = true;
        result.success = true;
        result.detailText = QStringLiteral("服务注册与服务文件均已删除。");
        return result;
    }
}

void ServiceDock::deleteSelectedService()
{
    deleteSelectedServiceInternal(false);
}

void ServiceDock::deleteSelectedServiceAndFile()
{
    deleteSelectedServiceInternal(true);
}

void ServiceDock::deleteSelectedServiceInternal(const bool deleteBinaryFile)
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const ServiceEntry kSelectedEntry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
    const QString kServiceNameText = kSelectedEntry.serviceNameText.trimmed();
    const QString kServiceFilePathText = selectedServiceFilePath(kSelectedEntry);
    if (deleteBinaryFile && kServiceFilePathText.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("无法确定该服务独有的文件路径，未执行删除。共享进程服务必须具有 ServiceDll。"));
        return;
    }

    if (!ks::ui::requestAdministratorRestartForFeature(
        this,
        deleteBinaryFile
            ? QStringLiteral("删除服务及其文件")
            : QStringLiteral("删除服务")))
    {
        return;
    }

    const QString kActionText = deleteBinaryFile
        ? QStringLiteral("删除服务并删除其文件")
        : QStringLiteral("删除服务");
    const QString kRiskDetailText = deleteBinaryFile
        ? QStringLiteral("该操作不可逆。程序会先重新查询配置、确认文件没有被其它服务引用，并严格等待 SCM 服务停止；只有服务注册删除成功后才会删除文件。\n\n服务：%1\n文件：%2\n来源：%3")
            .arg(kServiceNameText, kServiceFilePathText, kSelectedEntry.sourceStatusText)
        : QStringLiteral("该操作不可逆。SCM 可查询时将调用 DeleteService；仅注册表可见时将删除对应 Services 键树。服务文件不会被修改。\n\n服务：%1\n来源：%2")
            .arg(kServiceNameText, kSelectedEntry.sourceStatusText);
    const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
        this,
        QStringLiteral("高风险动作确认"),
        QStringLiteral("确认执行“%1”？\n\n%2").arg(kActionText, kRiskDetailText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmButton != QMessageBox::Yes)
    {
        return;
    }

    const QString kPendingNameKeyText = kServiceNameText.toLower();
    if (pendingDeleteServiceNameSet().contains(kPendingNameKeyText))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("该服务的删除任务正在执行，请等待当前任务完成。"));
        return;
    }

    pendingDeleteServiceNameSet().insert(kPendingNameKeyText);
    const int kProgressPid = kPro.add(
        this,
        "服务管理",
        kActionText.toStdString() + std::string(" - ") + kServiceNameText.toStdString());
    kPro.set(kProgressPid, "重新验证服务身份", 0, 20.0f);

    const KLogEvent kDeleteEvent;
    info << kDeleteEvent
        << "[ServiceDock] 开始删除服务, service="
        << kServiceNameText.toStdString()
        << ", deleteFile="
        << deleteBinaryFile
        << eol;

    const QPointer<ServiceDock> kGuardedSelf(this);
    QRunnable* const kDeleteTask = QRunnable::create(
        [kGuardedSelf,
            kSelectedEntry,
            kServiceNameText,
            kPendingNameKeyText,
            deleteBinaryFile,
            kActionText,
            kProgressPid,
            kDeleteEvent]()
        {
            kPro.set(kProgressPid, "停止并删除服务", 0, 55.0f);
            const ServiceDeleteResult kResult = performServiceDeletion(
                kSelectedEntry,
                deleteBinaryFile);

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                kAppInstance,
                [kGuardedSelf,
                    kServiceNameText,
                    kPendingNameKeyText,
                    deleteBinaryFile,
                    kActionText,
                    kProgressPid,
                    kDeleteEvent,
                    kResult]()
                {
                    pendingDeleteServiceNameSet().remove(kPendingNameKeyText);
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    kGuardedSelf->requestAsyncRefresh(true);
                    if (kResult.success)
                    {
                        info << kDeleteEvent
                            << "[ServiceDock] 删除服务完成, service="
                            << kServiceNameText.toStdString()
                            << ", deleteFile="
                            << deleteBinaryFile
                            << eol;
                        kPro.set(kProgressPid, "删除完成", 0, 100.0f);
                        QMessageBox::information(
                            kGuardedSelf.data(),
                            QStringLiteral("服务管理"),
                            QStringLiteral("%1完成。\n\n服务：%2%3\n%4")
                                .arg(
                                    kActionText,
                                    kServiceNameText,
                                    deleteBinaryFile
                                        ? QStringLiteral("\n文件：%1").arg(kResult.serviceFilePathText)
                                        : QString(),
                                    kResult.detailText));
                        return;
                    }

                    const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                        kGuardedSelf.data(),
                        kActionText,
                        kResult.errorCode);
                    err << kDeleteEvent
                        << "[ServiceDock] 删除服务失败, service="
                        << kServiceNameText.toStdString()
                        << ", partial="
                        << kResult.partialSuccess
                        << ", error="
                        << kResult.errorCode
                        << ", detail="
                        << kResult.detailText.toStdString()
                        << eol;
                    kPro.set(
                        kProgressPid,
                        kResult.partialSuccess ? "部分成功" : "删除失败",
                        0,
                        100.0f);
                    if (!kPrivilegePromptHandled)
                    {
                        QMessageBox::warning(
                            kGuardedSelf.data(),
                            kResult.partialSuccess
                                ? QStringLiteral("部分成功")
                                : QStringLiteral("服务管理"),
                            QStringLiteral("%1未完全完成。\n\n服务：%2\n文件：%3\nWin32：%4\n%5")
                                .arg(kActionText)
                                .arg(kServiceNameText)
                                .arg(kResult.serviceFilePathText.isEmpty()
                                    ? QStringLiteral("未涉及")
                                    : kResult.serviceFilePathText)
                                .arg(kResult.errorCode)
                                .arg(kResult.detailText));
                    }
                },
                Qt::QueuedConnection);
        });
    kDeleteTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kDeleteTask);
}
