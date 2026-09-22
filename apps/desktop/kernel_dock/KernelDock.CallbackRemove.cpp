#include "KernelDock.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QStandardItemModel>
#include <QStringList>
#include <QThreadPool>
#include <QVBoxLayout>

#include <atomic>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // g_callbackRemoveResolveGeneration：
    // - Purpose: Reverse lookup of service names eliminated by a newer 'safe removal' operation;
    // - Note: The manual removal panel has only one global instance; a file-level counter is used here to avoid modifying KernelDock.h.
    std::atomic<quint64> gCallbackRemoveResolveGeneration{ 0ULL };

    // callbackRemoveParseAddress：
    // - Purpose: Parse input text into a 64-bit address (supports 0x prefix).
    bool callbackRemoveParseAddress(const QString& textValue, quint64& addressOut)
    {
        QString normalizedText = textValue.trimmed();
        bool parseOk = false;

        if (normalizedText.isEmpty())
        {
            return false;
        }

        if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalizedText = normalizedText.mid(2);
        }

        addressOut = normalizedText.toULongLong(&parseOk, 16);
        return parseOk;
    }

    // callbackRemoveIoMessageText：
    // - Input: raw IO message from ArkDriverClient::CallbackRemoveResult.
    // - Handling: Convert low-level phrases like DeviceIoControl/unsupported/capability into readable diagnostics for the callback removal page.
    // - Returns: The text displayed in the details dialog; retains the failure reason needed by the user without directly exposing the IOCTL debug string.
    QString callbackRemoveIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return kernelText("kernel.callback.remove.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.remove.message.communication_failure", QStringLiteral("驱动 IOCTL 调用失败或 R3/R0 协议版本不匹配。"));
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.remove.message.unsupported", QStringLiteral("当前驱动暂不支持该回调移除入口。"));
        }
        if (kLowerText.contains(QStringLiteral("capability")) ||
            kLowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.remove.message.capability", QStringLiteral("动态偏移能力未满足，回调对象或模块归属暂不可解析。"));
        }
        return kTrimmedText;
    }

    // callbackRemoveNormalizePath: Normalizes the path to facilitate matching with driver service mappings.
    QString callbackRemoveNormalizePath(const QString& pathText)
    {
        QString normalizedText = pathText.trimmed().toLower();
        normalizedText.replace(QStringLiteral("\""), QString());
        normalizedText.replace(QStringLiteral("\\??\\"), QStringLiteral(""));
        normalizedText.replace(QStringLiteral("\\systemroot"), QStringLiteral("c:\\windows"));
        return normalizedText;
    }

    // callbackRemoveResolveServiceByModule: Infers the corresponding service name based on the module path.
    QString callbackRemoveResolveServiceByModule(const QString& modulePath)
    {
        const QString kNormalizedModulePath = callbackRemoveNormalizePath(modulePath);
        if (kNormalizedModulePath.isEmpty())
        {
            return QString();
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scmHandle == nullptr)
        {
            return QString();
        }

        DWORD requiredBytes = 0;
        DWORD serviceCount = 0;
        DWORD resumeHandle = 0;
        (void)::EnumServicesStatusExW(
            scmHandle,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            nullptr,
            0,
            &requiredBytes,
            &serviceCount,
            &resumeHandle,
            nullptr);
        if (requiredBytes == 0)
        {
            ::CloseServiceHandle(scmHandle);
            return QString();
        }

        QByteArray serviceBuffer;
        serviceBuffer.resize(static_cast<int>(requiredBytes));
        auto* serviceArray = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(serviceBuffer.data());
        if (!::EnumServicesStatusExW(
            scmHandle,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            reinterpret_cast<LPBYTE>(serviceArray),
            requiredBytes,
            &requiredBytes,
            &serviceCount,
            &resumeHandle,
            nullptr))
        {
            ::CloseServiceHandle(scmHandle);
            return QString();
        }

        QString mappedServiceName;
        for (DWORD index = 0; index < serviceCount; ++index)
        {
            SC_HANDLE serviceHandle = ::OpenServiceW(
                scmHandle,
                serviceArray[index].lpServiceName,
                SERVICE_QUERY_CONFIG);
            if (serviceHandle == nullptr)
            {
                continue;
            }

            DWORD configBytes = 0;
            (void)::QueryServiceConfigW(serviceHandle, nullptr, 0, &configBytes);
            if (configBytes == 0)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }

            QByteArray configBuffer;
            configBuffer.resize(static_cast<int>(configBytes));
            auto* configInfo = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
            if (::QueryServiceConfigW(serviceHandle, configInfo, configBytes, &configBytes) && configInfo->lpBinaryPathName != nullptr)
            {
                const QString kServiceBinaryPath = callbackRemoveNormalizePath(QString::fromWCharArray(configInfo->lpBinaryPathName));
                const QString kServiceFileName = QFileInfo(kServiceBinaryPath).fileName();
                if (!kServiceFileName.isEmpty() && kNormalizedModulePath.endsWith(kServiceFileName))
                {
                    mappedServiceName = QString::fromWCharArray(serviceArray[index].lpServiceName);
                    ::CloseServiceHandle(serviceHandle);
                    break;
                }
            }

            ::CloseServiceHandle(serviceHandle);
        }

        ::CloseServiceHandle(scmHandle);
        return mappedServiceName;
    }

    // callbackRemoveMappingText：
    // - Input: mappingFlags from the old removeExternalCallback response.
    // - Processing: Expand the mapping source bits defined in the current shared protocol and preserve unknown bits.
    // - Return: Mapping source text for display in the details panel.
    QString callbackRemoveMappingText(const unsigned long mappingFlags)
    {
        QStringList flagList;
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE) != 0UL)
        {
            flagList.push_back(QStringLiteral("module"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED) != 0UL)
        {
            flagList.push_back(QStringLiteral("enumerated"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API) != 0UL)
        {
            flagList.push_back(QStringLiteral("public api"));
        }

        const unsigned long kKnownFlags =
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
        const unsigned long kUnknownFlags = mappingFlags & ~kKnownFlags;
        if (kUnknownFlags != 0UL)
        {
            flagList.push_back(QStringLiteral("unknown=0x%1")
                .arg(static_cast<qulonglong>(kUnknownFlags), 8, 16, QChar('0'))
                .toUpper());
        }
        return flagList.isEmpty()
            ? kernelText("kernel.callback.remove.placeholder.none", QStringLiteral("<无>"))
            : flagList.join(QStringLiteral(", "));
    }

}

void KernelDock::initializeCallbackRemovePanel()
{
    if (callbackEnumPage_ == nullptr || callbackEnumLayout_ == nullptr || callbackRemoveLayout_ != nullptr)
    {
        return;
    }

    // This panel is created alongside the "Callback Enumeration" page to avoid occupying an independent top-level tab.
    // Input: no user data; Processing: create manual-type/address removal form; Return: none, widget belongs to Qt parent-child tree.
    callbackRemoveContentWidget_ = new QWidget(callbackEnumPage_);
    callbackRemoveContentWidget_->setObjectName(QStringLiteral("ksCallbackRemoveEmbeddedPanel"));
    callbackRemoveContentWidget_->setStyleSheet(QStringLiteral(
        "#ksCallbackRemoveEmbeddedPanel{border:1px solid %1;border-radius:3px;background:transparent;/* %2 */}")
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::surfaceHex()));

    callbackRemoveLayout_ = new QVBoxLayout(callbackRemoveContentWidget_);
    callbackRemoveLayout_->setContentsMargins(6, 6, 6, 6);
    callbackRemoveLayout_->setSpacing(6);

    QLabel* titleLabel = new QLabel(kernelText("kernel.callback.remove.title", QStringLiteral("手动回调移除")), callbackRemoveContentWidget_);
    titleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));
    callbackRemoveLayout_->addWidget(titleLabel, 0);

    callbackRemoveToolLayout_ = new QHBoxLayout();
    callbackRemoveToolLayout_->setContentsMargins(0, 0, 0, 0);
    callbackRemoveToolLayout_->setSpacing(6);

    callbackRemoveTypeCombo_ = new QComboBox(callbackRemoveContentWidget_);
    callbackRemoveTypeCombo_->addItem(kernelText("kernel.callback.remove.type.process", QStringLiteral("进程创建/退出 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS));
    callbackRemoveTypeCombo_->addItem(kernelText("kernel.callback.remove.type.thread", QStringLiteral("线程创建/退出 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD));
    callbackRemoveTypeCombo_->addItem(kernelText("kernel.callback.remove.type.image", QStringLiteral("镜像加载 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE));
    callbackRemoveTypeCombo_->addItem(QStringLiteral("Object Callback"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT));
    callbackRemoveTypeCombo_->addItem(QStringLiteral("Registry Callback"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY));
    callbackRemoveTypeCombo_->addItem(QStringLiteral("Minifilter"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER));
    callbackRemoveTypeCombo_->addItem(QStringLiteral("WFP Callout"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT));
    callbackRemoveTypeCombo_->addItem(QStringLiteral("ETW Provider/Consumer"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER));

    // Registry and ETW have no reliable safe path. Object remains selectable:
    // its typed callback address is resolved back to one unique V3 enumeration row.
    if (auto* callbackTypeModel = qobject_cast<QStandardItemModel*>(callbackRemoveTypeCombo_->model()))
    {
        for (int itemIndex = 0; itemIndex < callbackRemoveTypeCombo_->count(); ++itemIndex)
        {
            const quint32 kCallbackType = callbackRemoveTypeCombo_->itemData(itemIndex).toUInt();
            if (kCallbackType == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY
                || kCallbackType == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER)
            {
                if (QStandardItem* item = callbackTypeModel->item(itemIndex))
                {
                    item->setEnabled(false);
                    item->setToolTip(kernelText(
                        "kernel.callback.enum.remove.safe.unavailable",
                        QStringLiteral("当前记录不支持安全移除。")));
                }
            }
        }
    }

    callbackRemoveAddressEdit_ = new QLineEdit(callbackRemoveContentWidget_);
    callbackRemoveAddressEdit_->setPlaceholderText(kernelText("kernel.callback.remove.address.placeholder", QStringLiteral("输入回调地址（例如 0xFFFFF80012345678）")));
    callbackRemoveAddressEdit_->setClearButtonEnabled(true);

    callbackRemoveButton_ = new QPushButton(kernelText("kernel.callback.remove.button.safe", QStringLiteral("安全移除")), callbackRemoveContentWidget_);
    callbackRemoveButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    callbackRemoveStatusLabel_ = new QLabel(kernelText("kernel.callback.remove.status.waiting", QStringLiteral("状态：等待操作")), callbackRemoveContentWidget_);
    callbackRemoveStatusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    callbackRemoveToolLayout_->addWidget(new QLabel(kernelText("kernel.callback.remove.label.type", QStringLiteral("类型：")), callbackRemoveContentWidget_));
    callbackRemoveToolLayout_->addWidget(callbackRemoveTypeCombo_, 0);
    callbackRemoveToolLayout_->addWidget(callbackRemoveAddressEdit_, 1);
    callbackRemoveToolLayout_->addWidget(callbackRemoveButton_, 0);
    callbackRemoveLayout_->addLayout(callbackRemoveToolLayout_);
    callbackRemoveLayout_->addWidget(callbackRemoveStatusLabel_, 0);

    callbackEnumLayout_->addWidget(callbackRemoveContentWidget_, 0);

    connect(callbackRemoveButton_, &QPushButton::clicked, this, [this]() {
        quint64 callbackAddress = 0;
        if (!callbackRemoveParseAddress(callbackRemoveAddressEdit_->text(), callbackAddress) || callbackAddress == 0)
        {
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), kernelText("kernel.callback.remove.address.invalid", QStringLiteral("请输入合法的十六进制回调地址。")));
            return;
        }

        // The same "safe removal" requires a pre-confirmation on the enumeration page (see KernelDock.CallbackEnum.cpp).
        // callbackEnumConfirmSafeRemove: Yes|No, default No; however, this manual address entry path directly issues the removal.
        // Manual paths require extra confirmation: the address is typed directly by the user, with no source/trust/removal policy
        // metadata available for cross-verification. This is added here, with wording consistent with the enumeration page.
        const QString kRemoveConfirmText =
            kernelText("kernel.callback.remove.confirm", QStringLiteral(
                "即将按手工填写的地址移除内核回调。\n\n"
                "类别：%1\n"
                "地址：0x%2\n\n"
                "该地址由你手工输入，本页没有枚举行的来源与可信信息可供交叉核对。\n"
                "此操作会修改内核回调注册，可能影响系统稳定性。是否继续？"))
                .arg(callbackRemoveTypeCombo_->currentText())
                .arg(QString::number(callbackAddress, 16).toUpper());
        if (QMessageBox::question(
                this,
                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                kRemoveConfirmText,
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }

        const quint32 kSelectedCallbackType =
            static_cast<quint32>(callbackRemoveTypeCombo_->currentData().toUInt());
        if (kSelectedCallbackType == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT)
        {
            const KernelCallbackEnumEntry* matchedEntry = nullptr;
            std::size_t matchCount = 0U;
            for (const KernelCallbackEnumEntry& entry : callbackEnumRows_)
            {
                const bool kHasRemovalIdentity =
                    entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT
                    && entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
                    && entry.callbackAddress == callbackAddress
                    && entry.registrationAddress != 0U
                    && entry.rawStorageValue != 0U
                    && entry.generation != 0U
                    && entry.identityHash != 0U
                    && (entry.fieldFlags &
                        (KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE |
                         KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE)) != 0U
                    && (entry.removeBehavior &
                        (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                         KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)) ==
                        (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                         KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);
                if (!kHasRemovalIdentity)
                {
                    continue;
                }
                matchedEntry = &entry;
                ++matchCount;
            }

            if (matchCount != 1U || matchedEntry == nullptr)
            {
                callbackRemoveStatusLabel_->setText(kernelText(
                    "kernel.callback.enum.remove.safe.unavailable",
                    QStringLiteral("当前记录不支持安全移除。")));
                QMessageBox::warning(
                    this,
                    kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                    callbackRemoveStatusLabel_->text());
                refreshCallbackEnumAsync();
                return;
            }

            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST exRequest{};
            exRequest.size = sizeof(exRequest);
            exRequest.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
            exRequest.callbackClass = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
            exRequest.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION;
            exRequest.callbackAddress = matchedEntry->callbackAddress;
            exRequest.registrationAddress = matchedEntry->registrationAddress;
            exRequest.rawStorageValue = matchedEntry->rawStorageValue;
            exRequest.enumerationGeneration = matchedEntry->generation;
            exRequest.identityHash = matchedEntry->identityHash;
            exRequest.source = matchedEntry->source;
            exRequest.operationMask = matchedEntry->operationMask;
            exRequest.objectTypeMask = matchedEntry->objectTypeMask;
            exRequest.trustFlags = matchedEntry->trustFlags;
            exRequest.removeBehavior = matchedEntry->removeBehavior;

            const ksword::ark::DriverClient kDriverClient;
            const ksword::ark::CallbackRemoveExResult kRemoveResult =
                kDriverClient.removeExternalCallbackEx(exRequest);
            if (!kRemoveResult.io.ok)
            {
                callbackRemoveStatusLabel_->setText(
                    kernelText("kernel.callback.enum.remove.safe.io_failed", QStringLiteral("状态：安全移除失败，Win32=%1"))
                    .arg(static_cast<qulonglong>(kRemoveResult.io.win32Error)));
                QMessageBox::warning(
                    this,
                    kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                    callbackRemoveStatusLabel_->text());
                return;
            }

            const QString kResponseMessage = QString::fromWCharArray(kRemoveResult.response.message);
            if (kRemoveResult.response.ntstatus >= 0)
            {
                callbackRemoveStatusLabel_->setText(kernelText(
                    "kernel.callback.enum.remove.safe.completed",
                    QStringLiteral("状态：安全移除完成")));
                QMessageBox::information(
                    this,
                    kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                    kResponseMessage.isEmpty() ? callbackRemoveStatusLabel_->text() : kResponseMessage);
                refreshCallbackEnumAsync();
            }
            else
            {
                callbackRemoveStatusLabel_->setText(
                    kernelText("kernel.callback.enum.remove.safe.driver_failed", QStringLiteral("状态：驱动返回失败，NTSTATUS=%1"))
                    .arg(QStringLiteral("0x%1")
                        .arg(static_cast<qulonglong>(static_cast<quint32>(kRemoveResult.response.ntstatus)), 8, 16, QChar('0'))
                        .toUpper()));
                QMessageBox::warning(
                    this,
                    kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                    kResponseMessage.isEmpty() ? callbackRemoveStatusLabel_->text() : kResponseMessage);
            }
            return;
        }

        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = kSelectedCallbackType;
        requestPacket.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
        requestPacket.callbackAddress = callbackAddress;

        const ksword::ark::DriverClient kDriverClient;
        const bool kExperimentalUnlinkEnabled = kDriverClient.supportsExternalCallbackExperimentalUnlink();
        const ksword::ark::CallbackRemoveResult kRemoveResult = kDriverClient.removeExternalCallback(requestPacket);
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE& responsePacket = kRemoveResult.response;
        const DWORD kBytesReturned = kRemoveResult.io.bytesReturned;

        if (!kRemoveResult.io.ok)
        {
            callbackRemoveStatusLabel_->setText(kernelText("kernel.callback.remove.status.io_failed", QStringLiteral("状态：移除失败，error=%1"))
                .arg(kRemoveResult.io.win32Error));
            const QString kErrorDetailText = kernelText("kernel.callback.remove.detail.io_failed", QStringLiteral("回调移除失败，Win32 错误码=%1。\n地址=0x%2\n详情=%3"))
                .arg(kRemoveResult.io.win32Error)
                .arg(QString::number(callbackAddress, 16).toUpper())
                .arg(callbackRemoveIoMessageText(QString::fromStdString(kRemoveResult.io.message)));
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), kErrorDetailText);
            return;
        }

        const QString kModulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString kResponseServiceName = QString::fromWCharArray(responsePacket.serviceName);

        // composeCallbackRemoveDetailText：
        // - Input localServiceNameText: Local SCM service mapping result; use "Unresolved" as a placeholder if incomplete.
        // - Processing: Compose all fields of the current removal response into a detail text for reuse by both synchronous rendering and asynchronous completion.
        // - Return: The detail text for the result dialog.
        const auto kComposeCallbackRemoveDetailText =
            [typeText = callbackRemoveTypeCombo_->currentText(),
             callbackAddress,
             kBytesReturned,
             ntstatusValue = static_cast<quint32>(responsePacket.ntstatus),
             mappingText = callbackRemoveMappingText(responsePacket.mappingFlags),
             kModulePath,
             moduleBase = static_cast<quint64>(responsePacket.moduleBase),
             moduleSize = static_cast<quint64>(responsePacket.moduleSize),
             kResponseServiceName,
             kExperimentalUnlinkEnabled](const QString& localServiceNameText)
        {
            return kernelText("kernel.callback.remove.detail.full", QStringLiteral(
                "安全移除请求已执行。\n"
                "- 类型：%1\n"
                "- 地址：0x%2\n"
                "- 返回字节：%3\n"
                "- NTSTATUS：0x%4\n"
                "- 映射标志：%5\n"
                "- 模块路径：%6\n"
                "- 模块基址：0x%7\n"
                "- 模块大小：0x%8\n"
                "- 驱动返回服务名：%9\n"
                "- 本地服务映射：%10\n"
                "- 操作模式：%11"))
                .arg(typeText)
                .arg(QString::number(callbackAddress, 16).toUpper())
                .arg(kBytesReturned)
                .arg(QString::number(ntstatusValue, 16).rightJustified(8, QLatin1Char('0')).toUpper())
                .arg(mappingText)
                .arg(kModulePath.isEmpty() ? kernelText("kernel.callback.remove.placeholder.unresolved", QStringLiteral("未解析")) : kModulePath)
                .arg(QString::number(moduleBase, 16).toUpper())
                .arg(QString::number(moduleSize, 16).toUpper())
                .arg(kResponseServiceName.isEmpty() ? kernelText("kernel.callback.remove.placeholder.not_returned", QStringLiteral("未返回")) : kResponseServiceName)
                .arg(localServiceNameText)
                .arg(kExperimentalUnlinkEnabled
                    ? kernelText("kernel.callback.remove.unlink.compiled_but_unused", QStringLiteral("已编译扩展宏，但本页不执行 unlink"))
                    : kernelText("kernel.callback.remove.unlink.protocol_disabled", QStringLiteral("当前 shared 协议未启用 REMOVE_EXTERNAL_CALLBACK_EX")));
        };

        // Reverse lookup of local service names requires enumerating all SCM driver services and querying each via QueryServiceConfigW, taking up to seconds in the worst case.
        // The kernel callback has already changed; display the result popup only after the reverse
        // lookup completes to avoid showing incomplete details missing local service mappings.
        const QString kUnmatchedServiceText = kernelText("kernel.callback.remove.placeholder.unmatched", QStringLiteral("未匹配"));

        const QPointer<KernelDock> kGuardedSelf(this);
        const quint64 kRequestGeneration = gCallbackRemoveResolveGeneration.fetch_add(1ULL) + 1ULL;
        const bool kRemovalSucceeded = responsePacket.ntstatus >= 0;
        QThreadPool::globalInstance()->start(
            [kGuardedSelf, kRequestGeneration, kModulePath, kUnmatchedServiceText, kRemovalSucceeded, kComposeCallbackRemoveDetailText]()
            {
                const QString kResolvedServiceName = callbackRemoveResolveServiceByModule(kModulePath);
                const QString kLocalServiceNameText = kResolvedServiceName.isEmpty()
                    ? kUnmatchedServiceText
                    : kResolvedServiceName;

                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(kAppInstance,
                    [kGuardedSelf, kRequestGeneration, kLocalServiceNameText, kRemovalSucceeded, kComposeCallbackRemoveDetailText]()
                    {
                        if (kGuardedSelf == nullptr)
                        {
                            return;
                        }
                        if (gCallbackRemoveResolveGeneration.load() != kRequestGeneration)
                        {
                            return;
                        }
                        const QString kDetailText = kComposeCallbackRemoveDetailText(kLocalServiceNameText);
                        if (kRemovalSucceeded)
                        {
                            QMessageBox::information(
                                kGuardedSelf,
                                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                                kDetailText);
                        }
                        else
                        {
                            QMessageBox::warning(
                                kGuardedSelf,
                                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                                kDetailText);
                        }
                    });
            });

        if (responsePacket.ntstatus >= 0)
        {
            callbackRemoveStatusLabel_->setText(kernelText("kernel.callback.remove.status.completed", QStringLiteral("状态：移除完成。")));
        }
        else
        {
            callbackRemoveStatusLabel_->setText(kernelText("kernel.callback.remove.status.driver_failed", QStringLiteral("状态：驱动返回失败，NTSTATUS=0x%1"))
                .arg(QString::number(static_cast<quint32>(responsePacket.ntstatus), 16).toUpper()));
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), callbackRemoveStatusLabel_->text());
        }
    });
}
