#include "DriverDock.Internal.h"

// Note: The async communication flow for Issue #47 is independent of forced unloading to avoid further expanding the Operation aggregation file.
using namespace ksword::driver_dock_internal;

namespace
{
    // driverCommunicationActionText：
    // - Input: shared protocol action;
    // - Processing: Map to a short action name in the current language;
    // - Return: Preserve unknown values to avoid losing diagnostic data in logs.
    QString driverCommunicationActionText(const std::uint32_t action)
    {
        switch (action)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY:
            return driverText(
                "driver.operation.communication.action.query",
                QStringLiteral("查询 IRP 通信状态"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND:
            return driverText(
                "driver.operation.communication.action.blind",
                QStringLiteral("致盲 IRP 通信"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE:
            return driverText(
                "driver.operation.communication.action.restore",
                QStringLiteral("恢复 IRP 通信"));
        default:
            return driverText(
                "driver.operation.communication.action.unknown",
                QStringLiteral("未知动作(%1)"))
                .arg(action);
        }
    }

    // driverCommunicationStateText：
    // - Input: R0 communication control state;
    // - Processing: Distinguish between non-blinded, active, and third-party rewrite conflicts;
    // - Return: Localized text for operation logs.
    QString driverCommunicationStateText(const std::uint32_t state)
    {
        switch (state)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE:
            return driverText(
                "driver.operation.communication.state.inactive",
                QStringLiteral("未致盲"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_ACTIVE:
            return driverText(
                "driver.operation.communication.state.active",
                QStringLiteral("通信已致盲"));
        case KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT:
            return driverText(
                "driver.operation.communication.state.conflict",
                QStringLiteral("恢复冲突"));
        default:
            return driverText(
                "driver.operation.communication.state.unknown",
                QStringLiteral("未知状态(%1)"))
                .arg(state);
        }
    }
}

void DriverDock::controlDriverCommunication(
    const std::uint64_t moduleBaseValue,
    const QString& moduleName,
    const QString& driverObjectName,
    const std::uint64_t expectedDriverObjectAddress,
    const bool restoreCommunication)
{
    // Input: Immutable target identity and action direction copied before showing the confirmation dialog.
    // Processing: Blind requirement for canonical name matching DriverObject address; restore reliance solely on base address records saved by R0.
    // Return: None. Background results are written to the operation log via the UI thread.
    const QString kModuleNameText = moduleName.trimmed();
    QString driverObjectNameText = driverObjectName.trimmed();
    const bool kExactTargetReady =
        !driverObjectNameText.isEmpty() &&
        expectedDriverObjectAddress != 0U;

    if (moduleBaseValue == 0U ||
        (!restoreCommunication && !kExactTargetReady))
    {
        appendOperateLogLine(
            driverText(
                "driver.operation.communication.target_unresolved",
                QStringLiteral(
                    "IRP 通信操作已拒绝：需要已解析的 canonical DriverObject、对象地址，且 DriverStart 必须与模块基址一致。")));
        return;
    }
    if (driverObjectNameText.isEmpty())
    {
        driverObjectNameText = kModuleNameText;
    }

    const std::uint32_t kRequestedAction =
        restoreCommunication
        ? KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE
        : KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND;
    appendOperateLogLine(
        driverText(
            "driver.operation.communication.starting",
            QStringLiteral("开始 R0 %1：%2 | DriverObject=%3 | Base=%4"))
            .arg(
                driverCommunicationActionText(kRequestedAction),
                kModuleNameText,
                driverObjectNameText,
                formatCompactAddress(moduleBaseValue)));

    QPointer<DriverDock> guardThis(this);
    const std::wstring kCanonicalDriverNameWide =
        driverObjectNameText.toStdWString();
    auto* controlTask = QRunnable::create(
        [guardThis,
            kModuleNameText,
            moduleBaseValue,
            kCanonicalDriverNameWide,
            expectedDriverObjectAddress,
            restoreCommunication]()
        {
            const ksword::ark::DriverClient kDriverClient;
            const ksword::ark::DriverCommunicationControlResult kResult =
                restoreCommunication
                ? kDriverClient.restoreDriverCommunication(
                    moduleBaseValue,
                    kCanonicalDriverNameWide)
                : kDriverClient.blindDriverCommunication(
                    moduleBaseValue,
                    kCanonicalDriverNameWide,
                    expectedDriverObjectAddress);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kModuleNameText, moduleBaseValue, kResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString kLastStatusText = kResult.io.ok
                        ? formatNtStatusText(kResult.lastStatus)
                        : driverText(
                            "driver.operation.communication.last_status_unavailable",
                            QStringLiteral("<传输失败，R0 状态不可用>"));
                    guardThis->appendOperateLogLine(
                        driverText(
                            "driver.operation.communication.result",
                            QStringLiteral(
                                "IRP 通信操作完成：%1 | Base=%2 | Action=%3 | State=%4 | IO说明=%5 | Last=%6 | Targeted=%7 | Changed=%8 | Active=%9 | Owned=%10 | Conflict=%11 | Generation=%12 | Object=%13 | DriverStart=%14 | Reject=%15 | Name=%16"))
                            .arg(kModuleNameText)
                            .arg(formatCompactAddress(moduleBaseValue))
                            .arg(driverCommunicationActionText(kResult.action))
                            .arg(driverCommunicationStateText(kResult.state))
                            .arg(describeDriverCollection(kResult.io))
                            .arg(kLastStatusText)
                            .arg(formatHex32(kResult.targetedMask))
                            .arg(formatHex32(kResult.changedMask))
                            .arg(formatHex32(kResult.activeMask))
                            .arg(formatHex32(kResult.ownedMask))
                            .arg(formatHex32(kResult.conflictMask))
                            .arg(kResult.generation)
                            .arg(formatCompactAddress(kResult.driverObjectAddress))
                            .arg(formatCompactAddress(kResult.driverStart))
                            .arg(formatCompactAddress(kResult.rejectDispatchAddress))
                            .arg(QString::fromStdWString(kResult.driverName)));
                    if ((kResult.responseFlags &
                        KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE_FLAG_FOREIGN_CHANGE) != 0U)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.communication.foreign_change",
                                QStringLiteral(
                                    "恢复检测到第三方 MajorFunction 改写；冲突槽未被覆盖，恢复入口仍可重试。")));
                    }
                    if (kResult.io.ok)
                    {
                        guardThis->refreshLoadedModuleEvidenceAsync();
                    }
                },
                Qt::QueuedConnection);
        });
    controlTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(controlTask);
}
