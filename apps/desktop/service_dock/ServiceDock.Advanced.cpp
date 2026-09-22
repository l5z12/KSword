#include "ServiceDock.Internal.h"

#include <cwchar>
#include <sddl.h>

using namespace service_dock_detail;

namespace
{
    // parseMultiSzText: Parses Win32 MULTI_SZ text into a QStringList.
    QStringList parseMultiSzText(const wchar_t* multiSzPointer)
    {
        QStringList resultList;
        if (multiSzPointer == nullptr)
        {
            return resultList;
        }

        const wchar_t* cursorPointer = multiSzPointer;
        while (*cursorPointer != L'\0')
        {
            const QString kItemText = QString::fromWCharArray(cursorPointer).trimmed();
            if (!kItemText.isEmpty())
            {
                resultList.push_back(kItemText);
            }
            cursorPointer += wcslen(cursorPointer) + 1;
        }
        return resultList;
    }

    // queryConfig2BufferByName reads a variable-size SERVICE_CONFIG_* block via ks::service.
    bool queryConfig2BufferByName(
        const QString& serviceNameText,
        const DWORD infoLevel,
        std::vector<std::uint8_t>* dataBufferOut)
    {
        if (dataBufferOut == nullptr || serviceNameText.trimmed().isEmpty())
        {
            return false;
        }

        // UI passes only the service name and requested info level; ks::service owns SCM handles.
        return ks::service::queryServiceConfig2Raw(
            serviceNameText.trimmed().toStdWString(),
            static_cast<std::uint32_t>(infoLevel),
            dataBufferOut);
    }

    // queryServicePermissionVisible checks OpenService access through ks::service.
    bool queryServicePermissionVisible(const QString& serviceNameText, const DWORD desiredAccess)
    {
        return ks::service::canOpenServiceWithAccess(
            serviceNameText.trimmed().toStdWString(),
            static_cast<std::uint32_t>(desiredAccess));
    }

    // scActionTypeToText: Converts a failed action type value to readable text.
    QString scActionTypeToText(const SC_ACTION_TYPE actionTypeValue)
    {
        switch (actionTypeValue)
        {
        case SC_ACTION_NONE:
            return QStringLiteral("无动作");
        case SC_ACTION_RESTART:
            return QStringLiteral("重启服务");
        case SC_ACTION_REBOOT:
            return QStringLiteral("重启系统");
        case SC_ACTION_RUN_COMMAND:
            return QStringLiteral("执行命令");
        default:
            return QStringLiteral("未知");
        }
    }

    // triggerTypeToText purpose: Convert trigger type values into user-friendly text.
    QString triggerTypeToText(const DWORD triggerTypeValue)
    {
        switch (triggerTypeValue)
        {
        case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL:
            return QStringLiteral("设备接口到达");
        case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY:
            return QStringLiteral("IP 地址可用性变化");
        case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN:
            return QStringLiteral("域加入/退出");
        case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT:
            return QStringLiteral("防火墙端口事件");
        case SERVICE_TRIGGER_TYPE_GROUP_POLICY:
            return QStringLiteral("组策略变更");
        case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT:
            return QStringLiteral("网络端点");
        case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE:
            return QStringLiteral("自定义系统状态变化");
        case SERVICE_TRIGGER_TYPE_CUSTOM:
            return QStringLiteral("自定义触发器");
        default:
            return QStringLiteral("未知类型");
        }
    }

    // triggerActionToText: Converts a trigger action value to a user-friendly string.
    QString triggerActionToText(const DWORD triggerActionValue)
    {
        switch (triggerActionValue)
        {
        case SERVICE_TRIGGER_ACTION_SERVICE_START:
            return QStringLiteral("启动服务");
        case SERVICE_TRIGGER_ACTION_SERVICE_STOP:
            return QStringLiteral("停止服务");
        default:
            return QStringLiteral("未知动作");
        }
    }

    // guidToText: Converts a GUID to a standard string.
    QString guidToText(const GUID& guidValue)
    {
        wchar_t guidBuffer[64] = {};
        const int kGuidBufferCount = static_cast<int>(sizeof(guidBuffer) / sizeof(guidBuffer[0]));
        if (::StringFromGUID2(guidValue, guidBuffer, kGuidBufferCount) <= 0)
        {
            return QStringLiteral("<invalid-guid>");
        }
        return QString::fromWCharArray(guidBuffer);
    }

}

QString ServiceDock::queryServiceDllPathByName(const QString& serviceNameText) const
{
    const QString kNormalizedServiceNameText = serviceNameText.trimmed();
    if (kNormalizedServiceNameText.isEmpty())
    {
        return QString();
    }

    const QString kRegistryPathText = QStringLiteral(
        "SYSTEM\\CurrentControlSet\\Services\\%1\\Parameters").arg(kNormalizedServiceNameText);
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

bool ServiceDock::isServiceFilePresent(const QString& filePathText) const
{
    const QFileInfo kFileInfo(filePathText.trimmed());
    return kFileInfo.exists() && kFileInfo.isFile();
}

QString ServiceDock::buildProcessLinkDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;
    detailLineList.push_back(QStringLiteral("服务名：%1").arg(entry.serviceNameText));
    detailLineList.push_back(QStringLiteral("PID：%1").arg(entry.processId == 0 ? QStringLiteral("-") : QString::number(entry.processId)));
    detailLineList.push_back(QStringLiteral("状态：%1").arg(entry.stateText));

    if (entry.processId != 0)
    {
        const std::string kProcessPathText = ks::process::queryProcessPathByPid(entry.processId);
        const QString kHostProcessPathText = QString::fromStdString(kProcessPathText);
        detailLineList.push_back(QStringLiteral("宿主进程路径：%1").arg(kHostProcessPathText));
        detailLineList.push_back(QStringLiteral("宿主类型：%1").arg(
            kHostProcessPathText.contains(QStringLiteral("svchost.exe"), Qt::CaseInsensitive)
            ? QStringLiteral("svchost 共享宿主")
            : QStringLiteral("独立宿主")));

        QStringList sameHostServiceList;
        for (const ServiceEntry& loopEntry : serviceList_)
        {
            if (loopEntry.processId == entry.processId && loopEntry.currentState == SERVICE_RUNNING)
            {
                sameHostServiceList.push_back(loopEntry.serviceNameText);
            }
        }
        sameHostServiceList.removeDuplicates();
        detailLineList.push_back(QStringLiteral("同宿主服务数量：%1").arg(sameHostServiceList.size()));
        if (!sameHostServiceList.isEmpty())
        {
            detailLineList.push_back(QStringLiteral("同宿主服务：%1").arg(sameHostServiceList.join(QStringLiteral(", "))));
        }
    }
    else
    {
        detailLineList.push_back(QStringLiteral("运行关联：无"));
    }

    return detailLineList.join(QStringLiteral("\n"));
}

QString ServiceDock::buildRegistryFileDetailText(const ServiceEntry& entry) const
{
    const QString kRegistryPathText = QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\%1").arg(entry.serviceNameText);
    QStringList detailLineList;
    detailLineList.push_back(QStringLiteral("注册表路径：%1").arg(kRegistryPathText));
    detailLineList.push_back(QStringLiteral("BinaryPath：%1").arg(entry.commandLineText));
    detailLineList.push_back(QStringLiteral("BinaryPath存在：%1").arg(isServiceFilePresent(entry.imagePathText) ? QStringLiteral("是") : QStringLiteral("否")));
    detailLineList.push_back(QStringLiteral("ServiceDll：%1").arg(entry.serviceDllPathText.isEmpty() ? QStringLiteral("未配置") : entry.serviceDllPathText));
    if (!entry.serviceDllPathText.isEmpty())
    {
        detailLineList.push_back(QStringLiteral("ServiceDll存在：%1").arg(isServiceFilePresent(entry.serviceDllPathText) ? QStringLiteral("是") : QStringLiteral("否")));
    }
    return detailLineList.join(QStringLiteral("\n"));
}

QString ServiceDock::buildDependencyDetailText(const ServiceEntry& entry) const
{
    QStringList forwardServiceList;
    QStringList forwardGroupList;

    ks::service::ServiceConfig config;
    if (ks::service::queryServiceConfig(entry.serviceNameText.toStdWString(), &config) &&
        !config.dependenciesMultiSz.empty())
    {
        const QStringList kRawDependencyList = parseMultiSzText(config.dependenciesMultiSz.c_str());
        for (const QString& dependencyText : kRawDependencyList)
        {
            if (dependencyText.startsWith('+'))
            {
                forwardGroupList.push_back(dependencyText.mid(1));
            }
            else
            {
                forwardServiceList.push_back(dependencyText);
            }
        }
    }

    QStringList reverseServiceList;
    std::vector<std::wstring> reverseNames;
    if (ks::service::queryDependentServiceNames(
        entry.serviceNameText.toStdWString(),
        SERVICE_STATE_ALL,
        &reverseNames))
    {
        for (const std::wstring& reverseName : reverseNames)
        {
            reverseServiceList.push_back(QString::fromStdWString(reverseName));
        }
    }

    QStringList detailLineList;
    detailLineList.push_back(QStringLiteral("依赖树（文本）"));
    detailLineList.push_back(QStringLiteral("├─ 当前服务：%1").arg(entry.serviceNameText));
    if (forwardServiceList.isEmpty() && forwardGroupList.isEmpty())
    {
        detailLineList.push_back(QStringLiteral("├─ 正向依赖：无"));
    }
    else
    {
        for (const QString& serviceDependencyText : forwardServiceList)
        {
            const int kTargetIndex = findServiceIndexByName(serviceDependencyText);
            const QString kRunningMarkText =
                (kTargetIndex >= 0 && serviceList_[static_cast<std::size_t>(kTargetIndex)].currentState == SERVICE_RUNNING)
                ? QStringLiteral("运行中")
                : QStringLiteral("未运行/缺失");
            detailLineList.push_back(QStringLiteral("├─ 依赖服务：%1 [%2]").arg(serviceDependencyText).arg(kRunningMarkText));
        }
        for (const QString& groupDependencyText : forwardGroupList)
        {
            detailLineList.push_back(QStringLiteral("├─ 依赖组：%1").arg(groupDependencyText));
        }
    }
    if (reverseServiceList.isEmpty())
    {
        detailLineList.push_back(QStringLiteral("└─ 反向依赖：无"));
    }
    else
    {
        for (const QString& reverseServiceText : reverseServiceList)
        {
            detailLineList.push_back(QStringLiteral("└─ 被依赖：%1").arg(reverseServiceText));
        }
    }
    detailLineList.push_back(QStringLiteral("正向依赖数量：%1").arg(forwardServiceList.size() + forwardGroupList.size()));
    detailLineList.push_back(QStringLiteral("反向依赖数量：%1").arg(reverseServiceList.size()));
    return detailLineList.join(QStringLiteral("\n"));
}


QString ServiceDock::buildFailureActionDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;
    std::vector<std::uint8_t> failureBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_FAILURE_ACTIONS, &failureBuffer))
    {
        const SERVICE_FAILURE_ACTIONSW* failurePointer =
            reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(failureBuffer.data());
        detailLineList.push_back(QStringLiteral("ResetPeriod：%1 秒").arg(failurePointer->dwResetPeriod));
        detailLineList.push_back(QStringLiteral("RebootMessage：%1").arg(
            (failurePointer->lpRebootMsg != nullptr && wcslen(failurePointer->lpRebootMsg) > 0)
            ? QString::fromWCharArray(failurePointer->lpRebootMsg)
            : QStringLiteral("未配置")));
        detailLineList.push_back(QStringLiteral("Command：%1").arg(
            (failurePointer->lpCommand != nullptr && wcslen(failurePointer->lpCommand) > 0)
            ? QString::fromWCharArray(failurePointer->lpCommand)
            : QStringLiteral("未配置")));

        for (DWORD actionIndex = 0; actionIndex < failurePointer->cActions; ++actionIndex)
        {
            const SC_ACTION& actionItem = failurePointer->lpsaActions[actionIndex];
            const QString kActionNameText =
                (actionIndex == 0) ? QStringLiteral("第1次失败")
                : ((actionIndex == 1) ? QStringLiteral("第2次失败") : QStringLiteral("后续失败"));
            detailLineList.push_back(
                QStringLiteral("%1：%2，延迟 %3 ms")
                .arg(kActionNameText)
                .arg(scActionTypeToText(actionItem.Type))
                .arg(actionItem.Delay));
        }
    }
    else
    {
        detailLineList.push_back(QStringLiteral("FailureActions：未配置或读取失败"));
    }

    std::vector<std::uint8_t> failureFlagBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureFlagBuffer))
    {
        const SERVICE_FAILURE_ACTIONS_FLAG* flagPointer =
            reinterpret_cast<const SERVICE_FAILURE_ACTIONS_FLAG*>(failureFlagBuffer.data());
        detailLineList.push_back(QStringLiteral("FailureActionsFlag：%1").arg(flagPointer->fFailureActionsOnNonCrashFailures ? QStringLiteral("启用") : QStringLiteral("禁用")));
    }

    return detailLineList.join(QStringLiteral("\n"));
}


QString ServiceDock::buildTriggerDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;
    std::vector<std::uint8_t> triggerBuffer;
    if (!queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_TRIGGER_INFO, &triggerBuffer))
    {
        return QStringLiteral("触发器：未配置或当前系统不支持读取");
    }

    const SERVICE_TRIGGER_INFO* triggerInfoPointer =
        reinterpret_cast<const SERVICE_TRIGGER_INFO*>(triggerBuffer.data());
    detailLineList.push_back(QStringLiteral("触发器数量：%1").arg(triggerInfoPointer->cTriggers));
    for (DWORD triggerIndex = 0; triggerIndex < triggerInfoPointer->cTriggers; ++triggerIndex)
    {
        const SERVICE_TRIGGER& triggerItem = triggerInfoPointer->pTriggers[triggerIndex];
        detailLineList.push_back(QStringLiteral("---- Trigger #%1 ----").arg(triggerIndex + 1));
        detailLineList.push_back(QStringLiteral("类型：%1 (%2)")
            .arg(triggerTypeToText(triggerItem.dwTriggerType))
            .arg(triggerItem.dwTriggerType));
        detailLineList.push_back(QStringLiteral("动作：%1 (%2)")
            .arg(triggerActionToText(triggerItem.dwAction))
            .arg(triggerItem.dwAction));
        detailLineList.push_back(QStringLiteral("子类型GUID：%1")
            .arg((triggerItem.pTriggerSubtype != nullptr)
                ? guidToText(*triggerItem.pTriggerSubtype)
                : QStringLiteral("未提供")));
        detailLineList.push_back(QStringLiteral("数据项数量：%1").arg(triggerItem.cDataItems));

        for (DWORD dataIndex = 0; dataIndex < triggerItem.cDataItems; ++dataIndex)
        {
            const SERVICE_TRIGGER_SPECIFIC_DATA_ITEM& dataItem = triggerItem.pDataItems[dataIndex];
            QString dataPreviewText;
            if (dataItem.cbData == 0 || dataItem.pData == nullptr)
            {
                dataPreviewText = QStringLiteral("空数据");
            }
            else if (dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_STRING
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_LEVEL
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL)
            {
                dataPreviewText = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(dataItem.pData));
            }
            else
            {
                QByteArray rawBytes(reinterpret_cast<const char*>(dataItem.pData), static_cast<int>(dataItem.cbData));
                dataPreviewText = QString::fromLatin1(rawBytes.toHex(' '));
            }

            detailLineList.push_back(QStringLiteral("  数据项[%1] type=%2 size=%3 value=%4")
                .arg(dataIndex)
                .arg(dataItem.dwDataType)
                .arg(dataItem.cbData)
                .arg(dataPreviewText));
        }
    }

    return detailLineList.join(QStringLiteral("\n"));
}


QString ServiceDock::buildSecurityDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;

    std::vector<std::uint8_t> sidTypeBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_SERVICE_SID_INFO, &sidTypeBuffer))
    {
        const SERVICE_SID_INFO* sidInfoPointer = reinterpret_cast<const SERVICE_SID_INFO*>(sidTypeBuffer.data());
        detailLineList.push_back(QStringLiteral("ServiceSidType：%1").arg(sidInfoPointer->dwServiceSidType));
    }

    std::vector<std::uint8_t> privilegeBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &privilegeBuffer))
    {
        const SERVICE_REQUIRED_PRIVILEGES_INFOW* privilegeInfoPointer =
            reinterpret_cast<const SERVICE_REQUIRED_PRIVILEGES_INFOW*>(privilegeBuffer.data());
        const QStringList kPrivilegeList = parseMultiSzText(privilegeInfoPointer->pmszRequiredPrivileges);
        detailLineList.push_back(QStringLiteral("RequiredPrivileges：%1").arg(
            kPrivilegeList.isEmpty() ? QStringLiteral("未声明") : kPrivilegeList.join(QStringLiteral(", "))));
    }

    std::vector<std::uint8_t> launchProtectedBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_LAUNCH_PROTECTED, &launchProtectedBuffer))
    {
        const SERVICE_LAUNCH_PROTECTED_INFO* launchProtectedPointer =
            reinterpret_cast<const SERVICE_LAUNCH_PROTECTED_INFO*>(launchProtectedBuffer.data());
        detailLineList.push_back(QStringLiteral("LaunchProtected：%1").arg(launchProtectedPointer->dwLaunchProtected));
    }

    std::wstring sddlText;
    if (ks::service::queryServiceSecuritySddl(
        entry.serviceNameText.toStdWString(),
        DACL_SECURITY_INFORMATION,
        &sddlText))
    {
        detailLineList.push_back(QStringLiteral("SDDL：%1").arg(QString::fromStdWString(sddlText)));
    }

    detailLineList.push_back(QStringLiteral("权限可见化："));
    detailLineList.push_back(QStringLiteral("  Start：%1").arg(queryServicePermissionVisible(entry.serviceNameText, SERVICE_START) ? QStringLiteral("可用") : QStringLiteral("不可用")));
    detailLineList.push_back(QStringLiteral("  Stop：%1").arg(queryServicePermissionVisible(entry.serviceNameText, SERVICE_STOP) ? QStringLiteral("可用") : QStringLiteral("不可用")));
    detailLineList.push_back(QStringLiteral("  ChangeConfig：%1").arg(queryServicePermissionVisible(entry.serviceNameText, SERVICE_CHANGE_CONFIG) ? QStringLiteral("可用") : QStringLiteral("不可用")));
    detailLineList.push_back(QStringLiteral("  Delete：%1").arg(queryServicePermissionVisible(entry.serviceNameText, DELETE) ? QStringLiteral("可用") : QStringLiteral("不可用")));
    return detailLineList.join(QStringLiteral("\n"));
}


QString ServiceDock::buildRiskDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;
    detailLineList.push_back(QStringLiteral("风险摘要：%1").arg(entry.riskSummaryText));
    if (entry.riskTagList.isEmpty())
    {
        detailLineList.push_back(QStringLiteral("未命中风险标签。"));
    }
    else
    {
        for (const QString& riskTagText : entry.riskTagList)
        {
            detailLineList.push_back(QStringLiteral(" - %1").arg(riskTagText));
        }
    }
    return detailLineList.join(QStringLiteral("\n"));
}

QString ServiceDock::buildExportDetailText(const ServiceEntry& entry) const
{
    QStringList detailLineList;
    detailLineList.push_back(QStringLiteral("当前服务：%1").arg(entry.serviceNameText));
    detailLineList.push_back(QStringLiteral("当前可见服务数：%1").arg(serviceTable_ == nullptr ? 0 : serviceTable_->rowCount()));
    detailLineList.push_back(QStringLiteral("导出列表：支持 TSV（当前筛选结果）"));
    detailLineList.push_back(QStringLiteral("导出单服务：支持 JSON（完整配置快照）"));
    detailLineList.push_back(QStringLiteral("刷新策略：支持“刷新当前服务”与“刷新全部服务”分层更新"));
    return detailLineList.join(QStringLiteral("\n"));
}
