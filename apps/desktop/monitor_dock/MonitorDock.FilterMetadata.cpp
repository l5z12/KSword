#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    const std::vector<EtwPresetProviderDescriptor>& etwPresetProviderDescriptorList()
    {
        static const std::vector<EtwPresetProviderDescriptor> kProviderList{
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Process") },
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Thread"), EVENT_TRACE_FLAG_THREAD },
            { QStringLiteral("进程线程"), QStringLiteral("Microsoft-Windows-Kernel-Image"), EVENT_TRACE_FLAG_IMAGE_LOAD },
            { QStringLiteral("文件注册表"), QStringLiteral("Microsoft-Windows-Kernel-File") },
            { QStringLiteral("文件注册表"), QStringLiteral("Microsoft-Windows-Kernel-Registry") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-TCPIP") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-DNS-Client") },
            { QStringLiteral("网络通信"), QStringLiteral("Microsoft-Windows-Winsock-AFD") },
            { QStringLiteral("安全审计"), QStringLiteral("Microsoft-Windows-Security-Auditing") },
            { QStringLiteral("安全审计"), QStringLiteral("Microsoft-Windows-Windows Defender") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-PowerShell") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-WMI-Activity") },
            { QStringLiteral("脚本管理"), QStringLiteral("Microsoft-Windows-TaskScheduler") }
        };
        return kProviderList;
    }

    const EtwPresetProviderDescriptor* findEtwPresetProviderDescriptor(const QString& providerNameText)
    {
        const std::vector<EtwPresetProviderDescriptor>& descriptorList = etwPresetProviderDescriptorList();
        const auto kFound = std::find_if(
            descriptorList.cbegin(),
            descriptorList.cend(),
            [&providerNameText](const EtwPresetProviderDescriptor& descriptor) {
                return descriptor.providerNameText.compare(providerNameText, Qt::CaseInsensitive) == 0;
            });
        return kFound == descriptorList.cend() ? nullptr : &*kFound;
    }

    const QStringList& etwSimpleActionList()
    {
        static const QStringList kActionList{
            QStringLiteral("创建/启动"),
            QStringLiteral("打开"),
            QStringLiteral("关闭"),
            QStringLiteral("读取/查询"),
            QStringLiteral("写入/设置"),
            QStringLiteral("删除"),
            QStringLiteral("重命名"),
            QStringLiteral("连接"),
            QStringLiteral("发送"),
            QStringLiteral("接收")
        };
        return kActionList;
    }

    QString etwFilterStageText(const EtwFilterStage stage)
    {
        return stage == EtwFilterStage::kPre
            ? QStringLiteral("前置筛选")
            : QStringLiteral("后置筛选");
    }

    QString etwInferProviderCategory(const QString& providerNameText)
    {
        const QString kLower = providerNameText.toLower();
        if (kLower.contains(QStringLiteral("kernel-process"))
            || kLower.contains(QStringLiteral("kernel-thread"))
            || kLower.contains(QStringLiteral("kernel-image"))
            || kLower.contains(QStringLiteral("windows kernel trace")))
        {
            return QStringLiteral("进程线程");
        }
        if (kLower.contains(QStringLiteral("kernel-file"))
            || kLower.contains(QStringLiteral("kernel-registry")))
        {
            return QStringLiteral("文件注册表");
        }
        if (kLower.contains(QStringLiteral("tcpip"))
            || kLower.contains(QStringLiteral("dns-client"))
            || kLower.contains(QStringLiteral("winsock-afd")))
        {
            return QStringLiteral("网络通信");
        }
        if (kLower.contains(QStringLiteral("security-auditing"))
            || kLower.contains(QStringLiteral("defender")))
        {
            return QStringLiteral("安全审计");
        }
        if (kLower.contains(QStringLiteral("powershell"))
            || kLower.contains(QStringLiteral("wmi-activity"))
            || kLower.contains(QStringLiteral("taskscheduler")))
        {
            return QStringLiteral("脚本管理");
        }
        return QStringLiteral("自定义/其他");
    }

    // etwTimelineTypeFromCapturedRow：
    // - Purpose: normalize ETW captured rows into color/track types supported by the timeline control;
    // - Handling: Prioritizes categorizing events (process, thread, image, etc.) by Provider name, with semantic resource type as fallback.
    // - Returns: the typeText for the timeline point; returns "Other" if unknown.
    QString etwTimelineTypeFromCapturedRow(const MonitorDock::EtwCapturedEventRow& rowData)
    {
        const QString kProviderNameText = rowData.providerName.trimmed();
        if (kProviderNameText.contains(QStringLiteral("Kernel-Process"), Qt::CaseInsensitive))
        {
            return QStringLiteral("进程");
        }
        if (kProviderNameText.contains(QStringLiteral("Kernel-Thread"), Qt::CaseInsensitive))
        {
            return QStringLiteral("线程");
        }
        if (kProviderNameText.contains(QStringLiteral("Kernel-Image"), Qt::CaseInsensitive))
        {
            return QStringLiteral("镜像");
        }
        if (kProviderNameText.contains(QStringLiteral("Kernel-File"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("文件"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("文件");
        }
        if (kProviderNameText.contains(QStringLiteral("Kernel-Registry"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("注册表"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("注册表");
        }
        if (kProviderNameText.contains(QStringLiteral("DNS-Client"), Qt::CaseInsensitive))
        {
            return QStringLiteral("DNS");
        }
        if (kProviderNameText.contains(QStringLiteral("TCPIP"), Qt::CaseInsensitive)
            || kProviderNameText.contains(QStringLiteral("AFD"), Qt::CaseInsensitive)
            || kProviderNameText.contains(QStringLiteral("Winsock"), Qt::CaseInsensitive)
            || rowData.resourceTypeText.compare(QStringLiteral("网络"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("网络");
        }
        if (kProviderNameText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive))
        {
            return QStringLiteral("PowerShell");
        }
        if (kProviderNameText.contains(QStringLiteral("WMI-Activity"), Qt::CaseInsensitive))
        {
            return QStringLiteral("WMI");
        }
        if (kProviderNameText.contains(QStringLiteral("TaskScheduler"), Qt::CaseInsensitive))
        {
            return QStringLiteral("计划任务");
        }
        if (kProviderNameText.contains(QStringLiteral("Security-Auditing"), Qt::CaseInsensitive))
        {
            return QStringLiteral("安全审计");
        }
        if (kProviderNameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive))
        {
            return QStringLiteral("Defender");
        }
        if (rowData.providerCategory.compare(QStringLiteral("进程线程"), Qt::CaseInsensitive) == 0
            || rowData.resourceTypeText.compare(QStringLiteral("进程线程"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("进程");
        }
        return QStringLiteral("其他");
    }

    const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorById(const EtwFilterFieldId fieldId)
    {
        const std::vector<EtwFilterFieldDescriptor>& fieldList = etwFilterFieldDescriptorList();
        const auto kFound = std::find_if(
            fieldList.begin(),
            fieldList.end(),
            [fieldId](const EtwFilterFieldDescriptor& descriptor) {
                return descriptor.fieldId == fieldId;
            });
        return kFound == fieldList.end() ? nullptr : &(*kFound);
    }
}
