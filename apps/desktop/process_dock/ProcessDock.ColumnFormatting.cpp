#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

QString ProcessDock::formatColumnText(const ks::process::ProcessRecord& processRecord, const TableColumn column, const int depth) const
{
    switch (column)
    {
    case TableColumn::kName:
        Q_UNUSED(depth);
        return QString::fromStdString(processRecord.processName);
    case TableColumn::kPid:
        return QString::number(processRecord.pid);
    case TableColumn::kCpu:
        // CPU is formatted to two decimal places to avoid visual error where low-usage processes all display as 0.0.
        return QString::number(processRecord.cpuPercent, 'f', 2) + "%";
    case TableColumn::kRam:
        return processContextText("process.table.cell.ram", QStringLiteral("使用 %1 MB / 申请 %2 MB"))
            .arg(processRecord.workingSetMB, 0, 'f', 1)
            .arg(processRecord.ramMB, 0, 'f', 1);
    case TableColumn::kDisk:
        return QString::number(processRecord.diskMBps, 'f', 2) + " MB/s";
    case TableColumn::kGpu:
        return QString::number(processRecord.gpuPercent, 'f', 1) + "%";
    case TableColumn::kNet:
        return QStringLiteral("↓%1 / ↑%2 KB/s")
            .arg(processRecord.netRxKBps, 0, 'f', 2)
            .arg(processRecord.netTxKBps, 0, 'f', 2);
    case TableColumn::kSignature:
        // Display 'Vendor + Trust Status' text; show 'Unknown' if not populated.
        return QString::fromStdString(processRecord.signatureState.empty() ? "Unknown" : processRecord.signatureState);
    case TableColumn::kPath:
        return QString::fromStdString(processRecord.imagePath.empty() ? "-" : processRecord.imagePath);
    case TableColumn::kParentPid:
        return QString::number(processRecord.parentPid);
    case TableColumn::kCommandLine:
        return QString::fromStdString(processRecord.commandLine.empty() ? "-" : processRecord.commandLine);
    case TableColumn::kUser:
        return QString::fromStdString(processRecord.userName.empty() ? "-" : processRecord.userName);
    case TableColumn::kStartTime:
        return QString::fromStdString(processRecord.startTimeText);
    case TableColumn::kIsAdmin:
        // Represent admin status with a square + text (color is set when the table is rebuilt).
        return processRecord.isAdmin
            ? processContextText("process.table.cell.admin_yes", QStringLiteral("■ 是"))
            : processContextText("process.table.cell.admin_no", QStringLiteral("■ 否"));
    case TableColumn::kPplLevel:
        // PPL protection level enumeration is only refreshed manually by the user, not inherited from cache.
        if (!processRecord.protectionLevelKnown)
        {
            return QStringLiteral("未手动刷新");
        }
        return QString::fromStdString(processRecord.protectionLevelText.empty()
            ? "Unknown"
            : processRecord.protectionLevelText);
    case TableColumn::kProtection:
        if ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable (%1)").arg(processFieldSourceText(processRecord.r0ProtectionSource));
        }
        return QStringLiteral("%1 (%2)")
            .arg(byteHexText(processRecord.r0Protection))
            .arg(processFieldSourceText(processRecord.r0ProtectionSource));
    case TableColumn::kPpl:
        if ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return (processRecord.r0Protection == 0U)
            ? QStringLiteral("None (0x00)")
            : QStringLiteral("PPL %1").arg(byteHexText(processRecord.r0Protection));
    case TableColumn::kHandleCount:
        return QString::number(processRecord.handleCount);
    case TableColumn::kHandleTable:
        return pointerAvailabilityText(
            (processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U,
            processRecord.r0ObjectTableAddress,
            processRecord.r0ObjectTableSource);
    case TableColumn::kSectionObject:
        return pointerAvailabilityText(
            (processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U,
            processRecord.r0SectionObjectAddress,
            processRecord.r0SectionObjectSource);
    case TableColumn::kR0Status:
        return processR0StatusText(processRecord.r0Status);

    // ======== Task Manager 'Details' page aligned columns ======== Unified principle: Display placeholders
    // when fields are uncollected or the system does not provide them; do not use 0 to fake real values.
    case TableColumn::kPackageName:
        if (!processRecord.packageNameKnown)
        {
            return kProcessColumnUnavailableText;
        }
        // Unpackaged processes also appear blank in Task Manager; use a placeholder here to explicitly express 'not belonging to any package'.
        return processRecord.packageFullName.empty()
            ? kProcessColumnUnavailableText
            : QString::fromStdString(processRecord.packageFullName);
    case TableColumn::kStatus:
        if (!processRecord.processStateKnown)
        {
            return kProcessColumnUnavailableText;
        }
        return processRecord.processSuspended
            ? processContextText("process.table.cell.status_suspended", QStringLiteral("已挂起"))
            : processContextText("process.table.cell.status_running", QStringLiteral("正在运行"));
    case TableColumn::kSessionId:
        return QString::number(processRecord.sessionId);
    case TableColumn::kJobObject:
        // Job Object IDs lack a public query interface; here, explicitly distinguish between 'not in a job (0)' and 'belonging to a job'.
        if (!processRecord.jobObjectKnown)
        {
            return kProcessColumnUnavailableText;
        }
        return processRecord.inJobObject
            ? processContextText("process.table.cell.job_object_member", QStringLiteral("归属作业"))
            : QStringLiteral("0");
    case TableColumn::kCpuTime:
        return processCpuTimeText(processRecord.rawCpuTime100ns);
    case TableColumn::kCycleTime:
        return processRecord.cycleTimeKnown
            ? processGroupedNumberText(processRecord.cycleTime)
            : kProcessColumnUnavailableText;
    case TableColumn::kWorkingSet:
        return processKilobyteText(processRecord.rawWorkingSetBytes);
    case TableColumn::kPeakWorkingSet:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.peakWorkingSetBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kWorkingSetDelta:
        return processSignedKilobyteText(processRecord.workingSetDeltaBytes);
    case TableColumn::kActivePrivateWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.activePrivateWorkingSetBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kPrivateWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.privateWorkingSetBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kSharedWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.sharedWorkingSetBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kCommitSize:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.commitSizeBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kPagedPool:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.pagedPoolBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kNonPagedPool:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.nonPagedPoolBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kPageFaults:
        return processRecord.memoryDetailKnown
            ? processGroupedNumberText(processRecord.pageFaultCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kPageFaultDelta:
        return processRecord.memoryDetailKnown
            ? processGroupedSignedNumberText(processRecord.pageFaultDeltaCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kBasePriority:
        return QString::number(processRecord.basePriority);
    case TableColumn::kThreadCount:
        return QString::number(processRecord.threadCount);
    case TableColumn::kUserObjects:
        return processRecord.guiResourceKnown
            ? processGroupedNumberText(processRecord.userObjectCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kGdiObjects:
        return processRecord.guiResourceKnown
            ? processGroupedNumberText(processRecord.gdiObjectCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoReads:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioReadOperationCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoWrites:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioWriteOperationCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoOther:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioOtherOperationCount)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoReadBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioReadTransferBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoWriteBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioWriteTransferBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kIoOtherBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioOtherTransferBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kOsContext:
        // Images without a compatibility manifest also appear blank in Task Manager; a placeholder is used here to represent 'no declaration'.
        return processRecord.osContextText.empty()
            ? kProcessColumnUnavailableText
            : QString::fromStdString(processRecord.osContextText);
    case TableColumn::kPlatform:
        return processRecord.architectureText.empty()
            ? kProcessColumnUnavailableText
            : QString::fromStdString(processRecord.architectureText);
    case TableColumn::kUacVirtualization:
        return processFeatureStateText(processRecord.uacVirtualizationState);
    case TableColumn::kDescription:
        return processRecord.fileDescription.empty()
            ? kProcessColumnUnavailableText
            : QString::fromStdString(processRecord.fileDescription);
    case TableColumn::kDataExecutionPrevention:
        return processFeatureStateText(processRecord.dataExecutionPreventionState);
    case TableColumn::kControlFlowGuard:
        return processFeatureStateText(processRecord.controlFlowGuardState);
    case TableColumn::kHardwareStackProtection:
        return processFeatureStateText(processRecord.hardwareStackProtectionState);
    case TableColumn::kDpiAwareness:
        return processDpiAwarenessText(processRecord.dpiAwarenessLevel);
    case TableColumn::kEnterpriseContext:
        if (processRecord.enterpriseContextText.empty())
        {
            return kProcessColumnUnavailableText;
        }
        if (processRecord.enterpriseContextText == "Personal")
        {
            return processContextText("process.table.cell.enterprise_personal", QStringLiteral("个人"));
        }
        return QString::fromStdString(processRecord.enterpriseContextText);
    case TableColumn::kPowerThrottling:
        if (!processRecord.efficiencyModeSupported)
        {
            return kProcessColumnUnavailableText;
        }
        return processRecord.efficiencyModeEnabled
            ? processFeatureStateText(ks::process::ProcessFeatureState::kEnabled)
            : processFeatureStateText(ks::process::ProcessFeatureState::kDisabled);
    case TableColumn::kGpuEngine:
        return processRecord.gpuEngineText.empty()
            ? kProcessColumnUnavailableText
            : QString::fromStdString(processRecord.gpuEngineText);
    case TableColumn::kGpuDedicatedMemory:
        return processRecord.gpuMemoryKnown
            ? processMegabyteText(processRecord.gpuDedicatedMemoryBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kGpuSharedMemory:
        return processRecord.gpuMemoryKnown
            ? processMegabyteText(processRecord.gpuSharedMemoryBytes)
            : kProcessColumnUnavailableText;
    case TableColumn::kProcessType:
        // Row grouping depends on the type (Application / Background Process / Windows Process). This information
        // is stored in ProcessTableRow, not ProcessRecord, and is produced directly by processTableData.
        return QString();
    case TableColumn::kCpuCore:
        // The CPU core column is rendered exclusively by the delegate as a true per-core fan chart, without displaying additional text.
        return QString();
    case TableColumn::kInjectionSurface:
        return processInjectionSurfaceText(processRecord);
    default:
        return QString();
    }
}

QIcon ProcessDock::blueTintedIcon(const char* iconPath, const QSize& iconSize) const
{
    return tintedProcessTabIcon(iconPath, ksword_theme::primaryBlueColor, iconSize);
}

QIcon ProcessDock::tintedProcessTabIcon(
    const char* iconPath,
    const QColor& tintColor,
    const QSize& iconSize) const
{
    // SVG coloring flow: first render the transparent image using the original path, then overlay the specified color using SourceIn.
    QSvgRenderer renderer(QString::fromUtf8(iconPath));
    if (!renderer.isValid())
    {
        return QIcon(QString::fromUtf8(iconPath));
    }

    QPixmap iconPixmap(iconSize);
    iconPixmap.fill(Qt::transparent);

    QPainter painter(&iconPixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(iconPixmap.rect(), tintColor);
    painter.end();
    return QIcon(iconPixmap);
}

void ProcessDock::refreshSideTabIconContrast()
{
    if (sideTabWidget_ == nullptr)
    {
        return;
    }

    // The top Tab selected state has a deep blue background; change the current page icon to white to avoid blending into the background.
    const int kCurrentIndex = sideTabWidget_->currentIndex();
    const QColor kSelectedIconColor(255, 255, 255);
    const QIcon kProcessIcon = kCurrentIndex == sideTabWidget_->indexOf(processListPage_)
        ? tintedProcessTabIcon(kIconProcessMain, kSelectedIconColor)
        : blueTintedIcon(kIconProcessMain);
    const QIcon kThreadIcon = kCurrentIndex == sideTabWidget_->indexOf(threadPage_)
        ? tintedProcessTabIcon(kIconThreadTab, kSelectedIconColor)
        : blueTintedIcon(kIconThreadTab);
    const QIcon kCreateIcon = kCurrentIndex == sideTabWidget_->indexOf(createProcessPage_)
        ? tintedProcessTabIcon(kIconStart, kSelectedIconColor)
        : blueTintedIcon(kIconStart);

    if (processListPage_ != nullptr)
    {
        sideTabWidget_->setTabIcon(sideTabWidget_->indexOf(processListPage_), kProcessIcon);
    }
    if (threadPage_ != nullptr)
    {
        sideTabWidget_->setTabIcon(sideTabWidget_->indexOf(threadPage_), kThreadIcon);
    }
    if (createProcessPage_ != nullptr)
    {
        sideTabWidget_->setTabIcon(sideTabWidget_->indexOf(createProcessPage_), kCreateIcon);
    }
}

void ProcessDock::showActionResultMessage(
    const QString& title,
    const bool actionOk,
    const std::string& detailText,
    const KLogEvent& actionEvent)
{
    if (!actionOk)
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            title,
            QString::fromStdString(detailText));
    }
    // Unified action result logging: no longer pop up dialogs per specification to avoid frequent interruptions to the user workflow.
    const std::string kNormalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
    (actionOk ? info : err) << actionEvent
        << "[ProcessDock] 动作结果, title=" << title.toStdString()
        << ", actionOk=" << (actionOk ? "true" : "false")
        << ", detail=" << kNormalizedDetailText
        << eol;
}

std::string ProcessDock::buildRulerPrefix(const int depth)
{
    if (depth <= 0)
    {
        return std::string();
    }

    std::string prefixText;
    for (int index = 0; index < depth; ++index)
    {
        prefixText += (index + 1 == depth) ? "└─ " : "│  ";
    }
    return prefixText;
}

int ProcessDock::toColumnIndex(const TableColumn column)
{
    return static_cast<int>(column);
}

QString ProcessDock::processColumnDisplayName(const int columnIndex)
{
    // Input: column logical index.
    // Processing: Look up list header text and translate according to the current language; table definitions are in the anonymous namespace of this file.
    // Returns: column name; returns an empty string if the index is out of bounds, allowing the caller to skip the item.
    if (columnIndex < 0 || columnIndex >= kProcessTableHeaders.size())
    {
        return QString();
    }
    return translatedProcessHeader(columnIndex, kProcessTableHeaders.at(columnIndex));
}
