#include "MemoryDock.h"
#include "MemoryDock.Internal.h"
#include "../settings_dock/AppearanceSettings.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/HexEditorWidget.h"

#include <QByteArray>
#include <QComboBox>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVariant>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

namespace
{
    QString driverMemoryReadStatusText(const std::uint32_t readStatus)
    {
        // Input: KSWORD_ARK_MEMORY_READ_STATUS_* enum values returned by the driver.
        // Processing: Convert to a Chinese diagnosis directly displayable in the UI, avoiding users seeing only numeric status codes.
        // Returns: Status description string; unknown enum values are preserved to facilitate protocol mismatch localization.
        switch (readStatus)
        {
        case KSWORD_ARK_MEMORY_READ_STATUS_OK:
            return QStringLiteral("读取成功");
        case KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY:
            return QStringLiteral("部分读取成功");
        case KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED:
            return QStringLiteral("目标进程查找失败");
        case KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED:
            return QStringLiteral("内存复制失败");
        case KSWORD_ARK_MEMORY_READ_STATUS_RANGE_REJECTED:
            return QStringLiteral("地址范围被拒绝");
        case KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("响应缓冲区不足");
        case KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED:
            return QStringLiteral("目标范围不可读，已被驱动补零");
        case KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("未知读取状态(%1)").arg(readStatus);
        }
    }

    QString driverMemoryNtStatusText(const long status)
    {
        // Input: NTSTATUS passed through by the driver.
        // Processing: Always display as 8-digit hexadecimal to align with kernel logs and WinDbg.
        // Returns: a string in the format 0xC0000005.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    QString driverMemoryIoMessageText(const std::string& messageText)
    {
        // Input: raw io.message returned by ArkDriverClient.
        // Note: convert low-level text such as DeviceIoControl, unsupported, or empty messages into user-readable descriptions.
        // Return: Chinese text for the status bar, pop-up dialogs, and failure details.
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该内存读写入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该内存读写入口");
        }
        if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，未更新当前内存快照");
        }
        return kRawText;
    }

    bool driverMemoryReadStatusHasUsableBytes(const std::uint32_t readStatus)
    {
        // Input: Driver read status.
        // Processing: Only allow refreshing the Hex cache for complete or partial reads; do not mask full zero-padding as success.
        // Returns: true indicates response->data can be displayed as a genuine read result.
        return readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK ||
            readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
    }

    bool driverMemoryAddressLooksKernelVa(const std::uint64_t address)
    {
        // Input: The user's final requested virtual address.
        // Handling: Windows x64 kernel addresses typically reside in the canonical high-half; this is used
        // here only for R3 automatic IOCTL flag selection, while R0 will re-verify the address range.
        // Return: true indicates the address should be read as a kernel virtual address, not interpreted as the target process's user VA.
        return address >= 0xFFFF000000000000ULL;
    }
}

// ============================================================
// MemoryDock.DriverMemoryRw.cpp
// Purpose:
// - Responsible for R0 read, R3 cache editing, and diff write for the "Driver Memory Read/Write" page;
// - Maintained as an independent compilation unit to avoid new features depending on aggregate includes.
// ============================================================
void MemoryDock::updateDriverMemoryBaseComboFromProcessCache()
{
    // Return immediately if the control is uninitialized; this path may be reached during early construction or late destruction.
    if (driverMemoryBaseCombo_ == nullptr)
    {
        return;
    }

    // Asynchronous kernel module population also rebuilds this model; register for refresh only once before the popup lifecycle ends.
    if (isComboPopupVisible(driverMemoryBaseCombo_))
    {
        driverMemoryBaseComboRefreshPending_ = true;
        return;
    }
    driverMemoryBaseComboRefreshPending_ = false;

    // Save the user input text and current PID before refreshing to prevent the process list refresh from corrupting the base address being edited.
    const QString kPreviousText = driverMemoryBaseCombo_->currentText().trimmed();
    const int kPreviousIndex = driverMemoryBaseCombo_->currentIndex();
    const std::uint32_t kPreviousPid = (kPreviousIndex >= 0) ?
        static_cast<std::uint32_t>(driverMemoryBaseCombo_->itemData(kPreviousIndex, Qt::UserRole).toUInt()) :
        0U;

    // Block signals during dropdown rebuild; this control is used for filtering and reading, so it must not trigger a read operation during the process list refresh.
    QSignalBlocker blocker(driverMemoryBaseCombo_);
    driverMemoryBaseCombo_->clear();
    driverMemoryBaseCombo_->addItem("0", QVariant::fromValue(static_cast<uint>(0U)));
    driverMemoryBaseCombo_->setItemData(0, QString(), Qt::UserRole + 1);

    // The dropdown saves the PID and process name; the display text follows the format of the top process box for easy identification by PID.
    for (const ProcessEntry& entry : processCache_)
    {
        if (entry.pid == 0U)
        {
            continue;
        }

        const QString kItemText = QString("%1 [PID:%2]").arg(entry.processName).arg(entry.pid);
        driverMemoryBaseCombo_->addItem(kItemText, QVariant::fromValue(static_cast<uint>(entry.pid)));
        const int kRow = driverMemoryBaseCombo_->count() - 1;
        driverMemoryBaseCombo_->setItemData(kRow, entry.processName, Qt::UserRole + 1);
    }

    // Kernel module items are listed after process items. The display text is written directly as a parsable 'module_name+0' expression;
    // selecting it allows reading the module header, and manually adjusting the offset then locates any position within the module.
    if (!kernelModuleCache_.empty())
    {
        driverMemoryBaseCombo_->insertSeparator(driverMemoryBaseCombo_->count());
        for (const KernelModuleEntry& kernelEntry : kernelModuleCache_)
        {
            if (kernelEntry.moduleName.isEmpty() || kernelEntry.baseAddress == 0ULL)
            {
                continue;
            }

            const QString kItemText = QString("%1+0").arg(kernelEntry.moduleName);
            // PID bit kept at 0: process matching logic skips kernel module entries based on this, preventing module names from being misidentified as processes.
            driverMemoryBaseCombo_->addItem(kItemText, QVariant::fromValue(static_cast<uint>(0U)));
            const int kKernelRow = driverMemoryBaseCombo_->count() - 1;
            driverMemoryBaseCombo_->setItemData(kKernelRow, QString(), Qt::UserRole + 1);
            driverMemoryBaseCombo_->setItemData(
                kKernelRow,
                QVariant::fromValue(static_cast<qulonglong>(kernelEntry.baseAddress)),
                driverMemoryKernelModuleBaseRole());
            driverMemoryBaseCombo_->setItemData(
                kKernelRow,
                QString("内核模块 %1\n基址: 0x%2\n大小: %3 字节\n路径: %4")
                    .arg(kernelEntry.moduleName)
                    .arg(formatAddress(kernelEntry.baseAddress))
                    .arg(kernelEntry.sizeBytes)
                    .arg(kernelEntry.ntPath),
                Qt::ToolTipRole);
        }
    }

    // Prioritize restoring by the previously explicitly selected PID; fall back to restoring by input text if restoration fails.
    int restoreIndex = -1;
    if (kPreviousPid != 0U)
    {
        restoreIndex = driverMemoryBaseCombo_->findData(
            QVariant::fromValue(static_cast<uint>(kPreviousPid)),
            Qt::UserRole);
    }
    if (restoreIndex < 0 &&
        !kPreviousText.isEmpty() &&
        kPreviousText.compare("0", Qt::CaseInsensitive) != 0 &&
        !kPreviousText.startsWith("0x", Qt::CaseInsensitive))
    {
        (void)findDriverMemoryProcessComboMatch(kPreviousText, restoreIndex);
    }

    // Restore final display text; 0 or empty restores default base address, 0x text preserves user-input numeric base address.
    if (restoreIndex >= 0)
    {
        driverMemoryBaseCombo_->setCurrentIndex(restoreIndex);
    }
    else if (kPreviousText.isEmpty() || kPreviousText.compare("0", Qt::CaseInsensitive) == 0)
    {
        driverMemoryBaseCombo_->setCurrentIndex(0);
    }
    else
    {
        driverMemoryBaseCombo_->setEditText(kPreviousText);
    }
}

bool MemoryDock::findDriverMemoryProcessComboMatch(
    const QString& filterText,
    int& comboIndexOut) const
{
    // Output index defaults to invalid; the caller uses this to determine whether to prompt the user to reselect.
    comboIndexOut = -1;
    if (driverMemoryBaseCombo_ == nullptr)
    {
        return false;
    }

    const QString kNeedle = filterText.trimmed();
    if (kNeedle.isEmpty())
    {
        return false;
    }

    // First round: perform exact matching; PID, process name, and full display text can all be matched directly.
    for (int index = 0; index < driverMemoryBaseCombo_->count(); ++index)
    {
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            driverMemoryBaseCombo_->itemData(index, Qt::UserRole).toUInt());
        if (kPid == 0U)
        {
            continue;
        }

        const QString kItemText = driverMemoryBaseCombo_->itemText(index);
        const QString kProcessName = driverMemoryBaseCombo_->itemData(index, Qt::UserRole + 1).toString();
        const QString kPidText = QString::number(kPid);
        if (kPidText.compare(kNeedle, Qt::CaseInsensitive) == 0 ||
            kProcessName.compare(kNeedle, Qt::CaseInsensitive) == 0 ||
            kItemText.compare(kNeedle, Qt::CaseInsensitive) == 0)
        {
            comboIndexOut = index;
            return true;
        }
    }

    // Round 2: Fuzzy filtering. Non-0x inputs select the first item based on process name or inclusion in the dropdown display text.
    for (int index = 0; index < driverMemoryBaseCombo_->count(); ++index)
    {
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            driverMemoryBaseCombo_->itemData(index, Qt::UserRole).toUInt());
        if (kPid == 0U)
        {
            continue;
        }

        const QString kItemText = driverMemoryBaseCombo_->itemText(index);
        const QString kProcessName = driverMemoryBaseCombo_->itemData(index, Qt::UserRole + 1).toString();
        if (kItemText.contains(kNeedle, Qt::CaseInsensitive) ||
            kProcessName.contains(kNeedle, Qt::CaseInsensitive))
        {
            comboIndexOut = index;
            return true;
        }
    }

    return false;
}

bool MemoryDock::resolveDriverMemoryModuleExpression(
    const QString& expressionText,
    std::uint64_t& resolvedBaseOut,
    QString& errorTextOut) const
{
    resolvedBaseOut = 0ULL;
    errorTextOut.clear();

    // Use the last plus sign to separate the module and offset, accommodating the occasional presence of plus signs in module paths.
    const QString kTrimmedExpression = expressionText.trimmed();
    const int kPlusIndex = kTrimmedExpression.lastIndexOf(QLatin1Char('+'));
    if (kPlusIndex <= 0 || kPlusIndex >= kTrimmedExpression.size() - 1)
    {
        errorTextOut = QStringLiteral(
            "模块偏移格式无效。请使用“模块名+十六进制偏移”，例如 client.dll+C125D9。");
        return false;
    }

    QString moduleToken = kTrimmedExpression.left(kPlusIndex).trimmed();
    QString offsetToken = kTrimmedExpression.mid(kPlusIndex + 1).trimmed();
    if (moduleToken.size() >= 2 &&
        ((moduleToken.startsWith(QLatin1Char('"')) && moduleToken.endsWith(QLatin1Char('"'))) ||
         (moduleToken.startsWith(QLatin1Char('\'')) && moduleToken.endsWith(QLatin1Char('\'')))))
    {
        moduleToken = moduleToken.mid(1, moduleToken.size() - 2).trimmed();
    }
    if (offsetToken.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        offsetToken.remove(0, 2);
    }

    // Module offset follows common debugger notation: always parse as hexadecimal regardless of whether '0x' is present.
    bool offsetOk = false;
    const qulonglong kParsedOffset = offsetToken.toULongLong(&offsetOk, 16);
    if (moduleToken.isEmpty() || offsetToken.isEmpty() || !offsetOk)
    {
        errorTextOut = QStringLiteral(
            "模块偏移格式无效。偏移必须是十六进制数，例如 client.dll+C125D9 或 client.dll+0xC125D9。");
        return false;
    }

    const std::uint64_t kModuleOffset = static_cast<std::uint64_t>(kParsedOffset);

    // Under kernel virtual memory source mode, module names are always resolved as kernel modules, avoiding process module caches.
    if (currentDriverMemorySourceMode() == DriverMemorySourceMode::kKernelVirtual)
    {
        return resolveDriverMemoryKernelModuleExpression(
            moduleToken, kModuleOffset, resolvedBaseOut, errorTextOut);
    }

    // If no process is attached under the process source, fall back to kernel module parsing:
    // This allows users to input kernel expressions like CI.dll+1A2B without first attaching to any process.
    if (attachedPid_ == 0U)
    {
        QString kernelErrorText;
        if (resolveDriverMemoryKernelModuleExpression(
                moduleToken, kModuleOffset, resolvedBaseOut, kernelErrorText))
        {
            return true;
        }
        errorTextOut = QStringLiteral(
            "解析模块偏移前请先附加目标进程；若要定位内核模块，请把“来源”切换为内核虚拟内存。（%1）")
            .arg(kernelErrorText);
        return false;
    }
    if (moduleRefreshInProgress_.load())
    {
        errorTextOut = QStringLiteral("当前进程的模块列表仍在刷新，请等待刷新完成后重试。");
        return false;
    }
    if (moduleCache_.empty())
    {
        errorTextOut = QStringLiteral("当前进程没有可用的模块缓存，请先在“进程与模块”页刷新模块。");
        return false;
    }

    QString normalizedInputPath = moduleToken;
    normalizedInputPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const bool kInputContainsPath = normalizedInputPath.contains(QLatin1Char('\\'));
    const QString kInputFileName = QFileInfo(moduleToken).fileName();
    std::vector<const ModuleEntry*> matches;
    for (const ModuleEntry& entry : moduleCache_)
    {
        QString normalizedModulePath = entry.fullPath;
        normalizedModulePath.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const bool kMatched = kInputContainsPath
            ? normalizedModulePath.compare(normalizedInputPath, Qt::CaseInsensitive) == 0
            : entry.moduleName.compare(kInputFileName, Qt::CaseInsensitive) == 0;
        if (kMatched)
        {
            matches.push_back(&entry);
        }
    }

    if (matches.empty())
    {
        // Try the kernel module again if the user-mode module misses: many troubleshooting scenarios involve inspecting kernel symbols while attached to a process.
        QString kernelErrorText;
        if (resolveDriverMemoryKernelModuleExpression(
                moduleToken, kModuleOffset, resolvedBaseOut, kernelErrorText))
        {
            return true;
        }
        errorTextOut = QString("当前附加进程 PID=%1 与已加载内核模块中都未找到模块：%2。请刷新模块列表并确认模块名。")
            .arg(attachedPid_)
            .arg(moduleToken);
        return false;
    }
    if (matches.size() > 1U)
    {
        errorTextOut = QString("模块名 %1 匹配到 %2 个模块，请输入模块完整路径以消除歧义。")
            .arg(moduleToken)
            .arg(static_cast<qulonglong>(matches.size()));
        return false;
    }

    const ModuleEntry& matchedModule = *matches.front();
    if (matchedModule.baseAddress > (std::numeric_limits<std::uint64_t>::max)() - kModuleOffset)
    {
        errorTextOut = QStringLiteral("模块基址与偏移相加发生地址回绕，已拒绝。");
        return false;
    }

    resolvedBaseOut = matchedModule.baseAddress + kModuleOffset;
    return true;
}

bool MemoryDock::resolveDriverMemoryRequestFromUi(
    std::uint32_t& targetPidOut,
    QString& targetNameOut,
    std::uint64_t& offsetBaseOut,
    std::uint64_t& centerAddressOut,
    std::uint64_t& effectiveCenterAddressOut,
    QString& errorTextOut)
{
    // Clear outputs first to ensure the failure path does not leave behind results from the previous parse.
    targetPidOut = 0U;
    targetNameOut.clear();
    offsetBaseOut = 0ULL;
    centerAddressOut = 0ULL;
    effectiveCenterAddressOut = 0ULL;
    errorTextOut.clear();

    // An empty or 0 offset base means no base is added; also supports numeric base, target process, and module+offset.
    const QString kBaseText = (driverMemoryBaseCombo_ == nullptr) ?
        QStringLiteral("0") :
        driverMemoryBaseCombo_->currentText().trimmed();
    bool moduleExpressionResolved = false;
    if (kBaseText.isEmpty() || kBaseText.compare("0", Qt::CaseInsensitive) == 0)
    {
        offsetBaseOut = 0ULL;
    }
    else if (kBaseText.startsWith("0x", Qt::CaseInsensitive))
    {
        if (!parseUnsignedNumber(kBaseText, offsetBaseOut))
        {
            errorTextOut = "偏移基址格式无效，应输入 0 或 0x 开头的十六进制地址。";
            return false;
        }
    }
    else if (kBaseText.contains(QLatin1Char('+')))
    {
        if (!resolveDriverMemoryModuleExpression(
            kBaseText,
            offsetBaseOut,
            errorTextOut))
        {
            return false;
        }

        targetPidOut = attachedPid_;
        targetNameOut = attachedProcessName_;
        moduleExpressionResolved = true;
    }
    else
    {
        // Non-hex input filters by process; upon match, switch the dropdown to the actual process item.
        int matchedIndex = -1;
        if (!findDriverMemoryProcessComboMatch(kBaseText, matchedIndex))
        {
            errorTextOut = QString("未找到匹配进程：%1。请输入 0、0x基址、模块名+偏移，或进程名/PID。").arg(kBaseText);
            return false;
        }

        QSignalBlocker blocker(driverMemoryBaseCombo_);
        driverMemoryBaseCombo_->setCurrentIndex(matchedIndex);
        targetPidOut = static_cast<std::uint32_t>(
            driverMemoryBaseCombo_->itemData(matchedIndex, Qt::UserRole).toUInt());
        targetNameOut = driverMemoryBaseCombo_->itemData(matchedIndex, Qt::UserRole + 1).toString();
        offsetBaseOut = 0ULL;
    }

    // If the base address box does not explicitly select a process, prefer the attached PID, then fall back to the top current selection.
    if (targetPidOut == 0U && attachedPid_ != 0U)
    {
        targetPidOut = attachedPid_;
        targetNameOut = attachedProcessName_;
    }
    if (targetPidOut == 0U && processCombo_ != nullptr)
    {
        const int kProcessIndex = processCombo_->currentIndex();
        if (kProcessIndex >= 0)
        {
            targetPidOut = static_cast<std::uint32_t>(
                processCombo_->itemData(kProcessIndex, Qt::UserRole).toUInt());
            targetNameOut = processCombo_->itemData(kProcessIndex, Qt::UserRole + 1).toString();
        }
    }
    // When the module expression provides a complete location, the center address may be left empty, equivalent to an additional offset of 0.
    const QString kCenterAddressText = (driverMemoryAddressEdit_ == nullptr)
        ? QString()
        : driverMemoryAddressEdit_->text().trimmed();
    if (moduleExpressionResolved && kCenterAddressText.isEmpty())
    {
        centerAddressOut = 0ULL;
    }
    else if (!parseAddressText(kCenterAddressText, centerAddressOut))
    {
        errorTextOut = moduleExpressionResolved
            ? QStringLiteral("中心地址格式无效；可留空，或输入要叠加到模块偏移上的数值。")
            : QStringLiteral("中心地址格式无效。");
        return false;
    }
    if (centerAddressOut > (std::numeric_limits<std::uint64_t>::max)() - offsetBaseOut)
    {
        errorTextOut = "偏移基址与中心地址相加发生地址回绕，已拒绝。";
        return false;
    }

    effectiveCenterAddressOut = offsetBaseOut + centerAddressOut;
    if (driverMemoryAddressLooksKernelVa(effectiveCenterAddressOut))
    {
        targetPidOut = 0U;
        targetNameOut = QStringLiteral("Kernel VA");
        return true;
    }
    if (targetPidOut == 0U)
    {
        errorTextOut = "请选择有效目标进程；R0 读用户态 VA 需要 PID。若要读内核地址，请输入 0xFFFF... 高半区地址。";
        return false;
    }
    return true;
}

void MemoryDock::prepareDriverMemoryReadAtAddress(
    const std::uint64_t absoluteAddress,
    const std::uint64_t preferredBytes,
    const bool triggerRead)
{
    // Input: Process virtual address from a known valid source (memory region/module/search results, etc.).
    // Processing: Switch to the driver read/write page, fill in the absolute address, and adjust the read window to read forward from that address.
    // Returns: no return value; optionally triggers driverReadMemoryFromUi immediately.
    if (tabWidget_ != nullptr && tabDriverMemoryRw_ != nullptr)
    {
        tabWidget_->setCurrentWidget(tabDriverMemoryRw_);
    }
    if (driverMemoryBaseCombo_ != nullptr)
    {
        const int kPidIndex = driverMemoryBaseCombo_->findData(
            QVariant::fromValue(static_cast<uint>(attachedPid_)),
            Qt::UserRole);
        if (kPidIndex >= 0)
        {
            driverMemoryBaseCombo_->setCurrentIndex(kPidIndex);
        }
    }
    if (driverMemoryAddressEdit_ != nullptr)
    {
        driverMemoryAddressEdit_->setText(formatAddress(absoluteAddress));
    }

    if (preferredBytes > 0ULL &&
        driverMemoryBeforeSpin_ != nullptr &&
        driverMemoryAfterSpin_ != nullptr)
    {
        const std::uint64_t kCappedBytes = std::min<std::uint64_t>(
            preferredBytes,
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_READ_MAX_BYTES));
        driverMemoryBeforeSpin_->setValue(0);
        driverMemoryAfterSpin_->setValue(static_cast<int>(kCappedBytes));
    }

    if (driverMemoryRangeLabel_ != nullptr)
    {
        driverMemoryRangeLabel_->setText(QStringLiteral("范围: 已填入 %1，准备 R0 读取。")
            .arg(formatAddress(absoluteAddress)));
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(QStringLiteral("已从内存区域填入有效地址；点击 R0读取，或等待自动读取。"));
    }

    if (triggerRead)
    {
        driverReadMemoryFromUi();
    }
}

void MemoryDock::driverReadMemoryFromUi()
{
    // Physical memory is a fully independent channel: it does not resolve processes, modules, or offset base addresses, but directly uses the physical read implementation.
    if (currentDriverMemorySourceMode() == DriverMemorySourceMode::kPhysical)
    {
        driverReadPhysicalMemoryFromUi();
        return;
    }

    const QString kBaseInputText = (driverMemoryBaseCombo_ == nullptr)
        ? QString()
        : driverMemoryBaseCombo_->currentText().trimmed();

    // Read entry log: record the current attached PID and address text.
    KLogEvent readStartEvent;
    info << readStartEvent
        << "[MemoryDock] driverReadMemoryFromUi: 开始读取, attachedPid="
        << attachedPid_
        << ", baseText="
        << kBaseInputText.toStdString()
        << ", text="
        << driverMemoryAddressEdit_->text().trimmed().toStdString()
        << eol;

    // R0 memory read/write interface requires PID; no need to OpenProcess/Attach in R3 first; here we parse the independent target.
    std::uint32_t targetPid = 0U;
    QString targetProcessName;
    std::uint64_t offsetBase = 0ULL;
    std::uint64_t centerAddressInput = 0ULL;
    std::uint64_t centerAddress = 0ULL;
    QString resolveErrorText;
    if (!resolveDriverMemoryRequestFromUi(
        targetPid,
        targetProcessName,
        offsetBase,
        centerAddressInput,
        centerAddress,
        resolveErrorText))
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(resolveErrorText);
        }
        QMessageBox::warning(this, "驱动内存读写", resolveErrorText);
        return;
    }

    // Calculate read range:
    // - before/after: byte budgets on the left and right sides of the central address
    // - Use half-open interval [baseAddress, endAddress) to avoid reading 1 extra byte with old logic;
    // - On underflow at low addresses, clamp the start to 0 while preserving clear diagnostics to avoid the appearance of an unresponsive button.
    const std::uint64_t kBeforeBytes =
        static_cast<std::uint64_t>(driverMemoryBeforeSpin_->value());
    const std::uint64_t kAfterBytes =
        static_cast<std::uint64_t>(driverMemoryAfterSpin_->value());
    const std::uint64_t kBaseAddress =
        (centerAddress >= kBeforeBytes) ? (centerAddress - kBeforeBytes) : 0ULL;
    const bool kKernelAddressRead = driverMemoryAddressLooksKernelVa(centerAddress);
    if (kAfterBytes > (std::numeric_limits<std::uint64_t>::max)() - centerAddress)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText("读取范围发生地址回绕，已拒绝。");
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围发生地址回绕。");
        return;
    }
    const std::uint64_t kEndAddress = centerAddress + kAfterBytes;
    if (kEndAddress <= kBaseAddress)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText("读取范围为空或发生地址回绕，已拒绝。");
        }
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText("范围: 读取请求无效");
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围为空或发生地址回绕。");
        return;
    }

    // totalBytes: R0 single-read length, constrained by the shared protocol limit.
    const std::uint64_t kTotalBytes64 = kEndAddress - kBaseAddress;
    if (kTotalBytes64 == 0ULL || kTotalBytes64 > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText("读取范围超过驱动单次请求上限。");
        }
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(QString("范围: %1 - %2 | 请求长度: %3 字节，超过上限")
                .arg(formatAddress(kBaseAddress))
                .arg(formatAddress(kEndAddress - 1ULL))
                .arg(kTotalBytes64));
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围超过驱动单次请求上限。");
        return;
    }

    // Call ArkDriverClient; Dock does not directly call DeviceIoControl.
    QString requestRangeText = QString("范围: %1 - %2 | 请求: %3 字节 | %4 | 中心: %5")
        .arg(formatAddress(kBaseAddress))
        .arg(formatAddress(kEndAddress - 1ULL))
        .arg(kTotalBytes64)
        .arg(kKernelAddressRead
            ? QStringLiteral("内核地址")
            : QStringLiteral("PID: %1%2")
                .arg(targetPid)
                .arg(targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
        .arg(formatAddress(centerAddress));
    if (kBaseInputText.contains(QLatin1Char('+')))
    {
        requestRangeText += QString(" | 模块定位: %1 -> %2")
            .arg(kBaseInputText)
            .arg(formatAddress(offsetBase));
    }
    if (driverMemoryRangeLabel_ != nullptr)
    {
        driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | R0读取中..."));
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText("正在通过 R0 读取内存...");
    }

    // The DDMA backend is a completely different path: it translates VA to PA page-by-page and uses
    // disk DMA. Its response model is also not VirtualMemoryReadResult, so it requires a separate
    // branch that returns directly, without modifying the stable standard channel parsing logic below.
    if (currentDriverMemoryBackend() == ksword::memory_backend::MemoryAccessBackend::kDdma)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(
                QStringLiteral("正在通过 DDMA 逐页翻译并读取内存..."));
        }
        const ksword::memory_backend::AccessOutcome kDdmaOutcome =
            ksword::memory_backend::readVirtual(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                currentDdmaSession(),
                kKernelAddressRead ? 0U : targetPid,
                kBaseAddress,
                kTotalBytes64);
        if (!kDdmaOutcome.ok)
        {
            resetDriverMemoryRwState();
            if (driverMemoryRangeLabel_ != nullptr)
            {
                driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | DDMA失败"));
            }
            if (driverMemoryStatusLabel_ != nullptr)
            {
                driverMemoryStatusLabel_->setText(
                    QStringLiteral("DDMA 读取失败：%1").arg(kDdmaOutcome.failureText));
            }
            QMessageBox::warning(this, "驱动内存读写", kDdmaOutcome.failureText);
            return;
        }

        driverMemoryBaseAddress_ = kBaseAddress;
        driverMemoryOffsetBase_ = offsetBase;
        driverMemoryCenterAddress_ = centerAddress;
        driverMemorySnapshotPid_ = kKernelAddressRead ? 0U : targetPid;
        driverMemorySnapshotProcessName_ = targetProcessName;
        driverMemoryOriginalBytes_ = kDdmaOutcome.data;
        driverMemoryEditedBytes_ = driverMemoryOriginalBytes_;
        driverMemoryHasSnapshot_ = true;
        // Snapshots read via the virtual address channel are written back using virtual addresses, then routed according to the backend selection.
        driverMemorySnapshotIsPhysical_ = false;

        driverMemoryHexEditor_->setEditable(true);
        driverMemoryHexEditor_->setBytesPerRow(16);
        driverMemoryHexEditor_->setByteArray(
            driverMemoryEditedBytes_,
            driverMemoryBaseAddress_);
        refreshDriverMemoryViewsFromSnapshot();

        driverMemoryApplyButton_->setEnabled(false);
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | DDMA读取完成"));
        }
        QString ddmaStatusText = QStringLiteral("DDMA 读取完成：返回 %1 字节。")
            .arg(driverMemoryEditedBytes_.size());
        if (kDdmaOutcome.partial)
        {
            ddmaStatusText += QStringLiteral(
                " 有页无法翻译成物理地址，这些页已按 00 填充。");
        }
        if (kDdmaOutcome.scratchDirty)
        {
            ddmaStatusText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(ddmaStatusText);
        }
        return;
    }

    ksword::ark::DriverClient driverClient;
    const ksword::ark::VirtualMemoryReadResult kReadResult =
        driverClient.readVirtualMemory(
            targetPid,
            kBaseAddress,
            static_cast<std::uint32_t>(kTotalBytes64),
            KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE |
            (kKernelAddressRead ? KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS : 0UL));
    if (!kReadResult.io.ok)
    {
        resetDriverMemoryRwState();
        const QString kReadableIoMessage = driverMemoryIoMessageText(kReadResult.io.message);
        // privilegePromptHandled: Record whether the IOCTL privilege error has been handled by the recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("R0读取进程内存"),
            kReadResult.io.win32Error);
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | IOCTL失败"));
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(QString("R0读取失败：%1").arg(kReadableIoMessage));
        }
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                "驱动内存读写",
                QString("R0读取失败：\n%1").arg(kReadableIoMessage));
        }
        return;
    }

    const QString kReadStatusText = driverMemoryReadStatusText(kReadResult.readStatus);
    const QString kCopyStatusText = driverMemoryNtStatusText(kReadResult.copyStatus);
    if (!driverMemoryReadStatusHasUsableBytes(kReadResult.readStatus))
    {
        // privilegePromptHandled: Records whether the NTSTATUS privilege error was handled by the recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeNtStatus(
            this,
            QStringLiteral("R0读取进程内存"),
            static_cast<long>(kReadResult.copyStatus));
        const QString kFailureText = QString(
            "R0读取未取得可用字节：%1。\n\n"
            "目标=%2\n"
            "请求范围=%4 - %5\n"
            "请求长度=%6 字节\n"
            "copyStatus=%7\n\n"
            "提示：用户态 VA 请先在“内存区域”页选中 MEM_COMMIT 区域；内核 VA 请输入 0xFFFF... 高半区有效地址。")
            .arg(kReadStatusText)
            .arg(kKernelAddressRead
                ? QStringLiteral("内核地址")
                : QStringLiteral("PID=%1%2")
                    .arg(targetPid)
                    .arg(targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
            .arg(formatAddress(kBaseAddress))
            .arg(formatAddress(kEndAddress - 1ULL))
            .arg(kTotalBytes64)
            .arg(kCopyStatusText);

        resetDriverMemoryRwState();
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | 未读到可用字节"));
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            QString compactFailureText = kFailureText;
            compactFailureText.replace(QLatin1Char('\n'), QLatin1Char(' '));
            driverMemoryStatusLabel_->setText(compactFailureText);
        }
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, "驱动内存读写", kFailureText);
        }
        return;
    }

    // R0 pads unreadable regions with 00 as required, so the UI only requires the data length to match the request length.
    if (kReadResult.data.empty())
    {
        const QString kEmptyResponseText = QString(
            "R0响应无数据：readStatus=%1(%2)，source=%3，fieldFlags=0x%4，bytesRead=%5，bytesReturned=%6，copyStatus=%7，io=%8")
            .arg(kReadResult.readStatus)
            .arg(kReadStatusText)
            .arg(kReadResult.source)
            .arg(kReadResult.fieldFlags, 8, 16, QChar('0'))
            .arg(kReadResult.bytesRead)
            .arg(kReadResult.io.bytesReturned)
            .arg(kCopyStatusText)
            .arg(driverMemoryIoMessageText(kReadResult.io.message));
        resetDriverMemoryRwState();
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(requestRangeText + QStringLiteral(" | 响应无数据，详见状态栏"));
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(kEmptyResponseText);
        }
        QMessageBox::warning(this, "驱动内存读写", kEmptyResponseText);
        return;
    }

    // Cache the original backup and the edited copy; subsequent differences are compared only against the original.
    driverMemoryBaseAddress_ = kReadResult.requestedBaseAddress;
    driverMemoryOffsetBase_ = offsetBase;
    driverMemoryCenterAddress_ = centerAddress;
    driverMemorySnapshotPid_ = targetPid;
    driverMemorySnapshotProcessName_ = targetProcessName;
    driverMemoryOriginalBytes_ = QByteArray(
        reinterpret_cast<const char*>(kReadResult.data.data()),
        static_cast<int>(kReadResult.data.size()));
    driverMemoryEditedBytes_ = driverMemoryOriginalBytes_;
    driverMemoryHasSnapshot_ = true;
    // Snapshots read via the virtual memory channel are never physical snapshots; this is used to select the channel during write-back.
    driverMemorySnapshotIsPhysical_ = false;

    // Update HexEditor; edits modify only the R3 cache, and changes are submitted to R0 only after clicking 'Apply Differences'.
    driverMemoryHexEditor_->setEditable(true);
    driverMemoryHexEditor_->setBytesPerRow(16);
    driverMemoryHexEditor_->setByteArray(
        driverMemoryEditedBytes_,
        driverMemoryBaseAddress_);

    // Disassembly and text views refresh from the same snapshot to ensure all three views show consistent content.
    refreshDriverMemoryViewsFromSnapshot();

    // Refresh status label and button states.
    driverMemoryApplyButton_->setEnabled(false);
    driverMemoryApplyButton_->setToolTip(kKernelAddressRead
        ? QStringLiteral("将差异写回内核虚拟地址；需要二次确认和 Force。")
        : QString());
    driverMemoryRangeLabel_->setText(
        QString("范围: %1 - %2 | 长度: %3 字节 | PID: %4%5 | 基址: %6 | 中心: %7")
        .arg(formatAddress(driverMemoryBaseAddress_))
        .arg(formatAddress(driverMemoryBaseAddress_ + static_cast<std::uint64_t>(driverMemoryEditedBytes_.size()) - 1ULL))
        .arg(driverMemoryEditedBytes_.size())
        .arg(kKernelAddressRead ? 0U : targetPid)
        .arg(kKernelAddressRead
            ? QStringLiteral(" (Kernel VA)")
            : (targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
        .arg(formatAddress(offsetBase))
        .arg(formatAddress(centerAddress)));
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(
            QString("R0读取完成：%1，请求=%2 字节，返回=%3 字节，状态=%4(%5)，copyStatus=%6。输入中心=%7%8")
            .arg(kKernelAddressRead ? QStringLiteral("内核地址") : QStringLiteral("PID=%1").arg(targetPid))
            .arg(kReadResult.requestedBytes)
            .arg(kReadResult.data.size())
            .arg(kReadResult.readStatus)
            .arg(kReadStatusText)
            .arg(kCopyStatusText)
            .arg(formatAddress(centerAddressInput))
            .arg(kReadResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY
                ? QStringLiteral("；部分不可读字节已按 00 填充。")
                : QStringLiteral("。")));
    }

    // Read completion log: record range and protocol status.
    KLogEvent readFinishEvent;
    info << readFinishEvent
        << "[MemoryDock] driverReadMemoryFromUi: 读取完成, base="
        << formatAddress(driverMemoryBaseAddress_).toStdString()
        << ", pid="
        << targetPid
        << ", bytes="
        << driverMemoryEditedBytes_.size()
        << ", status="
        << kReadResult.readStatus
        << eol;
}

void MemoryDock::driverApplyMemoryDiffFromUi()
{
    // Application entry log: records whether a snapshot exists and the current cache size.
    KLogEvent applyStartEvent;
    info << applyStartEvent
        << "[MemoryDock] driverApplyMemoryDiffFromUi: 开始应用差异, hasSnapshot="
        << (driverMemoryHasSnapshot_ ? "true" : "false")
        << ", cacheBytes="
        << driverMemoryEditedBytes_.size()
        << eol;

    // Physical snapshots have neither a PID nor kernel VA characteristics; they must be explicitly allowed and routed through a separate write-back channel.
    const bool kPhysicalSnapshot = driverMemorySnapshotIsPhysical_;
    const bool kKernelAddressSnapshot =
        !kPhysicalSnapshot && driverMemoryAddressLooksKernelVa(driverMemoryBaseAddress_);
    if ((!kKernelAddressSnapshot && !kPhysicalSnapshot && driverMemorySnapshotPid_ == 0U)
        || !driverMemoryHasSnapshot_)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText("没有可应用的 R0 读取快照。");
        }
        QMessageBox::warning(this, "驱动内存读写", "没有可应用的 R0 读取快照。");
        return;
    }

    // Use the current data from HexEditor to avoid missing cache changes caused by direct paste or editing.
    driverMemoryEditedBytes_ = driverMemoryHexEditor_->data();
    std::vector<DriverDiffBlock> diffBlocks;
    collectDriverMemoryDiffBlocks(diffBlocks);
    if (diffBlocks.empty())
    {
        driverMemoryApplyButton_->setEnabled(false);
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText("没有检测到差异，无需写入。");
        }
        return;
    }

    // Dangerous confirmation policy only allows skipping redundant modal dialogs; R0 confirmation flags, snapshot comparison, and post-write status checks still execute.
    const bool kSuppressDangerousConfirmation =
        ks::settings::dangerousActionConfirmationsSuppressed();
    if (!kSuppressDangerousConfirmation)
    {
        const QMessageBox::StandardButton kConfirmResult = QMessageBox::question(
            this,
            "应用内存差异",
            QString(
                "将通过 R0 写入 %1 个差异块到 %2。\n"
                "内核或进程内存修改可能立即造成数据损坏、权限边界失效、进程崩溃或系统蓝屏。\n"
                "只写入和原始备份不同的字节，是否继续？")
            .arg(diffBlocks.size())
            .arg(kPhysicalSnapshot
                ? QStringLiteral("物理内存（无事务、无回滚）")
                : (kKernelAddressSnapshot
                    ? QStringLiteral("内核虚拟地址")
                    : QStringLiteral("PID=%1%2")
                        .arg(driverMemorySnapshotPid_)
                        .arg(driverMemorySnapshotProcessName_.isEmpty()
                            ? QString()
                            : QString(" (%1)").arg(driverMemorySnapshotProcessName_)))),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmResult != QMessageBox::Yes)
        {
            if (driverMemoryStatusLabel_ != nullptr)
            {
                driverMemoryStatusLabel_->setText("用户取消应用差异。");
            }
            return;
        }
    }
    else
    {
        KLogEvent suppressedConfirmationEvent;
        warn << suppressedConfirmationEvent
            << "[MemoryDock] dangerous confirmation suppressed by persistent setting; "
               "R0 snapshot verification and audit remain active, target="
            << (kPhysicalSnapshot
                ? "physical"
                : (kKernelAddressSnapshot ? "kernel-va" : "process-va"))
            << ", blocks="
            << diffBlocks.size()
            << eol;
    }

    // Physical memory writeback is an independent channel: submitted in 4KB slices, with no transactions and no failure rollback.
    if (kPhysicalSnapshot)
    {
        QString physicalFailureText;
        const bool kPhysicalWriteOk = applyDriverMemoryPhysicalDiff(diffBlocks, physicalFailureText);
        if (kPhysicalWriteOk)
        {
            // On full success, promote the edit cache to the new baseline; subsequent differences are calculated from here.
            driverMemoryOriginalBytes_ = driverMemoryEditedBytes_;
            if (driverMemoryApplyButton_ != nullptr)
            {
                driverMemoryApplyButton_->setEnabled(false);
            }
            if (driverMemoryStatusLabel_ != nullptr)
            {
                // The success path may still carry warnings (dirty sectors from DDMA or read-modify-write windows); here,
                // physicalFailureText must be displayed together and cannot be discarded just because true was returned.
                QString doneText =
                    QStringLiteral("物理内存写入完成，已提交 %1 个差异块。").arg(diffBlocks.size());
                if (!physicalFailureText.isEmpty())
                {
                    doneText += QStringLiteral(" ") + physicalFailureText;
                }
                driverMemoryStatusLabel_->setText(doneText);
            }
            refreshDriverMemoryViewsFromSnapshot();
            return;
        }

        // On failure, keep the baseline unchanged so the user can see which bytes still differ from the target.
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(QStringLiteral("物理内存写入失败。"));
        }
        QMessageBox::warning(this, "驱动内存读写", physicalFailureText);
        return;
    }

    // The DDMA backend path is entirely different: it does not use R0 virtual writes, nor kernel byte transactions or rollbacks.
    // Instead, it translates page-by-page to physical addresses for disk DMA. Use a separate branch and return immediately to avoid
    // modifying the standard write-back logic below (which includes transactions and rollbacks) into a dual-purpose implementation.
    if (currentDriverMemoryBackend() == ksword::memory_backend::MemoryAccessBackend::kDdma)
    {
        const std::uint32_t kDdmaTargetPid =
            kKernelAddressSnapshot ? 0U : driverMemorySnapshotPid_;
        std::uint64_t ddmaWrittenTotal = 0ULL;
        bool ddmaScratchDirty = false;
        bool ddmaLostUpdate = false;
        bool ddmaForceApproved = false;

        for (const DriverDiffBlock& block : diffBlocks)
        {
            ksword::memory_backend::AccessOutcome blockOutcome =
                ksword::memory_backend::writeVirtual(
                    ksword::memory_backend::MemoryAccessBackend::kDdma,
                    currentDdmaSession(),
                    kDdmaTargetPid,
                    block.address,
                    block.bytes,
                    ddmaForceApproved);

            // After the first block triggers a force confirmation, subsequent blocks in this round reuse the same approval.
            if (blockOutcome.forceRequired && !ddmaForceApproved)
            {
                if (!confirmForceDriverMemoryWrite(
                        block.address,
                        static_cast<std::uint32_t>(block.bytes.size()),
                        blockOutcome.failureText))
                {
                    if (driverMemoryStatusLabel_ != nullptr)
                    {
                        driverMemoryStatusLabel_->setText(
                            QStringLiteral("用户取消了 DDMA 强制写入。"));
                    }
                    return;
                }
                ddmaForceApproved = true;
                blockOutcome = ksword::memory_backend::writeVirtual(
                    ksword::memory_backend::MemoryAccessBackend::kDdma,
                    currentDdmaSession(),
                    kDdmaTargetPid,
                    block.address,
                    block.bytes,
                    true);
            }

            ddmaScratchDirty = ddmaScratchDirty || blockOutcome.scratchDirty;
            ddmaLostUpdate = ddmaLostUpdate || blockOutcome.lostUpdateWindow;
            ddmaWrittenTotal += blockOutcome.bytesDone;

            if (!blockOutcome.ok)
            {
                // DDMA writes have no transaction or rollback; on failure, stop immediately and report the amount written.
                QString failureText = QStringLiteral(
                    "DDMA 写入失败。\n%1\n本轮累计已写入 %2 字节，失败前的改动不会自动回滚。")
                    .arg(blockOutcome.failureText)
                    .arg(ddmaWrittenTotal);
                if (ddmaScratchDirty)
                {
                    failureText += QStringLiteral(
                        "\n严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
                }
                if (driverMemoryStatusLabel_ != nullptr)
                {
                    driverMemoryStatusLabel_->setText(QStringLiteral("DDMA 写入失败。"));
                }
                QMessageBox::warning(this, "驱动内存读写", failureText);
                return;
            }
        }

        driverMemoryOriginalBytes_ = driverMemoryEditedBytes_;
        if (driverMemoryApplyButton_ != nullptr)
        {
            driverMemoryApplyButton_->setEnabled(false);
        }
        QString ddmaDoneText = QStringLiteral(
            "DDMA 写入完成，已提交 %1 个差异块，共 %2 字节。")
            .arg(diffBlocks.size())
            .arg(ddmaWrittenTotal);
        if (ddmaLostUpdate)
        {
            ddmaDoneText += QStringLiteral(
                " 含非整页写入，驱动做了读-改-写，同页其它字节存在覆盖窗口。");
        }
        if (ddmaScratchDirty)
        {
            ddmaDoneText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(ddmaDoneText);
        }
        refreshDriverMemoryViewsFromSnapshot();
        return;
    }

    // Call the driver for writes in blocks; split blocks exceeding the driver limit.
    ksword::ark::DriverClient driverClient;
    std::uint64_t totalRequested = 0;
    std::uint64_t totalWritten = 0;
    int failedBlockCount = 0;
    bool forceWriteApproved = false;
    struct KernelMutationChunk
    {
        std::uint64_t transactionId = 0U;
        std::uint64_t address = 0U;
        std::vector<std::uint8_t> beforeBytes;
    };
    std::vector<KernelMutationChunk> kernelMutationChunks;
    std::uint64_t rollbackVerifiedBytes = 0U;
    int rollbackFailedCount = 0;
    // privilegePromptHandled: Tracks whether a privilege recovery prompt has already been displayed across write blocks.
    bool privilegePromptHandled = false;
    QString lastFailureText;

    for (const DriverDiffBlock& block : diffBlocks)
    {
        int offset = 0;
        while (offset < block.bytes.size())
        {
            const int kChunkBytes = std::min<int>(
                block.bytes.size() - offset,
                static_cast<int>(
                    kKernelAddressSnapshot
                        ? KSWORD_ARK_MUTATION_MAX_BYTES
                        : KSWORD_ARK_MEMORY_WRITE_MAX_BYTES));
            std::vector<std::uint8_t> chunk;
            chunk.resize(static_cast<std::size_t>(kChunkBytes));
            std::copy_n(
                reinterpret_cast<const std::uint8_t*>(block.bytes.constData() + offset),
                static_cast<std::size_t>(kChunkBytes),
                chunk.begin());

            const std::uint64_t kChunkAddress =
                block.address + static_cast<std::uint64_t>(offset);
            totalRequested += static_cast<std::uint64_t>(kChunkBytes);

            if (kKernelAddressSnapshot)
            {
                const std::uint64_t kSnapshotOffset =
                    kChunkAddress - driverMemoryBaseAddress_;
                if (kSnapshotOffset
                        > static_cast<std::uint64_t>(
                            driverMemoryOriginalBytes_.size())
                    || static_cast<std::uint64_t>(kChunkBytes)
                        > static_cast<std::uint64_t>(
                            driverMemoryOriginalBytes_.size())
                            - kSnapshotOffset)
                {
                    ++failedBlockCount;
                    lastFailureText = QStringLiteral(
                        "内核字节事务的 expected-before 超出原始快照边界。");
                    break;
                }

                std::vector<std::uint8_t> expectedBefore(
                    static_cast<std::size_t>(kChunkBytes));
                std::copy_n(
                    reinterpret_cast<const std::uint8_t*>(
                        driverMemoryOriginalBytes_.constData()
                        + static_cast<qsizetype>(
                            kSnapshotOffset)),
                    static_cast<std::size_t>(kChunkBytes),
                    expectedBefore.begin());

                ksword::ark::MutationPrepareInput prepareInput{};
                prepareInput.flags =
                    KSWORD_ARK_MUTATION_FLAG_DRY_RUN |
                    KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
                prepareInput.targetKind =
                    KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
                prepareInput.bytes =
                    static_cast<std::uint32_t>(kChunkBytes);
                prepareInput.targetAddress = kChunkAddress;
                prepareInput.afterBytes = chunk;
                prepareInput.expectedBeforeBytes = expectedBefore;
                const ksword::ark::MutationResponseResult kPrepareResult =
                    driverClient.prepareMutation(prepareInput);
                if (!kPrepareResult.io.ok
                    || kPrepareResult.status
                        != KSWORD_ARK_MUTATION_STATUS_PREPARED
                    || kPrepareResult.transactionId == 0U
                    || kPrepareResult.bytes
                        != static_cast<std::uint32_t>(kChunkBytes)
                    || kPrepareResult.beforeBytes.size()
                        < static_cast<std::size_t>(kChunkBytes)
                    || !std::equal(
                        expectedBefore.cbegin(),
                        expectedBefore.cend(),
                        kPrepareResult.beforeBytes.cbegin()))
                {
                    privilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            this,
                            QStringLiteral("R0内核字节事务 PREPARE"),
                            kPrepareResult.io.win32Error);
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 PREPARE 失败：地址=%1 请求=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(kChunkAddress))
                        .arg(kChunkBytes)
                        .arg(kPrepareResult.status)
                        .arg(driverMemoryNtStatusText(
                            kPrepareResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            kPrepareResult.io.message));
                    break;
                }

                KernelMutationChunk mutationChunk;
                mutationChunk.transactionId =
                    kPrepareResult.transactionId;
                mutationChunk.address = kChunkAddress;
                mutationChunk.beforeBytes = expectedBefore;
                kernelMutationChunks.push_back(
                    std::move(mutationChunk));

                const ksword::ark::MutationResponseResult kDryRunResult =
                    driverClient.commitMutation(
                        kPrepareResult.transactionId,
                        KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
                if (!kDryRunResult.io.ok
                    || kDryRunResult.status
                        != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 dry-run 失败：地址=%1 tx=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(kChunkAddress))
                        .arg(kPrepareResult.transactionId)
                        .arg(kDryRunResult.status)
                        .arg(driverMemoryNtStatusText(
                            kDryRunResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            kDryRunResult.io.message));
                    break;
                }

                const ksword::ark::MutationResponseResult kCommitResult =
                    driverClient.commitMutation(
                        kPrepareResult.transactionId,
                        KSWORD_ARK_MUTATION_FLAG_FORCE |
                        KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
                if (!kCommitResult.io.ok
                    || kCommitResult.status
                        != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 FORCE 提交失败：地址=%1 tx=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(kChunkAddress))
                        .arg(kPrepareResult.transactionId)
                        .arg(kCommitResult.status)
                        .arg(driverMemoryNtStatusText(
                            kCommitResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            kCommitResult.io.message));
                    break;
                }

                const ksword::ark::VirtualMemoryReadResult kVerifyResult =
                    driverClient.readVirtualMemory(
                        0U,
                        kChunkAddress,
                        static_cast<std::uint32_t>(kChunkBytes),
                        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                if (!kVerifyResult.io.ok
                    || kVerifyResult.readStatus
                        != KSWORD_ARK_MEMORY_READ_STATUS_OK
                    || kVerifyResult.data.size()
                        != static_cast<std::size_t>(kChunkBytes)
                    || !std::equal(
                        chunk.cbegin(),
                        chunk.cend(),
                        kVerifyResult.data.cbegin()))
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务提交后 R3 复读不一致：地址=%1 tx=%2 读取状态=%3 NT=%4")
                        .arg(formatAddress(kChunkAddress))
                        .arg(kPrepareResult.transactionId)
                        .arg(kVerifyResult.readStatus)
                        .arg(driverMemoryNtStatusText(
                            kVerifyResult.copyStatus));
                    break;
                }

                totalWritten +=
                    static_cast<std::uint64_t>(kChunkBytes);
                offset += kChunkBytes;
                continue;
            }

            unsigned long writeFlags = 0UL;
            if (forceWriteApproved)
            {
                writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
            }
            ksword::ark::VirtualMemoryWriteResult writeResult =
                driverClient.writeVirtualMemory(
                    driverMemorySnapshotPid_,
                    kChunkAddress,
                    chunk,
                    writeFlags);

            if (writeResult.io.ok &&
                writeResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED)
            {
                const QString kForcePromptText =
                    QString("驱动拒绝了普通内存写入请求。\n地址=%1\n请求=%2 字节\nR0 信息：%3")
                    .arg(formatAddress(kChunkAddress))
                    .arg(kChunkBytes)
                    .arg(driverMemoryIoMessageText(writeResult.io.message));
                if (!confirmForceDriverMemoryWrite(
                    kChunkAddress,
                    static_cast<std::uint32_t>(kChunkBytes),
                    kForcePromptText))
                {
                    ++failedBlockCount;
                    lastFailureText = QString("用户未强制继续，地址=%1 请求=%2。")
                        .arg(formatAddress(kChunkAddress))
                        .arg(kChunkBytes);
                    break;
                }

                forceWriteApproved = true;
                writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
                writeResult = driverClient.writeVirtualMemory(
                    driverMemorySnapshotPid_,
                    kChunkAddress,
                    chunk,
                    writeFlags);
            }

            totalWritten += static_cast<std::uint64_t>(writeResult.bytesWritten);
            if (!writeResult.io.ok ||
                writeResult.writeStatus != KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
                writeResult.bytesWritten != static_cast<std::uint32_t>(kChunkBytes))
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("R0写入进程内存"),
                    writeResult.io.win32Error);
                if (!privilegePromptHandled)
                {
                    privilegePromptHandled = ks::ui::promptForPrivilegeNtStatus(
                        this,
                        QStringLiteral("R0写入进程内存"),
                        static_cast<long>(writeResult.copyStatus));
                }
                ++failedBlockCount;
                lastFailureText = QString("地址=%1 请求=%2 写入=%3 状态=%4 NT=0x%5 信息=%6")
                    .arg(formatAddress(kChunkAddress))
                    .arg(kChunkBytes)
                    .arg(writeResult.bytesWritten)
                    .arg(writeResult.writeStatus)
                    .arg(static_cast<unsigned long>(writeResult.copyStatus), 8, 16, QChar('0'))
                    .arg(driverMemoryIoMessageText(writeResult.io.message));
                break;
            }

            offset += kChunkBytes;
        }

        if (failedBlockCount > 0)
        {
            break;
        }
    }

    if (kKernelAddressSnapshot && failedBlockCount != 0)
    {
        for (auto transaction =
                 kernelMutationChunks.crbegin();
             transaction != kernelMutationChunks.crend();
             ++transaction)
        {
            bool restored = false;
            const auto kReadExpectedBefore = [&driverClient,
                                             &transaction,
                                             &restored]()
            {
                const ksword::ark::VirtualMemoryReadResult kReadResult =
                    driverClient.readVirtualMemory(
                        0U,
                        transaction->address,
                        static_cast<std::uint32_t>(
                            transaction->beforeBytes.size()),
                        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                restored =
                    kReadResult.io.ok
                    && kReadResult.readStatus
                        == KSWORD_ARK_MEMORY_READ_STATUS_OK
                    && kReadResult.data.size()
                        == transaction->beforeBytes.size()
                    && std::equal(
                        transaction->beforeBytes.cbegin(),
                        transaction->beforeBytes.cend(),
                        kReadResult.data.cbegin());
            };
            kReadExpectedBefore();
            if (!restored)
            {
                const ksword::ark::MutationResponseResult kRollbackResult =
                    driverClient.rollbackMutation(
                        transaction->transactionId,
                        KSWORD_ARK_MUTATION_FLAG_FORCE |
                        KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
                if (kRollbackResult.io.ok
                    && (kRollbackResult.status
                            == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK
                        || kRollbackResult.status
                            == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE))
                {
                    kReadExpectedBefore();
                }
            }
            if (restored)
            {
                rollbackVerifiedBytes +=
                    transaction->beforeBytes.size();
            }
            else
            {
                ++rollbackFailedCount;
            }
        }
        lastFailureText += QString(
            "；回滚复核恢复=%1 字节，未恢复事务=%2")
            .arg(static_cast<qulonglong>(
                rollbackVerifiedBytes))
            .arg(rollbackFailedCount);
    }

    // On successful write, promote the current edit cache to the new backup to avoid reapplying the same delta.
    if (failedBlockCount == 0)
    {
        driverMemoryOriginalBytes_ = driverMemoryEditedBytes_;
        driverMemoryApplyButton_->setEnabled(false);
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(
                QString("应用完成：差异块=%1，请求写入=%2 字节，实际写入=%3 字节。")
                .arg(diffBlocks.size())
                .arg(static_cast<qulonglong>(totalRequested))
                .arg(static_cast<qulonglong>(totalWritten)));
        }
    }
    else
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(
                QString("应用部分失败：请求=%1 字节，已写=%2 字节，失败块=%3，%4")
                .arg(static_cast<qulonglong>(totalRequested))
                .arg(static_cast<qulonglong>(totalWritten))
                .arg(failedBlockCount)
                .arg(lastFailureText));
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(this, "驱动内存读写", driverMemoryStatusLabel_->text());
            }
        }
    }
}

void MemoryDock::resetDriverMemoryRwState()
{
    // Log cache clearing: record state before clearing.
    KLogEvent resetEvent;
    dbg << resetEvent
        << "[MemoryDock] resetDriverMemoryRwState: 清空驱动读写页缓存。"
        << eol;

    driverMemoryBaseAddress_ = 0;
    driverMemoryOffsetBase_ = 0;
    driverMemoryCenterAddress_ = 0;
    driverMemorySnapshotPid_ = 0;
    driverMemorySnapshotProcessName_.clear();
    driverMemoryOriginalBytes_.clear();
    driverMemoryEditedBytes_.clear();
    driverMemoryHasSnapshot_ = false;
    driverMemorySnapshotIsPhysical_ = false;

    if (driverMemoryHexEditor_ != nullptr)
    {
        driverMemoryHexEditor_->clearData();
        driverMemoryHexEditor_->setEditable(false);
    }
    if (driverMemoryApplyButton_ != nullptr)
    {
        driverMemoryApplyButton_->setEnabled(false);
    }
    if (driverMemoryRangeLabel_ != nullptr)
    {
        driverMemoryRangeLabel_->setText("范围: 未读取");
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText("缓存已清空。");
    }

    // The derived view must be cleared together; otherwise, disassembly and text pages will continue to display stale content from the previous round.
    driverMemoryDisasmRows_.clear();
    if (driverMemoryDisasmTable_ != nullptr)
    {
        driverMemoryDisasmTable_->setRowCount(0);
    }
    if (driverMemoryDisasmBackendLabel_ != nullptr)
    {
        driverMemoryDisasmBackendLabel_->setText(
            QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
    }
    if (driverMemoryTextView_ != nullptr)
    {
        driverMemoryTextView_->setRawText(
            QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
    }
}

bool MemoryDock::confirmForceDriverMemoryWrite(
    const std::uint64_t blockAddress,
    const std::uint32_t requestedBytes,
    const QString& failureText)
{
    // This is not affected by the 'skip dangerous operation re-confirmation' switch:
    // This switch promises to skip repeated prompts the user has already answered. However, reaching this function means
    // R0 just rejected the normal write; bypassing this protection is a new decision that requires a prompt every time.
    // Automatically returning true is equivalent to consenting on behalf of the user to a write that the driver has already rejected.

    // Forced confirmation entry: reached only after a standard write is rejected by R0.
    QMessageBox warningBox(this);
    warningBox.setIcon(QMessageBox::Warning);
    warningBox.setWindowTitle(QStringLiteral("强制写入确认"));
    warningBox.setText(QStringLiteral("R0 已拒绝普通内存写入请求。"));
    warningBox.setInformativeText(
        QStringLiteral("目标 PID=%1\n目标地址=%2\n请求长度=%3 字节\n\n%4\n\n强制继续会绕过本次普通请求保护，只应在确认目标进程和地址无误时使用。")
        .arg(driverMemorySnapshotPid_)
        .arg(formatAddress(blockAddress))
        .arg(requestedBytes)
        .arg(failureText));
    warningBox.setStandardButtons(QMessageBox::Cancel);
    warningBox.setDefaultButton(QMessageBox::Cancel);

    // Custom buttons are used to explicitly express the 'force' semantics, avoiding confusion where a standard Yes/Ok might be mistaken for a forced write.
    QPushButton* const kForceButton =
        warningBox.addButton(QStringLiteral("强制继续"), QMessageBox::DestructiveRole);
    warningBox.exec();

    // The return value is true only if the user clicks the force button; closing the window or canceling stops the write.
    return warningBox.clickedButton() == kForceButton;
}

void MemoryDock::collectDriverMemoryDiffBlocks(std::vector<DriverDiffBlock>& diffBlocksOut) const
{
    // Difference collection entry: The output container is owned by the caller; clear it here first.
    diffBlocksOut.clear();
    if (!driverMemoryHasSnapshot_ ||
        driverMemoryOriginalBytes_.size() != driverMemoryEditedBytes_.size())
    {
        return;
    }

    // Scan the entire buffer, merging adjacent changed bytes into contiguous blocks to reduce IOCTL calls.
    int index = 0;
    while (index < driverMemoryOriginalBytes_.size())
    {
        if (driverMemoryOriginalBytes_.at(index) == driverMemoryEditedBytes_.at(index))
        {
            ++index;
            continue;
        }

        const int kBlockStart = index;
        while (index < driverMemoryOriginalBytes_.size() &&
            driverMemoryOriginalBytes_.at(index) != driverMemoryEditedBytes_.at(index))
        {
            ++index;
        }

        DriverDiffBlock block{};
        block.address = driverMemoryBaseAddress_ + static_cast<std::uint64_t>(kBlockStart);
        block.bytes = driverMemoryEditedBytes_.mid(kBlockStart, index - kBlockStart);
        diffBlocksOut.push_back(std::move(block));
    }
}
