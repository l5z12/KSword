#include "MemoryDock.Internal.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/evidence/NumericTextParse.h"

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.ViewBreakpointUtil.cpp
// Purpose:
// - Responsible for memory viewer, breakpoints and bookmarks, and general formatting and parsing utility functions.
// - Focus on 'visual read/write + debugging assistance + text conversion' capabilities.
// ============================================================

void MemoryDock::jumpToAddressFromUi()
{
    // Address jump entry log: record the original user input.
    KLogEvent jumpFromUiEvent;
    info << jumpFromUiEvent
        << "[MemoryDock] jumpToAddressFromUi: 请求跳转, text="
        << viewAddressEdit_->text().trimmed().toStdString()
        << eol;

    // The address field supports decimal or 0x hexadecimal.
    std::uint64_t targetAddress = 0;
    if (!parseAddressText(viewAddressEdit_->text().trimmed(), targetAddress))
    {
        KLogEvent jumpFromUiParseFailEvent;
        warn << jumpFromUiParseFailEvent
            << "[MemoryDock] jumpToAddressFromUi: 地址解析失败。"
            << eol;
        QMessageBox::warning(this, "地址跳转", "地址格式无效。");
        return;
    }
    jumpToAddress(targetAddress);
}

void MemoryDock::jumpToAddress(const std::uint64_t address)
{
    // Jump log: record the target address and switch pages.
    KLogEvent jumpAddressEvent;
    info << jumpAddressEvent
        << "[MemoryDock] jumpToAddress: 跳转到地址="
        << formatAddress(address).toStdString()
        << eol;

    // Record the current base address for reuse by scrolling, editing, and status bar logic.
    currentViewerAddress_ = address;
    viewAddressEdit_->setText(formatAddress(address));

    // Automatically switches to Tab4 upon navigation, aligning with the expectation that double-clicking a module/region/search result opens the viewer.
    tabWidget_->setCurrentWidget(tabViewer_);
    reloadMemoryViewerPage();
}

void MemoryDock::reloadMemoryViewerPage()
{
    // Page reload log: output the current view address.
    KLogEvent reloadViewerStartEvent;
    dbg << reloadViewerStartEvent
        << "[MemoryDock] reloadMemoryViewerPage: 开始刷新, baseAddress="
        << formatAddress(currentViewerAddress_).toStdString()
        << eol;

    // When no target process is attached, the viewer only displays a prompt and does not attempt to read memory.
    if (attachedProcessHandle_ == nullptr)
    {
        currentViewerPageBytes_.clear();
        if (hexEditorWidget_ != nullptr)
        {
            hexEditorWidget_->setEditable(false);
            hexEditorWidget_->clearData();
        }
        viewProtectLabel_->setText("保护属性: -");
        viewerStatusLabel_->setText("未附加进程。");
        KLogEvent reloadViewerNoAttachEvent;
        warn << reloadViewerNoAttachEvent
            << "[MemoryDock] reloadMemoryViewerPage: 未附加进程，结束刷新。"
            << eol;
        return;
    }

    // Read a fixed 512 bytes per page to balance readability and refresh performance. The buffer
    // is allocated by the facade: each of the three channels determines its own byte count;
    // preparing a fixed-length buffer here would only create a false impression of "read full".
    SIZE_T bytesRead = 0;

    // The DDMA backend does not use ReadProcessMemory; it translates page-by-page to physical addresses and accesses via disk DMA, thus
    // seeing content redirected by SLAT. Pages that fail translation are padded with 00 by the backend facade and marked as partial.
    if (currentViewerBackend() == ksword::memory_backend::MemoryAccessBackend::kDdma)
    {
        const ksword::memory_backend::AccessOutcome kDdmaOutcome =
            ksword::memory_backend::readVirtual(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                currentDdmaSession(),
                attachedPid_,
                currentViewerAddress_,
                kHexPageBytes);
        if (!kDdmaOutcome.ok)
        {
            currentViewerPageBytes_.clear();
            if (hexEditorWidget_ != nullptr)
            {
                hexEditorWidget_->setEditable(false);
                hexEditorWidget_->clearData();
            }
            viewerStatusLabel_->setText(
                QStringLiteral("DDMA 读取失败：%1").arg(kDdmaOutcome.failureText));
            return;
        }

        currentViewerPageBytes_ = kDdmaOutcome.data;
        if (hexEditorWidget_ != nullptr)
        {
            // DDMA snapshot is displayed read-only: single-byte writes on this page go through WriteProcessMemory, which is a
            // different path than DDMA. Allowing editing would mislead users into thinking they are modifying the DMA view.
            hexEditorWidget_->setEditable(false);
            hexEditorWidget_->setBytesPerRow(16);
            hexEditorWidget_->setRegionData(
                currentViewerPageBytes_.constData(),
                static_cast<std::size_t>(currentViewerPageBytes_.size()),
                currentViewerAddress_);
        }
        QString ddmaStatusText = QStringLiteral("DDMA 读取完成：%1 字节（只读展示）。")
            .arg(currentViewerPageBytes_.size());
        if (kDdmaOutcome.partial)
        {
            ddmaStatusText += QStringLiteral(" 有页无法翻译成物理地址，已按 00 填充。");
        }
        if (kDdmaOutcome.scratchDirty)
        {
            ddmaStatusText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        viewerStatusLabel_->setText(ddmaStatusText);
        viewProtectLabel_->setText(QStringLiteral("保护属性: DDMA 通道不查询"));
        return;
    }

    // R3 and R0 share the same facade, differing only in enumeration values. **No automatic fallback**: The purpose of these three
    // channels in the dropdown is to show 'what each address can read independently'. Silently switching to another channel upon
    // failure would cause the displayed bytes to no longer reflect the user's selected channel, making differences invisible.
    const ksword::memory_backend::MemoryAccessBackend kSelectedBackend =
        currentViewerBackend();
    const ksword::memory_backend::AccessOutcome kReadOutcome =
        ksword::memory_backend::readVirtual(
            kSelectedBackend,
            currentDdmaSession(),
            attachedPid_,
            currentViewerAddress_,
            kHexPageBytes);
    const QString kChannelText =
        ksword::memory_backend::backendDisplayName(kSelectedBackend);

    if (!kReadOutcome.ok)
    {
        currentViewerPageBytes_.clear();
        if (hexEditorWidget_ != nullptr)
        {
            hexEditorWidget_->setEditable(false);
            hexEditorWidget_->clearData();
        }

        // On failure, we must determine the exact state of this address within the target process. Previously, VirtualQueryEx
        // only ran on the success path, so errors only provided a win32 error code. Error 299 is compatible with several
        // completely different causes: the attached process is not the target, the memory region has already been freed, or
        // it is a PAGE_GUARD page on the stack. None of these causes can be distinguished by the error code alone; guessing
        // is not a valid criterion. Once the region state is displayed, the causes are clearly distinguished.
        MEMORY_BASIC_INFORMATION failMbi{};
        const SIZE_T kFailQuerySize = ::VirtualQueryEx(
            attachedProcessHandle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentViewerAddress_)),
            &failMbi,
            sizeof(failMbi));
        QString regionText;
        if (kFailQuerySize == sizeof(failMbi))
        {
            regionText = QString("区域 %1 大小 %2 状态 %3 保护 %4")
                .arg(formatAddress(reinterpret_cast<std::uint64_t>(failMbi.BaseAddress)))
                .arg(static_cast<qulonglong>(failMbi.RegionSize))
                .arg(stateToText(static_cast<std::uint32_t>(failMbi.State)))
                .arg(protectToText(static_cast<std::uint32_t>(failMbi.Protect)));

            // MEM_FREE means 'there is no memory here', not 'cannot read'. None of the three channels can conjure
            // something that doesn't exist, so continuing to investigate on the read channel at this point is futile.
            // The most common cause is attaching to another process with the same name: for programs like QQ that spawn multiple instances
            // with identical names, an address copied from elsewhere may belong to one instance but be attached to another, triggering this
            // behavior. Since the count of same-name processes is readily available, display it directly instead of leaving users to guess.
            if (failMbi.State == MEM_FREE)
            {
                int sameNameCount = 0;
                for (const ProcessEntry& entry : processCache_)
                {
                    if (entry.processName.compare(attachedProcessName_, Qt::CaseInsensitive) == 0)
                    {
                        ++sameNameCount;
                    }
                }
                regionText += QStringLiteral("。该地址在这个进程里根本没有内存（MEM_FREE），不是读不到——换任何通道都一样");
                if (sameNameCount > 1)
                {
                    regionText += QString("。本机有 %1 个都叫 %2 的进程，地址很可能属于其中另一个，请核对 PID")
                        .arg(sameNameCount)
                        .arg(attachedProcessName_);
                }
            }
        }
        else
        {
            regionText = QStringLiteral("区域查询也失败，该地址在本进程中不存在");
        }

        // The low 64 KB is the null pointer guard for each process; the system never maps anything there, so this
        // region is always unreadable, regardless of the target process, permissions, or backend channel. It is
        // checked separately because its root cause is almost always an incorrect address rather than a read failure.
        constexpr std::uint64_t kNullGuardEnd = 0x10000ULL;
        const QString kGuardText = (currentViewerAddress_ < kNullGuardEnd)
            ? QStringLiteral("该地址落在进程的空指针保护区（低 64 KB）内，任何进程都不会在这里映射内存，请检查地址是否写少了位数。")
            : QString();
        viewerStatusLabel_->setText(
            QString("%1 读取失败：地址=%2（PID %3）。%4%5。%6")
            .arg(kChannelText)
            .arg(formatAddress(currentViewerAddress_))
            .arg(attachedPid_)
            .arg(kGuardText)
            .arg(kReadOutcome.failureText)
            .arg(regionText));
        KLogEvent reloadViewerReadFailEvent;
        err << reloadViewerReadFailEvent
            << "[MemoryDock] reloadMemoryViewerPage: 读取失败, backend="
            << kChannelText.toStdString()
            << ", address="
            << formatAddress(currentViewerAddress_).toStdString()
            << ", pid="
            << attachedPid_
            << ", reason="
            << kReadOutcome.failureText.toStdString()
            << ", region="
            << regionText.toStdString()
            << eol;
        return;
    }

    currentViewerPageBytes_ = kReadOutcome.data;
    bytesRead = static_cast<SIZE_T>(currentViewerPageBytes_.size());
    const bool kPartialRead = kReadOutcome.partial || (bytesRead < kHexPageBytes);

    // Project to a unified hex editor component.
    if (hexEditorWidget_ != nullptr)
    {
        hexEditorWidget_->setEditable(canReadWriteMemory_);
        hexEditorWidget_->setBytesPerRow(16);
        hexEditorWidget_->setRegionData(
            currentViewerPageBytes_.constData(),
            static_cast<std::size_t>(currentViewerPageBytes_.size()),
            currentViewerAddress_);
    }

    // Update the display of the current address protection attributes to help users determine if it is writable/executable.
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T kQuerySize = ::VirtualQueryEx(
        attachedProcessHandle_,
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentViewerAddress_)),
        &mbi,
        sizeof(mbi));
    if (kQuerySize == sizeof(mbi))
    {
        viewProtectLabel_->setText(
            QString("保护属性: %1 | 状态: %2 | 类型: %3")
            .arg(protectToText(static_cast<std::uint32_t>(mbi.Protect)))
            .arg(stateToText(static_cast<std::uint32_t>(mbi.State)))
            .arg(typeToText(static_cast<std::uint32_t>(mbi.Type))));

        // Writable and executable pages are the most suspicious combination; mark them directly
        // with semantic colors so users don't have to search through a long list of attribute
        // text. Since a snapshot token is fetched for color on every jump, this is safe.
        const std::uint32_t kBaseProtect = static_cast<std::uint32_t>(mbi.Protect) & 0xFFU;
        const bool kExecutable = (kBaseProtect == PAGE_EXECUTE
            || kBaseProtect == PAGE_EXECUTE_READ
            || kBaseProtect == PAGE_EXECUTE_READWRITE
            || kBaseProtect == PAGE_EXECUTE_WRITECOPY);
        const bool kWritable = (kBaseProtect == PAGE_READWRITE
            || kBaseProtect == PAGE_WRITECOPY
            || kBaseProtect == PAGE_EXECUTE_READWRITE
            || kBaseProtect == PAGE_EXECUTE_WRITECOPY);
        QString protectColor = ksword_theme::textSecondaryHex();
        if (kExecutable && kWritable)
        {
            protectColor = ksword_theme::errorHex();   // RWX: Highest risk.
        }
        else if (kExecutable)
        {
            protectColor = ksword_theme::warningHex(); // Executable but not writable.
        }
        else if (kWritable)
        {
            protectColor = ksword_theme::successHex(); // Ordinary readable/writable data pages.
        }
        viewProtectLabel_->setStyleSheet(QString("color:%1;").arg(protectColor));
    }
    else
    {
        viewProtectLabel_->setText("保护属性: (查询失败)");
        viewProtectLabel_->setStyleSheet(
            QString("color:%1;").arg(ksword_theme::textSecondaryHex()));
    }

    // When only a partial read occurs, this must be reported. Without this, the user sees a full screen of normal hex data
    // but remains unaware that the page becomes unmapped after a certain byte, meaning the remaining content does not exist.
    // The channel name must also be displayed: the same address may yield different content when read via the driver
    // channel versus RPM; without this, it is impossible to distinguish which source provided the current page on screen.
    if (kPartialRead)
    {
        viewerStatusLabel_->setText(
            QString("地址 %1 经%2只读到 %3 / %4 字节：其余部分不可读，内容不存在。")
            .arg(formatAddress(currentViewerAddress_))
            .arg(kChannelText)
            .arg(bytesRead)
            .arg(kHexPageBytes));
    }
    else
    {
        viewerStatusLabel_->setText(
            QString("地址 %1 经%2读取 %3 字节。")
            .arg(formatAddress(currentViewerAddress_))
            .arg(kChannelText)
            .arg(bytesRead));
    }

    // Refresh completion log: record the number of bytes successfully read on this page.
    KLogEvent reloadViewerFinishEvent;
    dbg << reloadViewerFinishEvent
        << "[MemoryDock] reloadMemoryViewerPage: 刷新完成, bytesRead="
        << bytesRead
        << eol;
}

bool MemoryDock::writeSingleByteAtViewer(
    const std::uint64_t absoluteAddress,
    const std::uint8_t value,
    QString& errorTextOut)
{
    // Single-byte write entry log: outputs the target address and target value.
    KLogEvent writeByteStartEvent;
    dbg << writeByteStartEvent
        << "[MemoryDock] writeSingleByteAtViewer: 请求写入, address="
        << formatAddress(absoluteAddress).toStdString()
        << ", value=0x"
        << QString("%1").arg(value, 2, 16, QChar('0')).toUpper().toStdString()
        << eol;

    // If not attached to a process or the handle is read-only, prohibit writes and explicitly return the failure reason.
    if (attachedProcessHandle_ == nullptr)
    {
        errorTextOut = "当前未附加进程，无法写入。";
        KLogEvent writeByteNoAttachEvent;
        warn << writeByteNoAttachEvent
            << "[MemoryDock] writeSingleByteAtViewer: 未附加进程。"
            << eol;
        return false;
    }
    if (!canReadWriteMemory_)
    {
        errorTextOut = "当前句柄为只读权限，无法写入内存。";
        KLogEvent writeByteReadonlyEvent;
        warn << writeByteReadonlyEvent
            << "[MemoryDock] writeSingleByteAtViewer: 当前句柄只读，拒绝写入。"
            << eol;
        return false;
    }

    SIZE_T bytesWritten = 0;
    const BOOL kWriteOk = ::WriteProcessMemory(
        attachedProcessHandle_,
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(absoluteAddress)),
        &value,
        sizeof(value),
        &bytesWritten);
    if (kWriteOk == FALSE || bytesWritten != sizeof(value))
    {
        errorTextOut = QString("WriteProcessMemory 失败，错误码=%1").arg(::GetLastError());
        KLogEvent writeByteFailEvent;
        err << writeByteFailEvent
            << "[MemoryDock] writeSingleByteAtViewer: 写入失败, error="
            << ::GetLastError()
            << eol;
        return false;
    }

    KLogEvent writeByteSuccessEvent;
    info << writeByteSuccessEvent
        << "[MemoryDock] writeSingleByteAtViewer: 写入成功, address="
        << formatAddress(absoluteAddress).toStdString()
        << eol;

    return true;
}

bool MemoryDock::addBreakpointByAddress(
    const std::uint64_t address,
    const QString& description,
    QString& errorTextOut)
{
    // Breakpoint addition entry log: records the address and description source.
    KLogEvent addBreakpointStartEvent;
    info << addBreakpointStartEvent
        << "[MemoryDock] addBreakpointByAddress: 请求添加断点, address="
        << formatAddress(address).toStdString()
        << ", description="
        << description.toStdString()
        << eol;

    // Software breakpoints rely on 0xCC writes, so write memory permissions are required.
    if (attachedProcessHandle_ == nullptr)
    {
        errorTextOut = "请先附加进程。";
        KLogEvent addBreakpointNoAttachEvent;
        warn << addBreakpointNoAttachEvent
            << "[MemoryDock] addBreakpointByAddress: 未附加进程。"
            << eol;
        return false;
    }
    if (!canReadWriteMemory_)
    {
        errorTextOut = "当前为只读句柄，无法设置断点。";
        KLogEvent addBreakpointReadonlyEvent;
        warn << addBreakpointReadonlyEvent
            << "[MemoryDock] addBreakpointByAddress: 句柄只读。"
            << eol;
        return false;
    }

    // Avoid writing duplicate breakpoints at the same address to improve breakpoint cache consistency.
    for (const BreakpointEntry& cachedBp : breakpointCache_)
    {
        if (cachedBp.address == address)
        {
            errorTextOut = "该地址已存在断点。";
            KLogEvent addBreakpointDuplicateEvent;
            warn << addBreakpointDuplicateEvent
                << "[MemoryDock] addBreakpointByAddress: 重复断点地址。"
                << eol;
            return false;
        }
    }

    std::uint8_t originalByte = 0;
    SIZE_T bytesRead = 0;
    const BOOL kReadOk = ::ReadProcessMemory(
        attachedProcessHandle_,
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
        &originalByte,
        sizeof(originalByte),
        &bytesRead);
    if (kReadOk == FALSE || bytesRead != sizeof(originalByte))
    {
        errorTextOut = QString("读取原始字节失败，错误码=%1").arg(::GetLastError());
        KLogEvent addBreakpointReadFailEvent;
        err << addBreakpointReadFailEvent
            << "[MemoryDock] addBreakpointByAddress: 读取原字节失败, error="
            << ::GetLastError()
            << eol;
        return false;
    }

    const std::uint8_t kInt3Byte = 0xCC;
    SIZE_T bytesWritten = 0;
    const BOOL kWriteOk = ::WriteProcessMemory(
        attachedProcessHandle_,
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
        &kInt3Byte,
        sizeof(kInt3Byte),
        &bytesWritten);
    if (kWriteOk == FALSE || bytesWritten != sizeof(kInt3Byte))
    {
        errorTextOut = QString("写入 0xCC 失败，错误码=%1").arg(::GetLastError());
        KLogEvent addBreakpointWriteFailEvent;
        err << addBreakpointWriteFailEvent
            << "[MemoryDock] addBreakpointByAddress: 写入0xCC失败, error="
            << ::GetLastError()
            << eol;
        return false;
    }

    BreakpointEntry bpEntry{};
    bpEntry.address = address;
    bpEntry.originalByte = originalByte;
    bpEntry.enabled = true;
    bpEntry.hitCount = 0;
    bpEntry.description = description;
    breakpointCache_.push_back(std::move(bpEntry));

    KLogEvent addBreakpointFinishEvent;
    info << addBreakpointFinishEvent
        << "[MemoryDock] addBreakpointByAddress: 添加成功, totalBreakpointCount="
        << breakpointCache_.size()
        << eol;
    return true;
}

bool MemoryDock::removeBreakpointByRow(const int row)
{
    if (row < 0 || row >= static_cast<int>(breakpointCache_.size()))
    {
        KLogEvent removeBreakpointInvalidRowEvent;
        warn << removeBreakpointInvalidRowEvent
            << "[MemoryDock] removeBreakpointByRow: row越界, row="
            << row
            << eol;
        return false;
    }

    // Before removal, if the breakpoint is enabled, restore the original byte first to avoid leaving dirty data in the target process.
    if (breakpointCache_[static_cast<std::size_t>(row)].enabled)
    {
        if (!setBreakpointEnabledByRow(row, false))
        {
            KLogEvent removeBreakpointDisableFailEvent;
            warn << removeBreakpointDisableFailEvent
                << "[MemoryDock] removeBreakpointByRow: 禁用断点失败, row="
                << row
                << eol;
            return false;
        }
    }

    breakpointCache_.erase(breakpointCache_.begin() + row);
    KLogEvent removeBreakpointFinishEvent;
    info << removeBreakpointFinishEvent
        << "[MemoryDock] removeBreakpointByRow: 删除成功, remainCount="
        << breakpointCache_.size()
        << eol;
    return true;
}

bool MemoryDock::setBreakpointEnabledByRow(const int row, const bool enabled)
{
    if (row < 0 || row >= static_cast<int>(breakpointCache_.size()))
    {
        KLogEvent setBreakpointInvalidRowEvent;
        warn << setBreakpointInvalidRowEvent
            << "[MemoryDock] setBreakpointEnabledByRow: row越界, row="
            << row
            << eol;
        return false;
    }
    if (attachedProcessHandle_ == nullptr || !canReadWriteMemory_)
    {
        KLogEvent setBreakpointNoPermissionEvent;
        warn << setBreakpointNoPermissionEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 句柄不可写, row="
            << row
            << eol;
        return false;
    }

    BreakpointEntry& bpEntry = breakpointCache_[static_cast<std::size_t>(row)];
    if (bpEntry.enabled == enabled)
    {
        KLogEvent setBreakpointNoopEvent;
        dbg << setBreakpointNoopEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 状态未变, row="
            << row
            << ", enabled="
            << (enabled ? "true" : "false")
            << eol;
        return true;
    }

    const std::uint8_t kTargetByte = enabled ? 0xCC : bpEntry.originalByte;
    SIZE_T bytesWritten = 0;
    const BOOL kWriteOk = ::WriteProcessMemory(
        attachedProcessHandle_,
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(bpEntry.address)),
        &kTargetByte,
        sizeof(kTargetByte),
        &bytesWritten);
    if (kWriteOk == FALSE || bytesWritten != sizeof(kTargetByte))
    {
        KLogEvent setBreakpointWriteFailEvent;
        err << setBreakpointWriteFailEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 写入断点字节失败, row="
            << row
            << ", error="
            << ::GetLastError()
            << eol;
        return false;
    }

    bpEntry.enabled = enabled;
    KLogEvent setBreakpointFinishEvent;
    info << setBreakpointFinishEvent
        << "[MemoryDock] setBreakpointEnabledByRow: 切换成功, row="
        << row
        << ", enabled="
        << (enabled ? "true" : "false")
        << eol;
    return true;
}

void MemoryDock::rebuildBreakpointTable()
{
    // Rebuild breakpoint table log: record the current number of breakpoints.
    KLogEvent rebuildBreakpointEvent;
    dbg << rebuildBreakpointEvent
        << "[MemoryDock] rebuildBreakpointTable: 重建断点表, count="
        << breakpointCache_.size()
        << eol;

    // The breakpoint table is a direct projection of m_breakpointCache to prevent divergence between UI and business data.
    breakpointTable_->setRowCount(static_cast<int>(breakpointCache_.size()));
    for (int row = 0; row < static_cast<int>(breakpointCache_.size()); ++row)
    {
        const BreakpointEntry& entry = breakpointCache_[static_cast<std::size_t>(row)];
        breakpointTable_->setItem(row, 0, new QTableWidgetItem(formatAddress(entry.address)));
        breakpointTable_->setItem(row, 1, new QTableWidgetItem(
            QString("0x%1").arg(entry.originalByte, 2, 16, QChar('0')).toUpper()));
        breakpointTable_->setItem(
            row,
            2,
            new QTableWidgetItem(ks::i18n::sourceText(
                entry.enabled ? QStringLiteral("启用") : QStringLiteral("禁用"))));
        breakpointTable_->setItem(row, 3, new QTableWidgetItem(QString::number(entry.hitCount)));
        breakpointTable_->setItem(row, 4, new QTableWidgetItem(entry.description));
    }
}

void MemoryDock::addBookmarkByAddress(const std::uint64_t address, const QString& noteText)
{
    // Add bookmark entry log: record address and remark.
    KLogEvent addBookmarkStartEvent;
    info << addBookmarkStartEvent
        << "[MemoryDock] addBookmarkByAddress: 请求添加书签, address="
        << formatAddress(address).toStdString()
        << ", note="
        << noteText.toStdString()
        << eol;

    // If a bookmark at the same address already exists, update only the note without inserting a duplicate.
    for (BookmarkEntry& bookmark : bookmarkCache_)
    {
        if (bookmark.address == address)
        {
            bookmark.noteText = noteText;
            KLogEvent addBookmarkUpdateEvent;
            dbg << addBookmarkUpdateEvent
                << "[MemoryDock] addBookmarkByAddress: 已存在地址，更新备注。"
                << eol;
            return;
        }
    }

    BookmarkEntry bookmark{};
    bookmark.address = address;
    bookmark.noteText = noteText;
    bookmark.addTimeText = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    // Attempt to read an initial value when adding; do not block the add flow on failure.
    if (attachedProcessHandle_ != nullptr)
    {
        QByteArray initialBytes(8, '\0');
        SIZE_T bytesRead = 0;
        if (::ReadProcessMemory(
            attachedProcessHandle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            initialBytes.data(),
            static_cast<SIZE_T>(initialBytes.size()),
            &bytesRead) != FALSE && bytesRead > 0)
        {
            bookmark.lastValueBytes = initialBytes.left(static_cast<int>(bytesRead));
        }
    }

    bookmarkCache_.push_back(std::move(bookmark));
    KLogEvent addBookmarkFinishEvent;
    info << addBookmarkFinishEvent
        << "[MemoryDock] addBookmarkByAddress: 添加完成, totalBookmarkCount="
        << bookmarkCache_.size()
        << eol;
}

void MemoryDock::rebuildBookmarkTable()
{
    // Rebuild bookmark table log: record the current number of bookmarks.
    KLogEvent rebuildBookmarkEvent;
    dbg << rebuildBookmarkEvent
        << "[MemoryDock] rebuildBookmarkTable: 重建书签表, count="
        << bookmarkCache_.size()
        << eol;

    // The bookmark table is fully rebuilt each time; the logic is clear, the quantity is typically small, and maintenance cost is minimal.
    bookmarkTable_->setRowCount(static_cast<int>(bookmarkCache_.size()));
    for (int row = 0; row < static_cast<int>(bookmarkCache_.size()); ++row)
    {
        const BookmarkEntry& bookmark = bookmarkCache_[static_cast<std::size_t>(row)];
        bookmarkTable_->setItem(row, 0, new QTableWidgetItem(formatAddress(bookmark.address)));

        // Note: The bookmark 'Current Value' defaults to display as a hexadecimal byte string, applicable for unknown variable types.
        const QString kValueText = bytesToDisplayString(bookmark.lastValueBytes, SearchValueType::kByteArray);
        bookmarkTable_->setItem(row, 1, new QTableWidgetItem(kValueText));
        bookmarkTable_->setItem(row, 2, new QTableWidgetItem(bookmark.noteText));
        bookmarkTable_->setItem(row, 3, new QTableWidgetItem(bookmark.addTimeText));
    }
}

void MemoryDock::refreshBookmarkValues()
{
    const QPointer<MemoryDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("memory-bookmark-periodic-values"),
        { bookmarkTable_ },
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshBookmarkValues();
            }
        }))
    {
        return;
    }

    // Log entry for refreshing bookmark values: record the current bookmark count.
    KLogEvent refreshBookmarkStartEvent;
    dbg << refreshBookmarkStartEvent
        << "[MemoryDock] refreshBookmarkValues: 开始刷新, bookmarkCount="
        << bookmarkCache_.size()
        << eol;

    // No need to refresh if the process is not attached or there are no bookmarks; return early to avoid meaningless system calls.
    if (attachedProcessHandle_ == nullptr || bookmarkCache_.empty())
    {
        KLogEvent refreshBookmarkSkipEvent;
        dbg << refreshBookmarkSkipEvent
            << "[MemoryDock] refreshBookmarkValues: 跳过刷新（未附加或无书签）。"
            << eol;
        return;
    }

    for (BookmarkEntry& bookmark : bookmarkCache_)
    {
        const int kRequestLength = std::max<int>(8, bookmark.lastValueBytes.size());
        QByteArray valueBytes(kRequestLength, '\0');
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ::ReadProcessMemory(
            attachedProcessHandle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(bookmark.address)),
            valueBytes.data(),
            static_cast<SIZE_T>(valueBytes.size()),
            &bytesRead);
        if (kReadOk != FALSE && bytesRead > 0)
        {
            bookmark.lastValueBytes = valueBytes.left(static_cast<int>(bytesRead));
        }
    }

    // Rebuild the table after refresh to ensure the user sees the latest read-back values.
    rebuildBookmarkTable();

    KLogEvent refreshBookmarkFinishEvent;
    dbg << refreshBookmarkFinishEvent
        << "[MemoryDock] refreshBookmarkValues: 刷新完成。"
        << eol;
}

void MemoryDock::updateStatusBarText()
{
    // Status bar refresh log: records current PID and privilege state.
    KLogEvent statusUpdateEvent;
    dbg << statusUpdateEvent
        << "[MemoryDock] updateStatusBarText: attachedPid="
        << attachedPid_
        << ", canReadWrite="
        << (canReadWriteMemory_ ? "true" : "false")
        << eol;

    // The status bar consists of three segments: process name, PID, and read/write status. Any status change is refreshed uniformly via this function.
    if (attachedPid_ == 0 || attachedProcessHandle_ == nullptr)
    {
        statusProcessLabel_->setText("进程: 未附加");
        statusPidLabel_->setText("PID: -");
        statusMemoryIoLabel_->setText("内存读写: 未就绪");
        if (dockHeaderStatusLabel_ != nullptr)
        {
            dockHeaderStatusLabel_->setText("未附加进程，请先选择目标并点击“附加”。");
        }
        // When the attachment state changes, the semantic colors must revert to the secondary color for 'Not Attached'.
        applyMemoryDockSemanticStyles();
        return;
    }

    statusProcessLabel_->setText(QString("进程: %1").arg(attachedProcessName_));
    statusPidLabel_->setText(QString("PID: %1").arg(attachedPid_));
    statusMemoryIoLabel_->setText(
        QString("内存读写: %1").arg(canReadWriteMemory_ ? "可读可写" : "只读"));
    if (dockHeaderStatusLabel_ != nullptr)
    {
        dockHeaderStatusLabel_->setText(
            QString("已附加 %1 (PID %2)，内存%3。")
                .arg(attachedProcessName_)
                .arg(attachedPid_)
                .arg(canReadWriteMemory_ ? "可读可写" : "只读"));
    }
    applyMemoryDockSemanticStyles();
}

bool MemoryDock::parseAddressText(const QString& text, std::uint64_t& valueOut)
{
    // Address parsing log: retain input text to locate format issues.
    KLogEvent parseAddressEvent;
    dbg << parseAddressEvent
        << "[MemoryDock] parseAddressText: text="
        << text.trimmed().toStdString()
        << eol;

    // The default radix for addresses without a prefix is hexadecimal, which differs from the rules used by the general numeric parser below.
    // Originally, both shared a parser that tried decimal first and fell back to hexadecimal on failure.
    // However, that hexadecimal fallback only applied to strings containing a–f: pure digit strings always
    // succeeded in decimal parsing. In this interface where all addresses are echoed with 0x, entering 1233
    // would jump to decimal 1233 (= 0x4D1) without error or warning, simply reading from the wrong location.
    const auto kParsed = ksword::evidence::parseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::kHexadecimal);
    if (!kParsed.ok)
    {
        return false;
    }
    valueOut = kParsed.value;
    return true;
}

bool MemoryDock::parseUnsignedNumber(const QString& text, std::uint64_t& valueOut)
{
    // This section uses 'quantity' semantics (byte values, lengths, etc. to search). Values without a prefix are decimal—quantities
    // are naturally spoken in decimal and should not be changed to match addresses. The 0x prefix remains strictly hexadecimal.
    const auto kParsed = ksword::evidence::parseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::kDecimal);
    if (!kParsed.ok)
    {
        return false;
    }
    valueOut = kParsed.value;
    return true;
}

QString MemoryDock::formatAddress(const std::uint64_t address)
{
    // Unify output to 16-bit hexadecimal for easier alignment and reading of 32/64-bit addresses in tables.
    const QString kHexText = QString("%1").arg(
        static_cast<qulonglong>(address),
        16,
        16,
        QChar('0')).toUpper();
    return QString("0x%1").arg(kHexText);
}

QString MemoryDock::formatSize(const std::uint64_t sizeBytes)
{
    // Human-readable byte display: automatically switch between B/KB/MB/GB, retaining two decimal places.
    constexpr double kKB = 1024.0;
    constexpr double kMB = 1024.0 * 1024.0;
    constexpr double kGB = 1024.0 * 1024.0 * 1024.0;

    const double kSizeValue = static_cast<double>(sizeBytes);
    if (kSizeValue >= kGB)
    {
        return QString("%1 GB").arg(kSizeValue / kGB, 0, 'f', 2);
    }
    if (kSizeValue >= kMB)
    {
        return QString("%1 MB").arg(kSizeValue / kMB, 0, 'f', 2);
    }
    if (kSizeValue >= kKB)
    {
        return QString("%1 KB").arg(kSizeValue / kKB, 0, 'f', 2);
    }
    return QString("%1 B").arg(sizeBytes);
}

QString MemoryDock::protectToText(const std::uint32_t protect)
{
    // The primary PAGE_* value retains only the lower 8 bits; the upper bits are modifier flags such as PAGE_GUARD or NOCACHE.
    const std::uint32_t kBaseProtect = protect & 0xFF;
    QString baseText;
    switch (kBaseProtect)
    {
    case PAGE_NOACCESS:          baseText = "---"; break;
    case PAGE_READONLY:          baseText = "R--"; break;
    case PAGE_READWRITE:         baseText = "RW-"; break;
    case PAGE_WRITECOPY:         baseText = "RC-"; break;
    case PAGE_EXECUTE:           baseText = "--X"; break;
    case PAGE_EXECUTE_READ:      baseText = "R-X"; break;
    case PAGE_EXECUTE_READWRITE: baseText = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: baseText = "RCX"; break;
    default:                     baseText = "UNK"; break;
    }

    // Overlay modifier markers to help users identify Guard/NoCache/WriteCombine features.
    if ((protect & PAGE_GUARD) != 0)
    {
        baseText += "|G";
    }
    if ((protect & PAGE_NOCACHE) != 0)
    {
        baseText += "|NC";
    }
    if ((protect & PAGE_WRITECOMBINE) != 0)
    {
        baseText += "|WC";
    }

    return baseText;
}

QString MemoryDock::stateToText(const std::uint32_t state)
{
    switch (state)
    {
    case MEM_COMMIT:  return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE:    return "MEM_FREE";
    default:          return QString("UNKNOWN(0x%1)").arg(state, 0, 16);
    }
}

QString MemoryDock::typeToText(const std::uint32_t type)
{
    switch (type)
    {
    case MEM_IMAGE:   return "IMAGE";
    case MEM_MAPPED:  return "MAPPED";
    case MEM_PRIVATE: return "PRIVATE";
    case 0:           return "-";
    default:          return QString("UNKNOWN(0x%1)").arg(type, 0, 16);
    }
}

QString MemoryDock::bytesToDisplayString(const QByteArray& bytes, const SearchValueType valueType)
{
    // Empty bytes are uniformly displayed as a hyphen to avoid ambiguity caused by blank cells in the table.
    if (bytes.isEmpty())
    {
        return "-";
    }

    switch (valueType)
    {
    case SearchValueType::kByte:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::uint8_t))) return "-";
        std::uint8_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString("%1 (0x%2)")
            .arg(value)
            .arg(value, 2, 16, QChar('0')).toUpper();
    }
    case SearchValueType::kInt16:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int16_t))) return "-";
        std::int16_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::kInt32:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int32_t))) return "-";
        std::int32_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::kInt64:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int64_t))) return "-";
        std::int64_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::kFloat32:
    {
        if (bytes.size() < static_cast<int>(sizeof(float))) return "-";
        float value = 0.0f;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 6);
    }
    case SearchValueType::kFloat64:
    {
        if (bytes.size() < static_cast<int>(sizeof(double))) return "-";
        double value = 0.0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 8);
    }
    case SearchValueType::kStringAscii:
    {
        return QString::fromLatin1(bytes);
    }
    case SearchValueType::kStringUnicode:
    {
        // UTF-16 byte length must be even; truncate the last byte if insufficient to prevent out-of-bounds access.
        const int kAlignedLength = bytes.size() - (bytes.size() % 2);
        if (kAlignedLength <= 0)
        {
            return "-";
        }
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(bytes.constData()),
            kAlignedLength / 2);
    }
    case SearchValueType::kByteArray:
    default:
    {
        // Default to displaying as a hexadecimal byte string, compatible with unknown types and bookmark display.
        QStringList parts;
        parts.reserve(bytes.size());
        for (int index = 0; index < bytes.size(); ++index)
        {
            const auto kByteValue = static_cast<unsigned char>(bytes.at(index));
            parts.push_back(QString("%1").arg(kByteValue, 2, 16, QChar('0')).toUpper());
        }
        return parts.join(' ');
    }
    }
}
