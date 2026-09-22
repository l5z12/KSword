#include "MemoryDock.Internal.h"
#include "../ui/KernelDisassemblyDialog.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/TableInteractionSupport.h"

// ============================================================
// MemoryDock.DriverMemoryView.cpp
// Purpose:
// - Multi-view presentation for the 'Driver Memory Read/Write' page: hexadecimal, disassembly, and text.
// - Provides two convenient entry points: snapshot dumping to a file and writing to an edit buffer as a string.
// - Only consume snapshot bytes cached by MemoryDock; do not initiate any IOCTLs.
// ============================================================

using namespace ksword::memory_dock_internal;

namespace
{
    // driverMemoryBytesText:
    // - Render a raw byte sequence as text for the 'Raw Bytes' column in the disassembly table.
    // - Input bytes: byte sequence of a single instruction.
    // - Processing: Convert each byte to a two-digit uppercase hexadecimal value separated by spaces.
    // - Returns: Text in the format "48 8B 05 A1"; returns an empty string for empty input.
    QString driverMemoryBytesText(const QByteArray& bytes)
    {
        QStringList byteTextList;
        byteTextList.reserve(static_cast<int>(bytes.size()));
        for (const char kRawByte : bytes)
        {
            // Convert to unsigned before formatting to avoid an FFFFFF prefix when char is negative.
            const std::uint8_t kByteValue = static_cast<std::uint8_t>(kRawByte);
            byteTextList.push_back(
                QStringLiteral("%1").arg(kByteValue, 2, 16, QChar('0')).toUpper());
        }
        return byteTextList.join(QLatin1Char(' '));
    }

    // driverMemoryHexAddressText:
    // - Unify the address column text format in the disassembly table.
    // - Input address: Absolute virtual instruction address;
    // - Processing: Pad to 16-bit fixed width with zeros and convert to uppercase, keeping the '0x' prefix lowercase to match other addresses on this page.
    // - Returns: Text in the format "0xFFFFF8034A1B2C00".
    QString driverMemoryHexAddressText(const std::uint64_t address)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // driverMemoryOffsetText:
    // - Unify the offset column text format in the disassembly table.
    // - Input byteOffset: byte offset of the instruction relative to the snapshot start;
    // - Processing: Convert to uppercase with 8-bit fixed width and zero-padding.
    // - Returns: Text in the format "0x00000010".
    QString driverMemoryOffsetText(const std::uint32_t byteOffset)
    {
        return QStringLiteral("0x%1")
            .arg(byteOffset, 8, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // driverMemoryReadOnlyItem:
    // - Generate a read-only cell for the disassembly table;
    // - Input text: Cell display text;
    // - Processing: Create a QTableWidgetItem and remove the editable flag.
    // - Return: Pointer to a table item where ownership is transferred to the caller.
    QTableWidgetItem* driverMemoryReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // driverMemoryPrintableText:
    // - Render raw bytes into printable string for text view.
    // - Input bytes: snapshot bytes; useUtf16: interpret as UTF-16LE if true, otherwise as single-byte ASCII.
    // - Processing: Replace all non-printable characters with dots to preserve layout stability (except newlines);
    // - Returns: Text ready to be inserted directly into a read-only editor.
    QString driverMemoryPrintableText(const QByteArray& bytes, const bool useUtf16)
    {
        QString resultText;
        if (useUtf16)
        {
            // UTF-16LE: One code unit per two bytes; trailing single byte is discarded.
            const qsizetype kUnitCount = bytes.size() / 2;
            resultText.reserve(static_cast<int>(kUnitCount));
            for (qsizetype unitIndex = 0; unitIndex < kUnitCount; ++unitIndex)
            {
                const std::uint16_t kCodeUnit = static_cast<std::uint16_t>(
                    static_cast<std::uint8_t>(bytes.at(unitIndex * 2))
                    | (static_cast<std::uint16_t>(
                        static_cast<std::uint8_t>(bytes.at(unitIndex * 2 + 1))) << 8));
                const QChar kUnitChar(kCodeUnit);
                resultText.append(kUnitChar.isPrint() ? kUnitChar : QChar(QLatin1Char('.')));
            }
            return resultText;
        }

        // Single-byte path: allow only printable ASCII characters; replace all others with dots to ensure column alignment.
        resultText.reserve(static_cast<int>(bytes.size()));
        for (const char kRawByte : bytes)
        {
            const std::uint8_t kByteValue = static_cast<std::uint8_t>(kRawByte);
            const bool kPrintable = (kByteValue >= 0x20U && kByteValue <= 0x7EU);
            resultText.append(kPrintable ? QChar(QLatin1Char(static_cast<char>(kByteValue)))
                                        : QChar(QLatin1Char('.')));
        }
        return resultText;
    }

    // driverMemoryTextViewLineWidth: Number of bytes rendered per line in the text view, consistent with the hex view.
    constexpr int kDriverMemoryTextViewLineWidth = 16;

    // driverMemoryMaxDisassemblyBytes: Maximum number of bytes consumed for a single disassembly operation.
    // Snapshots are capped at 1MB; full decoding would generate hundreds of thousands of lines and cripple the UI, so we truncate to 64KB here and note this in the interface.
    constexpr int kDriverMemoryMaxDisassemblyBytes = 64 * 1024;
}

ks::ui::DisassemblyArchitecture MemoryDock::currentDriverMemoryArchitecture() const
{
    // Kernel virtual addresses and physical memory snapshots are always decoded as x64: this project supports only 64-bit kernels.
    if (driverMemorySnapshotIsPhysical_
        || driverMemoryBaseAddress_ >= 0xFFFF000000000000ULL
        || driverMemorySnapshotPid_ == 0U)
    {
        return ks::ui::DisassemblyArchitecture::kX64;
    }

    // User-mode snapshot follows target process bitness: Code in WOW64 processes consists of 32-bit instructions.
    const HANDLE kProcessHandle = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        toDwordPid(driverMemorySnapshotPid_));
    if (kProcessHandle == nullptr)
    {
        // Conservatively assume x64 when the handle cannot be obtained, consistent with the default assumption of the read path on this page.
        return ks::ui::DisassemblyArchitecture::kX64;
    }

    BOOL isWow64Process = FALSE;
    const BOOL kQueryOk = ::IsWow64Process(kProcessHandle, &isWow64Process);
    ::CloseHandle(kProcessHandle);
    if (kQueryOk == FALSE)
    {
        return ks::ui::DisassemblyArchitecture::kX64;
    }
    return (isWow64Process != FALSE) ? ks::ui::DisassemblyArchitecture::kX86
                                     : ks::ui::DisassemblyArchitecture::kX64;
}

void MemoryDock::applyDriverMemoryViewMode(const DriverMemoryViewMode viewMode)
{
    // Log view switch: facilitates tracing which view the user was in when performing an operation.
    KLogEvent viewModeEvent;
    dbg << viewModeEvent
        << "[MemoryDock] applyDriverMemoryViewMode: 切换驱动内存读写页视图。"
        << eol;

    driverMemoryViewMode_ = viewMode;
    if (driverMemoryViewStack_ == nullptr)
    {
        return;
    }

    // Three views are pushed onto the stack in a fixed order; use the enum value to directly locate the page index.
    driverMemoryViewStack_->setCurrentIndex(static_cast<int>(viewMode));

    // Synchronize the segmented button's checked state to ensure it updates when switched via other entry points like the right-click menu.
    const auto kSyncToggle = [](QToolButton* button, const bool checked) {
        if (button == nullptr)
        {
            return;
        }
        const QSignalBlocker kBlocker(button);
        button->setChecked(checked);
    };
    kSyncToggle(driverMemoryHexViewButton_, viewMode == DriverMemoryViewMode::kHex);
    kSyncToggle(driverMemoryDisasmViewButton_, viewMode == DriverMemoryViewMode::kDisassembly);
    kSyncToggle(driverMemoryTextViewButton_, viewMode == DriverMemoryViewMode::kText);

    // Disassembly and text views use lazy rendering: decoding occurs only upon switching to avoid the full cost of decoding on every read.
    if (viewMode == DriverMemoryViewMode::kDisassembly)
    {
        rebuildDriverMemoryDisassemblyView();
    }
    else if (viewMode == DriverMemoryViewMode::kText)
    {
        rebuildDriverMemoryTextView();
    }
}

void MemoryDock::refreshDriverMemoryViewsFromSnapshot()
{
    // Unified entry point after snapshot changes: the hex view is managed by the caller; refresh the other two derived views here.
    if (driverMemoryViewMode_ == DriverMemoryViewMode::kDisassembly)
    {
        rebuildDriverMemoryDisassemblyView();
    }
    else if (driverMemoryViewMode_ == DriverMemoryViewMode::kText)
    {
        rebuildDriverMemoryTextView();
    }
    else
    {
        // When staying in the hex view, mark the other two views as pending reconstruction to avoid displaying stale content from the previous round.
        if (driverMemoryDisasmTable_ != nullptr)
        {
            driverMemoryDisasmTable_->setRowCount(0);
        }
        driverMemoryDisasmRows_.clear();
        if (driverMemoryTextView_ != nullptr)
        {
            driverMemoryTextView_->setRawText(QString());
        }
    }
}

void MemoryDock::rebuildDriverMemoryDisassemblyView()
{
    if (driverMemoryDisasmTable_ == nullptr)
    {
        return;
    }

    // Clear the table and display guidance text when no snapshot exists; perform no decoding.
    if (!driverMemoryHasSnapshot_ || driverMemoryEditedBytes_.isEmpty())
    {
        driverMemoryDisasmTable_->setRowCount(0);
        driverMemoryDisasmRows_.clear();
        if (driverMemoryDisasmBackendLabel_ != nullptr)
        {
            driverMemoryDisasmBackendLabel_->setText(
                QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
        }
        return;
    }

    // Disassembly always targets the 'current edit buffer' so instruction changes are visible immediately after modifying bytes.
    QByteArray decodeBytes = driverMemoryEditedBytes_;
    bool truncatedByBudget = false;
    if (decodeBytes.size() > kDriverMemoryMaxDisassemblyBytes)
    {
        decodeBytes = decodeBytes.left(kDriverMemoryMaxDisassemblyBytes);
        truncatedByBudget = true;
    }

    // Decoding is a pure function; it reads no memory and touches no UI, so it can run on the main thread with a 64KB budget.
    const ks::ui::DisassemblyArchitecture kArchitecture = currentDriverMemoryArchitecture();
    const ks::ui::DisassemblyResult kDecodeResult = ks::ui::InstructionDecoder::decode(
        decodeBytes,
        driverMemoryBaseAddress_,
        kArchitecture);
    driverMemoryDisasmRows_ = kDecodeResult.rows;

    // Merge the backend and truncation details into a single status line to avoid consuming additional UI height.
    if (driverMemoryDisasmBackendLabel_ != nullptr)
    {
        QString backendText = QStringLiteral("解码后端: %1 | 架构: %2 | 指令: %3 条")
            .arg(kDecodeResult.backendName)
            .arg(kArchitecture == ks::ui::DisassemblyArchitecture::kX64
                ? QStringLiteral("x64")
                : QStringLiteral("x86"))
            .arg(driverMemoryDisasmRows_.size());
        if (truncatedByBudget)
        {
            backendText += QStringLiteral(" | 已按 %1 KB 预算截断")
                .arg(kDriverMemoryMaxDisassemblyBytes / 1024);
        }
        if (!kDecodeResult.diagnosticText.isEmpty())
        {
            backendText += QStringLiteral(" | ") + kDecodeResult.diagnosticText;
        }
        driverMemoryDisasmBackendLabel_->setText(backendText);
    }

    // Disable sorting before and after bulk table population to avoid repeated re-sorting during row-by-row insertion.
    const bool kSortingWasEnabled = driverMemoryDisasmTable_->isSortingEnabled();
    driverMemoryDisasmTable_->setSortingEnabled(false);
    driverMemoryDisasmTable_->setRowCount(static_cast<int>(driverMemoryDisasmRows_.size()));

    // Bytes that failed to decode are highlighted with semantic colors to easily distinguish real instructions from db placeholders.
    const QColor kUndecodedColor = ksword_theme::textSecondaryColor();
    for (qsizetype rowIndex = 0; rowIndex < driverMemoryDisasmRows_.size(); ++rowIndex)
    {
        const ks::ui::DisassemblyRow& disasmRow = driverMemoryDisasmRows_.at(rowIndex);
        const int kTableRow = static_cast<int>(rowIndex);

        // Use numeric sort items for the address column to prevent degradation to string sorting when sorting by address.
        driverMemoryDisasmTable_->setItem(
            kTableRow,
            0,
            new ks::ui::NumericTableItem(
                driverMemoryHexAddressText(disasmRow.address),
                static_cast<qulonglong>(disasmRow.address)));
        driverMemoryDisasmTable_->setItem(
            kTableRow,
            1,
            new ks::ui::NumericTableItem(
                driverMemoryOffsetText(disasmRow.byteOffset),
                static_cast<qulonglong>(disasmRow.byteOffset)));
        driverMemoryDisasmTable_->setItem(
            kTableRow, 2, driverMemoryReadOnlyItem(driverMemoryBytesText(disasmRow.bytes)));
        driverMemoryDisasmTable_->setItem(
            kTableRow, 3, driverMemoryReadOnlyItem(disasmRow.mnemonic));
        driverMemoryDisasmTable_->setItem(
            kTableRow, 4, driverMemoryReadOnlyItem(disasmRow.operands));

        if (!disasmRow.decoded)
        {
            // db placeholder row: Dim the contrast of the entire row to indicate this is not a valid instruction.
            for (int columnIndex = 0; columnIndex < 5; ++columnIndex)
            {
                QTableWidgetItem* cellItem = driverMemoryDisasmTable_->item(kTableRow, columnIndex);
                if (cellItem != nullptr)
                {
                    cellItem->setForeground(kUndecodedColor);
                }
            }
        }
    }
    driverMemoryDisasmTable_->setSortingEnabled(kSortingWasEnabled);

    // Data batch changed; re-measure all column widths globally for auto-fit.
    ks::ui::requestTableColumnAutoFit(driverMemoryDisasmTable_);
}

void MemoryDock::rebuildDriverMemoryTextView()
{
    if (driverMemoryTextView_ == nullptr)
    {
        return;
    }

    // Provide a guide message consistent with the disassembly view when no snapshot exists.
    if (!driverMemoryHasSnapshot_ || driverMemoryEditedBytes_.isEmpty())
    {
        driverMemoryTextView_->setRawText(
            QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
        return;
    }

    // Text view renders line by line: left side shows the address, right side shows printable characters corresponding to the bytes on that line.
    const bool kUseUtf16 = (driverMemoryTextEncodingCombo_ != nullptr)
        && (driverMemoryTextEncodingCombo_->currentIndex() == 1);
    QString renderedText;
    renderedText.reserve(static_cast<int>(driverMemoryEditedBytes_.size() * 2));

    const qsizetype kTotalBytes = driverMemoryEditedBytes_.size();
    for (qsizetype lineStart = 0; lineStart < kTotalBytes; lineStart += kDriverMemoryTextViewLineWidth)
    {
        const qsizetype kLineBytes =
            std::min<qsizetype>(kDriverMemoryTextViewLineWidth, kTotalBytes - lineStart);
        const QByteArray kLineSlice = driverMemoryEditedBytes_.mid(lineStart, kLineBytes);
        const std::uint64_t kLineAddress =
            driverMemoryBaseAddress_ + static_cast<std::uint64_t>(lineStart);
        renderedText += QStringLiteral("%1  %2\n")
            .arg(driverMemoryHexAddressText(kLineAddress))
            .arg(driverMemoryPrintableText(kLineSlice, kUseUtf16));
    }

    // Must use setRawText: this is the raw content of the target memory and must never be translated line-by-line by language packs.
    driverMemoryTextView_->setRawText(renderedText);
}

void MemoryDock::dumpDriverMemorySnapshotToFile()
{
    // Log record for dump: This entry records the path where the target memory content is written to disk and must be traceable.
    KLogEvent dumpEvent;
    info << dumpEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 请求把当前快照写入文件。"
        << eol;

    if (!driverMemoryHasSnapshot_ || driverMemoryEditedBytes_.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // Default filename includes address and length to distinguish multiple dumps.
    const QString kDefaultName = QStringLiteral("memory_%1_%2bytes.bin")
        .arg(formatAddress(driverMemoryBaseAddress_))
        .arg(driverMemoryEditedBytes_.size());
    const QString kSelectedPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("把当前内存快照转存到文件"),
        kDefaultName,
        QStringLiteral("二进制文件 (*.bin);;十六进制文本 (*.txt);;所有文件 (*.*)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(kSelectedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("无法写入文件: %1").arg(outputFile.errorString()));
        return;
    }

    // Determine on-disk format based on extension: .txt uses human-readable hex dump; all others use raw bytes.
    const bool kAsHexText = kSelectedPath.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive);
    qint64 writtenBytes = 0;
    if (kAsHexText)
    {
        // Hexadecimal text format must match the hexadecimal view: address + 16 bytes + ASCII.
        QString dumpText;
        const qsizetype kTotalBytes = driverMemoryEditedBytes_.size();
        for (qsizetype lineStart = 0; lineStart < kTotalBytes; lineStart += kDriverMemoryTextViewLineWidth)
        {
            const qsizetype kLineBytes =
                std::min<qsizetype>(kDriverMemoryTextViewLineWidth, kTotalBytes - lineStart);
            const QByteArray kLineSlice = driverMemoryEditedBytes_.mid(lineStart, kLineBytes);
            dumpText += QStringLiteral("%1  %2  %3\n")
                .arg(driverMemoryHexAddressText(
                    driverMemoryBaseAddress_ + static_cast<std::uint64_t>(lineStart)))
                .arg(driverMemoryBytesText(kLineSlice), -47)
                .arg(driverMemoryPrintableText(kLineSlice, false));
        }
        const QByteArray kEncodedText = dumpText.toUtf8();
        writtenBytes = outputFile.write(kEncodedText);
    }
    else
    {
        writtenBytes = outputFile.write(driverMemoryEditedBytes_);
    }
    outputFile.close();

    if (writtenBytes < 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("写入过程中失败: %1").arg(outputFile.errorString()));
        return;
    }

    // Write the result to the status label on success to avoid interrupting the operation with a modal dialog.
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(
            QStringLiteral("已转存 %1 字节到 %2").arg(writtenBytes).arg(kSelectedPath));
    }

    KLogEvent dumpDoneEvent;
    info << dumpDoneEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 转存完成。"
        << eol;
}

void MemoryDock::writeStringIntoDriverMemoryBuffer()
{
    // Log string write: modifies the edit cache, affecting subsequent write-back operations.
    KLogEvent writeStringEvent;
    info << writeStringEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 打开字符串写入对话框。"
        << eol;

    if (!driverMemoryHasSnapshot_ || driverMemoryEditedBytes_.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // Dialog layout: target address, encoding, whether to append a terminating 0, and string content.
    QDialog stringDialog(this);
    stringDialog.setWindowTitle(QStringLiteral("字符串写入"));
    stringDialog.setModal(true);
    QVBoxLayout* dialogLayout = new QVBoxLayout(&stringDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);

    // The default address is taken from the current cursor position in the hex editor, aligning with the intuitive 'write where selected' behavior.
    const std::uint64_t kDefaultAddress = (driverMemoryHexEditor_ != nullptr)
        ? driverMemoryHexEditor_->selectedAbsoluteAddress()
        : driverMemoryBaseAddress_;
    QLineEdit* addressEdit = new QLineEdit(&stringDialog);
    addressEdit->setText(QStringLiteral("0x%1").arg(formatAddress(kDefaultAddress)));
    addressEdit->setToolTip(QStringLiteral("字符串写入的起始地址，必须落在当前快照范围内。"));

    QComboBox* encodingCombo = new QComboBox(&stringDialog);
    encodingCombo->addItem(QStringLiteral("ANSI / UTF-8 单字节"));
    encodingCombo->addItem(QStringLiteral("UTF-16LE 宽字符"));
    encodingCombo->setToolTip(QStringLiteral("选择字符串在目标内存里的编码方式。"));

    QCheckBox* nullTerminatedCheck = new QCheckBox(
        QStringLiteral("末尾补写结尾 0"), &stringDialog);
    nullTerminatedCheck->setChecked(true);
    nullTerminatedCheck->setToolTip(
        QStringLiteral("勾选后在字符串末尾补一个结尾 0，符合 C 字符串约定。"));

    QLineEdit* contentEdit = new QLineEdit(&stringDialog);
    contentEdit->setPlaceholderText(QStringLiteral("要写入的字符串内容"));
    contentEdit->setToolTip(QStringLiteral("按上面选定的编码转成字节后填入编辑缓存。"));

    formLayout->addWidget(new QLabel(QStringLiteral("起始地址"), &stringDialog), 0, 0);
    formLayout->addWidget(addressEdit, 0, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("编码"), &stringDialog), 1, 0);
    formLayout->addWidget(encodingCombo, 1, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("内容"), &stringDialog), 2, 0);
    formLayout->addWidget(contentEdit, 2, 1);
    formLayout->addWidget(nullTerminatedCheck, 3, 1);
    dialogLayout->addLayout(formLayout);

    // Explicit notification: this step modifies only the edit cache; actual memory writeback still requires clicking 'Apply Differences'.
    QLabel* hintLabel = new QLabel(
        QStringLiteral("字符串只填入本地编辑缓存，确认无误后再点“应用差异到真实内存”。"),
        &stringDialog);
    hintLabel->setWordWrap(true);
    dialogLayout->addWidget(hintLabel);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &stringDialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("填入缓存"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    dialogLayout->addWidget(buttonBox);
    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &stringDialog, &QDialog::accept);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &stringDialog, &QDialog::reject);

    if (stringDialog.exec() != QDialog::Accepted)
    {
        return;
    }

    // Parse the starting address; reject out-of-bounds values and never silently truncate.
    std::uint64_t targetAddress = 0ULL;
    if (!parseAddressText(addressEdit->text(), targetAddress))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址解析失败，请填写十六进制地址。"));
        return;
    }
    if (targetAddress < driverMemoryBaseAddress_)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址在当前快照范围之前，请重新填写。"));
        return;
    }

    // Convert the string to a byte sequence using the selected encoding.
    const QString kContentText = contentEdit->text();
    QByteArray payloadBytes;
    if (encodingCombo->currentIndex() == 1)
    {
        // UTF-16LE: Expand code units one by one in little-endian order to match the target memory layout.
        for (const QChar kContentChar : kContentText)
        {
            const std::uint16_t kCodeUnit = kContentChar.unicode();
            payloadBytes.append(static_cast<char>(kCodeUnit & 0xFFU));
            payloadBytes.append(static_cast<char>((kCodeUnit >> 8) & 0xFFU));
        }
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
            payloadBytes.append('\0');
        }
    }
    else
    {
        payloadBytes = kContentText.toUtf8();
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
        }
    }

    if (payloadBytes.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("内容为空，没有可写入的字节。"));
        return;
    }

    // Verify the entire byte range falls within the snapshot; reject immediately on out-of-bounds access to prevent partial writes that result in truncated strings.
    const std::uint64_t kWriteOffset = targetAddress - driverMemoryBaseAddress_;
    const std::uint64_t kSnapshotSize = static_cast<std::uint64_t>(driverMemoryEditedBytes_.size());
    if (kWriteOffset >= kSnapshotSize
        || (kSnapshotSize - kWriteOffset) < static_cast<std::uint64_t>(payloadBytes.size()))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("字符串长度超出当前快照范围，请扩大读取范围或换一个起始地址。"));
        return;
    }

    // Write to the edit cache and synchronously refresh the hex view to make changes immediately visible.
    for (qsizetype byteIndex = 0; byteIndex < payloadBytes.size(); ++byteIndex)
    {
        driverMemoryEditedBytes_[static_cast<qsizetype>(kWriteOffset) + byteIndex] =
            payloadBytes.at(byteIndex);
    }
    if (driverMemoryHexEditor_ != nullptr)
    {
        driverMemoryHexEditor_->setByteArray(driverMemoryEditedBytes_, driverMemoryBaseAddress_);
        driverMemoryHexEditor_->jumpToAbsoluteAddress(targetAddress);
    }
    refreshDriverMemoryViewsFromSnapshot();

    // Recalculate the difference blocks and determine whether the 'Apply Differences' button is enabled based on them.
    std::vector<DriverDiffBlock> diffBlocks;
    collectDriverMemoryDiffBlocks(diffBlocks);
    if (driverMemoryApplyButton_ != nullptr)
    {
        driverMemoryApplyButton_->setEnabled(!diffBlocks.empty());
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(
            QStringLiteral("已在 0x%1 填入 %2 字节字符串，当前共 %3 处差异待应用。")
                .arg(formatAddress(targetAddress))
                .arg(payloadBytes.size())
                .arg(diffBlocks.size()));
    }

    KLogEvent writeStringDoneEvent;
    info << writeStringDoneEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 字符串已填入编辑缓存。"
        << eol;
}

void MemoryDock::showDriverMemoryDisassemblyContextMenu(const QPoint& localPosition)
{
    if (driverMemoryDisasmTable_ == nullptr)
    {
        return;
    }

    // On right-click, set the clicked row as the current row first to ensure the copy action strictly targets the row the user sees.
    const QModelIndex kClickedIndex = driverMemoryDisasmTable_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        driverMemoryDisasmTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
    }

    const int kCurrentRow = driverMemoryDisasmTable_->currentRow();
    const bool kHasRow = (kCurrentRow >= 0 && kCurrentRow < driverMemoryDisasmRows_.size());

    QMenu menu(driverMemoryDisasmTable_);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyAddressAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")), QStringLiteral("复制地址"));
    QAction* copyBytesAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")), QStringLiteral("复制原始字节"));
    QAction* copyLineAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制整条指令"));
    menu.addSeparator();
    QAction* jumpHexAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), QStringLiteral("在十六进制视图中定位"));
    copyAddressAction->setEnabled(kHasRow);
    copyBytesAction->setEnabled(kHasRow);
    copyLineAction->setEnabled(kHasRow);
    jumpHexAction->setEnabled(kHasRow);

    QAction* selectedAction = menu.exec(
        driverMemoryDisasmTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr || !kHasRow)
    {
        return;
    }

    const ks::ui::DisassemblyRow& disasmRow = driverMemoryDisasmRows_.at(kCurrentRow);
    QClipboard* clipboard = QApplication::clipboard();
    if (selectedAction == copyAddressAction && clipboard != nullptr)
    {
        clipboard->setText(driverMemoryHexAddressText(disasmRow.address));
    }
    else if (selectedAction == copyBytesAction && clipboard != nullptr)
    {
        clipboard->setText(driverMemoryBytesText(disasmRow.bytes));
    }
    else if (selectedAction == copyLineAction && clipboard != nullptr)
    {
        // Concatenate the entire instruction into a single line as 'Address Bytes Mnemonic Operands' for easy pasting into notes.
        clipboard->setText(QStringLiteral("%1  %2  %3 %4")
            .arg(driverMemoryHexAddressText(disasmRow.address))
            .arg(driverMemoryBytesText(disasmRow.bytes))
            .arg(disasmRow.mnemonic)
            .arg(disasmRow.operands));
    }
    else if (selectedAction == jumpHexAction)
    {
        // Switch back to hex view and position the cursor at the first byte of the instruction.
        applyDriverMemoryViewMode(DriverMemoryViewMode::kHex);
        if (driverMemoryHexEditor_ != nullptr)
        {
            driverMemoryHexEditor_->jumpToAbsoluteAddress(disasmRow.address);
        }
    }
}
