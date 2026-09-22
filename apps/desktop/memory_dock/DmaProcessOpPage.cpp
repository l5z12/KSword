#include "DmaProcessOpPage.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"
#include "../../../shared/evidence/NumericTextParse.h"

#include <QCheckBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <algorithm>

using namespace ksword::evidence;

namespace ksword::memory_dock
{
    namespace
    {
        constexpr std::uint64_t kPageBytes = kDmaOpPageBytes;

        QString hex64(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0'))
                .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"));
        }

        QString hexDump(const std::vector<std::uint8_t>& bytes, const std::size_t limit)
        {
            QStringList parts;
            const std::size_t kShown = (std::min)(bytes.size(), limit);
            for (std::size_t i = 0U; i < kShown; ++i)
            {
                parts << QStringLiteral("%1").arg(bytes[i], 2, 16, QChar('0')).toUpper();
            }
            QString text = parts.join(QLatin1Char(' '));
            if (bytes.size() > kShown)
            {
                text += QStringLiteral(" …（共 %1 字节）").arg(bytes.size());
            }
            return text;
        }

        // parseHexPayload: Parses text like "90 48 31 C0" into bytes.
        //
        // Accept only pairs of hexadecimal digits; separators are flexible. Deliberately reject mixed "0x" prefixes or decimal digits.
        // The payload is machine code; a single byte misinterpreted as a different value becomes
        // a different instruction, and the error location is indistinguishable from the result.
        bool parseHexPayload(const QString& text, std::vector<std::uint8_t>& out, QString& errorOut)
        {
            out.clear();
            QString compact;
            for (const QChar kCh : text)
            {
                if (kCh.isSpace() || kCh == QLatin1Char(',') || kCh == QLatin1Char('-'))
                {
                    continue;
                }
                if (!isxdigit(static_cast<unsigned char>(kCh.toLatin1())))
                {
                    errorOut = QStringLiteral("载荷里出现了非十六进制字符：%1").arg(kCh);
                    return false;
                }
                compact.append(kCh);
            }
            if (compact.isEmpty())
            {
                errorOut = QStringLiteral("载荷为空。");
                return false;
            }
            if ((compact.size() % 2) != 0)
            {
                // An odd number of hex digits implies a missing digit. Padding with zero would silently alter the value of the last byte.
                errorOut = QStringLiteral("载荷的十六进制位数是奇数，缺了一位。");
                return false;
            }
            out.reserve(static_cast<std::size_t>(compact.size() / 2));
            for (int i = 0; i < compact.size(); i += 2)
            {
                bool ok = false;
                out.push_back(static_cast<std::uint8_t>(compact.mid(i, 2).toUInt(&ok, 16)));
                if (!ok)
                {
                    errorOut = QStringLiteral("载荷解析失败。");
                    return false;
                }
            }
            return true;
        }
    }

    DmaProcessOpPage::DmaProcessOpPage(QWidget* const parent)
        : QWidget(parent)
    {
        buildUi();
        wireSignals();
        refreshChannelAvailability();
        updateActionState();
    }

    DmaProcessOpPage::~DmaProcessOpPage() = default;

    void DmaProcessOpPage::buildUi()
    {
        QVBoxLayout* root = new QVBoxLayout(this);
        root->setContentsMargins(8, 8, 8, 8);
        root->setSpacing(8);

        QLabel* intro = new QLabel(this);
        intro->setWordWrap(true);
        intro->setTextInteractionFlags(Qt::TextSelectableByMouse);
        intro->setText(QStringLiteral("通过 DDMA 直接往目标进程的物理页里写字节。与“R-1 注入”不是同一件事：R-1 把载荷放在影子页里、真页从头到尾没被改过，还有一个武装好的触发点；DMA 一样都没有。这里改的是**真页**，任何读取路径都看得见（包括本工具自己的 R3/R0/HVM）；而且**没有触发**，载荷写完就躺在那里等目标自己执行到，写进一个永远不会被执行的位置等于什么都没做。每一次写入都强制先备份、写完立刻读回校验——DDMA 写入没有任何自证，驱动报成功只说明命令被接受，不说明物理页真的变了。"));
        root->addWidget(intro);

        targetLabel_ = new QLabel(QStringLiteral("未附加进程。"), this);
        targetLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        root->addWidget(targetLabel_);

        QGridLayout* form = new QGridLayout();
        form->setHorizontalSpacing(8);
        form->setVerticalSpacing(6);

        form->addWidget(new QLabel(QStringLiteral("目标虚拟地址"), this), 0, 0);
        addressEdit_ = new QLineEdit(this);
        addressEdit_->setPlaceholderText(QStringLiteral("目标进程里的地址，默认十六进制"));
        addressEdit_->setClearButtonEnabled(true);
        addressEdit_->setToolTip(QStringLiteral("注入时这个地址只用来定位所在的页，载荷会被排进页内的空隙里；写 UD2 时写的就是这个地址本身。"));
        form->addWidget(addressEdit_, 0, 1, 1, 3);

        form->addWidget(new QLabel(QStringLiteral("载荷（十六进制）"), this), 1, 0);
        payloadEdit_ = new QLineEdit(this);
        payloadEdit_->setPlaceholderText(QStringLiteral("例如 90 48 31 C0 C3"));
        payloadEdit_->setClearButtonEnabled(true);
        payloadEdit_->setToolTip(QStringLiteral("位置无关的机器码。只接受成对的十六进制数位，分隔符随意；位数为奇数会被拒绝而不是补零——补零会静默改变最后一个字节，也就是改变最后一条指令。"));
        form->addWidget(payloadEdit_, 1, 1, 1, 3);

        root->addLayout(form);

        forceCheck_ = new QCheckBox(QStringLiteral("附加 FORCE 标志（DDMA 写入要求）"), this);
        forceCheck_->setToolTip(QStringLiteral("驱动对 DDMA 写入要求显式的强制标志，缺了会被拒绝。"));
        acknowledgeCheck_ = new QCheckBox(
            QStringLiteral("我确认这会修改目标进程的真实内存页，并且由我负责还原"), this);
        root->addWidget(forceCheck_);
        unknownSharingCheck_ = new QCheckBox(
            QStringLiteral("目标页的共享性无法确认时仍然写入（后果可能波及其它进程）"), this);
        unknownSharingCheck_->setToolTip(QStringLiteral("只在“无法确认”时起作用。已经确认被其它进程共享的页没有任何开关能解锁——往一张共享的映像页写字节会打到每一个映射它的进程。"));
        root->addWidget(acknowledgeCheck_);
        root->addWidget(unknownSharingCheck_);

        QHBoxLayout* actions = new QHBoxLayout();
        actions->setContentsMargins(0, 0, 0, 0);
        actions->setSpacing(8);
        injectButton_ = new QPushButton(QStringLiteral("注入载荷到页内空隙"), this);
        injectButton_->setToolTip(QStringLiteral("在目标地址所在页里找一段至少 64 字节的填充（只认 0x00 与 0xCC），把载荷排进去。找不到足够长的空隙会拒绝，而不是凑合写在一段短的上——那与直接覆盖真代码没有区别。"));
        ud2Button_ = new QPushButton(QStringLiteral("写 UD2（让目标崩掉）"), this);
        ud2Button_->setToolTip(QStringLiteral("往目标地址写两字节 0F 0B。它不是一个可靠的结束：目标可能带异常处理器把 #UD 吞掉，生效与否还取决于那段代码会不会被执行到，而且会留下崩溃转储。"));
        restoreButton_ = new QPushButton(QStringLiteral("还原上一次写入"), this);
        actions->addWidget(injectButton_);
        actions->addWidget(ud2Button_);
        actions->addWidget(restoreButton_);
        actions->addStretch(1);
        root->addLayout(actions);

        channelHintLabel_ = new QLabel(this);
        channelHintLabel_->setWordWrap(true);
        root->addWidget(channelHintLabel_);

        statusLabel_ = new QLabel(QStringLiteral("尚未执行。"), this);
        statusLabel_->setWordWrap(true);
        statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        root->addWidget(statusLabel_);

        logText_ = new QPlainTextEdit(this);
        logText_->setReadOnly(true);
        logText_->setPlaceholderText(QStringLiteral("每一次写入的计划、备份与读回校验结果都会记在这里。备份是还原的唯一依据，别清空它。"));
        root->addWidget(logText_, 1);
    }

    void DmaProcessOpPage::wireSignals()
    {
        connect(injectButton_, &QPushButton::clicked, this, [this]() { performWrite(true); });
        connect(ud2Button_, &QPushButton::clicked, this, [this]() { performWrite(false); });
        connect(restoreButton_, &QPushButton::clicked, this, [this]() { restoreLastWrite(); });
        const auto kGate = [this](bool) { updateActionState(); };
        connect(forceCheck_, &QCheckBox::toggled, this, kGate);
        connect(acknowledgeCheck_, &QCheckBox::toggled, this, kGate);
        connect(unknownSharingCheck_, &QCheckBox::toggled, this, kGate);
        connect(addressEdit_, &QLineEdit::textChanged, this,
            [this](const QString&) { updateActionState(); });
    }

    void DmaProcessOpPage::setAttachedProcess(
        const std::uint32_t processId, const QString& processName)
    {
        attachedPid_ = processId;
        attachedProcessName_ = processName;
        targetLabel_->setText(processId == 0U
            ? QStringLiteral("未附加进程。")
            : QStringLiteral("目标：%1 [PID:%2]").arg(processName).arg(processId));
        updateActionState();
    }

    void DmaProcessOpPage::refreshChannelAvailability()
    {
        QString reason;
        const bool kUsable = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        if (kUsable)
        {
            channelHintLabel_->setText(QStringLiteral("DDMA 通道就绪。"));
            channelHintLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        else
        {
            channelHintLabel_->setText(
                QStringLiteral("DDMA 暂不可用：%1。本页的每一步都要经这条通道。").arg(reason));
            channelHintLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        updateActionState();
    }

    void DmaProcessOpPage::updateActionState()
    {
        QString reason;
        const bool kChannelReady = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        const bool kReady = kChannelReady
            && attachedPid_ != 0U
            && !addressEdit_->text().trimmed().isEmpty()
            && forceCheck_->isChecked()
            && acknowledgeCheck_->isChecked();
        injectButton_->setEnabled(kReady);
        ud2Button_->setEnabled(kReady);
        restoreButton_->setEnabled(kChannelReady && !records_.empty());
    }

    void DmaProcessOpPage::appendLog(const QString& line)
    {
        logText_->appendPlainText(line);
    }

    bool DmaProcessOpPage::resolveTargetPage(
        std::uint64_t& virtualAddressOut,
        std::uint64_t& pagePhysicalOut,
        std::vector<std::uint8_t>& pageBytesOut,
        QString& errorOut)
    {
        const auto kParsed = ksword::evidence::parseNumericText(
            addressEdit_->text().trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::kHexadecimal);
        if (!kParsed.ok)
        {
            errorOut = QStringLiteral("目标地址解析失败。无前缀按十六进制解释。");
            return false;
        }
        virtualAddressOut = kParsed.value;

        // Translate and read the entire page based on the page base address: The planning layer requires full page content to find gaps and backups, and
        // translation can only be performed page-by-page. Using the page base address here instead of the original address avoids translating the same page twice.
        const std::uint64_t kPageBase = virtualAddressOut & ~(kPageBytes - 1ULL);
        const ksword::ark::DriverClient kClient;
        const ksword::ark::VirtualAddressTranslateResult kTranslation =
            kClient.translateVirtualAddress(attachedPid_, kPageBase, 0UL);
        if (!kTranslation.io.ok || !kTranslation.resolved)
        {
            errorOut = kTranslation.io.ok
                ? QStringLiteral("该页翻译不出物理地址，可能未驻留。")
                : QStringLiteral("地址翻译失败：%1")
                      .arg(QString::fromStdString(kTranslation.io.message));
            return false;
        }
        pagePhysicalOut = kTranslation.physicalAddress;

        const ksword::memory_backend::AccessOutcome kReadOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                ksword::memory_backend::currentDdmaSession(),
                pagePhysicalOut,
                kPageBytes);
        if (!kReadOutcome.ok)
        {
            errorOut = QStringLiteral("读取目标页失败：%1").arg(kReadOutcome.failureText);
            return false;
        }
        if (static_cast<std::uint64_t>(kReadOutcome.data.size()) != kPageBytes)
        {
            // Reading fewer bytes prevents backing up a complete page, and the planning layer requires full pages. Reject here
            // rather than using the partial data, as calculating offsets from partial data would point to incorrect locations.
            errorOut = QStringLiteral("只读到 %1 / %2 字节，无法据此计划写入。")
                .arg(kReadOutcome.data.size()).arg(kPageBytes);
            return false;
        }
        pageBytesOut.assign(
            reinterpret_cast<const std::uint8_t*>(kReadOutcome.data.constData()),
            reinterpret_cast<const std::uint8_t*>(kReadOutcome.data.constData())
                + kReadOutcome.data.size());
        return true;
    }

    ksword::evidence::DmaTargetSharing DmaProcessOpPage::evaluateSharing(
        const std::uint64_t pageVirtualAddress,
        const std::uint64_t pagePhysical,
        QString& evidenceOut)
    {
        const ksword::ark::DriverClient kClient;
        const ksword::ark::VirtualMemoryQueryResult kSelf =
            kClient.queryVirtualMemory(attachedPid_, pageVirtualAddress,
                KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME);
        if (!kSelf.io.ok)
        {
            // When the region type cannot be determined, it cannot default to private. A query failure is distinct from 'confirming private'.
            evidenceOut = QStringLiteral("查询目标区域失败：%1")
                .arg(QString::fromStdString(kSelf.io.message));
            return ksword::evidence::evaluateTargetSharing(false, false, false);
        }

        const bool kIsPrivate = (kSelf.type == MEM_PRIVATE);
        if (kIsPrivate)
        {
            evidenceOut = QStringLiteral("区域类型 MEM_PRIVATE，不由节对象支撑。");
            return ksword::evidence::evaluateTargetSharing(true, false, false);
        }

        const QString kBackingFile = QString::fromStdWString(kSelf.mappedFileName);
        // Cross-process physical address mapping: Translating the same virtual address in another process mapping the same
        // file yields the same physical address only if they share the same page. This is the only true measurement; region
        // types are merely speculative, as a MEM_IMAGE page may have already become a private copy due to copy-on-write.
        const ksword::ark::ProcessEnumResult kProcesses = kClient.enumerateProcesses(0UL);
        int examined = 0;
        if (kProcesses.io.ok)
        {
            for (const auto& entry : kProcesses.entries)
            {
                const std::uint32_t kOtherPid = static_cast<std::uint32_t>(entry.processId);
                if (kOtherPid == attachedPid_ || kOtherPid == 0U || kOtherPid == 4U)
                {
                    continue;
                }
                if (examined >= 64)
                {
                    break;
                }
                const ksword::ark::VirtualMemoryQueryResult kOther =
                    kClient.queryVirtualMemory(kOtherPid, pageVirtualAddress,
                        KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME);
                if (!kOther.io.ok || kOther.state != MEM_COMMIT)
                {
                    continue;
                }
                if (QString::fromStdWString(kOther.mappedFileName) != kBackingFile)
                {
                    continue;
                }
                ++examined;
                const ksword::ark::VirtualAddressTranslateResult kOtherPa =
                    kClient.translateVirtualAddress(kOtherPid, pageVirtualAddress, 0UL);
                if (!kOtherPa.io.ok || !kOtherPa.resolved)
                {
                    continue;
                }
                if (kOtherPa.physicalAddress == pagePhysical)
                {
                    evidenceOut = QStringLiteral(
                        "PID %1 的同一虚拟地址落在同一张物理页 %2 上，支撑文件 %3。")
                        .arg(kOtherPid).arg(hex64(pagePhysical)).arg(kBackingFile);
                    return ksword::evidence::evaluateTargetSharing(false, true, true);
                }
                // Different physical addresses indicate copy-on-write has occurred; this process holds its own copy.
                evidenceOut = QStringLiteral(
                    "PID %1 映射同一文件但物理页不同（%2 vs %3），写时复制已经发生。")
                    .arg(kOtherPid).arg(hex64(kOtherPa.physicalAddress)).arg(hex64(pagePhysical));
                return ksword::evidence::evaluateTargetSharing(false, true, false);
            }
        }

        evidenceOut = QStringLiteral(
            "区域类型不是 MEM_PRIVATE（支撑文件 %1），但在检查过的进程里没找到第二个映射它的，无法比对物理页。")
            .arg(kBackingFile.isEmpty() ? QStringLiteral("未知") : kBackingFile);
        return ksword::evidence::evaluateTargetSharing(false, false, false);
    }

    void DmaProcessOpPage::performWrite(const bool injectPayload)
    {
        std::uint64_t virtualAddress = 0ULL;
        std::uint64_t pagePhysical = 0ULL;
        std::vector<std::uint8_t> pageBytes;
        QString error;
        if (!resolveTargetPage(virtualAddress, pagePhysical, pageBytes, error))
        {
            statusLabel_->setText(error);
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
            return;
        }

        // Sharing checks precede scheduling: even a perfectly calculated schedule on a shared page must not be executed.
        QString sharingEvidence;
        const DmaTargetSharing kSharing = evaluateSharing(
            virtualAddress & ~(kPageBytes - 1ULL), pagePhysical, sharingEvidence);
        appendLog(QStringLiteral("── 共享性检查：%1")
            .arg(QString::fromUtf8(dmaTargetSharingName(kSharing))));
        appendLog(QStringLiteral("   依据：%1").arg(sharingEvidence));

        if (kSharing == DmaTargetSharing::kSharedConfirmed)
        {
            // **No switch can unlock this.** DMA writes to physical pages, while Copy-On-Write relies on page-fault exceptions;
            // DMA does not trigger page faults. Writing bytes to a confirmed shared image page affects every process mapping
            // that page. Writing a UD2 instruction to an ntdll code page would cause all processes on the machine to crash when
            // they reach that address. This is not a consequence a user should be able to trigger with a single click.
            statusLabel_->setText(QStringLiteral(
                "已拒绝：目标页确认被其它进程共享。%1 DMA 不触发写时复制，写入会波及每一个映射这张页的进程。请改用 R-1 注入（它把载荷放在影子页里，作用域限定在单个进程），或选一张进程私有的页。")
                .arg(sharingEvidence));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::errorHex()));
            return;
        }
        if (kSharing == DmaTargetSharing::kSharingUnknown
            && !unknownSharingCheck_->isChecked())
        {
            statusLabel_->setText(QStringLiteral(
                "已拒绝：无法确认目标页是否被其它进程共享。%1 没找到第二个映射它的进程不等于没有。要继续，请勾选下面那一项并自行承担波及其它进程的可能。")
                .arg(sharingEvidence));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::warningHex()));
            return;
        }

        DmaWritePlan plan;
        QString description;
        if (injectPayload)
        {
            std::vector<std::uint8_t> payload;
            QString payloadError;
            if (!parseHexPayload(payloadEdit_->text(), payload, payloadError))
            {
                statusLabel_->setText(payloadError);
                statusLabel_->setStyleSheet(
                    QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
                return;
            }
            plan = planPayloadIntoCave(pageBytes, payload, kDmaOpMinCaveBytes);
            description = QStringLiteral("注入载荷 %1 字节").arg(payload.size());
        }
        else
        {
            const std::size_t kOffsetInPage =
                static_cast<std::size_t>(virtualAddress & (kPageBytes - 1ULL));
            plan = planBytesAtOffset(pageBytes, kOffsetInPage, undefinedInstructionBytes());
            description = QStringLiteral("写 UD2");
        }

        if (plan.status != DmaOpPlanStatus::kOk)
        {
            statusLabel_->setText(QStringLiteral("计划被拒绝：%1")
                .arg(QString::fromUtf8(dmaOpPlanStatusName(plan.status))));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
            return;
        }

        const std::uint64_t kWritePhysicalAddress =
            pagePhysical + static_cast<std::uint64_t>(plan.offsetInPage);
        appendLog(QStringLiteral("── %1").arg(description));
        appendLog(QStringLiteral("   目标 VA %1，页物理 %2，页内偏移 0x%3")
            .arg(hex64(virtualAddress)).arg(hex64(pagePhysical))
            .arg(QString::number(plan.offsetInPage, 16).toUpper()));
        appendLog(QStringLiteral("   备份（原始字节）：%1").arg(hexDump(plan.originalBytes, 32U)));
        appendLog(QStringLiteral("   将写入：%1").arg(hexDump(plan.bytesToWrite, 32U)));

        const QByteArray kPayloadBytes(
            reinterpret_cast<const char*>(plan.bytesToWrite.data()),
            static_cast<qsizetype>(plan.bytesToWrite.size()));
        const ksword::memory_backend::AccessOutcome kWriteOutcome =
            ksword::memory_backend::writePhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                ksword::memory_backend::currentDdmaSession(),
                kWritePhysicalAddress,
                kPayloadBytes,
                forceCheck_->isChecked());
        if (!kWriteOutcome.ok)
        {
            appendLog(QStringLiteral("   写入失败：%1").arg(kWriteOutcome.failureText));
            statusLabel_->setText(QStringLiteral("写入失败：%1").arg(kWriteOutcome.failureText));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::errorHex()));
            return;
        }
        if (kWriteOutcome.scratchDirty)
        {
            appendLog(QStringLiteral(
                "   严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。"));
        }

        // Read-back verification. This step is not an optional diagnostic: DDMA writes provide no
        // self-verification; a silent write failure and a successful write appear identical on the interface.
        const ksword::memory_backend::AccessOutcome kVerifyOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                ksword::memory_backend::currentDdmaSession(),
                kWritePhysicalAddress,
                static_cast<std::uint64_t>(plan.bytesToWrite.size()));
        std::vector<std::uint8_t> readback;
        if (kVerifyOutcome.ok)
        {
            readback.assign(
                reinterpret_cast<const std::uint8_t*>(kVerifyOutcome.data.constData()),
                reinterpret_cast<const std::uint8_t*>(kVerifyOutcome.data.constData())
                    + kVerifyOutcome.data.size());
        }
        const DmaWriteVerification kVerification =
            verifyWriteReadback(plan.bytesToWrite, readback);

        DmaOpRecord record;
        record.virtualAddress = virtualAddress;
        record.physicalAddress = kWritePhysicalAddress;
        record.offsetInPage = plan.offsetInPage;
        record.writtenBytes = plan.bytesToWrite;
        record.originalBytes = plan.originalBytes;
        record.description = description;
        record.verified = kVerification.matched;
        records_.push_back(record);

        if (kVerification.matched)
        {
            appendLog(QStringLiteral("   读回校验通过（%1 字节一致）。")
                .arg(kVerification.comparedBytes));
            statusLabel_->setText(QStringLiteral(
                "%1 完成并通过读回校验。注意：DMA 没有触发点，载荷要等目标自己执行到；真页已被修改，记得用“还原上一次写入”。")
                .arg(description));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        else
        {
            const QString kDetail = kVerification.readbackTooShort
                ? QStringLiteral("读回只有 %1 字节").arg(kVerification.comparedBytes)
                : QStringLiteral("第 %1 字节期望 %2、实际 %3")
                      .arg(kVerification.firstMismatchOffset)
                      .arg(QStringLiteral("%1").arg(kVerification.expectedByte, 2, 16, QChar('0')).toUpper())
                      .arg(QStringLiteral("%1").arg(kVerification.actualByte, 2, 16, QChar('0')).toUpper());
            appendLog(QStringLiteral("   读回校验失败：%1").arg(kDetail));
            // On verification failure, **do not** report "Write Success". The driver accepted the command, but the current state
            // of the physical page is uncertain—it may not have landed or may have landed partially. The backup remains intact.
            statusLabel_->setText(QStringLiteral(
                "%1 的写入命令被接受，但读回校验失败（%2）。目标页当前状态不确定，备份已记录，建议立刻还原。")
                .arg(description).arg(kDetail));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::errorHex()));
        }
        updateActionState();
    }

    void DmaProcessOpPage::restoreLastWrite()
    {
        if (records_.empty())
        {
            return;
        }
        const DmaOpRecord kRecord = records_.back();
        const QByteArray kOriginal(
            reinterpret_cast<const char*>(kRecord.originalBytes.data()),
            static_cast<qsizetype>(kRecord.originalBytes.size()));

        appendLog(QStringLiteral("── 还原 %1").arg(kRecord.description));
        const ksword::memory_backend::AccessOutcome kWriteOutcome =
            ksword::memory_backend::writePhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                ksword::memory_backend::currentDdmaSession(),
                kRecord.physicalAddress,
                kOriginal,
                true);
        if (!kWriteOutcome.ok)
        {
            appendLog(QStringLiteral("   还原失败：%1").arg(kWriteOutcome.failureText));
            statusLabel_->setText(QStringLiteral("还原失败：%1。备份仍然保留在日志里。")
                .arg(kWriteOutcome.failureText));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::errorHex()));
            return;
        }

        const ksword::memory_backend::AccessOutcome kVerifyOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                ksword::memory_backend::currentDdmaSession(),
                kRecord.physicalAddress,
                static_cast<std::uint64_t>(kRecord.originalBytes.size()));
        std::vector<std::uint8_t> readback;
        if (kVerifyOutcome.ok)
        {
            readback.assign(
                reinterpret_cast<const std::uint8_t*>(kVerifyOutcome.data.constData()),
                reinterpret_cast<const std::uint8_t*>(kVerifyOutcome.data.constData())
                    + kVerifyOutcome.data.size());
        }
        const DmaWriteVerification kVerification =
            verifyWriteReadback(kRecord.originalBytes, readback);
        if (!kVerification.matched)
        {
            appendLog(QStringLiteral("   还原后的读回校验失败，目标页仍处于未知状态。"));
            statusLabel_->setText(QStringLiteral(
                "还原命令被接受，但读回校验失败。目标页仍处于未知状态，备份保留在日志里。"));
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::errorHex()));
            return;
        }

        // Only remove the record if the verification passes: removing it without passing verification discards the sole basis for restoration.
        records_.pop_back();
        appendLog(QStringLiteral("   还原完成并通过读回校验。"));
        statusLabel_->setText(QStringLiteral("已还原并通过读回校验。"));
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        updateActionState();
    }
}
