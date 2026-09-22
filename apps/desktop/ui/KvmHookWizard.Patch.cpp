#include "KvmHookWizard.h"

#include "HexEditorWidget.h"
#include "KernelDisassemblyDialog.h"
#include "KvmControl.h"
#include "ThemeStatusRole.h"
#include "../internationalization/LanguageManager.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <thread>

// KvmHookWizard Step 2: Downgrade patch orchestration from 'manually typing 4096 bytes' to 'modifying only the bytes of interest'.
//
// The sole purpose of this entire file is one sentence: The shadow page for HOOK is **the one being executed** (driver-side flipped
// state secondary leaf = shadow page | EXECUTE, hvm_ept_view.c:186-190). Thus, the default state of the shadow page must match the
// target page byte-for-byte—users cannot turn a piece of kernel code into 0x00 by doing nothing. To achieve this, the buffer of
// HexEditorWidget is treated as the single source of truth: opening it loads the baseline full page; the final page is always the
// 'current editor value', and the patch is always the 'computed difference between the current editor value and the baseline'.
//
// Why maintain a parallel diff list? The three paths—revert, full-page paste, and jump-template writeback—all modify the buffer. A parallel
// list will diverge from the buffer on any of these paths, and the diverged portion is exactly what is used to construct shadow pages.

namespace
{
    // Several controls in Step 2 do not appear in the member list of KvmHookWizard.h (the header file is frozen; three .cpp files
    // implement in parallel and cannot add fields individually). They are attached to the dialog via objectName and retrieved
    // internally in this file using findChild—the search scope is limited to this dialog, preventing cross-dialog interference.
    constexpr const char* kModifiedTableName = "KvmHookWizardPatchModifiedTable";
    constexpr const char* kJumpOffsetEditName = "KvmHookWizardPatchJumpOffsetEdit";
    constexpr const char* kPasteGroupName = "KvmHookWizardPatchPasteGroup";
    constexpr const char* kPasteEditName = "KvmHookWizardPatchPasteEdit";
    constexpr const char* kPasteButtonName = "KvmHookWizardPatchPasteButton";
    constexpr const char* kPasteBodyName = "KvmHookWizardPatchPasteBody";
    constexpr const char* kDisassemblyHeadName = "KvmHookWizardPatchDisassemblyHead";

    // The maximum number of lines in the modified byte list. After a full-page paste, the diff may span 4096 lines; cramming
    // them all into the table would freeze the UI, while viewing line 4097 yields the same conclusion as viewing line 200.
    constexpr int kModifiedRowLimit = 256;

    // The disassembly panel only renders a segment near the patch. Decoding still strictly proceeds linearly from page offset 0; here we are only cropping
    // the **display**, not the decoding start point—starting decoding from a different offset would yield a different set of instruction boundaries.
    constexpr quint64 kDisassemblyContextBytes = 64;
    constexpr int kDisassemblyRowLimit = 200;

    // hexByteText: Two-digit hexadecimal representation of a byte.
    QString hexByteText(const quint8 value)
    {
        return QStringLiteral("%1")
            .arg(static_cast<unsigned int>(value), 2, 16, QLatin1Char('0'))
            .toUpper();
    }

    // parseHexUnsigned: Parses a hexadecimal unsigned number that may include a 0x prefix.
    quint64 parseHexUnsigned(const QString& text, bool* const okOut)
    {
        QString compact = text.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        compact.remove(QLatin1Char('`'));
        compact.remove(QLatin1Char('_'));
        if (compact.isEmpty())
        {
            if (okOut != nullptr)
            {
                *okOut = false;
            }
            return 0;
        }
        bool converted = false;
        const quint64 kValue = compact.toULongLong(&converted, 16);
        if (okOut != nullptr)
        {
            *okOut = converted;
        }
        return converted ? kValue : 0;
    }

    // parseHexBytes: Parses a hex string into bytes, **without zero-padding**.
    //
    // The existing KvmViewDialog::parseHexPage pads insufficient input on the right with zeros to fill a full page
    // (KvmViewDialog.cpp:65-66). For CLOAK, this results in reading zeros from the shadow; for HOOK, it causes the processor to execute
    // half a page of garbage. Therefore, this function only handles parsing; the caller must validate the length and reject if invalid.
    bool parseHexBytes(const QString& text, QByteArray* const bytesOut)
    {
        QString compact;
        compact.reserve(text.size());
        for (const QChar kCharacter : text)
        {
            if (kCharacter.isSpace())
            {
                continue;
            }
            if (kCharacter == QLatin1Char(',') || kCharacter == QLatin1Char('-'))
            {
                continue;
            }
            if (!isxdigit(kCharacter.toLatin1()))
            {
                return false;
            }
            compact.append(kCharacter);
        }
        if (compact.isEmpty() || (compact.size() % 2) != 0)
        {
            return false;
        }
        QByteArray bytes;
        bytes.reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int kValue = compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytes.append(static_cast<char>(kValue & 0xFFu));
        }
        if (bytesOut != nullptr)
        {
            *bytesOut = bytes;
        }
        return true;
    }

    // monospaceFont: Bytes and addresses must be monospaced; otherwise, differences in a column of hex values are indistinguishable.
    QFont monospaceFont()
    {
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
}

namespace ks::ui
{
    // -----------------------------------------------------------------
    // Read one page of bytes.
    // -----------------------------------------------------------------

    QByteArray readTargetPage(const quint64 pageBasePhysical, QString* const failureOut)
    {
        const quint32 kPageBytes = ksword::evidence::kPatchPageBytes;
        const quint32 kChunkBytes =
            static_cast<quint32>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);

        // Fragment size is determined by the protocol, not performance: the R-1 channel has a hard single-transaction limit.
        QByteArray page;
        page.reserve(static_cast<qsizetype>(kPageBytes));
        for (quint32 done = 0; done < kPageBytes; done += kChunkBytes)
        {
            const unsigned long kThisChunk = static_cast<unsigned long>(
                std::min<quint32>(kChunkBytes, kPageBytes - done));
            const ksword::kvm::KvmMemoryResult kResult =
                ksword::kvm::readPhysical(pageBasePhysical + done, kThisChunk);
            if (!kResult.ok)
            {
                if (failureOut != nullptr)
                {
                    *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：物理地址 0x%1 起的第 %2 片没读回来（%3）。基线不完整就不能拼影子页，因为缺的那一段会在被执行的那一页里留成零字节。"))
                        .arg(pageBasePhysical + done, 0, 16)
                        .arg(done / kChunkBytes + 1)
                        .arg(kResult.message);
                }
                return QByteArray();
            }
            if (kResult.data.size() != static_cast<qsizetype>(kThisChunk))
            {
                if (failureOut != nullptr)
                {
                    *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：物理地址 0x%1 起本该读回 %2 字节，实际只回了 %3 字节。这一页不完整，不能当基线用。"))
                        .arg(pageBasePhysical + done, 0, 16)
                        .arg(kThisChunk)
                        .arg(kResult.data.size());
                }
                return QByteArray();
            }
            page.append(kResult.data);
        }
        if (page.size() != static_cast<qsizetype>(kPageBytes))
        {
            if (failureOut != nullptr)
            {
                *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：拼出来的不是整整一页，本层拒绝返回一页残缺的字节。"));
            }
            return QByteArray();
        }
        if (failureOut != nullptr)
        {
            failureOut->clear();
        }
        return page;
    }

    // -----------------------------------------------------------------
    // Two non-trivial evaluations of KvmHookPlan.
    // -----------------------------------------------------------------

    QByteArray KvmHookPlan::composedShadowPage(QString* const failureReasonOut) const
    {
        const auto kFail = [failureReasonOut](const QString& reason) {
            if (failureReasonOut != nullptr)
            {
                *failureReasonOut = reason;
            }
            return QByteArray();
        };

        if (!baselineIsComplete())
        {
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：基线页不是整整 4096 字节，用它拼出来的那一页里会有一段不属于目标页的字节，而影子页正是被执行的那一份。")));
        }
        if (patchLength() > 0xFFFFFFFFULL)
        {
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁长度超出 32 位表示范围，几何判定无法进行。")));
        }

        const std::uint8_t* const kOriginalBytes =
            reinterpret_cast<const std::uint8_t*>(baselinePage.constData());
        const std::uint8_t* const kPatchPointer = patchBytes.isEmpty()
            ? nullptr
            : reinterpret_cast<const std::uint8_t*>(patchBytes.constData());

        const ksword::evidence::ComposedPage kComposed = ksword::evidence::composePage(
            kOriginalBytes,
            static_cast<std::uint32_t>(pageOffset),
            kPatchPointer,
            static_cast<std::uint32_t>(patchLength()));

        switch (kComposed.status)
        {
        case ksword::evidence::PatchComposeStatus::kOk:
            break;
        case ksword::evidence::PatchComposeStatus::kOriginalMissing:
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：没有原页字节。请先回到第 2 步重新抓一次基线页。")));
        case ksword::evidence::PatchComposeStatus::kPatchMissing:
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：声明了补丁长度却没有补丁字节。")));
        case ksword::evidence::PatchComposeStatus::kCrossesPageBoundary:
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁从页内偏移 0x%1 起共 %2 字节，越过了页尾。一条视图恰好覆盖一页，协议里没有 PageCount，同一条指令的取指跨两张视图页在两种后端下都是 fail-closed，拆成两条视图也救不了。"))
                .arg(kComposed.patchOffset, 0, 16)
                .arg(kComposed.patchLength));
        case ksword::evidence::PatchComposeStatus::kEmptyPatch:
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁为空。空补丁产出的影子页与原页逐位相同，那样一条 HOOK 视图什么都不改变，却会让人以为补丁装上了。")));
        default:
            return kFail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：构造层返回了一个本层不认识的状态。")));
        }

        if (failureReasonOut != nullptr)
        {
            failureReasonOut->clear();
        }
        return QByteArray(
            reinterpret_cast<const char*>(kComposed.bytes.data()),
            static_cast<qsizetype>(ksword::evidence::kPatchPageBytes));
    }

    ksword::evidence::CrossPageClassification KvmHookPlan::classifyPatchGeometry() const
    {
        const quint64 kLength = patchLength();
        if (kLength > 0xFFFFFFFFULL)
        {
            // 32-bit truncation would calculate an obviously out-of-bounds length as a small in-page value, so we block it here.
            return ksword::evidence::CrossPageClassification::kCrossesPage;
        }
        return ksword::evidence::classifyCrossPage(
            static_cast<std::uint32_t>(pageOffset),
            static_cast<std::uint32_t>(kLength));
    }

    // -----------------------------------------------------------------
    // Control tree for Step 2
    // -----------------------------------------------------------------

    QWidget* KvmHookWizard::buildPatchPage()
    {
        QWidget* const kPage = new QWidget(this);
        QVBoxLayout* const kRootLayout = new QVBoxLayout(kPage);

        QLabel* const kHintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("影子页是被执行的那一份：翻转态下处理器取指走影子页，所以它必须是「目标页原字节 + 你的补丁」完整的一页。下面的编辑器已经装入目标页当前的 4096 字节，默认与目标页逐字节相同——你只改关心的那几个字节即可。")),
            kPage);
        kHintLabel->setWordWrap(true);
        kRootLayout->addWidget(kHintLabel);

        QLabel* const kBoundaryLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("HOOK 不是安全边界：失败即放行，一个有权限的对手可以主动拆除它。这一页只保证字节算术正确。")),
            kPage);
        kBoundaryLabel->setWordWrap(true);
        kRootLayout->addWidget(kBoundaryLabel);

        QHBoxLayout* const kToolLayout = new QHBoxLayout();
        recaptureBaselineButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新抓取基线页")),
            kPage);
        recaptureBaselineButton_->setToolTip(
            ks::i18n::sourceText(QStringLiteral("重新从目标物理页读回 4096 字节。重抓会丢弃当前所有改动。")));
        kToolLayout->addWidget(recaptureBaselineButton_);

        revertPatchButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("还原为基线页")),
            kPage);
        revertPatchButton_->setToolTip(
            ks::i18n::sourceText(QStringLiteral("把编辑器恢复成刚抓回来的那一页，补丁清空。")));
        kToolLayout->addWidget(revertPatchButton_);
        kToolLayout->addStretch(1);
        kRootLayout->addLayout(kToolLayout);

        QSplitter* const kSplitter = new QSplitter(Qt::Horizontal, kPage);

        // ---- Left: Hex editor (source of truth) ----
        shadowEditor_ = new HexEditorWidget(kSplitter);
        shadowEditor_->setObjectName(QStringLiteral("KvmHookWizardShadowEditor"));
        shadowEditor_->setEditable(true);
        kSplitter->addWidget(shadowEditor_);

        // ---- Right: Modified bytes / Jump template / Disassembly ----
        QWidget* const kSideWidget = new QWidget(kSplitter);
        QVBoxLayout* const kSideLayout = new QVBoxLayout(kSideWidget);
        kSideLayout->setContentsMargins(0, 0, 0, 0);

        QGroupBox* const kModifiedGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("已修改字节（编辑器现值与基线页的现算差异）")),
            kSideWidget);
        QVBoxLayout* const kModifiedLayout = new QVBoxLayout(kModifiedGroup);
        QTableWidget* const kModifiedTable = new QTableWidget(0, 3, kModifiedGroup);
        kModifiedTable->setObjectName(QString::fromLatin1(kModifiedTableName));
        kModifiedTable->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("页内偏移"))
            << ks::i18n::sourceText(QStringLiteral("原值"))
            << ks::i18n::sourceText(QStringLiteral("新值")));
        kModifiedTable->horizontalHeader()->setStretchLastSection(true);
        kModifiedTable->verticalHeader()->setVisible(false);
        kModifiedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        kModifiedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        kModifiedTable->setFont(monospaceFont());
        kModifiedLayout->addWidget(kModifiedTable);
        kSideLayout->addWidget(kModifiedGroup, 1);

        // ---- Jump template ----
        QGroupBox* const kJumpGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("跳转模板")),
            kSideWidget);
        QFormLayout* const kJumpLayout = new QFormLayout(kJumpGroup);

        jumpTemplateBox_ = new QComboBox(kJumpGroup);
        jumpTemplateBox_->addItem(
            ks::i18n::sourceText(QStringLiteral("不使用模板（直接在左边改字节）")),
            static_cast<int>(JumpTemplate::kNone));
        jumpTemplateBox_->addItem(
            ks::i18n::sourceText(QStringLiteral("近跳 E9 rel32（5 字节，位移必须装得进 int32）")),
            static_cast<int>(JumpTemplate::kRel32Near));
        jumpTemplateBox_->addItem(
            ks::i18n::sourceText(QStringLiteral("绝对跳 FF 25（14 字节，无距离限制）")),
            static_cast<int>(JumpTemplate::kAbsolute14));
        kJumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("模板")),
            jumpTemplateBox_);

        jumpTargetEdit_ = new QLineEdit(kJumpGroup);
        jumpTargetEdit_->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
        jumpTargetEdit_->setFont(monospaceFont());
        kJumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("跳转目标虚拟地址（十六进制）")),
            jumpTargetEdit_);

        QLineEdit* const kJumpOffsetEdit = new QLineEdit(kJumpGroup);
        kJumpOffsetEdit->setObjectName(QString::fromLatin1(kJumpOffsetEditName));
        kJumpOffsetEdit->setPlaceholderText(QStringLiteral("0x0"));
        kJumpOffsetEdit->setFont(monospaceFont());
        kJumpOffsetEdit->setToolTip(
            ks::i18n::sourceText(QStringLiteral("补丁写进页内的哪个偏移。在左边点选一个字节会自动填这里。")));
        kJumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("写入页内偏移（十六进制）")),
            kJumpOffsetEdit);

        applyJumpButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("把编码结果写进编辑器")),
            kJumpGroup);
        kJumpLayout->addRow(applyJumpButton_);
        kSideLayout->addWidget(kJumpGroup);

        kSplitter->addWidget(kSideWidget);
        kSplitter->setStretchFactor(0, 3);
        kSplitter->setStretchFactor(1, 2);
        kRootLayout->addWidget(kSplitter, 1);

        // ---- Summary ----
        patchSummaryLabel_ = new QLabel(kPage);
        patchSummaryLabel_->setWordWrap(true);
        patchSummaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        kRootLayout->addWidget(patchSummaryLabel_);

        // ---- Disassembly (Reference Only, Not a Criterion) ----
        QGroupBox* const kDisassemblyGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("反汇编参考（不是判据）")),
            kPage);
        QVBoxLayout* const kDisassemblyLayout = new QVBoxLayout(kDisassemblyGroup);

        // This line is a requirement for honesty and must not be deleted: the InstructionDecoder in the repository only supports forward linear decoding,
        // lacking reverse capabilities. Decoding from any arbitrary offset is heuristic self-synchronization. The resulting 'instruction boundary
        // determination' would be a false predicate, so we explicitly do not perform it here; instead, this statement is displayed above the panel.
        QLabel* const kHonestyLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("线性反汇编从页首开始，落在数据区或对齐填充上会给出错误的指令边界 —— 请自行确认补丁点是指令边界。")),
            kDisassemblyGroup);
        kHonestyLabel->setWordWrap(true);
        kDisassemblyLayout->addWidget(kHonestyLabel);

        QLabel* const kHeadLabel = new QLabel(kDisassemblyGroup);
        kHeadLabel->setObjectName(QString::fromLatin1(kDisassemblyHeadName));
        kHeadLabel->setWordWrap(true);
        kDisassemblyLayout->addWidget(kHeadLabel);

        patchDisassemblyView_ = new QPlainTextEdit(kDisassemblyGroup);
        patchDisassemblyView_->setReadOnly(true);
        patchDisassemblyView_->setLineWrapMode(QPlainTextEdit::NoWrap);
        patchDisassemblyView_->setFont(monospaceFont());
        kDisassemblyLayout->addWidget(patchDisassemblyView_);
        kRootLayout->addWidget(kDisassemblyGroup, 1);

        // ---- Whole-page paste (expert entry, collapsed by default) ----
        QGroupBox* const kPasteGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("整页粘贴（专家入口）")),
            kPage);
        kPasteGroup->setObjectName(QString::fromLatin1(kPasteGroupName));
        kPasteGroup->setCheckable(true);
        kPasteGroup->setChecked(false);
        QVBoxLayout* const kPasteOuterLayout = new QVBoxLayout(kPasteGroup);
        QWidget* const kPasteBody = new QWidget(kPasteGroup);
        kPasteBody->setObjectName(QString::fromLatin1(kPasteBodyName));
        kPasteBody->setVisible(false);
        QVBoxLayout* const kPasteLayout = new QVBoxLayout(kPasteBody);
        kPasteLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* const kPasteHint = new QLabel(
            ks::i18n::sourceText(QStringLiteral("粘贴的十六进制必须恰好是 4096 字节。不足一页会被直接拒绝，不会右侧补零——补零意味着把半页垃圾装进那一份将要被执行的影子页。")),
            kPasteBody);
        kPasteHint->setWordWrap(true);
        kPasteLayout->addWidget(kPasteHint);

        QPlainTextEdit* const kPasteEdit = new QPlainTextEdit(kPasteBody);
        kPasteEdit->setObjectName(QString::fromLatin1(kPasteEditName));
        kPasteEdit->setFont(monospaceFont());
        kPasteEdit->setPlaceholderText(QStringLiteral("48 89 5C 24 08 ..."));
        kPasteLayout->addWidget(kPasteEdit);

        QPushButton* const kPasteButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("用粘贴的整页覆盖编辑器")),
            kPasteBody);
        kPasteButton->setObjectName(QString::fromLatin1(kPasteButtonName));
        kPasteLayout->addWidget(kPasteButton);

        kPasteOuterLayout->addWidget(kPasteBody);
        kRootLayout->addWidget(kPasteGroup);

        patchStatusLabel_ = new QLabel(kPage);
        patchStatusLabel_->setWordWrap(true);
        kRootLayout->addWidget(patchStatusLabel_);

        // ---- Connection ----
        connect(
            shadowEditor_,
            &HexEditorWidget::byteEdited,
            this,
            &KvmHookWizard::onShadowByteEdited);
        connect(
            shadowEditor_,
            &HexEditorWidget::currentAddressChanged,
            this,
            [this, kJumpOffsetEdit](const std::uint64_t absoluteAddress) {
                // The selected byte is the write target: let the user click it in the editor; no mental offset calculation needed.
                if (absoluteAddress < plan_.pageBasePhysical)
                {
                    return;
                }
                const quint64 kOffset = absoluteAddress - plan_.pageBasePhysical;
                if (kOffset >= ksword::evidence::kPatchPageBytes)
                {
                    return;
                }
                kJumpOffsetEdit->setText(QStringLiteral("0x%1").arg(kOffset, 0, 16));
            });
        connect(
            recaptureBaselineButton_,
            &QPushButton::clicked,
            this,
            [this]() { startBaselineCapture(); });
        connect(
            revertPatchButton_,
            &QPushButton::clicked,
            this,
            [this]() { revertPatch(); });
        connect(
            jumpTemplateBox_,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { updatePatchEnabledState(); });
        connect(
            applyJumpButton_,
            &QPushButton::clicked,
            this,
            [this]() {
                if (jumpTemplateBox_ == nullptr || jumpTargetEdit_ == nullptr)
                {
                    return;
                }
                const JumpTemplate kTemplateKind = static_cast<JumpTemplate>(
                    jumpTemplateBox_->currentData().toInt());
                bool converted = false;
                const quint64 kTargetVa =
                    parseHexUnsigned(jumpTargetEdit_->text(), &converted);
                if (!converted)
                {
                    if (patchStatusLabel_ != nullptr)
                    {
                        patchStatusLabel_->setText(ks::i18n::sourceText(
                            QStringLiteral("跳转目标不是一个合法的十六进制地址。")));
                        applyStatusRole(patchStatusLabel_, StatusRole::kError);
                    }
                    return;
                }
                applyJumpTemplate(kTemplateKind, kTargetVa);
            });
        connect(
            kPasteGroup,
            &QGroupBox::toggled,
            kPasteBody,
            &QWidget::setVisible);
        connect(
            kPasteButton,
            &QPushButton::clicked,
            this,
            [this, kPasteEdit]() {
                if (shadowEditor_ == nullptr || patchStatusLabel_ == nullptr)
                {
                    return;
                }
                if (!plan_.baselineIsComplete())
                {
                    patchStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：还没有基线页，无法判断粘贴进来的这一页改动了什么。")));
                    applyStatusRole(patchStatusLabel_, StatusRole::kError);
                    return;
                }
                QByteArray pasted;
                if (!parseHexBytes(kPasteEdit->toPlainText(), &pasted))
                {
                    patchStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：文本里有非十六进制字符，或者十六进制位数是奇数。")));
                    applyStatusRole(patchStatusLabel_, StatusRole::kError);
                    return;
                }
                if (pasted.size()
                    != static_cast<qsizetype>(ksword::evidence::kPatchPageBytes))
                {
                    // Zero-padding is intentionally omitted here: padding would load half-page garbage into the shadow page that gets executed.
                    patchStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：粘贴进来的是 %1 字节，而影子页必须恰好 4096 字节。这里不会替你右侧补零——补出来的那一半会被处理器当成指令执行。"))
                        .arg(pasted.size()));
                    applyStatusRole(patchStatusLabel_, StatusRole::kError);
                    return;
                }
                shadowEditor_->setByteArray(pasted, plan_.pageBasePhysical);
                shadowEditor_->setEditable(!busy_);
                recomputePatchFromEditor();
                updatePatchSummary();
                refreshPatchDisassembly();
                updatePatchEnabledState();
                patchStatusLabel_->setText(ks::i18n::sourceText(
                    QStringLiteral("整页已覆盖进编辑器，补丁按与基线页的差异重新算过。")));
                applyStatusRole(patchStatusLabel_, StatusRole::kInfo);
            });

        updatePatchSummary();
        updatePatchEnabledState();
        return kPage;
    }

    // -----------------------------------------------------------------
    // Baseline page capture
    // -----------------------------------------------------------------

    void KvmHookWizard::startBaselineCapture()
    {
        if (shadowEditor_ == nullptr)
        {
            return;
        }
        if (!plan_.resolved)
        {
            if (patchStatusLabel_ != nullptr)
            {
                patchStatusLabel_->setText(ks::i18n::sourceText(
                    QStringLiteral("目标还没有解析成功，没有可读的物理页。请回到第 1 步。")));
                applyStatusRole(patchStatusLabel_, StatusRole::kError);
            }
            return;
        }
        if (baselineInFlight_)
        {
            // Single-flight: only one page-read thread is allowed at a time; repeated clicks do not dispatch.
            return;
        }

        baselineInFlight_ = true;
        const quint64 kSequence = ++baselineSequence_;
        const quint64 kPageBase = plan_.pageBasePhysical;
        setBusy(true);
        updatePatchEnabledState();
        if (patchStatusLabel_ != nullptr)
        {
            patchStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("正在从 R-1 通道分四片读回目标页的 4096 字节……")));
            applyStatusRole(patchStatusLabel_, StatusRole::kInfo);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence, kPageBase]() {
            QString failure;
            const QByteArray kPage = readTargetPage(kPageBase, &failure);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, kPage, failure]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyBaselineCapture(kSequence, kPage, failure);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyBaselineCapture(
        const quint64 sequence,
        const QByteArray& page,
        const QString& failure)
    {
        // First, unconditionally clear the in-flight flag and busy state: this returning task is the one that
        // was in-flight; even if its sequence number is now invalid, it must still release the lock it holds.
        baselineInFlight_ = false;
        setBusy(false);
        if (sequence != baselineSequence_)
        {
            // A sequence number mismatch indicates this page was invalidated by subsequent input. Applying
            // it would cause a mismatch between the bytes in the editor and the address from Step 1.
            return;
        }
        if (shadowEditor_ == nullptr)
        {
            return;
        }

        if (page.size() != static_cast<qsizetype>(ksword::evidence::kPatchPageBytes))
        {
            plan_.baselinePage.clear();
            plan_.patchBytes.clear();
            shadowEditor_->setByteArray(QByteArray(), plan_.pageBasePhysical);
            if (patchStatusLabel_ != nullptr)
            {
                patchStatusLabel_->setText(failure.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("基线页抓取失败：没有读回完整的一页。"))
                    : failure);
                applyStatusRole(patchStatusLabel_, StatusRole::kError);
            }
            setStatusText(
                ks::i18n::sourceText(QStringLiteral("基线页抓取失败，第 2 步无法继续。")),
                KvmCheckVerdict::kFail);
            updatePatchSummary();
            refreshPatchDisassembly();
            updatePatchEnabledState();
            return;
        }

        plan_.baselinePage = page;
        plan_.patchBytes.clear();
        // In the default state, the target page matches byte-by-byte: the user doing nothing will not turn kernel code into 0x00.
        shadowEditor_->setByteArray(page, plan_.pageBasePhysical);
        shadowEditor_->setEditable(true);
        // The user cares about those specific bytes, not the page header.
        shadowEditor_->jumpToAbsoluteAddress(
            plan_.pageBasePhysical + plan_.pageOffset);

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (patchStatusLabel_ != nullptr)
        {
            patchStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("基线页已就位：物理页 0x%1 的 4096 字节，编辑器当前内容与目标页逐字节相同。"))
                .arg(plan_.pageBasePhysical, 0, 16));
            applyStatusRole(patchStatusLabel_, StatusRole::kSuccess);
        }
        setStatusText(
            ks::i18n::sourceText(QStringLiteral("基线页已抓取，可以开始编排补丁。")),
            KvmCheckVerdict::kPass);
    }

    // -----------------------------------------------------------------
    // Edit and recalculate patch
    // -----------------------------------------------------------------

    void KvmHookWizard::onShadowByteEdited(
        const std::uint64_t absoluteAddress,
        const std::uint8_t oldValue,
        const std::uint8_t newValue)
    {
        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (patchStatusLabel_ != nullptr)
        {
            const quint64 kOffset = absoluteAddress >= plan_.pageBasePhysical
                ? absoluteAddress - plan_.pageBasePhysical
                : 0ULL;
            patchStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("已改写页内偏移 0x%1：原值 %2 改成 %3。"))
                .arg(kOffset, 0, 16)
                .arg(hexByteText(oldValue))
                .arg(hexByteText(newValue)));
            applyStatusRole(patchStatusLabel_, StatusRole::kInfo);
        }
    }

    void KvmHookWizard::recomputePatchFromEditor()
    {
        if (shadowEditor_ == nullptr)
        {
            return;
        }

        // A patch is always the computed difference between the editor's current value and the baseline page. We do not maintain a parallel diff list:
        // All three paths (full-page paste, template rewrite, single-byte edit) modify the buffer, causing the parallel list to diverge.
        const QByteArray kCurrent = shadowEditor_->data();
        const QByteArray& baseline = plan_.baselinePage;

        // If there is no difference, reset the patch start to the offset within the page resolved in step 1:
        // This is the actual byte the user referred to, not the starting point left by the previous modification.
        const quint32 kResolvedOffset =
            static_cast<quint32>(plan_.fullPhysicalAddress & 0xFFFULL);

        if (baseline.size() != static_cast<qsizetype>(ksword::evidence::kPatchPageBytes)
            || kCurrent.size() != baseline.size())
        {
            plan_.patchBytes.clear();
            plan_.pageOffset = kResolvedOffset;
            return;
        }

        qsizetype firstDifference = -1;
        qsizetype lastDifference = -1;
        for (qsizetype index = 0; index < kCurrent.size(); ++index)
        {
            if (kCurrent.at(index) != baseline.at(index))
            {
                if (firstDifference < 0)
                {
                    firstDifference = index;
                }
                lastDifference = index;
            }
        }

        if (firstDifference < 0)
        {
            plan_.patchBytes.clear();
            plan_.pageOffset = kResolvedOffset;
            return;
        }

        plan_.pageOffset = static_cast<quint32>(firstDifference);
        plan_.patchBytes = kCurrent.mid(
            firstDifference,
            lastDifference - firstDifference + 1);
    }

    void KvmHookWizard::updatePatchSummary()
    {
        // ---- Modified Byte List ----
        QTableWidget* const kModifiedTable =
            findChild<QTableWidget*>(QString::fromLatin1(kModifiedTableName));
        if (kModifiedTable != nullptr)
        {
            kModifiedTable->setRowCount(0);
            if (shadowEditor_ != nullptr && plan_.baselineIsComplete())
            {
                const QByteArray kCurrent = shadowEditor_->data();
                if (kCurrent.size() == plan_.baselinePage.size())
                {
                    int row = 0;
                    for (qsizetype index = 0;
                        index < kCurrent.size() && row < kModifiedRowLimit;
                        ++index)
                    {
                        if (kCurrent.at(index) == plan_.baselinePage.at(index))
                        {
                            continue;
                        }
                        kModifiedTable->insertRow(row);
                        kModifiedTable->setItem(row, 0, new QTableWidgetItem(
                            QStringLiteral("0x%1")
                                .arg(static_cast<qulonglong>(index), 3, 16, QLatin1Char('0'))));
                        kModifiedTable->setItem(row, 1, new QTableWidgetItem(
                            hexByteText(static_cast<quint8>(
                                plan_.baselinePage.at(index)))));
                        kModifiedTable->setItem(row, 2, new QTableWidgetItem(
                            hexByteText(static_cast<quint8>(kCurrent.at(index)))));
                        ++row;
                    }
                }
            }
        }

        if (patchSummaryLabel_ == nullptr)
        {
            return;
        }

        QStringList lines;
        if (!plan_.baselineIsComplete())
        {
            lines << ks::i18n::sourceText(QStringLiteral("基线页尚未就位：还没有可编排的一页字节。"));
            patchSummaryLabel_->setText(lines.join(QStringLiteral("\n")));
            return;
        }

        lines << ks::i18n::sourceText(QStringLiteral("目标物理页 0x%1，第 1 步解析出的页内偏移 0x%2。"))
            .arg(plan_.pageBasePhysical, 0, 16)
            .arg(plan_.fullPhysicalAddress & 0xFFFULL, 0, 16);

        if (plan_.patchIsEmpty())
        {
            lines << ks::i18n::sourceText(QStringLiteral("当前补丁为空：编辑器内容与基线页逐字节相同。空补丁产出的影子页与原页一模一样，那样一条 HOOK 视图什么都不改变，所以第 4 步会拒绝安装。"));
        }
        else
        {
            lines << ks::i18n::sourceText(QStringLiteral("补丁起点页内偏移 0x%1，长度 %2 字节，结束偏移 0x%3（不含）。"))
                .arg(plan_.pageOffset, 0, 16)
                .arg(plan_.patchLength())
                .arg(plan_.patchEndOffset(), 0, 16);
        }

        const ksword::evidence::CrossPageClassification kClassification =
            plan_.classifyPatchGeometry();
        if (kClassification == ksword::evidence::CrossPageClassification::kInPage)
        {
            lines << ks::i18n::sourceText(QStringLiteral("几何判定：补丁完全落在这一页里。"));
        }
        else
        {
            lines << ks::i18n::sourceText(QStringLiteral("几何判定：补丁越过了页尾，第 4 步会直接拒绝。一条视图恰好覆盖一页，协议里没有 PageCount，装两条也救不了——同一条指令的取指跨两张视图页在两种后端下都是 fail-closed。"));
        }

        QString composeFailure;
        const QByteArray kComposed = plan_.composedShadowPage(&composeFailure);
        if (kComposed.size() == static_cast<qsizetype>(ksword::evidence::kPatchPageBytes))
        {
            lines << ks::i18n::sourceText(QStringLiteral("成品影子页可构造：整整 4096 字节，补丁区间以外与基线页逐位相同。"));
        }
        else
        {
            lines << composeFailure;
        }

        patchSummaryLabel_->setText(lines.join(QStringLiteral("\n")));

        // When a patch changes, the navigation gate must be re-evaluated.
        //
        // Placed here rather than at each individual call site because this file modifies patches via six paths
        // (single-byte edit, template back-write, full-page paste, restore, re-capture baseline, switch target);
        // missing any one of them produces identical symptoms: the summary claims 'Patch 21 bytes, geometric check
        // passed', while 'Next' remains disabled and the tooltip still shows 'Patch is empty' from the moment of entry.
        // The two sentences on the UI refer to two different moments; the user has no way to tell which one is stale.
        // As of 2026-09-07, actual testing confirms this state: none of the six paths refreshed the navigation gate.
        updateNavigationState();
    }

    void KvmHookWizard::refreshPatchDisassembly()
    {
        if (patchDisassemblyView_ == nullptr)
        {
            return;
        }
        QLabel* const kHeadLabel =
            findChild<QLabel*>(QString::fromLatin1(kDisassemblyHeadName));

        if (shadowEditor_ == nullptr || !plan_.baselineIsComplete())
        {
            patchDisassemblyView_->setPlainText(ks::i18n::sourceText(
                QStringLiteral("基线页尚未就位，没有可解码的字节。")));
            if (kHeadLabel != nullptr)
            {
                kHeadLabel->clear();
            }
            return;
        }

        const QByteArray kCurrent = shadowEditor_->data();
        if (kCurrent.isEmpty())
        {
            patchDisassemblyView_->clear();
            return;
        }

        // The base address is fixed to the page base; decoding always proceeds linearly from offset 0 at the start of the page.
        // Use the virtual page base address when a virtual address is present, as that is the actual address executed for this page,
        // ensuring relative jump targets align; if only a physical address exists, fall back to the physical page base address.
        const bool kHaveVirtual = plan_.hasVirtualAddress();
        const quint64 kDecodeBase = kHaveVirtual
            ? (plan_.virtualAddress & ~0xFFFULL)
            : plan_.pageBasePhysical;

        const DisassemblyResult kResult = InstructionDecoder::decode(
            kCurrent,
            kDecodeBase,
            DisassemblyArchitecture::kX64,
            static_cast<std::uint32_t>(ksword::evidence::kPatchPageBytes));

        if (kHeadLabel != nullptr)
        {
            kHeadLabel->setText(kHaveVirtual
                ? ks::i18n::sourceText(QStringLiteral("解码基址取虚拟页基址 0x%1，后端：%2。带 * 的行与补丁区间有重叠。"))
                    .arg(kDecodeBase, 0, 16)
                    .arg(kResult.backendName)
                : ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，解码基址退回物理页基址 0x%1，后端：%2。带 * 的行与补丁区间有重叠。"))
                    .arg(kDecodeBase, 0, 16)
                    .arg(kResult.backendName));
        }

        // The display window only clips rendering, not the decoding start point: stuffing 1500 rows per page into the text box and reflowing
        // on every keystroke would freeze the UI, while inspecting a few hundred rows outside the window yields no additional conclusions.
        const quint64 kPatchStart = static_cast<quint64>(plan_.pageOffset);
        const quint64 kPatchEnd = plan_.patchIsEmpty()
            ? kPatchStart + 1
            : plan_.patchEndOffset();
        const quint64 kWindowStart = kPatchStart > kDisassemblyContextBytes
            ? kPatchStart - kDisassemblyContextBytes
            : 0ULL;
        const quint64 kWindowEnd = kPatchEnd + kDisassemblyContextBytes;

        QStringList lines;
        for (const DisassemblyRow& row : kResult.rows)
        {
            const quint64 kRowStart = static_cast<quint64>(row.byteOffset);
            const quint64 kRowEnd = kRowStart
                + static_cast<quint64>(std::max<qsizetype>(row.bytes.size(), 1));
            if (kRowEnd <= kWindowStart || kRowStart >= kWindowEnd)
            {
                continue;
            }
            if (lines.size() >= kDisassemblyRowLimit)
            {
                lines << ks::i18n::sourceText(QStringLiteral("（后面的行已省略）"));
                break;
            }

            const bool kTouchesPatch =
                !plan_.patchIsEmpty() && kRowStart < kPatchEnd && kRowEnd > kPatchStart;
            lines << QStringLiteral("%1 %2  %3  %4 %5")
                .arg(kTouchesPatch ? QStringLiteral("*") : QStringLiteral(" "))
                .arg(row.address, 16, 16, QLatin1Char('0'))
                .arg(QString::fromLatin1(row.bytes.toHex(' ')).toUpper(), -32)
                .arg(row.mnemonic)
                .arg(row.operands);
        }

        if (lines.isEmpty())
        {
            lines << ks::i18n::sourceText(QStringLiteral("补丁附近没有解码出任何指令。"));
        }
        if (!kResult.diagnosticText.isEmpty())
        {
            lines << QString();
            lines << kResult.diagnosticText;
        }
        patchDisassemblyView_->setPlainText(lines.join(QStringLiteral("\n")));
    }

    // -----------------------------------------------------------------
    // Jump template
    // -----------------------------------------------------------------

    void KvmHookWizard::applyJumpTemplate(
        const JumpTemplate templateKind,
        const quint64 targetVa)
    {
        const auto kReject = [this](const QString& reason) {
            if (patchStatusLabel_ != nullptr)
            {
                patchStatusLabel_->setText(reason);
                applyStatusRole(patchStatusLabel_, StatusRole::kError);
            }
        };

        if (shadowEditor_ == nullptr)
        {
            return;
        }
        if (templateKind == JumpTemplate::kNone)
        {
            kReject(ks::i18n::sourceText(QStringLiteral("当前没有选择跳转模板，请直接在左边的十六进制编辑器里改字节。")));
            return;
        }
        if (!plan_.baselineIsComplete())
        {
            kReject(ks::i18n::sourceText(QStringLiteral("基线页还没有就位，没有可写入的一页字节。")));
            return;
        }
        if (!plan_.hasVirtualAddress())
        {
            // The displacement base for near jumps is the next instruction; the source address is taken from virtualAddress.
            // The entry point providing a direct physical address cannot obtain a trusted source address, so both templates are disabled.
            kReject(ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，跳转模板不可用：近跳的位移要按源虚拟地址算，而直接给物理地址的路径上没有可信的源地址。请改用左边的十六进制编辑器直接写字节。")));
            return;
        }

        QLineEdit* const kJumpOffsetEdit =
            findChild<QLineEdit*>(QString::fromLatin1(kJumpOffsetEditName));
        if (kJumpOffsetEdit == nullptr)
        {
            return;
        }
        bool converted = false;
        const quint64 kWriteOffset = parseHexUnsigned(kJumpOffsetEdit->text(), &converted);
        if (!converted)
        {
            kReject(ks::i18n::sourceText(QStringLiteral("写入页内偏移不是一个合法的十六进制数。在左边的编辑器里点选一个字节可以自动填上它。")));
            return;
        }
        if (kWriteOffset >= ksword::evidence::kPatchPageBytes)
        {
            kReject(ks::i18n::sourceText(QStringLiteral("写入页内偏移 0x%1 已经不在这一页里，一条视图恰好覆盖一页。"))
                .arg(kWriteOffset, 0, 16));
            return;
        }

        QByteArray encoded;
        if (templateKind == JumpTemplate::kRel32Near)
        {
            const quint64 kSourceVa = (plan_.virtualAddress & ~0xFFFULL) + kWriteOffset;
            const ksword::evidence::Rel32Jump kJump =
                ksword::evidence::encodeRel32Jump(kSourceVa, targetVa);
            if (!kJump.ok())
            {
                // Honestly reject and explain switching to an absolute jump; do not secretly replace the
                // encoding for the user: the five bytes replaced would not match the length read in the summary.
                kReject(ks::i18n::sourceText(QStringLiteral("近跳编码被拒绝：从 0x%1 跳到 0x%2 的位移是 %3，装不进 int32。请改用 14 字节的绝对跳 FF 25，它没有距离限制。"))
                    .arg(kSourceVa, 0, 16)
                    .arg(targetVa, 0, 16)
                    .arg(static_cast<qlonglong>(kJump.displacement)));
                return;
            }
            encoded = QByteArray(
                reinterpret_cast<const char*>(kJump.bytes.data()),
                static_cast<qsizetype>(ksword::evidence::kRel32JumpLength));
        }
        else
        {
            const auto kBytes = ksword::evidence::encodeAbsoluteJump(targetVa);
            encoded = QByteArray(
                reinterpret_cast<const char*>(kBytes.data()),
                static_cast<qsizetype>(ksword::evidence::kAbsoluteJumpLength));
        }

        if (kWriteOffset + static_cast<quint64>(encoded.size())
            > ksword::evidence::kPatchPageBytes)
        {
            // Reject cross-page writes directly and do not offer 'auto-split into two': page flips are
            // independent, and any exit in between could cause the guest to execute a half-instruction.
            kReject(ks::i18n::sourceText(QStringLiteral("模板写入被拒绝：从页内偏移 0x%1 起写 %2 字节会越过页尾。一条视图恰好覆盖一页，协议里没有 PageCount，拆成两条视图在两种后端下都是 fail-closed，所以这里不提供那个选项。"))
                .arg(kWriteOffset, 0, 16)
                .arg(encoded.size()));
            return;
        }

        for (qsizetype index = 0; index < encoded.size(); ++index)
        {
            const quint64 kAddress =
                plan_.pageBasePhysical + kWriteOffset + static_cast<quint64>(index);
            // setByteAtAbsoluteAddress does not emit byteEdited (starting from
            // HexEditorWidget.cpp:377), so the patch must be recalculated manually below.
            shadowEditor_->setByteAtAbsoluteAddress(
                kAddress,
                static_cast<std::uint8_t>(encoded.at(index)),
                index == encoded.size() - 1);
        }

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (patchStatusLabel_ != nullptr)
        {
            patchStatusLabel_->setText(templateKind == JumpTemplate::kRel32Near
                ? ks::i18n::sourceText(QStringLiteral("近跳已写入：页内偏移 0x%1 起 5 字节，目标 0x%2。"))
                    .arg(kWriteOffset, 0, 16)
                    .arg(targetVa, 0, 16)
                : ks::i18n::sourceText(QStringLiteral("绝对跳已写入：页内偏移 0x%1 起 14 字节，目标 0x%2。"))
                    .arg(kWriteOffset, 0, 16)
                    .arg(targetVa, 0, 16));
            applyStatusRole(patchStatusLabel_, StatusRole::kSuccess);
        }
    }

    void KvmHookWizard::revertPatch()
    {
        if (shadowEditor_ == nullptr)
        {
            return;
        }
        if (!plan_.baselineIsComplete())
        {
            return;
        }

        shadowEditor_->setByteArray(plan_.baselinePage, plan_.pageBasePhysical);
        shadowEditor_->setEditable(!busy_);
        plan_.patchBytes.clear();
        plan_.pageOffset = static_cast<quint32>(plan_.fullPhysicalAddress & 0xFFFULL);
        shadowEditor_->jumpToAbsoluteAddress(
            plan_.pageBasePhysical + plan_.pageOffset);

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (patchStatusLabel_ != nullptr)
        {
            patchStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("已还原为基线页，编辑器内容与目标页逐字节相同。")));
            applyStatusRole(patchStatusLabel_, StatusRole::kInfo);
        }
    }

    void KvmHookWizard::updatePatchEnabledState()
    {
        const bool kBaselineReady = plan_.baselineIsComplete();
        const bool kIdle = !busy_;
        const bool kHaveVirtual = plan_.hasVirtualAddress();

        if (shadowEditor_ != nullptr)
        {
            shadowEditor_->setEditable(kBaselineReady && kIdle);
        }
        if (recaptureBaselineButton_ != nullptr)
        {
            recaptureBaselineButton_->setEnabled(plan_.resolved && kIdle);
            recaptureBaselineButton_->setToolTip(plan_.resolved
                ? ks::i18n::sourceText(QStringLiteral("重新从目标物理页读回 4096 字节。重抓会丢弃当前所有改动。"))
                : ks::i18n::sourceText(QStringLiteral("第 1 步的目标还没有解析成功，没有可读的物理页。")));
        }
        if (revertPatchButton_ != nullptr)
        {
            revertPatchButton_->setEnabled(
                kBaselineReady && kIdle && !plan_.patchIsEmpty());
        }

        JumpTemplate selected = JumpTemplate::kNone;
        if (jumpTemplateBox_ != nullptr)
        {
            selected = static_cast<JumpTemplate>(
                jumpTemplateBox_->currentData().toInt());
            jumpTemplateBox_->setEnabled(kBaselineReady && kIdle && kHaveVirtual);
            jumpTemplateBox_->setToolTip(kHaveVirtual
                ? ks::i18n::sourceText(QStringLiteral("模板会把编码好的字节写进下面指定的页内偏移。"))
                : ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，跳转模板不可用：近跳的位移要按源虚拟地址算，而直接给物理地址的路径上没有可信的源地址。")));
        }
        const bool kJumpUsable =
            kBaselineReady && kIdle && kHaveVirtual && selected != JumpTemplate::kNone;
        if (jumpTargetEdit_ != nullptr)
        {
            jumpTargetEdit_->setEnabled(kJumpUsable);
        }
        if (applyJumpButton_ != nullptr)
        {
            applyJumpButton_->setEnabled(kJumpUsable);
        }
        QLineEdit* const kJumpOffsetEdit =
            findChild<QLineEdit*>(QString::fromLatin1(kJumpOffsetEditName));
        if (kJumpOffsetEdit != nullptr)
        {
            kJumpOffsetEdit->setEnabled(kJumpUsable);
        }

        QGroupBox* const kPasteGroup =
            findChild<QGroupBox*>(QString::fromLatin1(kPasteGroupName));
        if (kPasteGroup != nullptr)
        {
            kPasteGroup->setEnabled(kBaselineReady && kIdle);
        }
    }
}
