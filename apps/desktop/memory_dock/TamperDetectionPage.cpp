#include "TamperDetectionPage.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"
#include "../../../shared/evidence/NumericTextParse.h"
#include "../../../shared/evidence/PeImageMap.h"

#include <QFile>

#include <QCheckBox>
#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>

// ============================================================
// TamperDetectionPage.cpp
// Purpose: Collect bytes from multiple read paths, pass them to the shared/evidence decision layer, and display the conclusion.
// This file contains no verdict logic—if a verdict is wrong, it won't error but will quietly say
// "clean"; therefore, that part must reside where it can be covered by offline exhaustive testing.
// ============================================================

using namespace ksword::evidence;

namespace ksword::memory_dock
{
    namespace
    {
        // Compare page by page. The granularity is one page: a single DDMA transfer moves one page; using a
        // finer granularity would only exponentially increase disk round-trips without adding any criteria.
        constexpr std::uint64_t kPageBytes = 4096ULL;

        // Default value for the scan limit. DDMA performs four disk round-trips per page (backup sector → write → read →
        // restore). Since page count multiplied by round-trip count directly determines latency, a conservative default and an
        // explicit upper bound are required to prevent users from accidentally submitting requests that run for ten minutes.
        constexpr int kDefaultMaxPages = 64;
        constexpr int kHardMaxPages = 1024;

        // ScanOutcome: Output from the worker thread.
        struct ScanOutcome
        {
            std::vector<TamperPageResult> results;
            QString abortReason;   // Non-null indicates the full round did not complete; the reason must be returned to the UI truthfully.
        };

        // collectOnePage: Perform one sampling round on a single page.
        //
        // Physical addresses are translated by the caller before passing in, and **translated only once**: R0 physical reads and DDMA reads
        // must fall within the same physical page. If each performs its own translation here, any changes between the two translations
        // would be interpreted as content differences—this is a phantom reading that coincidentally resembles the target data.
        TamperRound collectOneRound(
            const TamperScanRequest& request,
            const ksword::ark::DriverClient& client,
            const ksword::evidence::PeImageMap& diskImageMap,
            const std::uint64_t virtualAddress,
            const std::uint64_t physicalAddress,
            const bool physicalValid)
        {
            TamperRound round;

            const auto kPushSample = [&round](
                const TamperReadPath path,
                const ksword::memory_backend::AccessOutcome& outcome)
            {
                TamperViewSample sample;
                sample.path = path;
                if (outcome.ok)
                {
                    sample.status = TamperSampleStatus::kRead;
                    sample.bytes.assign(
                        reinterpret_cast<const std::uint8_t*>(outcome.data.constData()),
                        reinterpret_cast<const std::uint8_t*>(outcome.data.constData())
                            + outcome.data.size());
                }
                else
                {
                    sample.status = TamperSampleStatus::kFailed;
                    sample.failureText = outcome.failureText.toStdString();
                }
                round.views.push_back(std::move(sample));
            };

            const auto kPushUnavailable = [&round](
                const TamperReadPath path, const QString& reason)
            {
                TamperViewSample sample;
                sample.path = path;
                sample.status = TamperSampleStatus::kUnavailable;
                sample.failureText = reason.toStdString();
                round.views.push_back(std::move(sample));
            };

            if (request.useUserMode)
            {
                kPushSample(
                    TamperReadPath::kUserModeVirtual,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::kUserMode,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useKernelVirtual)
            {
                kPushSample(
                    TamperReadPath::kKernelVirtual,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::kStandardDriver,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useKernelPhysical)
            {
                if (!physicalValid)
                {
                    kPushUnavailable(
                        TamperReadPath::kKernelPhysical,
                        QStringLiteral("该页的虚拟地址翻译不出物理地址"));
                }
                else
                {
                    kPushSample(
                        TamperReadPath::kKernelPhysical,
                        ksword::memory_backend::readPhysical(
                            ksword::memory_backend::MemoryAccessBackend::kStandardDriver,
                            request.ddmaSession,
                            physicalAddress,
                            kPageBytes));
                }
            }
            // HVM uses virtual addresses, not physical addresses: its independence stems from 'not calling
            // memory manager routines'; this property holds and is meaningful only for virtual address reads.
            // A discrepancy compared to R0 virtual reads indicates that MmCopyVirtualMemory has been hooked.
            if (request.useHvm)
            {
                kPushSample(
                    TamperReadPath::kHvmPrivateWindow,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::kHvm,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useDma)
            {
                if (!physicalValid)
                {
                    kPushUnavailable(
                        TamperReadPath::kDmaPhysical,
                        QStringLiteral("该页的虚拟地址翻译不出物理地址"));
                }
                else
                {
                    kPushSample(
                        TamperReadPath::kDmaPhysical,
                        ksword::memory_backend::readPhysical(
                            ksword::memory_backend::MemoryAccessBackend::kDdma,
                            request.ddmaSession,
                            physicalAddress,
                            kPageBytes));
                }
            }

            // Clean pages of the section object: the memory manager's own copy of "what this image should look
            // like". This source is **independent** from the disk file. Even if the file is modified, this
            // copy remains. Therefore, both static references are preserved; one does not replace the other.
            if (request.useImageSection)
            {
                TamperViewSample sample;
                sample.path = TamperReadPath::kImageSectionClean;
                const ksword::ark::ImageSectionPagesResult kSectionResult =
                    client.readImageSectionPages(
                        request.processId,
                        virtualAddress,
                        virtualAddress + kPageBytes,
                        0ULL,
                        1UL,
                        KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES);
                if (!kSectionResult.io.ok)
                {
                    sample.status = TamperSampleStatus::kFailed;
                    sample.failureText = kSectionResult.io.message;
                }
                else if (kSectionResult.entries.empty()
                    || !kSectionResult.entries.front().valid()
                    || !kSectionResult.entries.front().bytesPresent()
                    || kSectionResult.pageBytes.size() < kPageBytes)
                {
                    // When the prototype PTE is not in a valid architectural form (transition/pagefile
                    // encoding), the driver only reports 'not resident' without decoding and does not bring
                    // the page into memory. This is a coverage gap, not 'this page matches the reference'.
                    sample.status = TamperSampleStatus::kOutOfCoverage;
                    sample.failureText = "节对象未给出该页的干净字节（原型 PTE 未驻留或不可解码）";
                }
                else
                {
                    sample.status = TamperSampleStatus::kRead;
                    sample.bytes.assign(
                        kSectionResult.pageBytes.begin(),
                        kSectionResult.pageBytes.begin() + static_cast<std::ptrdiff_t>(kPageBytes));
                }
                round.views.push_back(std::move(sample));
            }

            // Disk image: normalize based on the **currently loaded base address** before comparison. The same file
            // contains different bytes at different base addresses due to relocations; comparing raw file content
            // would flag every normal load as a large discrepancy. Normalization, zero-padding regions, and
            // incomparable region logic are all reused from PeImageMap; this file does not parse PE headers itself.
            if (request.useOnDiskImage)
            {
                TamperViewSample sample;
                sample.path = TamperReadPath::kOnDiskImage;
                if (!diskImageMap.valid())
                {
                    sample.status = TamperSampleStatus::kUnavailable;
                    sample.failureText = std::string("磁盘映像不可用：")
                        + ksword::evidence::peParseStatusName(diskImageMap.status);
                }
                else if (virtualAddress < request.moduleBaseAddress)
                {
                    sample.status = TamperSampleStatus::kOutOfCoverage;
                    sample.failureText = "该页在模块基址之前，不属于这个映像";
                }
                else
                {
                    const std::uint64_t kRva64 = virtualAddress - request.moduleBaseAddress;
                    std::vector<std::uint8_t> normalized;
                    if (kRva64 > 0xFFFFFFFFULL
                        || !ksword::evidence::readNormalizedBytes(
                            diskImageMap,
                            static_cast<std::uint32_t>(kRva64),
                            static_cast<std::uint32_t>(kPageBytes),
                            normalized))
                    {
                        // readNormalizedBytes returning false means "this segment lacks file byte support or
                        // falls within a non-comparable range"—including zero-filled areas, section gaps,
                        // malformed sections, and unsupported relocations. It does **not** mean "no differences."
                        sample.status = TamperSampleStatus::kOutOfCoverage;
                        sample.failureText = "该页在磁盘映像里没有可比较的字节支撑（零填充区、节间隙或不可归一化范围）";
                    }
                    else
                    {
                        sample.status = TamperSampleStatus::kRead;
                        sample.bytes = std::move(normalized);
                    }
                }
                round.views.push_back(std::move(sample));
            }
            return round;
        }

        // runScan: Run the full scan in the worker thread. Do not touch any Qt controls.
        ScanOutcome runScan(const TamperScanRequest& request)
        {
            ScanOutcome outcome;
            const ksword::ark::DriverClient kClient;

            // Disk image is parsed **exactly once per full round**: it is static. Re-reading the file page-by-page would
            // cause hundreds or thousands of extra disk I/O operations per scan, and replacing the file mid-scan would cause
            // reference inconsistency across pages. Parsing occurs in a worker thread to avoid blocking the main thread.
            ksword::evidence::PeImageMap diskImageMap;
            if (request.useOnDiskImage)
            {
                QFile imageFile(request.moduleFilePath);
                if (!imageFile.open(QIODevice::ReadOnly))
                {
                    outcome.abortReason = QStringLiteral("打不开模块文件 %1：%2")
                        .arg(request.moduleFilePath)
                        .arg(imageFile.errorString());
                }
                else
                {
                    const QByteArray kFileBytes = imageFile.readAll();
                    diskImageMap = ksword::evidence::buildPeImageMap(
                        reinterpret_cast<const std::uint8_t*>(kFileBytes.constData()),
                        static_cast<std::size_t>(kFileBytes.size()),
                        request.moduleBaseAddress);
                }
            }

            for (std::uint64_t pageIndex = 0; pageIndex < request.pageCount; ++pageIndex)
            {
                TamperPageResult pageResult;
                pageResult.virtualAddress = request.startAddress + pageIndex * kPageBytes;

                // Translate once; both physical reads on this page share the result.
                const ksword::ark::VirtualAddressTranslateResult kTranslation =
                    kClient.translateVirtualAddress(
                        request.processId, pageResult.virtualAddress, 0UL);
                if (kTranslation.io.ok && kTranslation.resolved)
                {
                    pageResult.physicalAddress = kTranslation.physicalAddress;
                    pageResult.physicalAddressValid = true;
                }
                else
                {
                    pageResult.translateFailureText = kTranslation.io.ok
                        ? QStringLiteral("驱动未返回物理地址，该页可能未驻留")
                        : QString::fromStdString(kTranslation.io.message);
                }

                std::vector<TamperRound> rounds;
                rounds.reserve(static_cast<std::size_t>(request.roundCount));
                for (int round = 0; round < request.roundCount; ++round)
                {
                    rounds.push_back(collectOneRound(
                        request,
                        kClient,
                        diskImageMap,
                        pageResult.virtualAddress,
                        pageResult.physicalAddress,
                        pageResult.physicalAddressValid));
                }
                pageResult.finding = analyzeTamperRounds(rounds);
                outcome.results.push_back(std::move(pageResult));
            }
            return outcome;
        }

        // verdictColorHex: semantic color for the verdict. Use a warning color instead of a neutral color when the verdict is undetermined
        // — it must be distinguishable from "no issue" at a glance, as that is the most easily misread part of this entire page.
        QString verdictColorHex(const TamperVerdict verdict)
        {
            switch (verdict)
            {
            case TamperVerdict::kConsistent:
                return ksword_theme::successHex();
            case TamperVerdict::kCpuViewRedirected:
            case TamperVerdict::kUnexplainedDisagreement:
                return ksword_theme::errorHex();
            case TamperVerdict::kUserModeViewDiffers:
            case TamperVerdict::kLiveDiffersFromReference:
                return ksword_theme::warningHex();
            case TamperVerdict::kInconclusive:
                break;
            }
            return ksword_theme::warningHex();
        }
    }

    TamperDetectionPage::TamperDetectionPage(QWidget* const parent)
        : QWidget(parent)
    {
        buildUi();
        wireSignals();
        refreshChannelAvailability();
        updateRunButtonState();
    }

    TamperDetectionPage::~TamperDetectionPage() = default;

    void TamperDetectionPage::buildUi()
    {
        QVBoxLayout* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(8, 8, 8, 8);
        rootLayout->setSpacing(8);

        QLabel* introLabel = new QLabel(this);
        introLabel->setWordWrap(true);
        introLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        introLabel->setText(QStringLiteral("对同一段内存同时走多条相互独立的读取路径，逐页互比。R3 / R0 虚拟 / R0 物理都经过 CPU 的地址翻译，会被 SLAT / EPT 一起影响；DDMA 走磁盘控制器的总线主控 DMA，不经过 CPU 页表。CPU 侧与 DMA 侧对同一物理页给出不同答案，就是内存被重定向的直接证据——这类隐藏用“内存 vs 磁盘映像”的比对抓不到，因为影子页里放的正是磁盘上那份原始字节。"));
        rootLayout->addWidget(introLabel);

        QGridLayout* formLayout = new QGridLayout();
        formLayout->setHorizontalSpacing(8);
        formLayout->setVerticalSpacing(6);

        formLayout->addWidget(new QLabel(QStringLiteral("扫描目标"), this), 0, 0);
        targetCombo_ = new QComboBox(this);
        targetCombo_->setToolTip(QStringLiteral("选择要检查的模块，或选“自定义范围”后在右侧填写起始地址。"));
        formLayout->addWidget(targetCombo_, 0, 1);

        rangeStartEdit_ = new QLineEdit(this);
        rangeStartEdit_->setPlaceholderText(QStringLiteral("起始地址，默认十六进制"));
        rangeStartEdit_->setClearButtonEnabled(true);
        formLayout->addWidget(rangeStartEdit_, 0, 2);

        formLayout->addWidget(new QLabel(QStringLiteral("最多扫描页数"), this), 0, 3);
        maxPageSpin_ = new QSpinBox(this);
        maxPageSpin_->setRange(1, kHardMaxPages);
        maxPageSpin_->setValue(kDefaultMaxPages);
        maxPageSpin_->setToolTip(QStringLiteral("DDMA 每页要做四次磁盘往返（备份扇区→写→读→还原），页数乘轮数直接决定耗时。先用小范围定位，再扩大。"));
        formLayout->addWidget(maxPageSpin_, 0, 4);

        formLayout->addWidget(new QLabel(QStringLiteral("采样轮数"), this), 1, 0);
        roundSpin_ = new QSpinBox(this);
        roundSpin_->setRange(2, 10);
        roundSpin_->setValue(3);
        roundSpin_->setToolTip(QStringLiteral("一轮无法把篡改和采样窗口内的正常写入分开，所以最少两轮。只有每一轮都不一致才会升为结论。"));
        formLayout->addWidget(roundSpin_, 1, 1);

        QHBoxLayout* pathLayout = new QHBoxLayout();
        pathLayout->setContentsMargins(0, 0, 0, 0);
        pathLayout->setSpacing(10);
        useUserModeCheck_ = new QCheckBox(QStringLiteral("R3 用户态读"), this);
        useKernelVirtualCheck_ = new QCheckBox(QStringLiteral("R0 虚拟地址读"), this);
        useKernelPhysicalCheck_ = new QCheckBox(QStringLiteral("R0 物理地址读"), this);
        useHvmCheck_ = new QCheckBox(QStringLiteral("HVM 私有页表窗口"), this);
        useDmaCheck_ = new QCheckBox(QStringLiteral("DDMA 物理读"), this);
        useUserModeCheck_->setChecked(true);
        useKernelVirtualCheck_->setChecked(true);
        useKernelPhysicalCheck_->setChecked(true);
        useHvmCheck_->setChecked(true);
        useDmaCheck_->setChecked(true);
        useDmaCheck_->setToolTip(QStringLiteral("唯一一条不经过 CPU 页表的路径。去掉它之后，剩下的几条会被同一个隐藏者一起骗过，这一页就只能抓到普通补丁了。"));
        useImageSectionCheck_ = new QCheckBox(QStringLiteral("节对象干净页"), this);
        useOnDiskImageCheck_ = new QCheckBox(QStringLiteral("磁盘映像"), this);
        useImageSectionCheck_->setToolTip(QStringLiteral("内存管理器自己持有的那份“这个映像本来该是什么样”，与磁盘文件是两个互相独立的来源：文件被一起改掉时它还在。仅对已映射的映像页有效。"));
        useOnDiskImageCheck_->setToolTip(QStringLiteral("模块文件按当前加载基址归一化后的字节。只有选中具体模块时可用（自定义范围没有对应的文件与基址）。零填充区、节间隙和不可归一化的范围会如实报成“不覆盖”，不会补 00 参与比较。"));
        pathLayout->addWidget(useUserModeCheck_);
        pathLayout->addWidget(useKernelVirtualCheck_);
        pathLayout->addWidget(useKernelPhysicalCheck_);
        pathLayout->addWidget(useHvmCheck_);
        pathLayout->addWidget(useDmaCheck_);
        pathLayout->addWidget(useImageSectionCheck_);
        pathLayout->addWidget(useOnDiskImageCheck_);
        pathLayout->addStretch(1);
        formLayout->addLayout(pathLayout, 1, 2, 1, 3);

        rootLayout->addLayout(formLayout);

        QHBoxLayout* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setSpacing(8);
        runButton_ = new QPushButton(QStringLiteral("开始交叉检查"), this);
        actionLayout->addWidget(runButton_);
        channelHintLabel_ = new QLabel(this);
        channelHintLabel_->setWordWrap(true);
        actionLayout->addWidget(channelHintLabel_, 1);
        rootLayout->addLayout(actionLayout);

        statusLabel_ = new QLabel(QStringLiteral("尚未执行。"), this);
        statusLabel_->setWordWrap(true);
        statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        rootLayout->addWidget(statusLabel_);

        QSplitter* splitter = new QSplitter(Qt::Vertical, this);

        resultTable_ = new ks::ui::VisibleTableWidget(splitter);
        resultTable_->setColumnCount(5);
        resultTable_->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("虚拟地址"),
            QStringLiteral("物理地址"),
            QStringLiteral("结论"),
            QStringLiteral("分歧对数"),
            QStringLiteral("说明") });
        resultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        resultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        resultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        resultTable_->setAlternatingRowColors(true);
        resultTable_->verticalHeader()->setVisible(false);
        resultTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        splitter->addWidget(resultTable_);

        detailText_ = new QPlainTextEdit(splitter);
        detailText_->setReadOnly(true);
        detailText_->setPlaceholderText(QStringLiteral("选中上方任意一行查看该页每条路径的状态与逐对分歧。"));
        splitter->addWidget(detailText_);

        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        rootLayout->addWidget(splitter, 1);
    }

    void TamperDetectionPage::wireSignals()
    {
        connect(runButton_, &QPushButton::clicked, this, [this]() { startScan(); });
        connect(resultTable_, &QTableWidget::itemSelectionChanged, this,
            [this]() { renderSelectedDetail(); });
        connect(targetCombo_, &QComboBox::currentIndexChanged, this,
            [this](int) { updateRunButtonState(); });
        const auto kPathToggled = [this](bool) { updateRunButtonState(); };
        connect(useUserModeCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useKernelVirtualCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useKernelPhysicalCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useHvmCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useDmaCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useImageSectionCheck_, &QCheckBox::toggled, this, kPathToggled);
        connect(useOnDiskImageCheck_, &QCheckBox::toggled, this, kPathToggled);
    }

    void TamperDetectionPage::setAttachedProcess(
        const std::uint32_t processId, const QString& processName)
    {
        attachedPid_ = processId;
        attachedProcessName_ = processName;
        updateRunButtonState();
    }

    void TamperDetectionPage::setModuleCandidates(const std::vector<ModuleCandidate>& candidates)
    {
        moduleCandidates_ = candidates;
        const QString kPreviousText = targetCombo_->currentText();
        {
            const QSignalBlocker kBlocker(targetCombo_);
            targetCombo_->clear();
            targetCombo_->addItem(QStringLiteral("自定义范围"), QVariant::fromValue(-1));
            for (int index = 0; index < static_cast<int>(candidates.size()); ++index)
            {
                targetCombo_->addItem(candidates[static_cast<std::size_t>(index)].displayText, index);
            }
            const int kRestoredIndex = targetCombo_->findText(kPreviousText);
            targetCombo_->setCurrentIndex(kRestoredIndex >= 0 ? kRestoredIndex : 0);
        }
        updateRunButtonState();
    }

    void TamperDetectionPage::refreshChannelAvailability()
    {
        QString reason;
        const bool kDdmaUsable = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        useDmaCheck_->setEnabled(kDdmaUsable);

        // HVM availability is independent of DDMA and must be queried separately. When the window is not
        // calibrated, this channel still returns data (falling back to MmCopyMemory), but it is no longer
        // independent from R0. Since consistency between them cannot exclude memory manager hooking, it is marked
        // as unavailable rather than continuing to participate in comparisons with a silently failing property.
        QString hvmReason;
        const bool kHvmUsable = ksword::memory_backend::isHvmMemoryUsable(&hvmReason);
        useHvmCheck_->setEnabled(kHvmUsable);
        if (!kHvmUsable)
        {
            useHvmCheck_->setChecked(false);
            useHvmCheck_->setToolTip(hvmReason);
        }
        else
        {
            useHvmCheck_->setToolTip(QStringLiteral("改写自有页表项指向目标帧，整条路径不调用文档化的内存管理器例程。它同样受 SLAT / EPT 约束，与 R0 分歧说明的是内存管理器被挂了钩，不是重定向。"));
        }
        if (kDdmaUsable)
        {
            channelHintLabel_->setText(QStringLiteral("DDMA 通道就绪，本页可以判定 SLAT / EPT 级别的重定向。"));
            channelHintLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        else
        {
            // It must be explicitly stated which class of conclusions is lost without DDMA, rather than simply stating it is unavailable.
            // Otherwise, users might assume this page can still answer the same question even when DDMA is unavailable.
            useDmaCheck_->setChecked(false);
            channelHintLabel_->setText(
                QStringLiteral("DDMA 暂不可用：%1。没有这条路径时，其余几条都经过 CPU 页表、会被同一个隐藏者一起骗过，本页只能发现普通补丁，无法判定 SLAT / EPT 重定向。").arg(reason));
            channelHintLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        updateRunButtonState();
    }

    void TamperDetectionPage::updateRunButtonState()
    {
        // Disk images require both a file path and a load base address. Since 'custom range'
        // lacks both, we disable the option and explain why, rather than letting it run and
        // report numerous 'no-coverage' errors that users might mistake for normalization issues.
        const int kTargetIndex = targetCombo_->currentData().toInt();
        const bool kModuleSelected =
            kTargetIndex >= 0 && kTargetIndex < static_cast<int>(moduleCandidates_.size());
        useOnDiskImageCheck_->setEnabled(kModuleSelected);
        if (!kModuleSelected)
        {
            useOnDiskImageCheck_->setChecked(false);
        }

        int selectedPathCount = 0;
        selectedPathCount += useUserModeCheck_->isChecked() ? 1 : 0;
        selectedPathCount += useKernelVirtualCheck_->isChecked() ? 1 : 0;
        selectedPathCount += useKernelPhysicalCheck_->isChecked() ? 1 : 0;
        selectedPathCount += (useHvmCheck_->isEnabled() && useHvmCheck_->isChecked()) ? 1 : 0;
        selectedPathCount += (useDmaCheck_->isEnabled() && useDmaCheck_->isChecked()) ? 1 : 0;
        selectedPathCount += useImageSectionCheck_->isChecked() ? 1 : 0;
        selectedPathCount += (useOnDiskImageCheck_->isEnabled()
            && useOnDiskImageCheck_->isChecked()) ? 1 : 0;

        const bool kReady = (attachedPid_ != 0) && (selectedPathCount >= 2) && !scanInFlight_;
        runButton_->setEnabled(kReady);
        if (attachedPid_ == 0)
        {
            runButton_->setToolTip(QStringLiteral("请先在顶部附加一个进程。"));
        }
        else if (selectedPathCount < 2)
        {
            runButton_->setToolTip(QStringLiteral("至少要勾选两条路径才能互比。一条路径无从比对。"));
        }
        else
        {
            runButton_->setToolTip(QStringLiteral("对选中范围逐页采样并互比。"));
        }
    }

    bool TamperDetectionPage::parseScanRange(
        std::uint64_t& startOut, std::uint64_t& pageCountOut, QString& errorOut) const
    {
        const int kTargetIndex = targetCombo_->currentData().toInt();
        const std::uint64_t kMaxPages = static_cast<std::uint64_t>(maxPageSpin_->value());

        if (kTargetIndex >= 0 && kTargetIndex < static_cast<int>(moduleCandidates_.size()))
        {
            const ModuleCandidate& candidate =
                moduleCandidates_[static_cast<std::size_t>(kTargetIndex)];
            startOut = candidate.baseAddress & ~(kPageBytes - 1ULL);
            const std::uint64_t kModulePages =
                (candidate.sizeBytes + kPageBytes - 1ULL) / kPageBytes;
            pageCountOut = (std::min)(kMaxPages, (std::max)(std::uint64_t{1}, kModulePages));
            return true;
        }

        const auto kParsed = ksword::evidence::parseNumericText(
            rangeStartEdit_->text().trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::kHexadecimal);
        if (!kParsed.ok)
        {
            errorOut = QStringLiteral("起始地址解析失败。无前缀按十六进制解释，也可写 0x 前缀。");
            return false;
        }
        startOut = kParsed.value & ~(kPageBytes - 1ULL);
        pageCountOut = kMaxPages;
        return true;
    }

    void TamperDetectionPage::startScan()
    {
        if (scanInFlight_)
        {
            return;
        }

        TamperScanRequest request;
        QString rangeError;
        if (!parseScanRange(request.startAddress, request.pageCount, rangeError))
        {
            statusLabel_->setText(rangeError);
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
            return;
        }

        request.processId = attachedPid_;
        request.roundCount = roundSpin_->value();
        request.useUserMode = useUserModeCheck_->isChecked();
        request.useKernelVirtual = useKernelVirtualCheck_->isChecked();
        request.useKernelPhysical = useKernelPhysicalCheck_->isChecked();
        request.useHvm = useHvmCheck_->isEnabled() && useHvmCheck_->isChecked();
        request.useDma = useDmaCheck_->isEnabled() && useDmaCheck_->isChecked();
        request.useImageSection = useImageSectionCheck_->isChecked();
        request.useOnDiskImage =
            useOnDiskImageCheck_->isEnabled() && useOnDiskImageCheck_->isChecked();
        const int kSelectedTargetIndex = targetCombo_->currentData().toInt();
        if (kSelectedTargetIndex >= 0
            && kSelectedTargetIndex < static_cast<int>(moduleCandidates_.size()))
        {
            const ModuleCandidate& candidate =
                moduleCandidates_[static_cast<std::size_t>(kSelectedTargetIndex)];
            request.moduleBaseAddress = candidate.baseAddress;
            request.moduleFilePath = candidate.filePath;
        }
        // The session is copied by value into the request: during the worker thread's execution, DDMA page configurations may change, causing the
        // read reference to capture a half-new, half-old combination, meaning different pages in this round may use different temporary sectors.
        request.ddmaSession = ksword::memory_backend::currentDdmaSession();

        scanInFlight_ = true;
        ++scanGeneration_;
        const std::uint64_t kGeneration = scanGeneration_;
        updateRunButtonState();
        statusLabel_->setText(QStringLiteral("正在采样：%1 页 × %2 轮…")
            .arg(request.pageCount)
            .arg(request.roundCount));
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));

        QPointer<TamperDetectionPage> guardedSelf(this);
        QRunnable* const kTask = QRunnable::create([guardedSelf, request, kGeneration]() {
            const ScanOutcome kOutcome = runScan(request);
            const auto kSharedResults =
                std::make_shared<std::vector<TamperPageResult>>(kOutcome.results);
            const QString kAbortReason = kOutcome.abortReason;
            QTimer::singleShot(0, QCoreApplication::instance(),
                [guardedSelf, kSharedResults, kAbortReason, kGeneration]() {
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }
                    // Generation expired: a new scan was initiated during the previous one, so discard old results.
                    // Appending them would cause the UI to display a range that does not match what the user just submitted.
                    if (guardedSelf->scanGeneration_ != kGeneration)
                    {
                        return;
                    }
                    guardedSelf->scanInFlight_ = false;
                    guardedSelf->applyScanResults(*kSharedResults);
                    if (!kAbortReason.isEmpty())
                    {
                        // When the full round hasn't completed, the reason must override the summary: the summary's
                        // "Consistent N" is calculated based on a result missing one reference in this case.
                        guardedSelf->statusLabel_->setText(
                            QStringLiteral("%1 %2")
                                .arg(kAbortReason)
                                .arg(guardedSelf->statusLabel_->text()));
                        guardedSelf->statusLabel_->setStyleSheet(
                            QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
                    }
                    guardedSelf->updateRunButtonState();
                });
            });
        kTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(kTask);
    }

    void TamperDetectionPage::applyScanResults(const std::vector<TamperPageResult>& results)
    {
        results_ = results;
        resultTable_->setRowCount(static_cast<int>(results.size()));

        int redirectedCount = 0;
        int inconclusiveCount = 0;
        int consistentCount = 0;
        int otherFindingCount = 0;

        for (int row = 0; row < static_cast<int>(results.size()); ++row)
        {
            const TamperPageResult& pageResult = results[static_cast<std::size_t>(row)];
            const TamperVerdict kVerdict = pageResult.finding.verdict;
            switch (kVerdict)
            {
            case TamperVerdict::kCpuViewRedirected: ++redirectedCount; break;
            case TamperVerdict::kInconclusive: ++inconclusiveCount; break;
            case TamperVerdict::kConsistent: ++consistentCount; break;
            default: ++otherFindingCount; break;
            }

            resultTable_->setItem(row, 0, new QTableWidgetItem(
                QStringLiteral("0x%1").arg(pageResult.virtualAddress, 16, 16, QChar('0'))
                    .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"))));
            resultTable_->setItem(row, 1, new QTableWidgetItem(
                pageResult.physicalAddressValid
                    ? QStringLiteral("0x%1").arg(pageResult.physicalAddress, 12, 16, QChar('0'))
                          .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"))
                    : QStringLiteral("-")));

            QTableWidgetItem* const kVerdictItem =
                new QTableWidgetItem(QString::fromUtf8(tamperVerdictName(kVerdict)));
            kVerdictItem->setForeground(QColor(verdictColorHex(kVerdict)));
            resultTable_->setItem(row, 2, kVerdictItem);

            resultTable_->setItem(row, 3, new QTableWidgetItem(
                QString::number(pageResult.finding.disagreements.size())));

            QString noteText = QString::fromStdString(pageResult.finding.inconclusiveReason);
            if (noteText.isEmpty() && !pageResult.translateFailureText.isEmpty())
            {
                noteText = pageResult.translateFailureText;
            }
            if (noteText.isEmpty() && kVerdict == TamperVerdict::kCpuViewRedirected)
            {
                noteText = pageResult.finding.cpuMatchesStaticReference
                    ? QStringLiteral("CPU 侧与静态参考一致、DMA 侧不同：隐藏者正在给 CPU 看原始字节")
                    : QStringLiteral("CPU 侧与 DMA 侧持续不一致");
            }
            resultTable_->setItem(row, 4, new QTableWidgetItem(noteText));
        }
        resultTable_->resizeColumnsToContents();
        resultTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

        // In the summary, list "Undetermined" separately and ensure it is not visually grouped with "Consistent" to avoid misinterpretation as a positive result.
        // This means the page was not checked, not that the page is fine.
        QString summary = QStringLiteral("共 %1 页：一致 %2，重定向 %3，其它差异 %4，无法判定 %5。")
            .arg(results.size())
            .arg(consistentCount)
            .arg(redirectedCount)
            .arg(otherFindingCount)
            .arg(inconclusiveCount);
        if (redirectedCount > 0)
        {
            summary += QStringLiteral(" 存在 CPU 视图被重定向的页——这是 SLAT / EPT 级别隐藏的直接证据，请逐页查看明细。");
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::errorHex()));
        }
        else if (inconclusiveCount > 0)
        {
            summary += QStringLiteral(" 无法判定的页不代表干净，只代表没能在这些页上取到足够的可比对读数。");
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        else
        {
            statusLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        statusLabel_->setText(summary);

        if (!results.empty())
        {
            resultTable_->selectRow(0);
        }
        renderSelectedDetail();
    }

    void TamperDetectionPage::renderSelectedDetail()
    {
        const int kRow = resultTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(results_.size()))
        {
            detailText_->clear();
            return;
        }
        const TamperPageResult& pageResult = results_[static_cast<std::size_t>(kRow)];
        const TamperFinding& finding = pageResult.finding;

        QStringList lines;
        lines << QStringLiteral("虚拟地址 0x%1")
                     .arg(pageResult.virtualAddress, 16, 16, QChar('0')).toUpper();
        lines << QStringLiteral("结论：%1").arg(QString::fromUtf8(tamperVerdictName(finding.verdict)));
        lines << QStringLiteral("可比对轮数：%1").arg(finding.comparableRoundCount);
        if (!finding.inconclusiveReason.empty())
        {
            lines << QStringLiteral("未能判定的原因：%1")
                         .arg(QString::fromStdString(finding.inconclusiveReason));
        }

        lines << QString();
        lines << QStringLiteral("各路径最后一轮的状态：");
        for (const TamperViewSample& sample : finding.lastRoundStatus)
        {
            QString line = QStringLiteral("  %1 —— %2")
                .arg(QString::fromUtf8(tamperReadPathName(sample.path)))
                .arg(QString::fromUtf8(tamperSampleStatusName(sample.status)));
            if (!sample.failureText.empty())
            {
                line += QStringLiteral("（%1）").arg(QString::fromStdString(sample.failureText));
            }
            lines << line;
        }

        if (finding.disagreements.empty())
        {
            lines << QString();
            lines << QStringLiteral("未观察到任何一对路径之间的字节差异。");
        }
        else
        {
            lines << QString();
            lines << QStringLiteral("逐对分歧：");
            for (const TamperDisagreement& disagreement : finding.disagreements)
            {
                lines << QStringLiteral("  %1 ↔ %2：%3 / %4 轮不一致，首个不同在页内偏移 0x%5，两侧字节 %6 / %7，共 %8 字节不同")
                    .arg(QString::fromUtf8(tamperReadPathName(disagreement.left)))
                    .arg(QString::fromUtf8(tamperReadPathName(disagreement.right)))
                    .arg(disagreement.disagreeingRounds)
                    .arg(disagreement.comparableRounds)
                    .arg(QString::number(disagreement.firstDifferingOffset, 16).toUpper())
                    .arg(QStringLiteral("%1").arg(disagreement.leftByte, 2, 16, QChar('0')).toUpper())
                    .arg(QStringLiteral("%1").arg(disagreement.rightByte, 2, 16, QChar('0')).toUpper())
                    .arg(disagreement.differingByteCount);
            }
        }
        detailText_->setPlainText(lines.join(QLatin1Char('\n')));
    }
}
