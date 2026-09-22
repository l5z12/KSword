#include "SoundSourcePage.h"

#include "../../Theme.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHideEvent>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QRunnable>
#include <QSet>
#include <QShowEvent>
#include <QTableWidget>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>

// ============================================================
// SoundSourcePage.cpp
// Purpose:
// - Display the real-time R3 conclusion of 'who is making sound';
// - Display multi-source identity verification of session PIDs by R0.
// - Control high-density evidence table via A/B/C complementary column groups.
// ============================================================

namespace
{
    constexpr int kAutoRefreshIntervalMs = 1500;
    constexpr std::int64_t kRecentAudibleRetentionMs = 5000;

    enum SoundSourceColumn
    {
        kColumnVerdict = 0,
        kColumnProcess,
        kColumnPid,
        kColumnPeakMaximum,
        kColumnPeakAverage,
        kColumnSessionState,
        kColumnEndpoint,
        kColumnEndpointPeak,
        kColumnEndpointRole,
        kColumnSessionVolume,
        kColumnMuted,
        kColumnSessionName,
        kColumnSessionInstance,
        kColumnImagePath,
        kColumnCreationTime,
        kColumnKernelVerdict,
        kColumnKernelSources,
        kColumnKernelConfidence,
        kColumnKernelAnomaly,
        kColumnKernelObjects,
        kColumnEvidenceDetail,
        kColumnCount
    };

    // tableHeaders: Centralize column headers to prevent misalignment between column indices and display text.
    QStringList tableHeaders()
    {
        return {
            QStringLiteral("结论"),
            QStringLiteral("进程"),
            QStringLiteral("PID"),
            QStringLiteral("会话峰值"),
            QStringLiteral("平均峰值"),
            QStringLiteral("会话状态"),
            QStringLiteral("输出端点"),
            QStringLiteral("端点峰值"),
            QStringLiteral("默认角色"),
            QStringLiteral("会话音量"),
            QStringLiteral("静音"),
            QStringLiteral("会话名称"),
            QStringLiteral("会话实例"),
            QStringLiteral("映像路径"),
            QStringLiteral("R3 创建时间"),
            QStringLiteral("R0 结论"),
            QStringLiteral("R0 来源"),
            QStringLiteral("R0 置信度"),
            QStringLiteral("R0 异常"),
            QStringLiteral("R0 对象"),
            QStringLiteral("证据说明")
        };
    }

    // kernelSourceText: Expands shared protocol source bits into a human-readable matrix.
    QString kernelSourceText(const std::uint32_t sourceMask)
    {
        QStringList sourceNames;
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U)
        {
            sourceNames.push_back(QStringLiteral("Public API"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U)
        {
            sourceNames.push_back(QStringLiteral("ActiveProcessLinks"));
        }
        if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U)
        {
            sourceNames.push_back(QStringLiteral("PspCidTable"));
        }
        return sourceNames.isEmpty()
            ? QStringLiteral("不可用")
            : sourceNames.join(QStringLiteral(" + "));
    }

    // percentText: Converts audio volume from 0.0~1.0 to a compact percentage.
    QString percentText(const float value, const int decimals)
    {
        return QStringLiteral("%1%")
            .arg(static_cast<double>(value) * 100.0, 0, 'f', decimals);
    }

    // addressText: 0 indicates the field is unavailable; non-zero values are displayed in stable hexadecimal format.
    QString addressText(const std::uint64_t address)
    {
        if (address == 0U)
        {
            return QStringLiteral("不可用");
        }
        return QStringLiteral("0x%1").arg(address, 0, 16).toUpper();
    }
}

namespace ks::misc
{
    SoundSourcePage::SoundSourcePage(
        const std::uint32_t processIdFilter,
        const std::uint64_t expectedCreationTime100ns,
        QWidget* const parent)
        : QWidget(parent)
        , processIdFilter_(processIdFilter)
        , expectedCreationTime100ns_(expectedCreationTime100ns)
    {
        initializeUi();
        initializeConnections();
        applyColumnPreset(ColumnPreset::kOverview);
        applyThemeStyle();
    }

    void SoundSourcePage::showEvent(QShowEvent* const event)
    {
        QWidget::showEvent(event);
        if (autoRefreshCheck_ != nullptr &&
            autoRefreshCheck_->isChecked() &&
            refreshTimer_ != nullptr)
        {
            refreshTimer_->start();
        }
        if (records_.empty() && !refreshing_)
        {
            requestRefresh(false);
        }
    }

    void SoundSourcePage::hideEvent(QHideEvent* const event)
    {
        if (refreshTimer_ != nullptr)
        {
            refreshTimer_->stop();
        }
        QWidget::hideEvent(event);
    }

    void SoundSourcePage::changeEvent(QEvent* const event)
    {
        QWidget::changeEvent(event);
        if (event != nullptr &&
            (event->type() == QEvent::PaletteChange ||
             event->type() == QEvent::StyleChange ||
             event->type() == QEvent::ApplicationPaletteChange))
        {
            applyThemeStyle();
        }
    }

    void SoundSourcePage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(8);

        titleLabel_ = new QLabel(
            processIdFilter_ == 0U
                ? QStringLiteral("声音来源")
                : QStringLiteral("当前进程的声音来源"),
            this);
        titleLabel_->setToolTip(
            QStringLiteral("R3 采样 Core Audio 会话峰值、状态、音量与端点；R0 多源交叉核验会话 PID，只佐证进程身份，不读取或修改音频流。"));
        rootLayout->addWidget(titleLabel_);

        auto* toolbarLayout = new QHBoxLayout();
        toolbarLayout->setSpacing(6);
        refreshButton_ = new QToolButton(this);
        refreshButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        refreshButton_->setToolTip(QStringLiteral("立即重新采样声音来源，并重试 R0 证据"));
        toolbarLayout->addWidget(refreshButton_);

        autoRefreshCheck_ = new QCheckBox(QStringLiteral("自动刷新"), this);
        autoRefreshCheck_->setChecked(true);
        autoRefreshCheck_->setToolTip(
            QStringLiteral("页面可见时每 1.5 秒执行一次短时峰值采样"));
        toolbarLayout->addWidget(autoRefreshCheck_);

        showSilentCheck_ = new QCheckBox(QStringLiteral("显示静默会话"), this);
        showSilentCheck_->setChecked(false);
        showSilentCheck_->setToolTip(
            QStringLiteral("显示当前未检测到波形的全部输出音频会话"));
        toolbarLayout->addWidget(showSilentCheck_);
        toolbarLayout->addSpacing(10);

        columnPresetGroup_ = new QButtonGroup(this);
        columnPresetGroup_->setExclusive(true);
        overviewPresetButton_ = new QToolButton(this);
        audioPresetButton_ = new QToolButton(this);
        kernelPresetButton_ = new QToolButton(this);
        const QList<QToolButton*> kPresetButtons = {
            overviewPresetButton_,
            audioPresetButton_,
            kernelPresetButton_
        };
        const QStringList kPresetNames = {
            QStringLiteral("A"),
            QStringLiteral("B"),
            QStringLiteral("C")
        };
        const QStringList kPresetTooltips = {
            QStringLiteral("A：发声进程概览"),
            QStringLiteral("B：Core Audio 会话与端点链路"),
            QStringLiteral("C：R0 多源进程身份核验证据")
        };
        for (int buttonIndex = 0; buttonIndex < kPresetButtons.size(); ++buttonIndex)
        {
            QToolButton* const kPresetButton = kPresetButtons.at(buttonIndex);
            kPresetButton->setText(kPresetNames.at(buttonIndex));
            kPresetButton->setCheckable(true);
            kPresetButton->setToolTip(kPresetTooltips.at(buttonIndex));
            kPresetButton->setFixedSize(30, 26);
            columnPresetGroup_->addButton(kPresetButton, buttonIndex);
            toolbarLayout->addWidget(kPresetButton);
        }
        toolbarLayout->addStretch(1);
        rootLayout->addLayout(toolbarLayout);

        summaryLabel_ = new QLabel(
            QStringLiteral("尚未采样声音来源。"),
            this);
        summaryLabel_->setWordWrap(true);
        rootLayout->addWidget(summaryLabel_);

        statusLabel_ = new QLabel(QStringLiteral("等待刷新"), this);
        statusLabel_->setWordWrap(true);
        rootLayout->addWidget(statusLabel_);

        table_ = new QTableWidget(this);
        table_->setColumnCount(kColumnCount);
        table_->setHorizontalHeaderLabels(tableHeaders());
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table_->setAlternatingRowColors(true);
        table_->setSortingEnabled(false);
        table_->verticalHeader()->setVisible(false);
        table_->horizontalHeader()->setSectionsMovable(true);
        table_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
        table_->horizontalHeader()->setToolTip(
            QStringLiteral("右键表头可逐列显示或隐藏；手动调整后进入自定义列布局"));
        rootLayout->addWidget(table_, 1);

        refreshTimer_ = new QTimer(this);
        refreshTimer_->setInterval(kAutoRefreshIntervalMs);
        refreshTimer_->setTimerType(Qt::CoarseTimer);
    }

    void SoundSourcePage::initializeConnections()
    {
        connect(refreshButton_, &QToolButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });
        connect(refreshTimer_, &QTimer::timeout, this, [this]()
        {
            requestRefresh(false);
        });
        connect(autoRefreshCheck_, &QCheckBox::toggled, this, [this](const bool enabled)
        {
            if (enabled && isVisible())
            {
                refreshTimer_->start();
            }
            else
            {
                refreshTimer_->stop();
            }
        });
        connect(showSilentCheck_, &QCheckBox::toggled, this, [this]()
        {
            rebuildTable();
        });
        connect(columnPresetGroup_, &QButtonGroup::idClicked, this, [this](const int presetId)
        {
            if (presetId == 0)
            {
                applyColumnPreset(ColumnPreset::kOverview);
            }
            else if (presetId == 1)
            {
                applyColumnPreset(ColumnPreset::kAudioPath);
            }
            else if (presetId == 2)
            {
                applyColumnPreset(ColumnPreset::kKernelEvidence);
            }
        });
        connect(
            table_->horizontalHeader(),
            &QHeaderView::customContextMenuRequested,
            this,
            [this](const QPoint& position)
            {
                showHeaderContextMenu(position);
            });
    }

    void SoundSourcePage::requestRefresh(const bool manualRequest)
    {
        if (refreshing_)
        {
            return;
        }
        if (manualRequest)
        {
            // Manual refresh is an explicit user retry action, allowing re-probing of R0 that was previously unavailable.
            autoKernelProbeEnabled_ = true;
        }

        refreshing_ = true;
        refreshButton_->setEnabled(false);
        statusLabel_->setText(QStringLiteral("正在连续采样 Core Audio 会话峰值…"));
        const std::uint64_t kTicket = ++refreshTicket_;

        SoundSourceScanOptions options;
        options.processIdFilter = processIdFilter_;
        options.expectedCreationTime100ns = expectedCreationTime100ns_;
        options.includeKernelEvidence = autoKernelProbeEnabled_;
        options.sampleCount = 6;
        options.sampleIntervalMs = 40;

        const QPointer<SoundSourcePage> kGuardedPage(this);
        QRunnable* const kTask = QRunnable::create(
            [kGuardedPage, options, kTicket]()
            {
                SoundSourceScanResult result = detectSoundSources(options);
                SoundSourcePage* const kContextObject = kGuardedPage.data();
                if (kContextObject == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kContextObject,
                    [kGuardedPage, kTicket, result = std::move(result)]() mutable
                    {
                        if (!kGuardedPage.isNull())
                        {
                            kGuardedPage->applyScanResult(kTicket, result);
                        }
                    },
                    Qt::QueuedConnection);
            });
        QThreadPool::globalInstance()->start(kTask);
    }

    void SoundSourcePage::applyScanResult(
        const std::uint64_t ticket,
        const SoundSourceScanResult& result)
    {
        if (ticket != refreshTicket_)
        {
            return;
        }

        refreshing_ = false;
        refreshButton_->setEnabled(true);
        if (result.kernelAttempted && !result.kernelAvailable)
        {
            // Auto-refresh does not repeatedly trigger the R0 unavailable prompt; users can still explicitly retry when clicking refresh.
            autoKernelProbeEnabled_ = false;
        }

        std::vector<SoundSourceRecord> mergedRecords = result.records;
        mergeRecentHistory(mergedRecords);
        records_ = std::move(mergedRecords);
        rebuildTable();
        updateSummary(result);
    }

    void SoundSourcePage::mergeRecentHistory(
        std::vector<SoundSourceRecord>& records)
    {
        const std::int64_t kNowUnixMs = QDateTime::currentMSecsSinceEpoch();
        QSet<QString> currentKeys;
        for (SoundSourceRecord& record : records)
        {
            const QString kKey = recordKey(record);
            currentKeys.insert(kKey);
            if (record.currentlyAudible)
            {
                record.lastAudibleUnixMs = kNowUnixMs;
                recentRecords_.insert(kKey, record);
                continue;
            }

            const auto kRecentIterator = recentRecords_.constFind(kKey);
            if (kRecentIterator != recentRecords_.constEnd() &&
                kNowUnixMs - kRecentIterator->lastAudibleUnixMs <=
                    kRecentAudibleRetentionMs)
            {
                record.recentlyAudible = true;
                record.lastAudibleUnixMs = kRecentIterator->lastAudibleUnixMs;
                const double kElapsedSeconds =
                    static_cast<double>(kNowUnixMs - record.lastAudibleUnixMs) /
                    1000.0;
                record.verdictText =
                    QStringLiteral("最近发声（%1 秒前）").arg(kElapsedSeconds, 0, 'f', 1);
            }
        }

        for (auto iterator = recentRecords_.begin();
             iterator != recentRecords_.end();)
        {
            const std::int64_t kElapsedMs =
                kNowUnixMs - iterator->lastAudibleUnixMs;
            if (kElapsedMs > kRecentAudibleRetentionMs)
            {
                iterator = recentRecords_.erase(iterator);
                continue;
            }
            if (!currentKeys.contains(iterator.key()))
            {
                SoundSourceRecord recentRecord = iterator.value();
                recentRecord.currentlyAudible = false;
                recentRecord.recentlyAudible = true;
                const double kElapsedSeconds =
                    static_cast<double>(kElapsedMs) / 1000.0;
                recentRecord.verdictText =
                    QStringLiteral("最近发声（%1 秒前）").arg(kElapsedSeconds, 0, 'f', 1);
                records.push_back(std::move(recentRecord));
            }
            ++iterator;
        }

        std::stable_sort(
            records.begin(),
            records.end(),
            [](const SoundSourceRecord& left, const SoundSourceRecord& right)
            {
                if (left.currentlyAudible != right.currentlyAudible)
                {
                    return left.currentlyAudible;
                }
                if (left.recentlyAudible != right.recentlyAudible)
                {
                    return left.recentlyAudible;
                }
                return left.peakMaximum > right.peakMaximum;
            });
    }

    void SoundSourcePage::rebuildTable()
    {
        const bool kShowSilentSessions =
            showSilentCheck_ != nullptr && showSilentCheck_->isChecked();
        std::vector<const SoundSourceRecord*> visibleRecords;
        for (const SoundSourceRecord& record : records_)
        {
            if (kShowSilentSessions ||
                record.currentlyAudible ||
                record.recentlyAudible)
            {
                visibleRecords.push_back(&record);
            }
        }

        table_->setRowCount(static_cast<int>(visibleRecords.size()));
        for (int rowIndex = 0; rowIndex < static_cast<int>(visibleRecords.size()); ++rowIndex)
        {
            const SoundSourceRecord& record = *visibleRecords[static_cast<std::size_t>(rowIndex)];
            const QString kKernelObjectText =
                QStringLiteral("EPROCESS=%1；ObjectTable=%2")
                .arg(addressText(record.kernel.processObjectAddress))
                .arg(addressText(record.kernel.objectTableAddress));
            const QString kCreationTimeText = record.creationTime100ns == 0U
                ? QStringLiteral("不可用")
                : QStringLiteral("0x%1").arg(record.creationTime100ns, 0, 16).toUpper();
            const QString kAnomalyText = record.kernel.attempted
                ? QStringLiteral("0x%1").arg(record.kernel.anomalyFlags, 0, 16).toUpper()
                : QStringLiteral("未采样");
            const QString kConfidenceText = record.kernel.attempted
                ? QStringLiteral("%1").arg(record.kernel.confidence)
                : QStringLiteral("未采样");
            const QStringList kValues = {
                record.verdictText,
                record.processName,
                QString::number(record.processId),
                percentText(record.peakMaximum, 3),
                percentText(record.peakAverage, 3),
                record.stateText,
                record.endpointName,
                percentText(record.endpointPeakMaximum, 3),
                record.endpointRoleText,
                record.volumeAvailable
                    ? percentText(record.sessionVolume, 1)
                    : QStringLiteral("不可用"),
                record.muted ? QStringLiteral("是") : QStringLiteral("否"),
                record.sessionName,
                record.sessionInstanceId,
                record.imagePath,
                kCreationTimeText,
                record.kernel.attempted
                    ? record.kernel.statusText
                    : QStringLiteral("未采样"),
                record.kernel.attempted
                    ? kernelSourceText(record.kernel.sourceMask)
                    : QStringLiteral("未采样"),
                kConfidenceText,
                kAnomalyText,
                record.kernel.attempted
                    ? kKernelObjectText
                    : QStringLiteral("未采样"),
                record.kernel.detailText
            };

            for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
            {
                auto* item = new QTableWidgetItem(kValues.at(columnIndex));
                item->setToolTip(kValues.at(columnIndex));
                if (record.currentlyAudible)
                {
                    item->setBackground(ksword_theme::successBackgroundColor());
                }
                else if (record.recentlyAudible)
                {
                    item->setBackground(ksword_theme::warningBackgroundColor());
                }
                if (columnIndex == kColumnPid)
                {
                    item->setTextAlignment(Qt::AlignCenter);
                }
                table_->setItem(rowIndex, columnIndex, item);
            }
        }
        table_->resizeColumnsToContents();
    }

    void SoundSourcePage::updateSummary(const SoundSourceScanResult& result)
    {
        if (!result.audioQueryOk)
        {
            summaryLabel_->setText(
                processIdFilter_ == 0U
                    ? QStringLiteral("未能读取系统输出音频会话。")
                    : QStringLiteral("未能读取当前进程的输出音频会话。"));
            statusLabel_->setText(result.diagnosticText);
            return;
        }

        QSet<QString> currentSourceKeys;
        QSet<QString> recentSourceKeys;
        int activeSessionCount = 0;
        int corroboratedCount = 0;
        for (const SoundSourceRecord& record : records_)
        {
            const QString kSourceKey = record.processId == 0U
                ? record.processName
                : QString::number(record.processId);
            if (record.currentlyAudible)
            {
                currentSourceKeys.insert(kSourceKey);
            }
            else if (record.recentlyAudible)
            {
                recentSourceKeys.insert(kSourceKey);
            }
            if (record.sessionActive)
            {
                ++activeSessionCount;
            }
            if (record.currentlyAudible && record.kernel.corroborated)
            {
                ++corroboratedCount;
            }
        }

        if (processIdFilter_ != 0U &&
            currentSourceKeys.isEmpty() &&
            recentSourceKeys.isEmpty())
        {
            summaryLabel_->setText(
                QStringLiteral("当前进程在本次采样窗口内没有发声。"));
        }
        else
        {
            summaryLabel_->setText(
                QStringLiteral(
                    "确认正在发声：%1 个进程；最近发声：%2 个进程；活动会话：%3；其中 R0 多源一致：%4。")
                .arg(currentSourceKeys.size())
                .arg(recentSourceKeys.size())
                .arg(activeSessionCount)
                .arg(corroboratedCount));
        }

        QString statusText = QStringLiteral("Core Audio 采样窗口：%1 ms。")
            .arg(result.sampleWindowMs);
        if (result.kernelAttempted && !result.kernelAvailable)
        {
            statusText += QStringLiteral(
                " R0 当前不可用，自动刷新将继续保留 R3 检测；点击刷新按钮可重新尝试 R0。");
            if (!result.kernelDiagnosticText.isEmpty())
            {
                statusText += QStringLiteral(" ") + result.kernelDiagnosticText;
            }
        }
        else if (result.kernelAvailable)
        {
            statusText += QStringLiteral(" R0 进程身份核验已完成。");
            if (!result.kernelDiagnosticText.isEmpty())
            {
                statusText += QStringLiteral(" ") + result.kernelDiagnosticText;
            }
        }
        else
        {
            statusText += QStringLiteral(" 本轮没有需要 R0 核验的活动 PID。");
        }
        statusLabel_->setText(statusText);
    }

    void SoundSourcePage::applyColumnPreset(const ColumnPreset preset)
    {
        QSet<int> visibleColumns;
        if (preset == ColumnPreset::kOverview)
        {
            visibleColumns = {
                kColumnVerdict,
                kColumnProcess,
                kColumnPid,
                kColumnPeakMaximum,
                kColumnEndpoint,
                kColumnKernelVerdict
            };
        }
        else if (preset == ColumnPreset::kAudioPath)
        {
            visibleColumns = {
                kColumnVerdict,
                kColumnProcess,
                kColumnPid,
                kColumnPeakMaximum,
                kColumnSessionState,
                kColumnEndpoint,
                kColumnEndpointRole,
                kColumnSessionVolume,
                kColumnMuted,
                kColumnSessionName
            };
        }
        else if (preset == ColumnPreset::kKernelEvidence)
        {
            visibleColumns = {
                kColumnVerdict,
                kColumnProcess,
                kColumnPid,
                kColumnKernelVerdict,
                kColumnKernelSources,
                kColumnKernelConfidence,
                kColumnKernelAnomaly,
                kColumnKernelObjects,
                kColumnEvidenceDetail
            };
        }
        else
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
        {
            table_->setColumnHidden(
                columnIndex,
                !visibleColumns.contains(columnIndex));
        }
        columnPreset_ = preset;
        overviewPresetButton_->setChecked(preset == ColumnPreset::kOverview);
        audioPresetButton_->setChecked(preset == ColumnPreset::kAudioPath);
        kernelPresetButton_->setChecked(preset == ColumnPreset::kKernelEvidence);
        table_->resizeColumnsToContents();
    }

    void SoundSourcePage::showHeaderContextMenu(const QPoint& position)
    {
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        const QStringList kHeaders = tableHeaders();
        for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
        {
            QAction* const kColumnAction = menu.addAction(kHeaders.at(columnIndex));
            kColumnAction->setCheckable(true);
            kColumnAction->setChecked(!table_->isColumnHidden(columnIndex));
            kColumnAction->setData(columnIndex);
        }

        QAction* const kSelectedAction = menu.exec(
            table_->horizontalHeader()->mapToGlobal(position));
        if (kSelectedAction == nullptr)
        {
            return;
        }
        const int kColumnIndex = kSelectedAction->data().toInt();
        if (kColumnIndex < 0 || kColumnIndex >= kColumnCount)
        {
            return;
        }
        table_->setColumnHidden(kColumnIndex, !kSelectedAction->isChecked());
        setCustomColumnLayout();
    }

    void SoundSourcePage::setCustomColumnLayout()
    {
        columnPreset_ = ColumnPreset::kCustom;
        columnPresetGroup_->setExclusive(false);
        overviewPresetButton_->setChecked(false);
        audioPresetButton_->setChecked(false);
        kernelPresetButton_->setChecked(false);
        columnPresetGroup_->setExclusive(true);
    }

    void SoundSourcePage::applyThemeStyle()
    {
        titleLabel_->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryColorHex()));
        summaryLabel_->setStyleSheet(
            QStringLiteral("font-weight:600;color:%1;")
            .arg(ksword_theme::textPrimaryColorHex()));
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
            .arg(ksword_theme::textSecondaryColorHex()));

        const QString kPresetButtonStyle = QStringLiteral(
            "QToolButton{background:%1;color:%2;border:1px solid %3;border-radius:4px;}"
            "QToolButton:hover{border-color:%4;background:%5;}"
            "QToolButton:checked{background:%4;color:%6;border-color:%4;}"
            "QToolButton:disabled{color:%7;background:%1;border-color:%3;}")
            .arg(ksword_theme::surfaceColorHex())
            .arg(ksword_theme::textPrimaryColorHex())
            .arg(ksword_theme::borderColorHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::surfaceAltColorHex())
            .arg(ksword_theme::onAccentHex())
            .arg(ksword_theme::textDisabledColorHex());
        refreshButton_->setStyleSheet(kPresetButtonStyle);
        overviewPresetButton_->setStyleSheet(kPresetButtonStyle);
        audioPresetButton_->setStyleSheet(kPresetButtonStyle);
        kernelPresetButton_->setStyleSheet(kPresetButtonStyle);
    }

    QString SoundSourcePage::recordKey(
        const SoundSourceRecord& record) const
    {
        QString sessionKey = record.sessionInstanceId;
        if (sessionKey.trimmed().isEmpty())
        {
            sessionKey = record.sessionIdentifier;
        }
        if (sessionKey.trimmed().isEmpty())
        {
            sessionKey = QStringLiteral("pid:%1").arg(record.processId);
        }
        return record.endpointId + QStringLiteral("|") + sessionKey;
    }
}
