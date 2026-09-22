#include "ThreadAffinityMenu.h"

#include "../internationalization/LanguageManager.h"
#include "../../../shared/ThreadAffinityR3.h"
#include "../Theme.h"

#include <QAction>
#include <QHBoxLayout>
#include <QMenu>
#include <QSignalBlocker>
#include <QStyle>
#include <QToolButton>
#include <QWidget>
#include <QWidgetAction>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
    QString affinityText(const char* const key, const QString& fallback)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallback);
    }

    QString detailTextForResult(const bool success, const std::string& detailText)
    {
        if (success)
        {
            return affinityText(
                "process.thread.affinity.status.updated",
                QStringLiteral("线程亲和性已更新。"));
        }
        const QString kDetail = QString::fromStdString(detailText);
        return kDetail.isEmpty()
            ? affinityText(
                "process.thread.affinity.status.failed",
                QStringLiteral("线程亲和性设置失败。"))
            : affinityText(
                "process.thread.affinity.status.failed_with_detail",
                QStringLiteral("线程亲和性设置失败：%1"))
                  .arg(kDetail);
    }

    QString processorDisplayText(
        const ksword::thread_affinity_r3::LogicalProcessorState& processor,
        const bool includeProcessorGroup)
    {
        QString text = includeProcessorGroup
            ? QStringLiteral("G%1:L%2")
                  .arg(processor.coordinate.group)
                  .arg(processor.coordinate.logicalIndex)
            : QStringLiteral("L%1").arg(processor.coordinate.logicalIndex);
        if (!processor.topologyLabel.empty())
        {
            text += QStringLiteral("\n") + QString::fromStdString(processor.topologyLabel);
        }
        return text;
    }

    bool hasMultipleProcessorGroups(
        const std::vector<ksword::thread_affinity_r3::LogicalProcessorState>& processors)
    {
        std::uint16_t firstGroup = 0U;
        bool hasFirstGroup = false;
        for (const auto& processor : processors)
        {
            if (!hasFirstGroup)
            {
                firstGroup = processor.coordinate.group;
                hasFirstGroup = true;
            }
            else if (processor.coordinate.group != firstGroup)
            {
                return true;
            }
        }
        return false;
    }
}

namespace ks::process
{
    QMenu* addThreadAffinitySubMenu(
        QMenu* const parentMenu,
        const QIcon& icon,
        const DWORD targetProcessId,
        const DWORD targetThreadId,
        const std::uint64_t targetThreadCreationTime100ns,
        const QString& menuStyle,
        ThreadAffinityMenuResultHandler resultHandler)
    {
        if (parentMenu == nullptr)
        {
            return nullptr;
        }

        QMenu* const kAffinityMenu = parentMenu->addMenu(
            icon,
            affinityText(
                "process.thread.menu.affinity",
                QStringLiteral("线程亲和性")));
        kAffinityMenu->setStyleSheet(menuStyle);
        kAffinityMenu->setToolTipsVisible(true);
        kAffinityMenu->setToolTip(
            affinityText(
                "process.thread.menu.affinity.tooltip",
                QStringLiteral("按逻辑处理器切换此线程的 CPU Set；蓝色按钮表示已启用。")));

        auto snapshot = std::make_shared<ksword::thread_affinity_r3::Snapshot>();
        std::string readDetailText;
        const bool kQueryOk = ksword::thread_affinity_r3::queryThreadAffinityState(
            targetThreadId,
            targetProcessId,
            targetThreadCreationTime100ns,
            snapshot.get(),
            &readDetailText);
        if (!kQueryOk)
        {
            kAffinityMenu->setEnabled(false);
            kAffinityMenu->setToolTip(
                affinityText(
                    "process.thread.menu.affinity.unavailable",
                    QStringLiteral("无法读取此线程的 CPU Set 亲和性。")) +
                (readDetailText.empty()
                    ? QString()
                    : QStringLiteral("\n") + QString::fromStdString(readDetailText)));
            return kAffinityMenu;
        }

        const bool kIncludeProcessorGroup = hasMultipleProcessorGroups(snapshot->processors);
        const QString kCoreButtonStyle = QStringLiteral(
            "QToolButton {"
            "  min-width:42px; min-height:28px; padding:2px 6px;"
            "  color:%1; background:transparent; border:1px solid %2; border-radius:4px;"
            "}"
            "QToolButton:hover { border-color:%3; background:%4; }"
            "QToolButton:checked { color:%5; background:%3; border-color:%3; }")
                .arg(ksword_theme::textPrimaryHex())
                .arg(ksword_theme::borderHex())
                .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
                .arg(ksword_theme::surfaceAltHex())
                .arg(ksword_theme::onAccentDynamicHex());

        QAction* const kFollowProcessAction = kAffinityMenu->addAction(
            affinityText(
                "process.thread.menu.affinity.follow_process",
                QStringLiteral("跟随进程 CPU Set")));
        kFollowProcessAction->setToolTip(
            affinityText(
                "process.thread.menu.affinity.follow_process.tooltip",
                QStringLiteral("清除线程单独的 CPU Set 选择，继续受所属进程和线程组约束。")));

        const auto kCoreButtons = std::make_shared<std::vector<QToolButton*>>(
            snapshot->processors.size(),
            nullptr);
        const auto kUpdateCoreButtons = [snapshot, kCoreButtons]()
        {
            const std::size_t kButtonCount = std::min(
                kCoreButtons->size(),
                snapshot->processors.size());
            for (std::size_t index = 0U; index < kButtonCount; ++index)
            {
                QToolButton* const kButton = (*kCoreButtons)[index];
                if (kButton == nullptr)
                {
                    continue;
                }
                const auto& processor = snapshot->processors[index];
                const QSignalBlocker kBlocker(kButton);
                kButton->setEnabled(processor.available);
                kButton->setChecked(processor.available && processor.selected);
                kButton->style()->unpolish(kButton);
                kButton->style()->polish(kButton);
                kButton->update();
            }
        };

        const auto kApplyRule = [snapshot,
                                    targetProcessId,
                                    targetThreadId,
                                    targetThreadCreationTime100ns,
                                    resultHandler,
                                    kUpdateCoreButtons](
                                   const ksword::thread_affinity_r3::Rule& rule)
        {
            std::string updateDetailText;
            const bool kSetOk = ksword::thread_affinity_r3::setThreadAffinityRule(
                targetThreadId,
                targetProcessId,
                targetThreadCreationTime100ns,
                rule,
                &updateDetailText);
            if (kSetOk)
            {
                ksword::thread_affinity_r3::Snapshot refreshedSnapshot;
                std::string refreshDetailText;
                if (ksword::thread_affinity_r3::queryThreadAffinityState(
                        targetThreadId,
                        targetProcessId,
                        targetThreadCreationTime100ns,
                        &refreshedSnapshot,
                        &refreshDetailText))
                {
                    *snapshot = std::move(refreshedSnapshot);
                    kUpdateCoreButtons();
                }
                else
                {
                    updateDetailText = refreshDetailText;
                }
            }
            if (resultHandler)
            {
                resultHandler(kSetOk, detailTextForResult(kSetOk, updateDetailText));
            }
        };

        QObject::connect(kFollowProcessAction, &QAction::triggered, kAffinityMenu,
            [kApplyRule]()
            {
                ksword::thread_affinity_r3::Rule rule;
                rule.followProcessCpuSets = true;
                kApplyRule(rule);
            });

        constexpr std::size_t kAffinityMatrixColumnCount = 6U;
        for (std::size_t rowStart = 0U;
             rowStart < snapshot->processors.size();
             rowStart += kAffinityMatrixColumnCount)
        {
            QWidgetAction* const kRowAction = new QWidgetAction(kAffinityMenu);
            QWidget* const kRowWidget = new QWidget(kAffinityMenu);
            QHBoxLayout* const kRowLayout = new QHBoxLayout(kRowWidget);
            kRowLayout->setContentsMargins(8, 3, 8, 3);
            kRowLayout->setSpacing(6);
            const std::size_t kRowEnd = std::min(
                rowStart + kAffinityMatrixColumnCount,
                snapshot->processors.size());
            for (std::size_t index = rowStart; index < kRowEnd; ++index)
            {
                const auto kCoordinate = snapshot->processors[index].coordinate;
                QToolButton* const kCoreButton = new QToolButton(kRowWidget);
                kCoreButton->setText(processorDisplayText(snapshot->processors[index], kIncludeProcessorGroup));
                kCoreButton->setCheckable(true);
                kCoreButton->setAutoRaise(false);
                kCoreButton->setFocusPolicy(Qt::NoFocus);
                kCoreButton->setStyleSheet(kCoreButtonStyle);
                kCoreButton->setToolTip(
                    affinityText(
                        "process.thread.menu.affinity.core_tooltip",
                        QStringLiteral("%1；点击切换此线程的 CPU Set。"))
                        .arg(processorDisplayText(snapshot->processors[index], kIncludeProcessorGroup)) +
                    (snapshot->processors[index].constrainedByThreadOrProcessAffinity
                        ? QStringLiteral("\n") + affinityText(
                            "process.thread.menu.affinity.constraint_tooltip",
                            QStringLiteral("受线程组或所属进程的 CPU Set 规则约束，当前不可调度到此处理器。"))
                        : QString()));
                kRowLayout->addWidget(kCoreButton);
                (*kCoreButtons)[index] = kCoreButton;
                QObject::connect(kCoreButton, &QToolButton::clicked, kAffinityMenu,
                    [snapshot, kCoordinate, kCoreButton, kApplyRule, kUpdateCoreButtons](const bool enabled)
                    {
                        ksword::thread_affinity_r3::Rule nextRule;
                        if (snapshot->followsProcessCpuSets)
                        {
                            for (const auto& processor : snapshot->processors)
                            {
                                if (processor.available)
                                {
                                    nextRule.processors.push_back(processor.coordinate);
                                }
                            }
                        }
                        else
                        {
                            for (const auto& processor : snapshot->processors)
                            {
                                if (processor.available && processor.selected)
                                {
                                    nextRule.processors.push_back(processor.coordinate);
                                }
                            }
                        }
                        auto coordinateIt = std::find(
                            nextRule.processors.begin(),
                            nextRule.processors.end(),
                            kCoordinate);
                        if (enabled && coordinateIt == nextRule.processors.end())
                        {
                            nextRule.processors.push_back(kCoordinate);
                        }
                        else if (!enabled && coordinateIt != nextRule.processors.end())
                        {
                            nextRule.processors.erase(coordinateIt);
                        }
                        ksword::thread_affinity_r3::normalizeCoordinates(&nextRule.processors);
                        if (nextRule.processors.empty())
                        {
                            const QSignalBlocker kBlocker(kCoreButton);
                            kCoreButton->setChecked(true);
                            kUpdateCoreButtons();
                            return;
                        }
                        kApplyRule(nextRule);
                    });
            }
            kRowLayout->addStretch(1);
            kRowAction->setDefaultWidget(kRowWidget);
            kAffinityMenu->addAction(kRowAction);
        }

        kFollowProcessAction->setEnabled(std::any_of(
            snapshot->processors.begin(),
            snapshot->processors.end(),
            [](const ksword::thread_affinity_r3::LogicalProcessorState& processor)
            {
                return processor.available;
            }));
        kUpdateCoreButtons();
        return kAffinityMenu;
    }
}
