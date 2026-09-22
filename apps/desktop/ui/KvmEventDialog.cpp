#include "KvmEventDialog.h"

#include "KvmControl.h"
#include "../internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // Polling interval: fast enough to keep up with human vision, but not so fast as to saturate the driver-side state locks.
    constexpr int kPollIntervalMs = 500;
    // Maximum table rows: discard the oldest rows during long-term observation.
    constexpr int kMaxTableRows = 2000;

    // describeEventType: Translates the event type into a sentence.
    QString describeEventType(const unsigned long type)
    {
        switch (type)
        {
        case KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT:
            return ks::i18n::sourceText(QStringLiteral("VM-exit"));
        case KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION:
            return ks::i18n::sourceText(QStringLiteral("EPT 违例"));
        case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX:
            return ks::i18n::sourceText(QStringLiteral("嵌套 VMX"));
        case KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT:
            return ks::i18n::sourceText(QStringLiteral("致命退出"));
        case KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE:
            return ks::i18n::sourceText(QStringLiteral("生命周期"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知类型"));
    }

    // describeAccess: Translates EPT access types into RWX shorthand.
    QString describeAccess(const unsigned long access)
    {
        QString text;
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0)
        {
            text += QLatin1Char('R');
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0)
        {
            text += QLatin1Char('W');
        }
        if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0)
        {
            text += QLatin1Char('X');
        }
        return text;
    }
}

KvmEventDialog::KvmEventDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM 事件流")));
    setObjectName(QStringLiteral("KvmEventDialog"));
    buildUi();
    // Fetch once immediately on open; no need to wait for the first poll cycle.
    poll();
}

void KvmEventDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("事件环是有界的：丢弃计数非零说明消费跟不上产生速度，中间有缺口。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    eventTable_ = new QTableWidget(0, 8, this);
    eventTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("序号"))
        << ks::i18n::sourceText(QStringLiteral("类型"))
        << ks::i18n::sourceText(QStringLiteral("退出原因"))
        << ks::i18n::sourceText(QStringLiteral("访问"))
        << ks::i18n::sourceText(QStringLiteral("物理地址"))
        << ks::i18n::sourceText(QStringLiteral("Guest RIP"))
        << ks::i18n::sourceText(QStringLiteral("规则/视图"))
        << ks::i18n::sourceText(QStringLiteral("处理器")));
    eventTable_->horizontalHeader()->setStretchLastSection(true);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kRootLayout->addWidget(eventTable_, 1);

    QGridLayout* const kButtonLayout = new QGridLayout();
    followCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("自动滚动到最新")), this);
    followCheck_->setChecked(true);
    pauseButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("暂停")), this);
    clearButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清空")), this);
    kButtonLayout->addWidget(followCheck_, 0, 0);
    kButtonLayout->addWidget(pauseButton_, 0, 1);
    kButtonLayout->addWidget(clearButton_, 0, 2);
    kRootLayout->addLayout(kButtonLayout);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(pauseButton_, &QPushButton::clicked, this, [this]() {
        paused_ = !paused_;
        pauseButton_->setText(paused_
            ? ks::i18n::sourceText(QStringLiteral("继续"))
            : ks::i18n::sourceText(QStringLiteral("暂停")));
    });
    connect(clearButton_, &QPushButton::clicked, this, [this]() {
        // Clear only the UI, not the driver-side ring: historical data in the ring remains meaningful for other consumers.
        eventTable_->setRowCount(0);
        droppedTotal_ = 0;
    });

    pollTimer_ = new QTimer(this);
    pollTimer_->setInterval(kPollIntervalMs);
    connect(pollTimer_, &QTimer::timeout, this, [this]() {
        poll();
    });
    pollTimer_->start();
    resize(900, 560);
}

void KvmEventDialog::trimRows()
{
    // Remove from head instead of rebuilding: preserve user's current selection and scroll position.
    while (eventTable_->rowCount() > kMaxTableRows)
    {
        eventTable_->removeRow(0);
    }
}

void KvmEventDialog::poll()
{
    // Do not send IOCTLs or advance the cursor while paused; upon resuming, unread events remain available.
    if (paused_ || pollInFlight_)
    {
        return;
    }
    pollInFlight_ = true;
    QPointer<KvmEventDialog> safeThis(this);
    const unsigned long long kAfterSequence = afterSequence_;
    std::thread([safeThis, kAfterSequence]() {
        const ksword::kvm::KvmEventResult kResult =
            ksword::kvm::readEvents(kAfterSequence, false);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->pollInFlight_ = false;
                if (!kResult.ok)
                {
                    safeThis->statusLabel_->setText(kResult.message);
                    return;
                }
                QTableWidget* const kTable = safeThis->eventTable_;
                for (const auto& entry : kResult.events)
                {
                    const int kRow = kTable->rowCount();
                    kTable->insertRow(kRow);
                    kTable->setItem(kRow, 0, new QTableWidgetItem(
                        QString::number(entry.sequence)));
                    kTable->setItem(kRow, 1, new QTableWidgetItem(
                        describeEventType(entry.type)));
                    kTable->setItem(kRow, 2, new QTableWidgetItem(
                        QString::number(entry.exitReason)));
                    kTable->setItem(kRow, 3, new QTableWidgetItem(
                        describeAccess(entry.access)));
                    kTable->setItem(kRow, 4, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.guestPhysicalAddress, 0, 16)));
                    kTable->setItem(kRow, 5, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.guestRip, 0, 16)));
                    kTable->setItem(kRow, 6, new QTableWidgetItem(
                        entry.ruleId != 0
                            ? QString::number(entry.ruleId)
                            : QString()));
                    kTable->setItem(kRow, 7, new QTableWidgetItem(
                        QStringLiteral("%1:%2")
                            .arg(entry.processorGroup)
                            .arg(entry.processorNumber)));
                    // The cursor only advances forward; repeated reads do not cause duplicate screen updates.
                    if (entry.sequence >= safeThis->afterSequence_)
                    {
                        safeThis->afterSequence_ = entry.sequence;
                    }
                }
                safeThis->droppedTotal_ += kResult.droppedRows;
                safeThis->trimRows();
                if (safeThis->followCheck_->isChecked() &&
                    kTable->rowCount() > 0)
                {
                    kTable->scrollToBottom();
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("已显示 %1 行，环内待取 %2 行，累计丢弃 %3 行。"))
                        .arg(kTable->rowCount())
                        .arg(kResult.availableRows)
                        .arg(safeThis->droppedTotal_));
            },
            Qt::QueuedConnection);
    }).detach();
}
