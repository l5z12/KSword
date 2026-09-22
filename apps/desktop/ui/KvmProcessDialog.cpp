#include "KvmProcessDialog.h"

#include "KvmControl.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"

#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QVariant>

#include <thread>

namespace
{
    // describeDisposition: Translates the disposition type into a sentence.
    QString describeDisposition(const unsigned long disposition)
    {
        switch (disposition)
        {
        case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:
            return ks::i18n::sourceText(QStringLiteral("冻结（注入 #PF，可逆）"));
        case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE:
            return ks::i18n::sourceText(QStringLiteral("结束（注入 #UD，不可逆）"));
        case KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED:
            // This state only appears for records revoked during residency: both the record and hierarchy still
            // exist, but no one will switch into them. Hiding it would make users think the revocation failed.
            return ks::i18n::sourceText(QStringLiteral("已解除（层次待回收）"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知处置"));
    }

    // describeFiller: Original filler bytes in the gap. 0xCC and 0x90 are compiler-inserted
    // alignment padding between functions; 0x00 is usually section tail or uninitialized regions.
    // Which one is used determines what to suspect, so it is a table column rather than just logged.
    QString describeFiller(const unsigned long filler)
    {
        return QStringLiteral("0x%1")
            .arg(filler & 0xFFu, 2, 16, QLatin1Char('0')).toUpper();
    }

    // parseProcessId: Decimal PID. Reject empty strings and invalid inputs; do not guess 0 for the user.
    bool parseProcessId(const QString& text, unsigned long* valueOut)
    {
        bool converted = false;
        const unsigned long kValue = text.trimmed().toULong(&converted, 10);
        if (!converted)
        {
            return false;
        }
        *valueOut = kValue;
        return true;
    }

    // parseOptionalHex: Parses hexadecimal values with an optional '0x' prefix. An empty string is valid and signifies 'defer to
    // downstream' (e.g., the entry page for handling or the local resolution of LoadLibraryW), in which case 0 is written back.
    bool parseOptionalHex(const QString& text, unsigned long long* valueOut)
    {
        QString compact = text.trimmed();
        if (compact.isEmpty())
        {
            *valueOut = 0;
            return true;
        }
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        bool converted = false;
        const unsigned long long kValue = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = kValue;
        return true;
    }

    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }
}

KvmProcessDialog::KvmProcessDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM R-1 进程处置与注入")));
    setObjectName(QStringLiteral("KvmProcessDialog"));
    buildUi();
    updateEnabledState();
    refreshDispositions();
    refreshInjections();
}

void KvmProcessDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("这两组操作都要求：先开启 CR3 追踪（靠地址空间认目标）、用 EPTP 切换后端准备资源、并且常驻停着。这不是安全边界：目标只要换掉自己那一页的客户物理页就不在被拒绝的页上了，失败即放行。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    tabs_ = new QTabWidget(this);
    tabs_->addTab(
        buildDispositionPage(),
        ks::i18n::sourceText(QStringLiteral("进程处置")));
    tabs_->addTab(
        buildInjectionPage(),
        ks::i18n::sourceText(QStringLiteral("DLL 注入")));
    kRootLayout->addWidget(tabs_, 1);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);
    resize(880, 560);
}

QWidget* KvmProcessDialog::buildDispositionPage()
{
    QWidget* const kPage = new QWidget(this);
    QVBoxLayout* const kLayout = new QVBoxLayout(kPage);

    QFormLayout* const kForm = new QFormLayout();
    dispositionPidEdit_ = new QLineEdit(kPage);
    dispositionPidEdit_->setPlaceholderText(QStringLiteral("1234"));
    kForm->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")),
        dispositionPidEdit_);
    dispositionAddressEdit_ = new QLineEdit(kPage);
    dispositionAddressEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示由驱动取主映像入口页")));
    dispositionAddressEdit_->setToolTip(ks::i18n::sourceText(QStringLiteral("要拒绝执行的客户线性地址。入口页对刚起来的进程有效；已经跑进消息循环的进程未必会再执行到它，而没被执行到的拒绝等于什么都没做——那时应当填一个目标线程此刻正在执行的地址。")));
    kForm->addRow(
        ks::i18n::sourceText(QStringLiteral("客户线性地址（十六进制）")),
        dispositionAddressEdit_);
    kLayout->addLayout(kForm);

    dispositionTable_ = new QTableWidget(0, 7, kPage);
    dispositionTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("PID"))
        << ks::i18n::sourceText(QStringLiteral("处置"))
        << ks::i18n::sourceText(QStringLiteral("页目录基址"))
        << ks::i18n::sourceText(QStringLiteral("客户物理地址"))
        << ks::i18n::sourceText(QStringLiteral("客户线性地址"))
        << ks::i18n::sourceText(QStringLiteral("拦截次数"))
        << ks::i18n::sourceText(QStringLiteral("层次序号")));
    dispositionTable_->horizontalHeader()->setStretchLastSection(true);
    dispositionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    dispositionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    dispositionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kLayout->addWidget(dispositionTable_, 1);

    QGridLayout* const kButtons = new QGridLayout();
    freezeButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("冻结进程")), kPage);
    freezeButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("拒绝目标页执行并注入 #PF。目标线程会在那一页上自旋，拦截次数持续增长正是它还活着的证据。可逆。")));
    terminateButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("结束进程")), kPage);
    terminateButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("拒绝目标页执行并注入 #UD，由来宾自己走进程退出流程。不可逆。")));
    releaseDispositionButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("撤销选中")), kPage);
    releaseAllDispositionsButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部撤销")), kPage);
    refreshDispositionsButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), kPage);
    kButtons->addWidget(freezeButton_, 0, 0);
    kButtons->addWidget(terminateButton_, 0, 1);
    kButtons->addWidget(releaseDispositionButton_, 0, 2);
    kButtons->addWidget(releaseAllDispositionsButton_, 0, 3);
    kButtons->addWidget(refreshDispositionsButton_, 0, 4);
    kLayout->addLayout(kButtons);

    connect(freezeButton_, &QPushButton::clicked, this, [this]() { startFreeze(); });
    connect(terminateButton_, &QPushButton::clicked, this, [this]() { startTerminate(); });
    connect(releaseDispositionButton_, &QPushButton::clicked, this, [this]() {
        startReleaseDisposition();
    });
    connect(releaseAllDispositionsButton_, &QPushButton::clicked, this, [this]() {
        startReleaseAllDispositions();
    });
    connect(refreshDispositionsButton_, &QPushButton::clicked, this, [this]() {
        refreshDispositions();
    });
    return kPage;
}

QWidget* KvmProcessDialog::buildInjectionPage()
{
    QWidget* const kPage = new QWidget(this);
    QVBoxLayout* const kLayout = new QVBoxLayout(kPage);

    QLabel* const kNote = new QLabel(
        ks::i18n::sourceText(QStringLiteral("机制是分离视图加线程劫持：目标进程里不会多出线程或内存区域，一个内核 API 都不调。代价是要你指定一页——驱动不猜“哪一页会被执行到”，猜错的表现是载荷装上了却永远不执行，从外面看和成功完全一样。")),
        kPage);
    kNote->setWordWrap(true);
    kLayout->addWidget(kNote);

    QFormLayout* const kForm = new QFormLayout();
    injectPidEdit_ = new QLineEdit(kPage);
    injectPidEdit_->setPlaceholderText(QStringLiteral("1234"));
    kForm->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")),
        injectPidEdit_);
    injectAddressEdit_ = new QLineEdit(kPage);
    injectAddressEdit_->setPlaceholderText(QStringLiteral("00007FF6C1230000"));
    injectAddressEdit_->setToolTip(ks::i18n::sourceText(QStringLiteral("要劫持的那一页里的任意客户线性地址，必填。取目标某个线程此刻正在执行的位置，那一页按定义会被执行到。")));
    kForm->addRow(
        ks::i18n::sourceText(QStringLiteral("被劫持页的线性地址（十六进制）")),
        injectAddressEdit_);
    injectLoadLibraryEdit_ = new QLineEdit(kPage);
    injectLoadLibraryEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示由本程序就地解析")));
    injectLoadLibraryEdit_->setToolTip(ks::i18n::sourceText(QStringLiteral("kernel32 的 ASLR 每次启动重定一次而不是每进程一次，所以本进程解析出来的 LoadLibraryW 对目标同样成立。只有目标运行在不同的会话映像布局下才需要自己填。")));
    kForm->addRow(
        ks::i18n::sourceText(QStringLiteral("LoadLibraryW 地址（十六进制）")),
        injectLoadLibraryEdit_);

    QWidget* const kPathRow = new QWidget(kPage);
    QGridLayout* const kPathLayout = new QGridLayout(kPathRow);
    kPathLayout->setContentsMargins(0, 0, 0, 0);
    injectPathEdit_ = new QLineEdit(kPathRow);
    injectPathEdit_->setPlaceholderText(QStringLiteral("C:\\path\\to\\payload.dll"));
    injectBrowseButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("浏览...")), kPathRow);
    kPathLayout->addWidget(injectPathEdit_, 0, 0);
    kPathLayout->addWidget(injectBrowseButton_, 0, 1);
    kForm->addRow(ks::i18n::sourceText(QStringLiteral("DLL 路径")), kPathRow);
    kLayout->addLayout(kForm);

    injectionTable_ = new QTableWidget(0, 8, kPage);
    injectionTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("PID"))
        << ks::i18n::sourceText(QStringLiteral("被劫持页"))
        << ks::i18n::sourceText(QStringLiteral("客户物理地址"))
        << ks::i18n::sourceText(QStringLiteral("空隙偏移"))
        << ks::i18n::sourceText(QStringLiteral("空隙字节数"))
        << ks::i18n::sourceText(QStringLiteral("填充字节"))
        << ks::i18n::sourceText(QStringLiteral("执行次数"))
        << ks::i18n::sourceText(QStringLiteral("视图编号")));
    injectionTable_->horizontalHeader()->setStretchLastSection(true);
    injectionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    injectionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    injectionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kLayout->addWidget(injectionTable_, 1);

    QGridLayout* const kButtons = new QGridLayout();
    injectButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("注入 DLL")), kPage);
    releaseInjectionButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("撤销选中")), kPage);
    releaseAllInjectionsButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部撤销")), kPage);
    refreshInjectionsButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), kPage);
    kButtons->addWidget(injectButton_, 0, 0);
    kButtons->addWidget(releaseInjectionButton_, 0, 1);
    kButtons->addWidget(releaseAllInjectionsButton_, 0, 2);
    kButtons->addWidget(refreshInjectionsButton_, 0, 3);
    kLayout->addLayout(kButtons);

    connect(injectBrowseButton_, &QPushButton::clicked, this, [this]() {
        const QString kChosen = QFileDialog::getOpenFileName(
            this,
            ks::i18n::sourceText(QStringLiteral("选择要注入的 DLL")),
            QString(),
            ks::i18n::sourceText(QStringLiteral("动态链接库 (*.dll)")));
        if (!kChosen.isEmpty())
        {
            // normalize to backslashes: the payload is passed verbatim to LoadLibraryW in
            // the target process, while QFileDialog returns forward slashes on Windows.
            injectPathEdit_->setText(QDir::toNativeSeparators(kChosen));
        }
    });
    connect(injectButton_, &QPushButton::clicked, this, [this]() { startInject(); });
    connect(releaseInjectionButton_, &QPushButton::clicked, this, [this]() {
        startReleaseInjection();
    });
    connect(releaseAllInjectionsButton_, &QPushButton::clicked, this, [this]() {
        startReleaseAllInjections();
    });
    connect(refreshInjectionsButton_, &QPushButton::clicked, this, [this]() {
        refreshInjections();
    });
    return kPage;
}

void KvmProcessDialog::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能下达处置或注入"));
    for (QPushButton* const kButton : {
             freezeButton_, terminateButton_,
             releaseDispositionButton_, releaseAllDispositionsButton_,
             injectButton_, releaseInjectionButton_,
             releaseAllInjectionsButton_ })
    {
        if (kButton == nullptr)
        {
            continue;
        }
        kButton->setEnabled(kWriteAllowed && !busy_);
        // The write permission gate description is appended to the button's own description, not replacing it.
        //
        // Directly overwriting would permanently displace the long explanations for the 'Freeze Process' buttons describing their function:
        // Write permissions can be toggled back and forth within this process, but the override is one-way; when toggling back, the original text is already lost.
        // On the first call, store the original text in a dynamic property; subsequently, rebuild based on it each time.
        const QVariant kStored = kButton->property("ks_base_tooltip");
        const QString kBase = kStored.isValid() ? kStored.toString() : kButton->toolTip();
        if (!kStored.isValid())
        {
            kButton->setProperty("ks_base_tooltip", kBase);
        }
        kButton->setToolTip(kWriteAllowed ? kBase
            : kBase.isEmpty() ? kWriteHint : kBase + QLatin1Char('\n') + kWriteHint);
    }
    for (QPushButton* const kButton : {
             refreshDispositionsButton_, refreshInjectionsButton_ })
    {
        if (kButton != nullptr)
        {
            kButton->setEnabled(!busy_);
        }
    }
    if (injectBrowseButton_ != nullptr)
    {
        injectBrowseButton_->setEnabled(!busy_);
    }
}

void KvmProcessDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

bool KvmProcessDialog::readSelectedProcessId(
    QTableWidget* const table,
    unsigned long* const processIdOut)
{
    if (table == nullptr)
    {
        return false;
    }
    const int kRow = table->currentRow();
    if (kRow < 0 || table->item(kRow, 0) == nullptr)
    {
        return false;
    }
    *processIdOut = table->item(kRow, 0)->text().toULong();
    return true;
}

void KvmProcessDialog::refreshDispositions()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmProcessResult kResult =
            ksword::kvm::listProcessDispositions();
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
                safeThis->setBusy(false);
                if (!kResult.ok)
                {
                    safeThis->statusLabel_->setText(kResult.message);
                    return;
                }
                QTableWidget* const kTable = safeThis->dispositionTable_;
                kTable->setRowCount(kResult.dispositions.size());
                for (int row = 0; row < kResult.dispositions.size(); ++row)
                {
                    const auto& entry = kResult.dispositions.at(row);
                    kTable->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.processId)));
                    kTable->setItem(row, 1, new QTableWidgetItem(
                        describeDisposition(entry.disposition)));
                    kTable->setItem(row, 2, new QTableWidgetItem(
                        hex64(entry.directoryBase)));
                    kTable->setItem(row, 3, new QTableWidgetItem(
                        hex64(entry.guestPhysicalAddress)));
                    kTable->setItem(row, 4, new QTableWidgetItem(
                        hex64(entry.guestLinearAddress)));
                    kTable->setItem(row, 5, new QTableWidgetItem(
                        QString::number(entry.interceptCount)));
                    kTable->setItem(row, 6, new QTableWidgetItem(
                        QString::number(entry.hierarchyIndex)));
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条进程处置。"))
                        .arg(kResult.rowCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::refreshInjections()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmInjectResult kResult = ksword::kvm::listInjections();
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
                safeThis->setBusy(false);
                if (!kResult.ok)
                {
                    safeThis->statusLabel_->setText(kResult.message);
                    return;
                }
                QTableWidget* const kTable = safeThis->injectionTable_;
                kTable->setRowCount(kResult.injections.size());
                for (int row = 0; row < kResult.injections.size(); ++row)
                {
                    const auto& entry = kResult.injections.at(row);
                    kTable->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.processId)));
                    kTable->setItem(row, 1, new QTableWidgetItem(
                        hex64(entry.guestLinearAddress)));
                    kTable->setItem(row, 2, new QTableWidgetItem(
                        hex64(entry.guestPhysicalAddress)));
                    kTable->setItem(row, 3, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.caveOffset, 3, 16, QLatin1Char('0'))));
                    kTable->setItem(row, 4, new QTableWidgetItem(
                        QString::number(entry.caveBytes)));
                    kTable->setItem(row, 5, new QTableWidgetItem(
                        describeFiller(entry.caveFiller)));
                    kTable->setItem(row, 6, new QTableWidgetItem(
                        QString::number(entry.executionCount)));
                    kTable->setItem(row, 7, new QTableWidgetItem(
                        QString::number(entry.viewId)));
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条 R-1 注入。"))
                        .arg(kResult.rowCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startFreeze()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    if (!parseProcessId(dispositionPidEdit_->text(), &processId))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    if (!parseOptionalHex(dispositionAddressEdit_->text(), &address))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("客户线性地址不是合法的十六进制数。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmProcessFreeze"),
            ks::i18n::sourceText(QStringLiteral("冻结进程")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("目标线程会在被拒绝的那一页上持续自旋，直到这条处置被撤销。若目标是系统进程或正持有锁，系统可能整体失去响应。"))))
    {
        return;
    }
    setBusy(true);
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral("正在下达冻结...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address]() {
        const ksword::kvm::KvmProcessResult kResult =
            ksword::kvm::freezeProcess(processId, address);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startTerminate()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    if (!parseProcessId(dispositionPidEdit_->text(), &processId))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    if (!parseOptionalHex(dispositionAddressEdit_->text(), &address))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("客户线性地址不是合法的十六进制数。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmProcessTerminate"),
            ks::i18n::sourceText(QStringLiteral("结束进程")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("向目标注入无效指令异常，由来宾自己走进程退出流程。不可逆，目标未保存的数据会丢失；若目标是系统进程，系统可能崩溃。"))))
    {
        return;
    }
    setBusy(true);
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral("正在下达结束...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address]() {
        const ksword::kvm::KvmProcessResult kResult =
            ksword::kvm::terminateProcess(processId, address);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startReleaseDisposition()
{
    unsigned long processId = 0;
    if (!readSelectedProcessId(dispositionTable_, &processId))
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条处置。")));
        return;
    }
    setBusy(true);
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral("正在撤销处置...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId]() {
        const ksword::kvm::KvmProcessResult kResult =
            ksword::kvm::releaseProcessDisposition(processId);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startReleaseAllDispositions()
{
    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在撤销全部处置...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmProcessResult kResult =
            ksword::kvm::releaseAllProcessDispositions();
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshDispositions();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startInject()
{
    unsigned long processId = 0;
    unsigned long long address = 0;
    unsigned long long loadLibrary = 0;
    if (!parseProcessId(injectPidEdit_->text(), &processId))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("PID 不是合法的十进制数。")));
        return;
    }
    // This address differs from the handler's requirement: it is mandatory. Leaving it empty implies the driver must guess which
    // page will be executed; since a wrong guess is indistinguishable from success, we reject it here rather than passing 0.
    if (!parseOptionalHex(injectAddressEdit_->text(), &address) || address == 0)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("被劫持页的线性地址必填，且必须是合法的十六进制数。")));
        return;
    }
    if (!parseOptionalHex(injectLoadLibraryEdit_->text(), &loadLibrary))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("LoadLibraryW 地址不是合法的十六进制数。")));
        return;
    }
    const QString kPath = injectPathEdit_->text().trimmed();
    if (kPath.isEmpty())
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("请先选择要注入的 DLL。")));
        return;
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmProcessInject"),
            ks::i18n::sourceText(QStringLiteral("R-1 注入 DLL")),
            ks::i18n::sourceText(QStringLiteral("PID %1")).arg(processId),
            ks::i18n::sourceText(QStringLiteral("将在目标进程的一页可执行内存上建立影子页并劫持其执行流。载荷在目标进程上下文里运行，出错会让目标崩溃；若目标是系统进程，系统可能崩溃。"))))
    {
        return;
    }
    setBusy(true);
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral("正在安装注入...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId, address, loadLibrary, kPath]() {
        const ksword::kvm::KvmInjectResult kResult =
            ksword::kvm::injectDll(processId, address, loadLibrary, kPath);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startReleaseInjection()
{
    unsigned long processId = 0;
    if (!readSelectedProcessId(injectionTable_, &processId))
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条注入。")));
        return;
    }
    setBusy(true);
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral("正在撤销注入...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis, processId]() {
        const ksword::kvm::KvmInjectResult kResult =
            ksword::kvm::releaseInjection(processId);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmProcessDialog::startReleaseAllInjections()
{
    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在撤销全部注入...")));
    QPointer<KvmProcessDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmInjectResult kResult =
            ksword::kvm::releaseAllInjections();
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshInjections();
            },
            Qt::QueuedConnection);
    }).detach();
}
