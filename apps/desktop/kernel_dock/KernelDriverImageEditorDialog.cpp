#include "KernelDriverImageEditorDialog.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <iterator>
#include <limits>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum Column : int
    {
        kColumnSelected = 0,
        kColumnField,
        kColumnCurrent,
        kColumnDesired,
        kColumnState,
        kColumnOriginal,
        kColumnApplied,
        kColumnCount
    };

    struct FieldRowSpec
    {
        std::uint32_t mask;
        const char* translationKey;
        const char* fallbackText;
        bool naturalUlong;
    };

    constexpr FieldRowSpec kFieldRows[] = {
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START,
          "kernel.driver_image.field.driver_start",
          "DriverObject->DriverStart", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE,
          "kernel.driver_image.field.driver_size",
          "DriverObject->DriverSize", true },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION,
          "kernel.driver_image.field.driver_section",
          "DriverObject->DriverSection", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE,
          "kernel.driver_image.field.kldr_dll_base",
          "KLDR_DATA_TABLE_ENTRY.DllBase", false },
        { KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE,
          "kernel.driver_image.field.kldr_size",
          "KLDR_DATA_TABLE_ENTRY.SizeOfImage", true },
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QTableWidgetItem* selectionItem()
    {
        auto* item = new QTableWidgetItem();
        item->setFlags(
            (item->flags() | Qt::ItemIsUserCheckable) &
            ~Qt::ItemIsEditable);
        item->setCheckState(Qt::Checked);
        return item;
    }

    QString ioMessageText(const std::string& text)
    {
        return QString::fromUtf8(
            text.c_str(),
            static_cast<int>(text.size()));
    }

    QString maskText(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 8, 16, QChar('0'))
            .toUpper();
    }
}

KernelDriverImageEditorDialog::KernelDriverImageEditorDialog(
    const QString& driverObjectName,
    QWidget* parent)
    : QDialog(parent),
      requestedDriverName_(driverObjectName.trimmed())
{
    initializeUi();
    QTimer::singleShot(0, this, [this]() { refreshSnapshot(); });
}

// Build a clearly opaque advanced editor; each executable button has an icon and a consequence description.
void KernelDriverImageEditorDialog::initializeUi()
{
    setObjectName(QStringLiteral("kernelDriverImageEditorDialog"));
    setWindowTitle(kernelText(
        "kernel.driver_image.title",
        QStringLiteral("DriverObject / KLDR 镜像事务编辑器")));
    resize(1240, 860);
    setModal(true);
    setStyleSheet(ksword_theme::opaqueDialogStyle(objectName()));

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(8);

    riskLabel_ = new QLabel(
        kernelText(
            "kernel.driver_image.risk",
            QStringLiteral("极高风险：本页允许任意修改 DriverStart、DriverSize、DriverSection、KLDR DllBase/SizeOfImage，并可把任意驱动从 PsLoadedModuleList 摘链或重新插入。错误值可能立即蓝屏、破坏 I/O、触发 PatchGuard、损坏崩溃转储/符号解析，或使恢复记录永久失效；这里只告知风险，不按驱动类别或值限制操作。")),
        this);
    riskLabel_->setWordWrap(true);
    riskLabel_->setStyleSheet(
        QStringLiteral(
            "color:%1;background:%2;font-weight:700;"
            "border:1px solid %1;padding:8px;")
            .arg(ksword_theme::errorHex())
            .arg(ksword_theme::surfaceAltColorHex()));
    rootLayout->addWidget(riskLabel_);

    auto* identityLayout = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        kernelText(
            "kernel.driver_image.refresh",
            QStringLiteral("刷新完整快照")),
        this);
    refreshButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    refreshButton_->setToolTip(kernelText(
        "kernel.driver_image.tooltip.refresh",
        QStringLiteral("重新引用 DriverObject，并在真实加载器资源下刷新五字段与链状态")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    identityLabel_ = new QLabel(this);
    identityLabel_->setWordWrap(true);
    identityLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    identityLayout->addWidget(refreshButton_);
    identityLayout->addWidget(identityLabel_, 1);
    rootLayout->addLayout(identityLayout);

    table_ = new QTableWidget(
        static_cast<int>(std::size(kFieldRows)),
        kColumnCount,
        this);
    table_->setHorizontalHeaderLabels({
        kernelText("kernel.driver_image.header.selected", QStringLiteral("选择")),
        kernelText("kernel.driver_image.header.field", QStringLiteral("字段")),
        kernelText("kernel.driver_image.header.current", QStringLiteral("当前值")),
        kernelText("kernel.driver_image.header.desired", QStringLiteral("目标值")),
        kernelText("kernel.driver_image.header.state", QStringLiteral("事务状态")),
        kernelText("kernel.driver_image.header.original", QStringLiteral("记录原值")),
        kernelText("kernel.driver_image.header.applied", QStringLiteral("已应用值")),
    });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setStyleSheet(
        QStringLiteral(
            "QTableWidget{background:%1;alternate-background-color:%2;color:%3;}"
            "QHeaderView::section{background:%2;color:%3;border:1px solid %4;font-weight:600;}"
            "QTableWidget::item:selected{background:%5;color:%6;}")
            .arg(ksword_theme::surfaceColorHex())
            .arg(ksword_theme::surfaceAltColorHex())
            .arg(ksword_theme::textPrimaryColorHex())
            .arg(ksword_theme::borderColorHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::onAccentHex()));
    table_->setColumnWidth(kColumnSelected, 62);
    table_->setColumnWidth(kColumnField, 270);
    table_->setColumnWidth(kColumnCurrent, 190);
    table_->setColumnWidth(kColumnDesired, 190);
    table_->setColumnWidth(kColumnState, 125);
    table_->setColumnWidth(kColumnOriginal, 190);

    for (int row = 0; row < static_cast<int>(std::size(kFieldRows)); ++row)
    {
        const FieldRowSpec& spec = kFieldRows[row];
        table_->setItem(row, kColumnSelected, selectionItem());
        table_->setItem(
            row,
            kColumnField,
            readOnlyItem(kernelText(
                spec.translationKey,
                QString::fromLatin1(spec.fallbackText))));
        table_->setItem(row, kColumnCurrent, readOnlyItem(QStringLiteral("-")));
        table_->setItem(row, kColumnDesired, new QTableWidgetItem(QStringLiteral("0x0")));
        table_->setItem(
            row,
            kColumnState,
            readOnlyItem(kernelText(
                "kernel.driver_image.state.inactive",
                QStringLiteral("未受管"))));
        table_->setItem(row, kColumnOriginal, readOnlyItem(QStringLiteral("-")));
        table_->setItem(row, kColumnApplied, readOnlyItem(QStringLiteral("-")));
    }
    rootLayout->addWidget(table_, 2);

    auto* actionLayout = new QHBoxLayout();
    restoreLinkCheckBox_ = new QCheckBox(
        kernelText(
            "kernel.driver_image.restore_link",
            QStringLiteral("恢复时同时重新插入 PsLoadedModuleList")),
        this);
    applyButton_ = new QPushButton(
        kernelText("kernel.driver_image.apply", QStringLiteral("原子应用字段")),
        this);
    hideButton_ = new QPushButton(
        kernelText("kernel.driver_image.hide", QStringLiteral("从加载链隐藏")),
        this);
    restoreButton_ = new QPushButton(
        kernelText("kernel.driver_image.restore", QStringLiteral("恢复受管状态")),
        this);
    abandonButton_ = new QPushButton(
        kernelText("kernel.driver_image.abandon", QStringLiteral("放弃恢复记录")),
        this);

    applyButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
    hideButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_uncritical.svg")));
    restoreButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    abandonButton_->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    applyButton_->setToolTip(kernelText(
        "kernel.driver_image.tooltip.apply",
        QStringLiteral("按当前代次与期望快照一次性 CAS 修改所有勾选字段")));
    hideButton_->setToolTip(kernelText(
        "kernel.driver_image.tooltip.hide",
        QStringLiteral("在 PsLoadedModuleResource 独占锁内按精确邻接摘链并自环")));
    restoreButton_->setToolTip(kernelText(
        "kernel.driver_image.tooltip.restore",
        QStringLiteral("只恢复仍由本事务拥有的字段；链优先原位置，否则插入当前尾部")));
    abandonButton_->setToolTip(kernelText(
        "kernel.driver_image.tooltip.abandon",
        QStringLiteral("保持当前字段和链不变，永久删除 KSword 保存的原值与恢复资格")));
    for (QPushButton* button :
         { applyButton_, hideButton_, restoreButton_, abandonButton_ })
    {
        button->setStyleSheet(ksword_theme::themedButtonStyle());
    }

    actionLayout->addWidget(restoreLinkCheckBox_);
    actionLayout->addStretch(1);
    actionLayout->addWidget(applyButton_);
    actionLayout->addWidget(hideButton_);
    actionLayout->addWidget(restoreButton_);
    actionLayout->addWidget(abandonButton_);
    rootLayout->addLayout(actionLayout);

    auto* detailLabel = new QLabel(
        kernelText(
            "kernel.driver_image.details",
            QStringLiteral("加载器资源、链与事务证据")),
        this);
    detailLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(detailLabel);
    detailEditor_ = new CodeEditorWidget(this);
    detailEditor_->setReadOnly(true);
    detailEditor_->setMinimumHeight(210);
    rootLayout->addWidget(detailEditor_, 1);

    auto* bottomLayout = new QHBoxLayout();
    statusLabel_ = new QLabel(
        kernelText(
            "kernel.driver_image.status.waiting",
            QStringLiteral("状态：等待查询")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto* closeButton = new QPushButton(
        kernelText("kernel.driver_image.close", QStringLiteral("关闭")),
        this);
    closeButton->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    closeButton->setStyleSheet(ksword_theme::themedButtonStyle());
    bottomLayout->addWidget(statusLabel_, 1);
    bottomLayout->addWidget(closeButton);
    rootLayout->addLayout(bottomLayout);

    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshSnapshot();
    });
    connect(applyButton_, &QPushButton::clicked, this, [this]() {
        applySelectedFields();
    });
    connect(hideButton_, &QPushButton::clicked, this, [this]() {
        hideFromLoadedModuleList();
    });
    connect(restoreButton_, &QPushButton::clicked, this, [this]() {
        restoreManagedState();
    });
    connect(abandonButton_, &QPushButton::clicked, this, [this]() {
        abandonRecoveryRecord();
    });
    setActionsEnabled(false, false);
}

// Identity initial check does not require DriverStart to be non-zero, so even if the field is corrupted, the transaction recovery path can still be entered by object name.
void KernelDriverImageEditorDialog::refreshSnapshot()
{
    setActionsEnabled(false, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.identity_querying",
            QStringLiteral("状态：正在引用 DriverObject...")),
        ksword_theme::infoHex());

    const ksword::ark::DriverClient kClient;
    const auto kIdentity =
        kClient.queryDriverObject(requestedDriverName_.toStdWString());
    if (!kIdentity.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.identity_failed",
                QStringLiteral("状态：DriverObject 查询失败：%1"))
                .arg(ioMessageText(kIdentity.io.message)),
            ksword_theme::errorHex());
        return;
    }
    if (kIdentity.lastStatus < 0 || kIdentity.driverObjectAddress == 0U)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.identity_unavailable",
                QStringLiteral("状态：R0 未返回可引用 DriverObject，NTSTATUS=%1"))
                .arg(ntStatusText(kIdentity.lastStatus)),
            ksword_theme::errorHex());
        return;
    }

    canonicalDriverName_ = kIdentity.driverName.empty()
        ? requestedDriverName_
        : QString::fromStdWString(kIdentity.driverName);
    // Do not treat the current DriverStart, which may have been modified by this transaction, as a stable identity.
    // Zero-based addressing allows R0 to first query for existing records using the precise object; if no record exists, an initial identity is established from real-time fields.
    moduleBase_ = 0U;
    driverObjectAddress_ = kIdentity.driverObjectAddress;

    ksword::ark::DriverImageControlResult result{};
    (void)queryTransaction(result, true);
}

// Call this function before each destructive action to refresh the generation and adjacency; the target input cell can optionally be preserved.
bool KernelDriverImageEditorDialog::queryTransaction(
    ksword::ark::DriverImageControlResult& resultOut,
    const bool resetDesiredValues)
{
    if (canonicalDriverName_.isEmpty() || driverObjectAddress_ == 0U)
    {
        return false;
    }

    const ksword::ark::DriverClient kClient;
    resultOut = kClient.queryDriverImage(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        driverObjectAddress_);
    if (!resultOut.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.transaction_query_failed",
                QStringLiteral("状态：镜像事务查询失败：%1"))
                .arg(ioMessageText(resultOut.io.message)),
            ksword_theme::errorHex());
        return false;
    }

    applyResultToView(resultOut, resetDesiredValues);
    if (resultOut.lastStatus < 0)
    {
        setStatus(
            kernelText(
                "kernel.driver_image.status.transaction_failed",
                QStringLiteral("状态：R0 事务查询失败，NTSTATUS=%1，loader=%2"))
                .arg(ntStatusText(resultOut.lastStatus))
                .arg(ntStatusText(resultOut.loaderStatus)),
            ksword_theme::errorHex());
        return false;
    }

    setStatus(
        kernelText(
            "kernel.driver_image.status.ready",
            QStringLiteral("状态：快照已锁定；generation=%1，字段掩码=%2，loader=%3"))
            .arg(resultOut.generation)
            .arg(maskText(resultOut.managedFieldMask))
            .arg(ntStatusText(resultOut.loaderStatus)),
        ksword_theme::successHex());
    return true;
}

// Atomic batch modification uses only the freshly queried currentValues as expected; address ownership is not filtered during parsing.
void KernelDriverImageEditorDialog::applySelectedFields()
{
    const std::uint32_t kFieldMask = selectedFieldMask();
    if (kFieldMask == 0U)
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_image.no_fields",
                QStringLiteral("至少勾选一个要修改的字段。")));
        return;
    }

    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }
    ksword::ark::DriverImageValues desiredValues{};
    QString parseError;
    if (!parseDesiredValues(desiredValues, parseError))
    {
        QMessageBox::warning(this, windowTitle(), parseError);
        return;
    }

    const QString kWarning = kernelText(
        "kernel.driver_image.apply.warning",
        QStringLiteral("即将对 %1 原子修改勾选字段（mask=%2，generation=%3）。R0 不检查指针是否映射、可执行、属于目标镜像或满足 ABI；DriverSize/SizeOfImage 只验证真实 ULONG 宽度。错误值可能立即蓝屏、破坏卸载与转储，或触发 PatchGuard。"))
        .arg(canonicalDriverName_)
        .arg(maskText(kFieldMask))
        .arg(snapshot.generation);
    if (!confirmDanger(kWarning, kernelText("kernel.driver_image.apply", QStringLiteral("原子应用字段"))))
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.applyDriverImageFields(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        kFieldMask,
        driverObjectAddress_,
        snapshot.generation,
        snapshot.currentValues,
        desiredValues);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }

    applyResultToView(kResult, kResult.lastStatus >= 0);
    setStatus(
        kernelText(
            "kernel.driver_image.status.applied",
            QStringLiteral("状态：字段应用完成，NTSTATUS=%1，changed=%2，generation=%3"))
            .arg(ntStatusText(kResult.lastStatus))
            .arg(maskText(kResult.changedFieldMask))
            .arg(kResult.generation),
        kResult.lastStatus >= 0
            ? ksword_theme::warningHex()
            : ksword_theme::errorHex());
}

// Chain unloading always returns the queried bidirectional adjacency; R0 then validates under the real ERESOURCE.
void KernelDriverImageEditorDialog::hideFromLoadedModuleList()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }

    const QString kWarning = kernelText(
        "kernel.driver_image.hide.warning",
        QStringLiteral("即将把 %1 从 PsLoadedModuleList 摘链并把其 InLoadOrderLinks 设为自环。该动作不会卸载镜像，但可能立即触发 PatchGuard，使卸载、崩溃转储、符号解析和模块枚举失效；隐藏 KSword 自身也可能让恢复通道在崩溃前来不及执行。"))
        .arg(canonicalDriverName_);
    if (!confirmDanger(kWarning, kernelText("kernel.driver_image.hide", QStringLiteral("从加载链隐藏"))))
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.hideDriverImage(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        driverObjectAddress_,
        snapshot.generation,
        snapshot.currentLinkFlink,
        snapshot.currentLinkBlink);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }

    applyResultToView(kResult, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.hidden",
            QStringLiteral("状态：摘链请求完成，NTSTATUS=%1，generation=%2"))
            .arg(ntStatusText(kResult.lastStatus))
            .arg(kResult.generation),
        kResult.lastStatus >= 0
            ? ksword_theme::warningHex()
            : ksword_theme::errorHex());
}

// Restoration only overwrites fields that still equal the transaction's applied value; third-party values enter conflict and are not overwritten.
void KernelDriverImageEditorDialog::restoreManagedState()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }

    const std::uint32_t kFieldMask = selectedFieldMask();
    const bool kRestoreLink =
        restoreLinkCheckBox_ != nullptr &&
        restoreLinkCheckBox_->isChecked();
    if (kFieldMask == 0U && !kRestoreLink)
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_image.restore.empty",
                QStringLiteral("没有勾选字段，也没有选择恢复加载链。")));
        return;
    }

    const QString kWarning = kernelText(
        "kernel.driver_image.restore.warning",
        QStringLiteral("即将恢复 %1 的受管字段（mask=%2）%3。只有 current==applied 的值会恢复；加载链原邻居仍相邻时回原位，否则插入当前尾部。竞争值保持不变并报告冲突。"))
        .arg(canonicalDriverName_)
        .arg(maskText(kFieldMask))
        .arg(kRestoreLink
            ? kernelText(
                "kernel.driver_image.restore.with_link",
                QStringLiteral("，并重新插入 PsLoadedModuleList"))
            : QString());
    if (!confirmDanger(kWarning, kernelText("kernel.driver_image.restore", QStringLiteral("恢复受管状态"))))
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.restoreDriverImage(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        kFieldMask,
        kRestoreLink,
        driverObjectAddress_,
        snapshot.generation);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }

    applyResultToView(kResult, kResult.lastStatus >= 0);
    const QString kPosition =
        (kResult.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_ORIGINAL_POSITION) != 0U
        ? kernelText(
            "kernel.driver_image.restore.position.original",
            QStringLiteral("原位置"))
        : ((kResult.responseFlags &
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_LIST_TAIL) != 0U
            ? kernelText(
                "kernel.driver_image.restore.position.tail",
                QStringLiteral("当前尾部"))
            : QStringLiteral("-"));
    setStatus(
        kernelText(
            "kernel.driver_image.status.restored",
            QStringLiteral("状态：恢复完成，NTSTATUS=%1，changed=%2，链位置=%3"))
            .arg(ntStatusText(kResult.lastStatus))
            .arg(maskText(kResult.changedFieldMask))
            .arg(kPosition),
        kResult.lastStatus >= 0
            ? ksword_theme::successHex()
            : ksword_theme::errorHex());
}

// Abandonment is an irreversible record deletion; the current fields, hidden chain, and third-party conflicts are all preserved as-is.
void KernelDriverImageEditorDialog::abandonRecoveryRecord()
{
    ksword::ark::DriverImageControlResult snapshot{};
    if (!queryTransaction(snapshot, false))
    {
        return;
    }
    if ((snapshot.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT) == 0U)
    {
        return;
    }

    const QString kWarning = kernelText(
        "kernel.driver_image.abandon.warning",
        QStringLiteral("即将永久放弃 %1 的全部恢复记录。当前任意字段值、隐藏链状态和冲突都不会改变；KSword 将释放 DriverObject 引用，并失去自动恢复所需的原值与邻居。"))
        .arg(canonicalDriverName_);
    if (!confirmDanger(kWarning, kernelText("kernel.driver_image.abandon", QStringLiteral("放弃恢复记录"))))
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.abandonDriverImage(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        driverObjectAddress_,
        snapshot.generation);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }

    applyResultToView(kResult, false);
    setStatus(
        kernelText(
            "kernel.driver_image.status.abandoned",
            QStringLiteral("状态：恢复记录已放弃，NTSTATUS=%1；当前危险状态保持不变"))
            .arg(ntStatusText(kResult.lastStatus)),
        kResult.lastStatus >= 0
            ? ksword_theme::warningHex()
            : ksword_theme::errorHex());
}

// The response is the UI's sole source of truth; any failed response also refreshes conflicts and current values to avoid displaying stale snapshots.
void KernelDriverImageEditorDialog::applyResultToView(
    const ksword::ark::DriverImageControlResult& result,
    const bool resetDesiredValues)
{
    if (!result.driverName.empty())
    {
        canonicalDriverName_ =
            QString::fromStdWString(result.driverName);
    }
    moduleBase_ = result.targetModuleBase;
    driverObjectAddress_ = result.driverObjectAddress;
    currentLinkFlink_ = result.currentLinkFlink;
    currentLinkBlink_ = result.currentLinkBlink;
    generation_ = result.generation;
    responseFlags_ = result.responseFlags;
    managedFieldMask_ = result.managedFieldMask;

    const bool kRecordPresent =
        (result.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT) != 0U;
    for (int row = 0; row < static_cast<int>(std::size(kFieldRows)); ++row)
    {
        const std::uint32_t kField = kFieldRows[row].mask;
        const std::uint64_t kCurrent = fieldValue(result.currentValues, row);
        currentValues_[static_cast<std::size_t>(row)] = kCurrent;
        table_->item(row, kColumnCurrent)->setText(pointerText(kCurrent));
        if (resetDesiredValues)
        {
            table_->item(row, kColumnDesired)->setText(pointerText(kCurrent));
        }

        QString stateText;
        if ((result.conflictFieldMask & kField) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.conflict",
                QStringLiteral("外部冲突"));
        }
        else if ((result.ownedFieldMask & kField) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.owned",
                QStringLiteral("事务拥有"));
        }
        else if ((result.managedFieldMask & kField) != 0U)
        {
            stateText = kernelText(
                "kernel.driver_image.state.managed",
                QStringLiteral("已记录"));
        }
        else
        {
            stateText = kernelText(
                "kernel.driver_image.state.inactive",
                QStringLiteral("未受管"));
        }
        table_->item(row, kColumnState)->setText(stateText);
        table_->item(row, kColumnOriginal)->setText(
            kRecordPresent && (result.managedFieldMask & kField) != 0U
                ? pointerText(fieldValue(result.originalValues, row))
                : QStringLiteral("-"));
        table_->item(row, kColumnApplied)->setText(
            kRecordPresent && (result.managedFieldMask & kField) != 0U
                ? pointerText(fieldValue(result.appliedValues, row))
                : QStringLiteral("-"));
    }

    identityLabel_->setText(
        kernelText(
            "kernel.driver_image.identity",
            QStringLiteral("对象：%1    DriverObject=%2    冻结模块基址=%3"))
            .arg(
                canonicalDriverName_,
                pointerText(driverObjectAddress_),
                pointerText(moduleBase_)));
    updateDetails(result);
    setActionsEnabled(result.lastStatus >= 0, kRecordPresent);
}

// The details text retains every address and flag to facilitate copying to a debugger for verification, rather than providing only a 'success/failure' summary.
void KernelDriverImageEditorDialog::updateDetails(
    const ksword::ark::DriverImageControlResult& result)
{
    QString linkState = kernelText(
        "kernel.driver_image.link.unknown",
        QStringLiteral("未知/不可用"));
    if ((result.responseFlags &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.conflict",
            QStringLiteral("冲突"));
    }
    else if ((result.responseFlags &
              KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.hidden",
            QStringLiteral("隐藏/自环"));
    }
    else if ((result.responseFlags &
              KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE) != 0U)
    {
        linkState = kernelText(
            "kernel.driver_image.link.visible",
            QStringLiteral("可见/双向一致"));
    }

    QString detail;
    detail += kernelText(
        "kernel.driver_image.detail.status",
        QStringLiteral("Protocol=%1  Action=%2  State=%3  Generation=%4\nLastStatus=%5  LoaderStatus=%6\n"))
        .arg(result.version)
        .arg(result.action)
        .arg(result.state)
        .arg(result.generation)
        .arg(ntStatusText(result.lastStatus))
        .arg(ntStatusText(result.loaderStatus));
    detail += kernelText(
        "kernel.driver_image.detail.identity",
        QStringLiteral("DriverName=%1\nTargetModuleBase=%2  DriverObject=%3  SelfDriverObject=%4\n"))
        .arg(
            canonicalDriverName_,
            pointerText(result.targetModuleBase),
            pointerText(result.driverObjectAddress),
            pointerText(result.selfDriverObjectAddress));
    detail += kernelText(
        "kernel.driver_image.detail.masks",
        QStringLiteral("Managed=%1  Owned=%2  Conflict=%3  Changed=%4\nResponseFlags=%5  LayoutFlags=%6\n"))
        .arg(maskText(result.managedFieldMask))
        .arg(maskText(result.ownedFieldMask))
        .arg(maskText(result.conflictFieldMask))
        .arg(maskText(result.changedFieldMask))
        .arg(maskText(result.responseFlags))
        .arg(maskText(result.layoutFlags));
    detail += kernelText(
        "kernel.driver_image.detail.loader",
        QStringLiteral("LoaderEntry=%1  LoaderLink=%2\nPsLoadedModuleList=%3  PsLoadedModuleResource=%4\n"))
        .arg(
            pointerText(result.loaderEntryAddress),
            pointerText(result.loaderLinkAddress),
            pointerText(result.listHeadAddress),
            pointerText(result.listResourceAddress));
    detail += kernelText(
        "kernel.driver_image.detail.links",
        QStringLiteral("LinkState=%1\nCurrent.Flink=%2  Current.Blink=%3\nOriginal.Flink=%4  Original.Blink=%5\n"))
        .arg(linkState)
        .arg(pointerText(result.currentLinkFlink))
        .arg(pointerText(result.currentLinkBlink))
        .arg(pointerText(result.originalLinkFlink))
        .arg(pointerText(result.originalLinkBlink));
    detail += kernelText(
        "kernel.driver_image.detail.policy",
        QStringLiteral("Policy=warn-only; no target-class or requested-value restrictions.\nRestore uses ownership checks; competing values are reported and preserved."));
    detailEditor_->setText(detail);
}

// Enable buttons based on responsiveness; this only prevents requests without identity/record, not restricted by target type.
void KernelDriverImageEditorDialog::setActionsEnabled(
    const bool querySucceeded,
    const bool recordPresent)
{
    const bool kLoaderReady =
        (responseFlags_ &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LOADER_AVAILABLE) != 0U &&
        (responseFlags_ &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LIST_LOCK_AVAILABLE) != 0U;
    const bool kLinkVisible =
        (responseFlags_ &
         KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE) != 0U;
    const bool kLinkTracked =
        (responseFlags_ &
         (KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN |
          KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_OWNED |
          KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT)) != 0U;

    applyButton_->setEnabled(querySucceeded);
    hideButton_->setEnabled(querySucceeded && kLoaderReady && kLinkVisible);
    restoreButton_->setEnabled(querySucceeded && recordPresent);
    abandonButton_->setEnabled(querySucceeded && recordPresent);
    restoreLinkCheckBox_->setEnabled(
        querySucceeded && recordPresent && kLinkTracked);
    restoreLinkCheckBox_->setChecked(kLinkTracked);
}

// Status labels use explicit theme colors, avoiding inheritance of potential transparency or low-contrast styles from the parent window.
void KernelDriverImageEditorDialog::setStatus(
    const QString& text,
    const QString& colorHex)
{
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(colorHex));
}

// Each checkbox directly maps to a shared protocol bit, supporting single-field or batch transactions in any combination.
std::uint32_t KernelDriverImageEditorDialog::selectedFieldMask() const
{
    std::uint32_t mask = 0U;
    for (int row = 0; row < static_cast<int>(std::size(kFieldRows)); ++row)
    {
        const QTableWidgetItem* item =
            table_->item(row, kColumnSelected);
        if (item != nullptr && item->checkState() == Qt::Checked)
        {
            mask |= kFieldRows[row].mask;
        }
    }
    return mask;
}

// Unchecked fields retain current values; checked fields accept 0, decimal, or 0x hexadecimal full 64-bit numbers.
bool KernelDriverImageEditorDialog::parseDesiredValues(
    ksword::ark::DriverImageValues& valuesOut,
    QString& errorOut) const
{
    const std::uint32_t kFieldMask = selectedFieldMask();
    for (int row = 0; row < static_cast<int>(std::size(kFieldRows)); ++row)
    {
        setFieldValue(
            valuesOut,
            row,
            currentValues_[static_cast<std::size_t>(row)]);
        if ((kFieldMask & kFieldRows[row].mask) == 0U)
        {
            continue;
        }

        std::uint64_t value = 0U;
        const QTableWidgetItem* item =
            table_->item(row, kColumnDesired);
        if (item == nullptr || !parseUnsigned64(item->text(), value))
        {
            errorOut = kernelText(
                "kernel.driver_image.invalid_value",
                QStringLiteral("%1 的目标值无效；允许 0、十进制和 0x 十六进制。"))
                .arg(table_->item(row, kColumnField)->text());
            return false;
        }
        if (kFieldRows[row].naturalUlong &&
            value > std::numeric_limits<std::uint32_t>::max())
        {
            errorOut = kernelText(
                "kernel.driver_image.size_out_of_range",
                QStringLiteral("%1 是内核 ULONG 字段，目标值不能超过 0xFFFFFFFF；该检查只防止协议静默截断。"))
                .arg(table_->item(row, kColumnField)->text());
            return false;
        }
        setFieldValue(valuesOut, row, value);
    }
    return true;
}

// Two-step confirmation only proves the user has read the warning; the action name and button text must match to avoid policy restrictions.
bool KernelDriverImageEditorDialog::confirmDanger(
    const QString& warningText,
    const QString& phrase) const
{
    auto* self = const_cast<KernelDriverImageEditorDialog*>(this);
    if (QMessageBox::warning(
        self,
        windowTitle(),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return false;
    }

    // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; the phrase is used only to describe this action.
    return QMessageBox::warning(
        self,
        windowTitle(),
        kernelText(
            "kernel.driver_image.confirm.final",
            QStringLiteral("确认执行“%1”？请确保已知晓上述风险。"))
            .arg(phrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) == QMessageBox::Yes;
}

std::uint64_t KernelDriverImageEditorDialog::fieldValue(
    const ksword::ark::DriverImageValues& values,
    const int row)
{
    switch (row)
    {
    case 0: return values.driverStart;
    case 1: return values.driverSize;
    case 2: return values.driverSection;
    case 3: return values.kldrDllBase;
    case 4: return values.kldrSizeOfImage;
    default: return 0U;
    }
}

void KernelDriverImageEditorDialog::setFieldValue(
    ksword::ark::DriverImageValues& values,
    const int row,
    const std::uint64_t value)
{
    switch (row)
    {
    case 0: values.driverStart = value; break;
    case 1: values.driverSize = value; break;
    case 2: values.driverSection = value; break;
    case 3: values.kldrDllBase = value; break;
    case 4: values.kldrSizeOfImage = value; break;
    default: break;
    }
}

QString KernelDriverImageEditorDialog::pointerText(
    const std::uint64_t address)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverImageEditorDialog::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(
            static_cast<qulonglong>(
                static_cast<std::uint32_t>(status)),
            8,
            16,
            QChar('0'))
        .toUpper();
}

bool KernelDriverImageEditorDialog::parseUnsigned64(
    const QString& text,
    std::uint64_t& valueOut)
{
    bool ok = false;
    const qulonglong kValue = text.trimmed().toULongLong(&ok, 0);
    if (!ok)
    {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(kValue);
    return true;
}
