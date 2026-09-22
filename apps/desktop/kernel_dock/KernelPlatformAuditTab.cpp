#include "KernelPlatformAuditTab.h"

#include "KernelCleanImageBaseline.h"
#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHash>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#pragma comment(lib, "Version.lib")

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum PlatformColumn : int
    {
        kColumnName = 0,
        kColumnIndex,
        kColumnLiveAddress,
        kColumnOriginalAddress,
        kColumnHook,
        kColumnModule,
        kColumnVendor,
        kColumnTableAddress,
        kColumnSignature,
        kColumnConfidence,
        kColumnStatus,
        kColumnDetail,
        kColumnCount
    };

    enum PlatformItemRole : int
    {
        kRoleScope = Qt::UserRole + 101,
        kRoleEntryIndex,
        kRoleTableAddress
    };

    QTableWidgetItem* readOnlyPlatformItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // applyLiveAddressHeaderTooltip：
    // - Input table: audit page table; editable: whether this scope has writable function slots;
    // - Processing: Move the editability check from the original top persistent banner to the 'Current Address' column header; skip for read-only pages.
    // - Returns: Nothing.
    void applyLiveAddressHeaderTooltip(QTableWidget* table, const bool editable)
    {
        if (table == nullptr)
        {
            return;
        }
        QTableWidgetItem* headerItem = table->horizontalHeaderItem(kColumnLiveAddress);
        if (headerItem == nullptr)
        {
            return;
        }
        headerItem->setToolTip(editable
            ? kernelText(
                "kernel.platform.header.live.editable.tooltip",
                QStringLiteral(
                    "仅函数槽可改写；R0 会复核表身份、旧值与目标可执行节，"
                    "但无法证明函数签名兼容，错误地址会立即造成冻结或蓝屏。"))
            : QString());
    }

    // g_platformModuleCompanyMutex / g_platformModuleCompanyCache：
    // - Purpose: Process-level shared cache mapping modulePath to CompanyName.
    // - Input: written once by the worker thread of refreshAsync in the background after parsing;
    // - Output: populatePage performs only a table lookup; the UI thread no longer opens *.sys files to read version resource sections.
    std::mutex gPlatformModuleCompanyMutex;
    QHash<QString, QString> gPlatformModuleCompanyCache;

    // platformModuleCompanyLookup：
    // - Input modulePath: module path in the audit line; companyNameOut: vendor name to write back on match;
    // - Processing: Lock and query shared cache without any disk access;
    // - Returns: true if found; false if not found, without modifying companyNameOut.
    bool platformModuleCompanyLookup(const QString& modulePath, QString& companyNameOut)
    {
        const std::lock_guard kCacheLock(gPlatformModuleCompanyMutex);
        const auto kCacheIterator = gPlatformModuleCompanyCache.constFind(modulePath);
        if (kCacheIterator == gPlatformModuleCompanyCache.constEnd())
        {
            return false;
        }
        companyNameOut = kCacheIterator.value();
        return true;
    }

    // platformModuleCompanyStore：
    // - Input modulePath: module path in the audit row; companyName: vendor name parsed in the background;
    // - Processing: Acquire lock to write to shared cache for reuse by all subsequent pages and refresh operations.
    // - Returns: Nothing.
    void platformModuleCompanyStore(const QString& modulePath, const QString& companyName)
    {
        const std::lock_guard kCacheLock(gPlatformModuleCompanyMutex);
        gPlatformModuleCompanyCache.insert(modulePath, companyName);
    }

    QString platformColumnButtonStyle(const bool selected)
    {
        return QStringLiteral(
            "QPushButton{min-width:28px;padding:4px 8px;border:1px solid %1;"
            "background:%2;color:%3;}"
            "QPushButton:hover{background:%4;}")
            .arg(ksword_theme::borderHex())
            .arg(selected
                     ? ksword_theme::kPrimaryBlueHex
                     : ksword_theme::surfaceAltHex())
            .arg(selected
                     ? ksword_theme::onAccentDynamicHex()
                     : ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHoverHex);
    }

    bool validateRuntimeCleanPointer(
        const ks::kernel::CleanImageBaselineResult& baseline,
        const std::uint64_t runtimePointer,
        std::uint64_t& runtimeAddressOut)
    {
        runtimeAddressOut = 0U;
        if (!baseline.available ||
            !baseline.identityMatched ||
            !baseline.diskTrustVerified ||
            !baseline.codeIntegrityTrusted ||
            baseline.moduleBase == 0U ||
            baseline.moduleSize == 0U ||
            runtimePointer < baseline.moduleBase)
        {
            return false;
        }
        const std::uint64_t kRva =
            runtimePointer - baseline.moduleBase;
        if (kRva >= baseline.moduleSize)
        {
            return false;
        }
        runtimeAddressOut = runtimePointer;
        return true;
    }

    void enrichWdfFunctionBaselines(
        ksword::ark::PlatformAuditResult& result)
    {
        std::uint64_t tableAddress = 0U;
        std::size_t functionCount = 0U;
        for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
        {
            if (entry.scope !=
                    KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS ||
                entry.rowKind != KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION ||
                entry.tableAddress == 0U ||
                entry.entryIndex >= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS)
            {
                continue;
            }
            if (tableAddress == 0U)
            {
                tableAddress = entry.tableAddress;
            }
            else if (tableAddress != entry.tableAddress)
            {
                // Reject establishing a mixed baseline when two binding tables appear in the same response.
                return;
            }
            functionCount = std::max(
                functionCount,
                static_cast<std::size_t>(entry.entryIndex) + 1U);
        }
        if (tableAddress == 0U ||
            functionCount == 0U ||
            functionCount >
                std::numeric_limits<std::uint32_t>::max() /
                    sizeof(std::uint64_t))
        {
            return;
        }

        const std::uint32_t kTableBytes = static_cast<std::uint32_t>(
            functionCount * sizeof(std::uint64_t));
        const ks::kernel::CleanImageBaselineResult kBaseline =
            ks::kernel::KernelCleanImageBaseline::compareAddress(
                tableAddress,
                kTableBytes,
                {},
                true);
        if (!kBaseline.available ||
            !kBaseline.diskTrustVerified ||
            kBaseline.cleanBytes.size() != kTableBytes)
        {
            return;
        }

        for (KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
        {
            if (entry.scope !=
                    KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS ||
                entry.rowKind != KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION ||
                entry.tableAddress != tableAddress ||
                entry.entryIndex >= functionCount)
            {
                continue;
            }
            const std::size_t kByteOffset =
                static_cast<std::size_t>(entry.entryIndex) *
                sizeof(std::uint64_t);
            if (kByteOffset > kBaseline.cleanBytes.size() ||
                sizeof(std::uint64_t) >
                    kBaseline.cleanBytes.size() - kByteOffset)
            {
                continue;
            }

            std::uint64_t runtimePointer = 0U;
            std::memcpy(
                &runtimePointer,
                kBaseline.cleanBytes.data() + kByteOffset,
                sizeof(runtimePointer));
            std::uint64_t originalAddress = 0U;
            if (!validateRuntimeCleanPointer(
                    kBaseline,
                    runtimePointer,
                    originalAddress))
            {
                continue;
            }

            entry.originalAddress = originalAddress;
            entry.originalAddressSource =
                KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_DISK_IMAGE;
            entry.fieldFlags |=
                KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
                KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED;
            const bool kLiveSlotObserved =
                (entry.fieldFlags &
                 KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS) != 0UL ||
                entry.detailCode ==
                    KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT;
            if (kLiveSlotObserved &&
                entry.liveAddress != entry.originalAddress &&
                entry.hookStatus != KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS)
            {
                entry.fieldFlags |=
                    KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS;
                entry.detailArgs[0] = entry.liveAddress;
                entry.detailArgs[1] = entry.originalAddress;
                entry.detailArgs[2] = kBaseline.relativeVirtualAddress;
                entry.detailArgs[3] = entry.entryIndex;
                entry.hookStatus =
                    KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
                entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
                entry.status =
                    KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
                entry.lastStatus =
                    static_cast<long>(0xC000003EUL);
                entry.detailCode =
                    KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MISMATCH;
            }
            // Slot value equality only proves the binding table pointer hasn't been replaced, not that the function entry
            // hasn't been inline hooked; existing Suspicious entries already carry more specific owner/section/jump
            // evidence. Both cases retain the R0 conclusion, only supplementing with independent disk baseline fields.
        }
    }
}

KernelPlatformAuditTab::KernelPlatformAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      mode_(mode)
{
    initializeUi();
}

KernelPlatformAuditTab::~KernelPlatformAuditTab()
{
    {
        const std::lock_guard kLock(refreshMutex_);
        closing_ = true;
        if (refreshThread_.joinable())
        {
            // Note: Cancel the synchronous DeviceIoControl currently awaited by this worker. Failure only
            // indicates no cancellable synchronous I/O exists at this moment; a join is still required afterward.
            (void)::CancelSynchronousIo(refreshThread_.native_handle());
        }
    }
    if (refreshThread_.joinable())
    {
        refreshThread_.join();
    }
}

void KernelPlatformAuditTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void KernelPlatformAuditTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void KernelPlatformAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // Note: The read-only audit page no longer reserves top space with a persistent banner; the edit judgment criteria are now attached to the 'Current
    // Address' list header. When actually editing, the risk warning in the dialog and the secondary confirmation before writing will still be fully restated.
    auto* toolbar = new QHBoxLayout();
    toolbar->setContentsMargins(0, 0, 0, 0);
    toolbar->setSpacing(0);
    refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    refreshButton_->setToolTip(kernelText(
        "kernel.platform.toolbar.refresh.tooltip",
        QStringLiteral("重新读取经过结构与模块边界验证的只读审计快照")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    columnGroupAButton_ = new QPushButton(QStringLiteral("A"), this);
    columnGroupBButton_ = new QPushButton(QStringLiteral("B"), this);
    columnGroupCButton_ = new QPushButton(QStringLiteral("C"), this);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(kernelText(
        "kernel.platform.filter.placeholder",
        QStringLiteral("过滤名称 / 模块 / 厂商 / 状态 / 备注")));
    statusLabel_ = new QLabel(
        kernelText("kernel.platform.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    toolbar->addWidget(refreshButton_);
    toolbar->addSpacing(6);
    toolbar->addWidget(columnGroupAButton_);
    toolbar->addWidget(columnGroupBButton_);
    toolbar->addWidget(columnGroupCButton_);
    toolbar->addSpacing(6);
    toolbar->addWidget(filterEdit_, 1);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    innerTabs_ = new QTabWidget(this);
    innerTabs_->setDocumentMode(true);
    if (mode_ == Mode::kHal)
    {
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            kernelText("kernel.platform.hal.dispatch", QStringLiteral("HalDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            kernelText("kernel.platform.hal.private", QStringLiteral("HalPrivateDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            kernelText("kernel.platform.hal.acpi", QStringLiteral("HalAcpiDispatchTable")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            kernelText("kernel.platform.hal.subcomponents", QStringLiteral("HalSubComponents")));
    }
    else
    {
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            kernelText("kernel.platform.wdf.functions", QStringLiteral("WDF 函数")));
        addPage(
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS,
            kernelText("kernel.platform.wdf.callbacks", QStringLiteral("WDF 回调")));
    }
    rootLayout->addWidget(innerTabs_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(columnGroupAButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(0); });
    connect(columnGroupBButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(1); });
    connect(columnGroupCButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(2); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    updateColumnGroupButtons();
}

void KernelPlatformAuditTab::retranslateUi()
{
    QList<QTableView*> platformTables;
    platformTables.reserve(pages_.size());
    for (const Page& page : pages_)
    {
        platformTables.push_back(page.table);
    }
    if (ks::ui::isTableUiCommitBlockedByContextMenu(platformTables))
    {
        const QPointer<KernelPlatformAuditTab> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-platform-audit-retranslate"),
            platformTables,
            [kSafeThis]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->retranslateUi();
                }
            });
        return;
    }

    if (refreshButton_ != nullptr)
    {
        refreshButton_->setToolTip(kernelText(
            "kernel.platform.toolbar.refresh.tooltip",
            QStringLiteral("重新读取经过结构与模块边界验证的只读审计快照")));
    }
    if (columnGroupAButton_ != nullptr &&
        columnGroupBButton_ != nullptr &&
        columnGroupCButton_ != nullptr)
    {
        columnGroupAButton_->setToolTip(kernelText(
            "kernel.platform.columns.a",
            QStringLiteral("A：地址定位")));
        columnGroupBButton_->setToolTip(kernelText(
            "kernel.platform.columns.b",
            QStringLiteral("B：签名验证")));
        columnGroupCButton_->setToolTip(kernelText(
            "kernel.platform.columns.c",
            QStringLiteral("C：全部字段")));
        updateColumnGroupButtons();
    }
    if (filterEdit_ != nullptr)
    {
        filterEdit_->setPlaceholderText(kernelText(
            "kernel.platform.filter.placeholder",
            QStringLiteral("过滤名称 / 模块 / 厂商 / 状态 / 备注")));
    }

    const QStringList kHeaders = {
        kernelText("kernel.platform.header.name", QStringLiteral("函数 / 回调")),
        kernelText("kernel.platform.header.index", QStringLiteral("索引")),
        kernelText("kernel.platform.header.live", QStringLiteral("当前地址")),
        kernelText("kernel.platform.header.original", QStringLiteral("原始地址")),
        kernelText("kernel.platform.header.hook", QStringLiteral("Hook")),
        kernelText("kernel.platform.header.module", QStringLiteral("模块")),
        kernelText("kernel.platform.header.vendor", QStringLiteral("厂商")),
        kernelText("kernel.platform.header.table", QStringLiteral("表地址")),
        kernelText("kernel.platform.header.signature", QStringLiteral("签名策略")),
        kernelText("kernel.platform.header.confidence", QStringLiteral("置信度")),
        kernelText("kernel.platform.header.status", QStringLiteral("状态")),
        kernelText("kernel.platform.header.detail", QStringLiteral("备注"))
    };
    for (std::size_t index = 0U; index < pages_.size(); ++index)
    {
        Page& page = pages_[index];
        if (page.table != nullptr)
        {
            page.table->setHorizontalHeaderLabels(kHeaders);
            // setHorizontalHeaderLabels rebuilds header items; tooltips must be reattached to match the current language.
            applyLiveAddressHeaderTooltip(page.table, scopeIsEditable(page.scope));
        }
        QString title;
        switch (page.scope)
        {
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH:
            title = kernelText(
                "kernel.platform.hal.dispatch",
                QStringLiteral("HalDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE:
            title = kernelText(
                "kernel.platform.hal.private",
                QStringLiteral("HalPrivateDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI:
            title = kernelText(
                "kernel.platform.hal.acpi",
                QStringLiteral("HalAcpiDispatchTable"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS:
            title = kernelText(
                "kernel.platform.hal.subcomponents",
                QStringLiteral("HalSubComponents"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS:
            title = kernelText(
                "kernel.platform.wdf.functions",
                QStringLiteral("WDF 函数"));
            break;
        case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS:
            title = kernelText(
                "kernel.platform.wdf.callbacks",
                QStringLiteral("WDF 回调"));
            break;
        default:
            break;
        }
        if (innerTabs_ != nullptr &&
            index < static_cast<std::size_t>(innerTabs_->count()) &&
            !title.isEmpty())
        {
            innerTabs_->setTabText(static_cast<int>(index), title);
        }
    }

    if (refreshRunning_)
    {
        statusLabel_->setText(kernelText(
            "kernel.platform.status.refreshing",
            QStringLiteral("状态：正在读取只读审计快照...")));
    }
    else if (hasResult_)
    {
        applyResult(lastResult_);
    }
    else
    {
        statusLabel_->setText(kernelText(
            "kernel.platform.status.waiting",
            QStringLiteral("状态：等待刷新")));
    }
}

void KernelPlatformAuditTab::addPage(const unsigned long scope, const QString& title)
{
    auto* table = new ks::ui::VisibleTableWidget(innerTabs_);
    table->setColumnCount(kColumnCount);
    table->setHorizontalHeaderLabels({
        kernelText("kernel.platform.header.name", QStringLiteral("函数 / 回调")),
        kernelText("kernel.platform.header.index", QStringLiteral("索引")),
        kernelText("kernel.platform.header.live", QStringLiteral("当前地址")),
        kernelText("kernel.platform.header.original", QStringLiteral("原始地址")),
        kernelText("kernel.platform.header.hook", QStringLiteral("Hook")),
        kernelText("kernel.platform.header.module", QStringLiteral("模块")),
        kernelText("kernel.platform.header.vendor", QStringLiteral("厂商")),
        kernelText("kernel.platform.header.table", QStringLiteral("表地址")),
        kernelText("kernel.platform.header.signature", QStringLiteral("签名策略")),
        kernelText("kernel.platform.header.confidence", QStringLiteral("置信度")),
        kernelText("kernel.platform.header.status", QStringLiteral("状态")),
        kernelText("kernel.platform.header.detail", QStringLiteral("备注"))
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    if (scopeIsEditable(scope))
    {
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(
            table,
            &QTableWidget::customContextMenuRequested,
            this,
            [this, table, scope](const QPoint& position)
            {
                showContextMenu(table, scope, position);
            });
    }
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setStretchLastSection(true);
    // After removing the permanently visible risk banner at the top, the pre-event scope is now attached to the header of the 'Current Address' list.
    // Omitting this line causes the risk message to appear only after entering the edit dialog.
    applyLiveAddressHeaderTooltip(table, scopeIsEditable(scope));
    innerTabs_->addTab(table, title);
    pages_.push_back(Page{ scope, table });
    applyColumnGroup();
}

void KernelPlatformAuditTab::refreshAsync()
{
    if (refreshRunning_)
    {
        return;
    }
    if (refreshThread_.joinable())
    {
        // Note: m_refreshRunning is only cleared by GUI callbacks, so upon reaching this point,
        // the previous worker has completed; join only reclaims the handle, not the ongoing query.
        refreshThread_.join();
    }
    {
        const std::lock_guard kLock(refreshMutex_);
        if (closing_)
        {
            return;
        }
    }
    refreshRunning_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText(
        "kernel.platform.status.refreshing",
        QStringLiteral("状态：正在读取只读审计快照...")));

    const unsigned long kScope =
        mode_ == Mode::kHal
            ? (KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS)
            : (KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS |
               KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS);
    {
        const std::lock_guard kLock(refreshMutex_);
        if (closing_)
        {
            refreshRunning_ = false;
            refreshButton_->setEnabled(true);
            return;
        }
        refreshThread_ = std::thread([this, kScope]()
        {
            ksword::ark::DriverClient client;
            auto result = client.queryPlatformAudit(kScope);
            if (result.io.ok)
            {
                enrichWdfFunctionBaselines(result);
            }

            {
                const std::lock_guard kWorkerLock(refreshMutex_);
                if (closing_)
                {
                    return;
                }
            }
            // Note: Parsing CompanyName requires opening \SystemRoot\System32\drivers\*.sys files and parsing version
            // resource sections, which involves synchronous disk I/O and must remain on a worker thread. After writing
            // results to the process-level cache, populatePage performs only table lookups across pages and refreshes.
            for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
            {
                const QString kModulePath =
                    fixedWide(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS);
                QString cachedCompanyName;
                if (platformModuleCompanyLookup(kModulePath, cachedCompanyName))
                {
                    continue;
                }
                platformModuleCompanyStore(kModulePath, companyNameForModule(kModulePath));
            }
            {
                const std::lock_guard kWorkerLock(refreshMutex_);
                if (closing_)
                {
                    return;
                }
                const bool kPosted = QMetaObject::invokeMethod(
                    this,
                    [this, result = std::move(result)]() mutable
                    {
                        {
                            const std::lock_guard kGuiLock(refreshMutex_);
                            if (closing_)
                            {
                                return;
                            }
                        }
                        applyResult(std::move(result));
                    },
                    Qt::QueuedConnection);
                // Note: The receiver is the page itself; QObject destruction discards pending events.
                // If dispatch fails, the worker does not directly touch the GUI.
                Q_UNUSED(kPosted);
            }
        });
    }
}

void KernelPlatformAuditTab::applyResult(ksword::ark::PlatformAuditResult result)
{
    QList<QTableView*> platformTables;
    platformTables.reserve(pages_.size());
    for (const Page& page : pages_)
    {
        platformTables.push_back(page.table);
    }
    if (ks::ui::isTableUiCommitBlockedByContextMenu(platformTables))
    {
        // All platform audit pages originate from the same R0 return; they must be committed atomically within the same generation.
        const QPointer<KernelPlatformAuditTab> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-platform-audit-apply"),
            platformTables,
            [kSafeThis, result = std::move(result)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyResult(std::move(result));
                }
            });
        return;
    }

    lastResult_ = result;
    hasResult_ = true;
    refreshRunning_ = false;
    refreshButton_->setEnabled(true);
    for (Page& page : pages_)
    {
        populatePage(page, result);
    }
    applyColumnGroup();
    applyFilter();

    if (!result.io.ok)
    {
        statusLabel_->setText(kernelText(
            "kernel.platform.status.failed",
            QStringLiteral("状态：查询失败 - %1"))
            .arg(QString::fromStdString(result.io.message)));
        return;
    }
    statusLabel_->setText(kernelText(
        "kernel.platform.status.summary",
        QStringLiteral("状态：%1/%2 行，Build %3，Flags 0x%4"))
        .arg(result.entries.size())
        .arg(result.totalCount)
        .arg(result.buildNumber)
        .arg(result.responseFlags, 0, 16));
}

void KernelPlatformAuditTab::populatePage(
    Page& page,
    const ksword::ark::PlatformAuditResult& result)
{
    if (page.table == nullptr)
    {
        return;
    }
    page.table->setRowCount(0);
    for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : result.entries)
    {
        // Note: Global failures (e.g., module snapshot unavailable) return the combined scope
        // of the current request; combined diagnostics must be visible on every affected page.
        if ((entry.scope & page.scope) == 0UL)
        {
            continue;
        }
        const int kRow = page.table->rowCount();
        page.table->insertRow(kRow);
        QString signatureDisplay = signatureText(entry.signatureId);
        if (entry.prologueSignatureId != 0UL)
        {
            signatureDisplay += kernelText(
                "kernel.platform.signature.prologue_suffix",
                QStringLiteral(" / 函数头格式-%1"))
                .arg(entry.prologueSignatureId);
        }
        const QString kModulePath =
            fixedWide(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS);
        // Note: The company name is pre-resolved by the worker thread and written to the process-level cache; here, only a table lookup is performed.
        // A miss can only occur on the path where old results are replayed before the worker runs;
        // keep the placeholder and never fall back to synchronous disk reads on the UI thread.
        QString companyNameText = QStringLiteral("-");
        (void)platformModuleCompanyLookup(kModulePath, companyNameText);
        const std::array<QString, kColumnCount> kCells = {
            fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS),
            QString::number(entry.entryIndex),
            addressText(entry.liveAddress),
            addressText(entry.originalAddress),
            hookText(entry.hookStatus),
            kModulePath,
            companyNameText,
            addressText(entry.tableAddress),
            signatureDisplay,
            QStringLiteral("%1%").arg(entry.confidence),
            statusText(entry.status, entry.lastStatus),
            detailText(entry)
        };
        for (int column = 0; column < kColumnCount; ++column)
        {
            auto* item = readOnlyPlatformItem(
                kCells[static_cast<std::size_t>(column)]);
            if (column == kColumnName)
            {
                item->setData(
                    kRoleScope,
                    QVariant::fromValue<qulonglong>(entry.scope));
                item->setData(
                    kRoleEntryIndex,
                    QVariant::fromValue<qulonglong>(entry.entryIndex));
                item->setData(
                    kRoleTableAddress,
                    QVariant::fromValue<qulonglong>(entry.tableAddress));
            }
            page.table->setItem(kRow, column, item);
        }
    }
}

void KernelPlatformAuditTab::showContextMenu(
    QTableWidget* table,
    const unsigned long scope,
    const QPoint& position)
{
    if (!scopeIsEditable(scope) || table == nullptr)
    {
        return;
    }
    const QModelIndex kIndex = table->indexAt(position);
    if (!kIndex.isValid())
    {
        return;
    }
    table->setCurrentCell(kIndex.row(), kIndex.column());
    const QTableWidgetItem* nameItem = table->item(kIndex.row(), kColumnName);
    if (nameItem == nullptr)
    {
        return;
    }
    const unsigned long kEntryIndex =
        nameItem->data(kRoleEntryIndex).toULongLong();
    const unsigned long long kTableAddress =
        nameItem->data(kRoleTableAddress).toULongLong();
    const auto kEntryIt = std::find_if(
        lastResult_.entries.cbegin(),
        lastResult_.entries.cend(),
        [scope, kEntryIndex, kTableAddress](
            const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry)
        {
            return entry.scope == scope &&
                entry.entryIndex == kEntryIndex &&
                entry.tableAddress == kTableAddress;
        });

    QMenu menu(table);
    QAction* editAction = menu.addAction(kernelText(
        "kernel.platform.slot.edit.action",
        QStringLiteral("编辑 %1 函数槽..."))
        .arg(tableFamilyName()));
    const bool kEditable =
        kEntryIt != lastResult_.entries.cend() &&
        kEntryIt->rowKind == KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION &&
        kEntryIt->slotKind == KSWORD_ARK_PLATFORM_SLOT_FUNCTION &&
        kEntryIt->tableAddress != 0ULL &&
        (kEntryIt->fieldFlags &
         KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED) != 0UL;
    editAction->setEnabled(kEditable);
    editAction->setToolTip(kEditable
        ? kernelText(
            "kernel.platform.slot.edit.action.tooltip",
            QStringLiteral("输入新的已加载内核模块可执行地址，并经过双重确认后原子替换"))
        : kernelText(
            "kernel.platform.slot.edit.unavailable.tooltip",
            QStringLiteral("仅结构已验证且具有表地址的函数槽可编辑")));
    if (menu.exec(table->viewport()->mapToGlobal(position)) == editAction &&
        kEditable)
    {
        editFunctionSlot(*kEntryIt);
    }
}

void KernelPlatformAuditTab::editFunctionSlot(
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry)
{
    const QString kFamilyName = tableFamilyName();
    QDialog editor(this);
    editor.setObjectName(QStringLiteral("ksPlatformSlotEditDialog"));
    editor.setStyleSheet(ksword_theme::opaqueDialogStyle(editor.objectName()));
    editor.setWindowTitle(kernelText(
        "kernel.platform.slot.edit.dialog.title",
        QStringLiteral("编辑 %1 函数槽"))
        .arg(kFamilyName));
    auto* layout = new QVBoxLayout(&editor);
    QString riskText = kernelText(
        "kernel.platform.slot.edit.dialog.risk",
        QStringLiteral(
            "目标地址必须位于已加载内核模块的可执行节。R0 仍无法验证函数原型、调用约定或运行时语义；"
            "不兼容的地址可能在该槽下一次被调用时立即使系统崩溃。"));
    if (mode_ == Mode::kWdf)
    {
        riskText.append(QChar(QLatin1Char('\n')));
        riskText.append(kernelText(
            "kernel.platform.slot.edit.dialog.risk.shared",
            QStringLiteral(
                "该槽位于 Wdf01000.sys 的只读节，由系统上所有 KMDF 驱动共享；"
                "R0 会为它建立临时 MDL 可写别名后提交，改动对每一个 KMDF 驱动同时生效。")));
    }
    auto* riskLabel = new QLabel(riskText, &editor);
    riskLabel->setWordWrap(true);
    riskLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::warningHex()));
    layout->addWidget(riskLabel);

    auto* form = new QFormLayout();
    form->addRow(
        kernelText("kernel.platform.slot.edit.field.name", QStringLiteral("函数槽")),
        new QLabel(
            fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS),
            &editor));
    form->addRow(
        kernelText("kernel.platform.slot.edit.field.table", QStringLiteral("表地址")),
        new QLabel(addressText(entry.tableAddress), &editor));
    form->addRow(
        kernelText("kernel.platform.slot.edit.field.current", QStringLiteral("当前地址")),
        new QLabel(addressText(entry.liveAddress), &editor));
    auto* addressEdit = new QLineEdit(&editor);
    addressEdit->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
    addressEdit->setText(addressText(entry.liveAddress));
    addressEdit->selectAll();

    // Provide a one-click fill-in entry when a disk baseline is available: restoring overwritten slots is the most common
    // use case for this page; manually typing a 16-digit hexadecimal address is slow and prone to single-digit errors.
    const bool kBaselineAvailable =
        (entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS) != 0UL &&
        entry.originalAddress != 0ULL;
    if (kBaselineAvailable)
    {
        auto* originalRow = new QWidget(&editor);
        auto* originalLayout = new QHBoxLayout(originalRow);
        originalLayout->setContentsMargins(0, 0, 0, 0);
        originalLayout->addWidget(
            new QLabel(addressText(entry.originalAddress), originalRow), 1);
        auto* restoreButton = new QPushButton(
            kernelText(
                "kernel.platform.slot.edit.field.original.fill",
                QStringLiteral("填入")),
            originalRow);
        restoreButton->setToolTip(kernelText(
            "kernel.platform.slot.edit.field.original.fill.tooltip",
            QStringLiteral("把磁盘映像基线解析出的原始地址填入下方输入框")));
        restoreButton->setStyleSheet(ksword_theme::themedButtonStyle());
        const unsigned long long kOriginalAddress = entry.originalAddress;
        connect(
            restoreButton,
            &QPushButton::clicked,
            addressEdit,
            [addressEdit, kOriginalAddress]()
            {
                addressEdit->setText(addressText(kOriginalAddress));
                addressEdit->selectAll();
                addressEdit->setFocus();
            });
        originalLayout->addWidget(restoreButton);
        form->addRow(
            kernelText(
                "kernel.platform.slot.edit.field.original",
                QStringLiteral("原始地址（磁盘基线）")),
            originalRow);
    }
    form->addRow(
        kernelText("kernel.platform.slot.edit.field.new", QStringLiteral("新函数地址")),
        addressEdit);
    layout->addLayout(form);

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &editor);
    buttons->button(QDialogButtonBox::Ok)->setText(kernelText(
        "kernel.platform.slot.edit.continue",
        QStringLiteral("继续风险确认")));
    connect(buttons, &QDialogButtonBox::accepted, &editor, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &editor, &QDialog::reject);
    layout->addWidget(buttons);
    addressEdit->setFocus();
    if (editor.exec() != QDialog::Accepted)
    {
        return;
    }

    unsigned long long newAddress = 0ULL;
    if (!parseAddress(addressEdit->text(), newAddress))
    {
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.platform.slot.edit.invalid.title",
                QStringLiteral("地址无效")),
            kernelText(
                "kernel.platform.slot.edit.invalid.body",
                QStringLiteral("请输入非零的 64 位十六进制内核地址。")));
        return;
    }
    if (newAddress == entry.liveAddress)
    {
        QMessageBox::information(
            this,
            kernelText(
                "kernel.platform.slot.edit.no_change.title",
                QStringLiteral("表项未修改")),
            kernelText(
                "kernel.platform.slot.edit.no_change.body",
                QStringLiteral("新地址与当前地址相同，没有执行写入。")));
        return;
    }
    if (!confirmSlotEdit(entry, newAddress))
    {
        return;
    }

    ksword::ark::DriverClient client;
    const auto kResult = client.editPlatformAuditEntry(
        entry.scope,
        entry.entryIndex,
        entry.tableAddress,
        entry.liveAddress,
        newAddress,
        true);
    if (!kResult.io.ok ||
        kResult.response.status != KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.platform.slot.edit.failed.title",
                QStringLiteral("%1 表项编辑失败")).arg(kFamilyName),
            kResult.io.ok
                ? controlStatusText(
                    kResult.response.status,
                    kResult.response.lastStatus)
                : kernelText(
                    "kernel.platform.slot.edit.transport_failed",
                    QStringLiteral("R0 控制失败：%1"))
                    .arg(QString::fromStdString(kResult.io.message)));
        refreshAsync();
        return;
    }

    QString successBody = kernelText(
        "kernel.platform.slot.edit.succeeded.body",
        QStringLiteral("%1 已从 %2 原子替换为 %3。页面将立即重新读取 R0 快照。"))
        .arg(fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS))
        .arg(addressText(kResult.response.previousValue))
        .arg(addressText(kResult.response.currentValue));
    if ((kResult.response.responseFlags &
         KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_ALIAS_WRITE) != 0UL)
    {
        successBody.append(QChar(QLatin1Char('\n')));
        successBody.append(kernelText(
            "kernel.platform.slot.edit.succeeded.alias",
            QStringLiteral("槽位所在节只读，本次写入经 R0 的临时 MDL 可写别名提交。")));
    }
    QMessageBox::information(
        this,
        kernelText(
            "kernel.platform.slot.edit.succeeded.title",
            QStringLiteral("%1 表项已修改")).arg(kFamilyName),
        successBody);
    refreshAsync();
}

bool KernelPlatformAuditTab::confirmSlotEdit(
    const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry,
    const unsigned long long newAddress)
{
    const QString kFamilyName = tableFamilyName();
    QString confirmBody = kernelText(
        "kernel.platform.slot.edit.confirm.body",
        QStringLiteral(
            "即将修改 %1：\n%2 → %3\n\n"
            "这会立即改变内核控制流。地址即使位于可执行节，也可能因函数签名不兼容造成冻结、蓝屏或数据损坏。"
            "请确认已保存工作，并且当前环境允许整机故障。"))
        .arg(fixedWide(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS))
        .arg(addressText(entry.liveAddress))
        .arg(addressText(newAddress));
    if (mode_ == Mode::kWdf)
    {
        confirmBody.append(QChar(QLatin1Char('\n')));
        confirmBody.append(kernelText(
            "kernel.platform.slot.edit.confirm.shared",
            QStringLiteral(
                "该槽属于全系统共享的 KMDF 绑定表，KSword 自身的驱动也在使用它；"
                "一旦不可用，可能连卸载驱动这条退路都会失效。")));
    }

    QMessageBox warningBox(this);
    warningBox.setObjectName(QStringLiteral("ksPlatformSlotEditRiskDialog"));
    warningBox.setStyleSheet(
        ksword_theme::opaqueDialogStyle(warningBox.objectName()));
    warningBox.setIcon(QMessageBox::Warning);
    warningBox.setWindowTitle(kernelText(
        "kernel.platform.slot.edit.confirm.title",
        QStringLiteral("%1 内核函数指针风险确认")).arg(kFamilyName));
    warningBox.setText(confirmBody);
    warningBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    warningBox.setDefaultButton(QMessageBox::Cancel);
    if (warningBox.exec() != QMessageBox::Ok)
    {
        return false;
    }

    // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; defaults to focusing 'No' to prevent accidental triggers.
    QMessageBox finalBox(this);
    finalBox.setIcon(QMessageBox::Warning);
    finalBox.setWindowTitle(kernelText(
        "kernel.platform.slot.edit.final.title",
        QStringLiteral("最终确认")));
    finalBox.setText(kernelText(
        "kernel.platform.slot.edit.final.body",
        QStringLiteral("确认执行 %1 函数指针替换？该操作会改变内核控制流，可能导致蓝屏。"))
        .arg(kFamilyName));
    finalBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    finalBox.setDefaultButton(QMessageBox::No);
    return finalBox.exec() == QMessageBox::Yes;
}

bool KernelPlatformAuditTab::scopeIsEditable(const unsigned long scope)
{
    return scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH ||
        scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE ||
        scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI ||
        scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS ||
        scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS;
}

QString KernelPlatformAuditTab::tableFamilyName() const
{
    return mode_ == Mode::kHal
        ? kernelText("kernel.platform.family.hal", QStringLiteral("HAL"))
        : kernelText("kernel.platform.family.wdf", QStringLiteral("KMDF 绑定表"));
}

void KernelPlatformAuditTab::setColumnGroup(const int groupIndex)
{
    columnGroupIndex_ = std::clamp(groupIndex, 0, 2);
    updateColumnGroupButtons();
    applyColumnGroup();
}

void KernelPlatformAuditTab::applyColumnGroup()
{
    const int kGroupIndex = columnGroupIndex_;
    for (const Page& page : pages_)
    {
        if (page.table == nullptr)
        {
            continue;
        }
        for (int column = 0; column < kColumnCount; ++column)
        {
            bool visible = kGroupIndex == 2;
            if (kGroupIndex == 0)
            {
                visible = column == kColumnName ||
                    column == kColumnLiveAddress ||
                    column == kColumnOriginalAddress ||
                    column == kColumnHook ||
                    column == kColumnModule ||
                    column == kColumnStatus;
            }
            else if (kGroupIndex == 1)
            {
                visible = column == kColumnName ||
                    column == kColumnIndex ||
                    column == kColumnTableAddress ||
                    column == kColumnSignature ||
                    column == kColumnConfidence ||
                    column == kColumnDetail;
            }
            page.table->setColumnHidden(column, !visible);
        }
    }
}

void KernelPlatformAuditTab::updateColumnGroupButtons()
{
    const std::array<QPushButton*, 3> kButtons = {
        columnGroupAButton_,
        columnGroupBButton_,
        columnGroupCButton_
    };
    for (std::size_t index = 0U; index < kButtons.size(); ++index)
    {
        if (kButtons[index] != nullptr)
        {
            kButtons[index]->setStyleSheet(
                platformColumnButtonStyle(
                    static_cast<int>(index) == columnGroupIndex_));
        }
    }
}

void KernelPlatformAuditTab::applyFilter()
{
    const QString kFilterText = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    for (const Page& page : pages_)
    {
        if (page.table == nullptr)
        {
            continue;
        }
        for (int row = 0; row < page.table->rowCount(); ++row)
        {
            bool matched = kFilterText.isEmpty();
            for (int column = 0; !matched && column < page.table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = page.table->item(row, column);
                matched = item != nullptr && item->text().contains(kFilterText, Qt::CaseInsensitive);
            }
            page.table->setRowHidden(row, !matched);
        }
    }
}

QString KernelPlatformAuditTab::fixedWide(const wchar_t* text, const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return QString();
    }
    int length = 0;
    while (length < capacity && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, length);
}

QString KernelPlatformAuditTab::addressText(const unsigned long long address)
{
    return address == 0ULL
        ? QStringLiteral("-")
        : QStringLiteral("0x%1").arg(address, 16, 16, QLatin1Char('0')).toUpper();
}

QString KernelPlatformAuditTab::controlStatusText(
    const unsigned long status,
    const long lastStatus)
{
    QString reason;
    switch (status)
    {
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_CONFIRMATION_REQUIRED:
        reason = kernelText(
            "kernel.platform.slot.edit.status.confirmation_required",
            QStringLiteral("确认信息被拒绝"));
        break;
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_UNSUPPORTED:
        reason = kernelText(
            "kernel.platform.slot.edit.status.unsupported",
            QStringLiteral("当前系统布局未通过表重新定位验证"));
        break;
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_STALE_SNAPSHOT:
        reason = kernelText(
            "kernel.platform.slot.edit.status.stale",
            QStringLiteral("表地址或槽位当前值已变化，快照过期"));
        break;
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_TARGET_INVALID:
        reason = kernelText(
            "kernel.platform.slot.edit.status.target_invalid",
            QStringLiteral("目标地址不属于已加载内核模块的可执行节"));
        break;
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_WRITE_FAILED:
        reason = kernelText(
            "kernel.platform.slot.edit.status.write_failed",
            QStringLiteral("原子写入失败；槽位在只读节时，HVCI 会拒绝建立可写别名"));
        break;
    case KSWORD_ARK_PLATFORM_CONTROL_STATUS_SAFETY_DENIED:
        reason = kernelText(
            "kernel.platform.slot.edit.status.safety_denied",
            QStringLiteral("中央内核修改安全策略拒绝了操作"));
        break;
    default:
        reason = kernelText(
            "kernel.platform.slot.edit.status.invalid",
            QStringLiteral("请求或响应无效"));
        break;
    }
    return kernelText(
        "kernel.platform.slot.edit.status.format",
        QStringLiteral("%1（NTSTATUS 0x%2）"))
        .arg(reason)
        .arg(
            static_cast<unsigned long>(lastStatus),
            8,
            16,
            QLatin1Char('0'))
        .toUpper();
}

bool KernelPlatformAuditTab::parseAddress(
    const QString& text,
    unsigned long long& addressOut)
{
    QString normalized = text.trimmed();
    if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        normalized.remove(0, 2);
    }
    bool ok = false;
    const qulonglong kValue = normalized.toULongLong(&ok, 16);
    if (!ok || kValue == 0ULL)
    {
        addressOut = 0ULL;
        return false;
    }
    addressOut = static_cast<unsigned long long>(kValue);
    return true;
}

QString KernelPlatformAuditTab::statusText(const unsigned long status, const long lastStatus)
{
    QString text;
    switch (status)
    {
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK:
        text = kernelText("kernel.platform.value.ok", QStringLiteral("已读取"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL:
        text = kernelText("kernel.platform.value.partial", QStringLiteral("部分"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED:
        text = kernelText("kernel.platform.value.unsupported", QStringLiteral("不支持 / 失败关闭"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH:
        text = kernelText("kernel.platform.value.signature_mismatch", QStringLiteral("签名不匹配"));
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED:
        text = kernelText("kernel.platform.value.query_failed", QStringLiteral("查询失败"));
        break;
    default:
        text = kernelText("kernel.platform.value.unavailable", QStringLiteral("不可用"));
        break;
    }
    return QStringLiteral("%1 (0x%2)")
        .arg(text)
        .arg(static_cast<unsigned long>(lastStatus), 8, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelPlatformAuditTab::hookText(const unsigned long hookStatus)
{
    switch (hookStatus)
    {
    case KSWORD_ARK_PLATFORM_HOOK_CLEAN:
        return kernelText("kernel.platform.hook.clean", QStringLiteral("Clean"));
    case KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS:
        return kernelText("kernel.platform.hook.suspicious", QStringLiteral("Suspicious"));
    case KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED:
        return kernelText("kernel.platform.hook.unsupported", QStringLiteral("Unsupported"));
    default:
        return kernelText("kernel.platform.hook.unknown", QStringLiteral("Unknown"));
    }
}

QString KernelPlatformAuditTab::signatureText(const unsigned long signatureId)
{
    switch (signatureId)
    {
    case KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6:
        return kernelText("kernel.platform.signature.public_hal_v6", QStringLiteral("公开 HAL v6"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5:
        return kernelText("kernel.platform.signature.public_hal_v4_v5", QStringLiteral("公开 HAL v4/v5"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE:
        return kernelText("kernel.platform.signature.wdf_binding", QStringLiteral("KMDF 绑定表"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE:
        return kernelText("kernel.platform.signature.x64_format", QStringLiteral("x64 函数头格式"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY:
        return kernelText("kernel.platform.signature.exact_export", QStringLiteral("精确导出 / 失败关闭"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED:
        return kernelText("kernel.platform.signature.rip_masked", QStringLiteral("有界 byte/mask + RIP-relative"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V51:
        return kernelText("kernel.platform.signature.private_v51", QStringLiteral("HAL 私有表 v51 / 0x4B0"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V54:
        return kernelText("kernel.platform.signature.private_v54", QStringLiteral("HAL 私有表 v54 / 0x4D8"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V58:
        return kernelText("kernel.platform.signature.private_v58", QStringLiteral("HAL 私有表 v58 / 0x4F0"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61:
        return kernelText("kernel.platform.signature.private_v61", QStringLiteral("HAL 私有表 v61 / 0x518"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V4:
        return kernelText("kernel.platform.signature.acpi_v4", QStringLiteral("HAL ACPI v4 / 21 项"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V5:
        return kernelText("kernel.platform.signature.acpi_v5", QStringLiteral("HAL ACPI v5 / 18 项"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_22:
        return kernelText("kernel.platform.signature.subcomponents_22", QStringLiteral("HAL 子组件 / 22 对"));
    case KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_21:
        return kernelText("kernel.platform.signature.subcomponents_21", QStringLiteral("HAL 子组件 / 21 对"));
    default:
        return QStringLiteral("-");
    }
}

QString KernelPlatformAuditTab::detailText(
    const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry)
{
    const auto kHex = [](const unsigned long long value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    };

    switch (entry.detailCode)
    {
    case KSWORD_ARK_PLATFORM_DETAIL_OWNER_CONSISTENT:
        return kernelText(
            "kernel.platform.detail.owner_consistent",
            QStringLiteral("owner 与执行节一致；没有独立基线，结论保持 Unknown。"));
    case KSWORD_ARK_PLATFORM_DETAIL_OWNER_MISMATCH:
        return kernelText(
            "kernel.platform.detail.owner_mismatch",
            QStringLiteral("地址 %1 不属于该槽允许的 provider（策略 %2）。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(entry.detailArgs[2]);
    case KSWORD_ARK_PLATFORM_DETAIL_NON_EXECUTABLE:
        return kernelText(
            "kernel.platform.detail.non_executable",
            QStringLiteral("地址 %1 不在所属模块的可执行节。"))
            .arg(kHex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT:
        return kernelText(
            "kernel.platform.detail.null_slot",
            QStringLiteral("槽位为空（offset/index %1）。"))
            .arg(kHex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED:
        return kernelText(
            "kernel.platform.detail.read_failed",
            QStringLiteral("已验证范围内读取失败（offset/address %1，size %2）。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(entry.detailArgs[1]);
    case KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED:
        return kernelText(
            "kernel.platform.detail.build_unsupported",
            QStringLiteral("Build %1 没有经过验证的结构/定位描述，当前 scope 失败关闭。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH:
        return kernelText(
            "kernel.platform.detail.version_mismatch",
            QStringLiteral("结构版本不匹配：期望 %1，实际 %2；当前 scope 失败关闭。"))
            .arg(entry.detailArgs[0])
            .arg(entry.detailArgs[1]);
    case KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID:
        return kernelText(
            "kernel.platform.detail.range_invalid",
            QStringLiteral("表的完整范围/所属节验证失败（期望字节 %1）。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE:
        return kernelText(
            "kernel.platform.detail.locator_not_unique",
            QStringLiteral("可信锚点小窗口内出现多个完整候选，拒绝选择。"));
    case KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND:
        return kernelText(
            "kernel.platform.detail.locator_not_found",
            QStringLiteral("可信锚点小窗口内没有唯一且完整验证的候选，当前 scope 失败关闭。"));
    case KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID:
        return kernelText(
            "kernel.platform.detail.table_invalid",
            QStringLiteral("表元数据或完整结构验证失败。"));
    case KSWORD_ARK_PLATFORM_DETAIL_MODULE_SNAPSHOT_FAILED:
        return kernelText(
            "kernel.platform.detail.module_snapshot_failed",
            QStringLiteral("无法取得加载模块快照；没有 owner 证据时拒绝审计。"));
    case KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE:
        return kernelText(
            "kernel.platform.detail.scalar_value",
            QStringLiteral("标量值 %1（结构字节/offset %2）。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(kHex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_DUMMY_SLOT:
        return kernelText(
            "kernel.platform.detail.dummy_slot",
            QStringLiteral("该描述明确标记为 dummy，不按函数指针解释；原值 %1。"))
            .arg(kHex(entry.detailArgs[0]));
    case KSWORD_ARK_PLATFORM_DETAIL_DETOUR_EXTERNAL:
        return kernelText(
            "kernel.platform.detail.detour_external",
            QStringLiteral("检测到跳转：%1 -> %2，目标不属于允许的 provider。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(kHex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_DETOUR_SAME_OWNER:
        return kernelText(
            "kernel.platform.detail.detour_same_owner",
            QStringLiteral("检测到同一允许 provider 内的跳转：%1 -> %2；没有独立基线，保持 Unknown。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(kHex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_FORMAT_RECOGNIZED:
        return kernelText(
            "kernel.platform.detail.format_recognized",
            QStringLiteral("owner/执行节一致，函数头格式 %1 可识别；格式仅为提示，没有独立基线，保持 Unknown。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_PLATFORM_DETAIL_FORMAT_UNKNOWN:
        return kernelText(
            "kernel.platform.detail.format_unknown",
            QStringLiteral("owner/执行节一致，但函数头不匹配通用格式；没有独立基线，保持 Unknown。"));
    case KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID:
        return kernelText(
            "kernel.platform.detail.wdf_table_invalid",
            QStringLiteral("WDF 完整绑定表不在 Wdf01000.sys 的同一非执行节，或表项数无效。"));
    case KSWORD_ARK_PLATFORM_DETAIL_WDF_INDEX_INVALID:
        return kernelText(
            "kernel.platform.detail.wdf_index_invalid",
            QStringLiteral("WDF 表项索引/指针无效。"));
    case KSWORD_ARK_PLATFORM_DETAIL_ACPI_V5_VALIDATED:
        return kernelText(
            "kernel.platform.detail.acpi_v5_validated",
            QStringLiteral("HAL ACPI v5 的 Signature、Version 和 18 个函数已完整验证。"));
    case KSWORD_ARK_PLATFORM_DETAIL_SUBCOMPONENT_VALIDATED:
        return kernelText(
            "kernel.platform.detail.subcomponent_validated",
            QStringLiteral("22 对函数/UTF-16 名称（含 Qos）已完整验证。"));
    case KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MATCH:
        return kernelText(
            "kernel.platform.detail.baseline_match",
            QStringLiteral("已验证磁盘映像基线匹配：当前地址 %1，原始地址 %2。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(kHex(entry.detailArgs[1]));
    case KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MISMATCH:
        return kernelText(
            "kernel.platform.detail.baseline_mismatch",
            QStringLiteral("已验证磁盘映像基线不匹配：当前地址 %1，原始地址 %2。"))
            .arg(kHex(entry.detailArgs[0]))
            .arg(kHex(entry.detailArgs[1]));
    default:
        return QStringLiteral("-");
    }
}

QString KernelPlatformAuditTab::companyNameForModule(const QString& modulePath)
{
    if (modulePath.trimmed().isEmpty())
    {
        return QStringLiteral("-");
    }

    QString path = QDir::fromNativeSeparators(modulePath.trimmed());
    if (path.startsWith(QStringLiteral("/SystemRoot/"), Qt::CaseInsensitive))
    {
        wchar_t windowsDirectory[MAX_PATH] = {};
        const UINT kLength =
            ::GetWindowsDirectoryW(windowsDirectory, ARRAYSIZE(windowsDirectory));
        if (kLength == 0U || kLength >= ARRAYSIZE(windowsDirectory))
        {
            return QStringLiteral("-");
        }
        path = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectory)) +
            path.mid(QStringLiteral("/SystemRoot").size());
    }
    else if (path.startsWith(QStringLiteral("/??/")) ||
             path.startsWith(QStringLiteral("//?/")))
    {
        path.remove(0, 4);
    }
    if (!QDir::isAbsolutePath(path))
    {
        return QStringLiteral("-");
    }
    path = QDir::toNativeSeparators(QDir::cleanPath(path));

    DWORD ignored = 0UL;
    const DWORD kBytes = ::GetFileVersionInfoSizeW(
        reinterpret_cast<LPCWSTR>(path.utf16()),
        &ignored);
    if (kBytes == 0UL ||
        kBytes > static_cast<DWORD>(std::numeric_limits<int>::max()))
    {
        return QStringLiteral("-");
    }
    std::vector<unsigned char> versionData(kBytes);
    if (!::GetFileVersionInfoW(
            reinterpret_cast<LPCWSTR>(path.utf16()),
            0UL,
            kBytes,
            versionData.data()))
    {
        return QStringLiteral("-");
    }

    struct Translation
    {
        WORD language;
        WORD codePage;
    };
    Translation* translations = nullptr;
    UINT translationBytes = 0U;
    std::vector<Translation> candidates;
    if (::VerQueryValueW(
            versionData.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<void**>(&translations),
            &translationBytes) &&
        translations != nullptr)
    {
        const UINT kCount = translationBytes / sizeof(Translation);
        candidates.assign(translations, translations + kCount);
    }
    candidates.push_back(Translation{ 0x0409U, 0x04B0U });

    for (const Translation kCandidate : candidates)
    {
        const QString kBlock = QStringLiteral(
            "\\StringFileInfo\\%1%2\\CompanyName")
            .arg(kCandidate.language, 4, 16, QLatin1Char('0'))
            .arg(kCandidate.codePage, 4, 16, QLatin1Char('0'));
        wchar_t* company = nullptr;
        UINT companyChars = 0U;
        if (::VerQueryValueW(
                versionData.data(),
                reinterpret_cast<LPCWSTR>(kBlock.utf16()),
                reinterpret_cast<void**>(&company),
                &companyChars) &&
            company != nullptr &&
            companyChars > 1U)
        {
            const QString kValue =
                QString::fromWCharArray(
                    company,
                    static_cast<int>(companyChars - 1U))
                    .trimmed();
            if (!kValue.isEmpty())
            {
                return kValue;
            }
        }
    }
    return QStringLiteral("-");
}
