#include "ServiceDock.Internal.h"
#include "../ui/TableInteractionSupport.h"

using namespace service_dock_detail;

ServiceDock::ServiceDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    syncToolbarStateWithSelection();

    KLogEvent initEvent;
    info << initEvent << "[ServiceDock] 服务管理页面初始化完成。" << eol;
}

ServiceDock::~ServiceDock()
{
    if (refreshThread_ != nullptr && refreshThread_->joinable())
    {
        refreshThread_->join();
    }

    KLogEvent destroyEvent;
    info << destroyEvent << "[ServiceDock] 服务管理页面已析构。" << eol;
}

void ServiceDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (initialRefreshDone_)
    {
        return;
    }

    initialRefreshDone_ = true;
    if (summaryLabel_ != nullptr)
    {
        summaryLabel_->setText(QStringLiteral("状态：首次打开，准备加载服务列表..."));
    }

    // Defer the initial refresh trigger until the event loop to ensure the page becomes visible before loading.
    QTimer::singleShot(0, this, [this]()
        {
            requestAsyncRefresh(true);
        });
}

void ServiceDock::focusServiceByName(const QString& serviceNameText)
{
    const QString kTargetServiceName = serviceNameText.trimmed();
    if (kTargetServiceName.isEmpty())
    {
        return;
    }

    pendingFocusServiceName_ = kTargetServiceName;

    for (int rowIndex = 0; rowIndex < serviceTable_->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* nameItem = serviceTable_->item(rowIndex, toServiceColumn(ServiceColumn::kName));
        if (nameItem == nullptr)
        {
            continue;
        }

        const QString kRowServiceName = nameItem->data(service_dock_detail::kServiceNameRole).toString();
        if (QString::compare(kRowServiceName, kTargetServiceName, Qt::CaseInsensitive) == 0)
        {
            serviceTable_->selectRow(rowIndex);
            serviceTable_->scrollToItem(nameItem, QAbstractItemView::PositionAtCenter);
            pendingFocusServiceName_.clear();
            return;
        }
    }

    if (serviceTable_->rowCount() == 0 || refreshInProgress_)
    {
        requestAsyncRefresh(true);
    }
}

void ServiceDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshQueued_ = true;
        }
        if (summaryLabel_ != nullptr)
        {
            summaryLabel_->setText(QStringLiteral("状态：服务刷新进行中，已排队新的请求"));
        }
        return;
    }

    if (refreshThread_ != nullptr && refreshThread_->joinable())
    {
        refreshThread_->join();
    }

    refreshInProgress_ = true;
    refreshQueued_ = false;
    progressPid_ = kPro.add(this, "服务管理", "枚举服务列表");
    kPro.set(progressPid_, "打开服务控制管理器", 0, 10.0f);
    if (summaryLabel_ != nullptr)
    {
        summaryLabel_->setText(QStringLiteral("状态：后台正在枚举服务..."));
    }

    // The entire refresh chain uses a single KLogEvent to facilitate tracking the complete process by GUID later.
    const KLogEvent kRefreshEvent;
    info << kRefreshEvent << "[ServiceDock] 开始后台刷新服务列表。" << eol;

    const QPointer<ServiceDock> kSafeThis(this);
    refreshThread_ = std::make_unique<std::thread>([kSafeThis, kRefreshEvent]()
        {
            if (kSafeThis.isNull())
            {
                return;
            }

            std::vector<ServiceEntry> serviceList;
            serviceList.reserve(512);
            QString errorText;
            bool success = true;

            kPro.set(kSafeThis->progressPid_, "读取 Win32 服务列表", 0, 45.0f);
            kSafeThis->enumerateServiceList(&serviceList, &errorText);
            if (!errorText.trimmed().isEmpty())
            {
                success = false;
            }

            kPro.set(kSafeThis->progressPid_, "整理服务列表数据", 0, 88.0f);
            if (kSafeThis.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                kSafeThis,
                [kSafeThis, kRefreshEvent, serviceList = std::move(serviceList), errorText, success]() mutable
                {
                    if (kSafeThis.isNull())
                    {
                        return;
                    }

                    kSafeThis->applyRefreshResult(std::move(serviceList), errorText, success);
                    if (success)
                    {
                        info << kRefreshEvent << "[ServiceDock] 后台刷新服务列表成功。" << eol;
                    }
                    else
                    {
                        err << kRefreshEvent
                            << "[ServiceDock] 后台刷新服务列表失败, error="
                            << errorText.toStdString()
                            << eol;
                    }
                },
                Qt::QueuedConnection);
        });
}

void ServiceDock::applyRefreshResult(
    std::vector<ServiceEntry> serviceList,
    const QString& errorText,
    const bool success)
{
    if (ks::ui::isTableUiCommitBlockedByContextMenu({serviceTable_}))
    {
        const QPointer<ServiceDock> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("service-table-refresh-apply"),
            {serviceTable_},
            [kSafeThis,
                serviceList = std::move(serviceList),
                errorText,
                success]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyRefreshResult(
                        std::move(serviceList),
                        errorText,
                        success);
                }
            });
        return;
    }

    std::sort(
        serviceList.begin(),
        serviceList.end(),
        [](const ServiceEntry& left, const ServiceEntry& right)
        {
            const int kDisplayCompareResult = QString::compare(
                left.displayNameText,
                right.displayNameText,
                Qt::CaseInsensitive);
            if (kDisplayCompareResult != 0)
            {
                return kDisplayCompareResult < 0;
            }
            return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
        });

    serviceList_ = std::move(serviceList);
    rebuildServiceTable();

    if (!pendingFocusServiceName_.trimmed().isEmpty())
    {
        const QString kPendingNameText = pendingFocusServiceName_;
        pendingFocusServiceName_.clear();
        focusServiceByName(kPendingNameText);
    }

    if (success)
    {
        if (summaryLabel_ != nullptr)
        {
            summaryLabel_->setText(QStringLiteral("状态：服务刷新完成，共 %1 条").arg(serviceList_.size()));
        }
        if (progressPid_ != 0)
        {
            kPro.set(progressPid_, "服务刷新完成", 0, 100.0f);
        }
    }
    else
    {
        if (summaryLabel_ != nullptr)
        {
            summaryLabel_->setText(QStringLiteral("状态：刷新失败，%1").arg(errorText));
        }
        if (progressPid_ != 0)
        {
            kPro.set(progressPid_, "服务刷新失败", 0, 100.0f);
        }
        QMessageBox::warning(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("服务列表刷新失败：\n%1").arg(errorText));
    }

    refreshInProgress_ = false;

    if (refreshQueued_)
    {
        requestAsyncRefresh(false);
    }
}

void ServiceDock::applyServiceUpdateToCache(const ServiceEntry& updatedEntry)
{
    const int kEntryIndex = findServiceIndexByName(updatedEntry.serviceNameText);
    if (kEntryIndex >= 0 && kEntryIndex < static_cast<int>(serviceList_.size()))
    {
        serviceList_[static_cast<std::size_t>(kEntryIndex)] = updatedEntry;
    }
}
