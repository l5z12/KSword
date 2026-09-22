#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::startWmiSubscription()
{
    if (wmiSubscribeRunning_.load())
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略启动WMI订阅：当前已在运行。"
            << eol;
        return;
    }

    // Even if the previous thread has naturally exited, std::thread must still be joined; otherwise,
    // overwriting the unique_ptr would destroy a joinable thread and trigger std::terminate.
    if (wmiSubscribeThread_ != nullptr && wmiSubscribeThread_->joinable())
    {
        wmiSubscribeThread_->join();
        wmiSubscribeThread_.reset();
    }

    std::vector<QString> classList;
    for (int row = 0; row < wmiEventClassTable_->rowCount(); ++row)
    {
        QTableWidgetItem* checkItem = wmiEventClassTable_->item(row, 0);
        QTableWidgetItem* classItem = wmiEventClassTable_->item(row, 1);
        if (checkItem != nullptr && classItem != nullptr && checkItem->checkState() == Qt::Checked)
        {
            classList.push_back(classItem->text().trimmed());
        }
    }

    if (classList.empty())
    {
        KLogEvent event;
        warn << event
            << "[MonitorDock] 启动WMI订阅失败：未选择事件类。"
            << eol;
        QMessageBox::information(this, QStringLiteral("WMI订阅"), QStringLiteral("请至少选择一个事件类。"));
        return;
    }

    const QString kWhereClause = wmiWhereEditor_->toPlainText().trimmed();

    {
        KLogEvent event;
        info << event
            << "[MonitorDock] 启动WMI订阅, classCount="
            << classList.size()
            << ", whereClause="
            << kWhereClause.toStdString()
            << eol;
    }

    wmiSubscribeRunning_.store(true);
    wmiSubscribePaused_.store(false);
    wmiSubscribeStopFlag_.store(false);

    if (wmiSubscribeProgressPid_ == 0)
    {
        wmiSubscribeProgressPid_ = kPro.addReusable(this, "监控", "WMI订阅");
    }
    kPro.set(wmiSubscribeProgressPid_, "建立WMI订阅", 0, 10.0f);

    wmiSubscribeStatusLabel_->setText(QStringLiteral("● 订阅中"));
    ks::ui::applyStatusRole(wmiSubscribeStatusLabel_, ks::ui::StatusRole::kInfo);
    if (wmiUiUpdateTimer_ != nullptr && !wmiUiUpdateTimer_->isActive())
    {
        wmiUiUpdateTimer_->start();
    }
    {
        // Clear the pending flush queue before starting a new subscription to prevent residual events from mixing into the new session.
        std::lock_guard<std::mutex> lock(wmiPendingMutex_);
        wmiPendingRows_.clear();
    }

    QPointer<MonitorDock> guardThis(this);
    wmiSubscribeThread_ = std::make_unique<std::thread>([guardThis, classList, kWhereClause]() {
        QString errorText;
        if (!initCom(&errorText))
        {
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->wmiSubscribeRunning_.store(false);
                guardThis->wmiSubscribeStatusLabel_->setText(QString("● 初始化失败: %1").arg(errorText));
                ks::ui::applyStatusRole(guardThis->wmiSubscribeStatusLabel_, ks::ui::StatusRole::kError);
                if (guardThis->wmiSubscribeProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI订阅失败", 0, 100.0f);
                    guardThis->wmiSubscribeProgressPid_ = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI COM初始化完成", 0, 20.0f);
        }, Qt::QueuedConnection);

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->wmiSubscribeRunning_.store(false);
                guardThis->wmiSubscribeStatusLabel_->setText(QString("● 连接失败: %1").arg(errorText));
                ks::ui::applyStatusRole(guardThis->wmiSubscribeStatusLabel_, ks::ui::StatusRole::kError);
                if (guardThis->wmiSubscribeProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI连接失败", 0, 100.0f);
                    guardThis->wmiSubscribeProgressPid_ = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI服务连接成功", 0, 30.0f);
        }, Qt::QueuedConnection);

        struct ClassEnum
        {
            QString className;
            CComPtr<IEnumWbemClassObject> enumerator;
        };

        std::vector<ClassEnum> enums;
        for (std::size_t classIndex = 0; classIndex < classList.size(); ++classIndex)
        {
            const QString kClassName = classList[classIndex];
            if (guardThis == nullptr || guardThis->wmiSubscribeStopFlag_.load())
            {
                break;
            }

            const float kSetupProgressValue = 30.0f
                + (classList.empty()
                    ? 0.0f
                    : (static_cast<float>(classIndex + 1) * 15.0f / static_cast<float>(classList.size())));
            QMetaObject::invokeMethod(qApp, [guardThis, kSetupProgressValue, kClassName]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                kPro.set(
                    guardThis->wmiSubscribeProgressPid_,
                    QString("建立订阅: %1").arg(kClassName).toStdString(),
                    0,
                    kSetupProgressValue);
            }, Qt::QueuedConnection);

            QString query = QStringLiteral("SELECT * FROM %1").arg(kClassName);
            if (!kWhereClause.isEmpty())
            {
                query += QStringLiteral(" WHERE ") + kWhereClause;
            }

            CComPtr<IEnumWbemClassObject> enumerator;
            const HRESULT kSubResult = service->ExecNotificationQuery(
                bstr_t("WQL"),
                bstr_t(query.toStdWString().c_str()),
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                nullptr,
                &enumerator);

            if (SUCCEEDED(kSubResult) && enumerator != nullptr)
            {
                enums.push_back(ClassEnum{ kClassName, enumerator });
            }
            else
            {
                KLogEvent event;
                warn << event
                    << "[MonitorDock] WMI订阅类创建失败, className="
                    << kClassName.toStdString()
                    << ", query="
                    << query.toStdString()
                    << ", hr="
                    << static_cast<unsigned long>(kSubResult)
                    << eol;
            }
        }

        if (enums.empty())
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->wmiSubscribeRunning_.store(false);
                guardThis->wmiSubscribeStatusLabel_->setText(QStringLiteral("● 未建立任何有效订阅"));
                ks::ui::applyStatusRole(guardThis->wmiSubscribeStatusLabel_, ks::ui::StatusRole::kError);
                if (guardThis->wmiSubscribeProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI订阅失败(无有效类)", 0, 100.0f);
                    guardThis->wmiSubscribeProgressPid_ = 0;
                }
            }, Qt::QueuedConnection);
            return;
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI订阅已建立", 0, 45.0f);
        }, Qt::QueuedConnection);

        std::size_t eventCount = 0;
        while (guardThis != nullptr && !guardThis->wmiSubscribeStopFlag_.load())
        {
            if (guardThis->wmiSubscribePaused_.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
                continue;
            }

            bool hasEvent = false;
            for (ClassEnum& classEnum : enums)
            {
                if (guardThis == nullptr || guardThis->wmiSubscribeStopFlag_.load())
                {
                    break;
                }

                CComPtr<IWbemClassObject> eventObject;
                ULONG count = 0;
                const HRESULT kNextResult = classEnum.enumerator->Next(100, 1, &eventObject, &count);
                if (FAILED(kNextResult) || count == 0 || eventObject == nullptr)
                {
                    continue;
                }

                hasEvent = true;
                ++eventCount;

                QString pidText = QStringLiteral("-");
                QString detailText;

                VARIANT targetValue;
                ::VariantInit(&targetValue);
                if (SUCCEEDED(eventObject->Get(L"TargetInstance", 0, &targetValue, nullptr, nullptr))
                    && targetValue.vt == VT_UNKNOWN
                    && targetValue.punkVal != nullptr)
                {
                    CComPtr<IWbemClassObject> targetObject;
                    targetValue.punkVal->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&targetObject));
                    if (targetObject != nullptr)
                    {
                        VARIANT processIdValue;
                        VARIANT nameValue;
                        ::VariantInit(&processIdValue);
                        ::VariantInit(&nameValue);
                        targetObject->Get(L"ProcessId", 0, &processIdValue, nullptr, nullptr);
                        targetObject->Get(L"Name", 0, &nameValue, nullptr, nullptr);

                        const QString kPidPart = variantToText(processIdValue);
                        const QString kNamePart = variantToText(nameValue);
                        if (!kPidPart.isEmpty() || !kNamePart.isEmpty())
                        {
                            pidText = QStringLiteral("%1 / %2").arg(kPidPart, kNamePart);
                        }

                        ::VariantClear(&processIdValue);
                        ::VariantClear(&nameValue);
                    }
                }
                ::VariantClear(&targetValue);

                eventObject->BeginEnumeration(0);
                int propertyCount = 0;
                while (propertyCount < 8)
                {
                    BSTR propertyName = nullptr;
                    VARIANT propertyValue;
                    CIMTYPE typeValue = 0;
                    LONG flavor = 0;
                    ::VariantInit(&propertyValue);

                    const HRESULT kNextProperty = eventObject->Next(0, &propertyName, &propertyValue, &typeValue, &flavor);
                    if (kNextProperty == WBEM_S_NO_MORE_DATA)
                    {
                        ::VariantClear(&propertyValue);
                        break;
                    }

                    if (SUCCEEDED(kNextProperty) && propertyName != nullptr)
                    {
                        if (!detailText.isEmpty())
                        {
                            detailText += QStringLiteral("; ");
                        }
                        detailText += QString::fromWCharArray(propertyName) + QStringLiteral("=") + variantToText(propertyValue);
                        ++propertyCount;
                    }

                    if (propertyName != nullptr)
                    {
                        ::SysFreeString(propertyName);
                    }
                    ::VariantClear(&propertyValue);
                }
                eventObject->EndEnumeration();

                if (detailText.isEmpty())
                {
                    detailText = QStringLiteral("<无详情>");
                }

                if (guardThis != nullptr)
                {
                    // High-frequency events are queued first and batch-refreshed by the UI throttler to avoid triggering table re-layout for every event.
                    guardThis->enqueueWmiEventRow(classEnum.className, classEnum.className, pidText, detailText);
                }
            }

            if (!hasEvent)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }

            if (guardThis != nullptr && eventCount % 20 == 0)
            {
                const float kProgressValue = 45.0f + static_cast<float>(std::min<std::size_t>(eventCount, 200)) * 0.25f;
                QMetaObject::invokeMethod(qApp, [guardThis, kProgressValue]() {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI事件接收中", 0, std::min(kProgressValue, 95.0f));
                }, Qt::QueuedConnection);
            }
        }

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->flushWmiPendingRows();
            if (guardThis->wmiUiUpdateTimer_ != nullptr)
            {
                guardThis->wmiUiUpdateTimer_->stop();
            }
            guardThis->wmiSubscribeRunning_.store(false);
            guardThis->wmiSubscribePaused_.store(false);
            guardThis->wmiSubscribeStatusLabel_->setText(QStringLiteral("● 已停止"));
            ks::ui::applyStatusRole(guardThis->wmiSubscribeStatusLabel_, ks::ui::StatusRole::kIdle);
            if (guardThis->wmiSubscribeProgressPid_ != 0)
            {
                kPro.set(guardThis->wmiSubscribeProgressPid_, "WMI订阅结束", 0, 100.0f);
                guardThis->wmiSubscribeProgressPid_ = 0;
            }

            KLogEvent event;
            info << event
                << "[MonitorDock] WMI订阅线程已退出。"
                << eol;
        }, Qt::QueuedConnection);
    });
}

void MonitorDock::stopWmiSubscription()
{
    stopWmiSubscriptionInternal(false);
}

void MonitorDock::stopWmiSubscriptionInternal(bool waitForThread)
{
    {
        KLogEvent event;
        info << event
            << "[MonitorDock] 停止WMI订阅请求, waitForThread="
            << (waitForThread ? "true" : "false")
            << eol;
    }

    wmiSubscribeStopFlag_.store(true);

    if (wmiSubscribeStatusLabel_ != nullptr)
    {
        wmiSubscribeStatusLabel_->setText(QStringLiteral("● 停止中..."));
        ks::ui::applyStatusRole(wmiSubscribeStatusLabel_, ks::ui::StatusRole::kWarning);
    }

    if (wmiSubscribeThread_ == nullptr || !wmiSubscribeThread_->joinable())
    {
        wmiSubscribeThread_.reset();
        wmiSubscribeRunning_.store(false);
        wmiSubscribePaused_.store(false);
        if (wmiUiUpdateTimer_ != nullptr)
        {
            wmiUiUpdateTimer_->stop();
        }
        if (wmiSubscribeProgressPid_ != 0)
        {
            kPro.set(wmiSubscribeProgressPid_, "WMI订阅结束", 0, 100.0f);
            wmiSubscribeProgressPid_ = 0;
        }
        KLogEvent event;
        dbg << event
            << "[MonitorDock] 停止WMI订阅：当前无活动线程。"
            << eol;
        return;
    }

    if (waitForThread)
    {
        // Destruction path: Synchronously wait for the thread to exit, ensuring no concurrent access during object destruction.
        wmiSubscribeThread_->join();
        wmiSubscribeThread_.reset();
        wmiSubscribeRunning_.store(false);
        wmiSubscribePaused_.store(false);
        if (wmiUiUpdateTimer_ != nullptr)
        {
            wmiUiUpdateTimer_->stop();
        }
        if (wmiSubscribeProgressPid_ != 0)
        {
            kPro.set(wmiSubscribeProgressPid_, "WMI订阅结束", 0, 100.0f);
            wmiSubscribeProgressPid_ = 0;
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] 停止WMI订阅：同步等待线程结束完成。"
            << eol;
        return;
    }

    // Retain ownership of m_wmiSubscribeThread so the destructor can wait for the COM/WMI query loop to
    // truly exit, preventing the background thread from accessing members after MonitorDock is released.
}

void MonitorDock::setWmiSubscriptionPaused(bool paused)
{
    if (!wmiSubscribeRunning_.load())
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略WMI暂停操作：订阅未运行。"
            << eol;
        return;
    }

    wmiSubscribePaused_.store(paused);
    if (paused)
    {
        wmiSubscribeStatusLabel_->setText(QStringLiteral("● 已暂停"));
        ks::ui::applyStatusRole(wmiSubscribeStatusLabel_, ks::ui::StatusRole::kWarning);
    }
    else
    {
        wmiSubscribeStatusLabel_->setText(QStringLiteral("● 订阅中"));
        ks::ui::applyStatusRole(wmiSubscribeStatusLabel_, ks::ui::StatusRole::kInfo);
    }

    KLogEvent event;
    info << event
        << "[MonitorDock] WMI订阅暂停状态变更, paused="
        << (paused ? "true" : "false")
        << eol;
}

void MonitorDock::enqueueWmiEventRow(
    const QString& providerName,
    const QString& className,
    const QString& pidAndName,
    const QString& detailText)
{
    // The background thread only writes to the pending queue to avoid triggering table repaints directly, which would cause main thread jitter.
    QStringList rowValues;
    rowValues.reserve(5);
    rowValues << QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
        << providerName
        << className
        << pidAndName
        << detailText;

    std::lock_guard<std::mutex> lock(wmiPendingMutex_);
    wmiPendingRows_.push_back(std::move(rowValues));
}

void MonitorDock::flushWmiPendingRows()
{
    // Enters the menu commit gate first, then removes the event from the shared queue;
    // 'latest-wins' only merges timeouts and does not overwrite already retrieved WMI data.
    const QPointer<MonitorDock> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-wmi-event-flush"),
        { wmiEventTable_ },
        [kGuardThis]()
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->flushWmiPendingRows();
            }
        }))
    {
        return;
    }

    // Main thread batch flush: Limit the number of rows per cycle to prevent blocking the UI by inserting too many rows at once.
    std::vector<QStringList> rowsToFlush;
    {
        std::lock_guard<std::mutex> lock(wmiPendingMutex_);
        if (wmiPendingRows_.empty())
        {
            return;
        }

        constexpr std::size_t kMaxRowsPerFlush = 240;
        const std::size_t kFlushCount = std::min<std::size_t>(kMaxRowsPerFlush, wmiPendingRows_.size());
        rowsToFlush.reserve(kFlushCount);
        for (std::size_t rowIndex = 0; rowIndex < kFlushCount; ++rowIndex)
        {
            rowsToFlush.push_back(std::move(wmiPendingRows_[rowIndex]));
        }
        using DiffType = std::vector<QStringList>::difference_type;
        wmiPendingRows_.erase(
            wmiPendingRows_.begin(),
            wmiPendingRows_.begin() + static_cast<DiffType>(kFlushCount));
    }

    for (const QStringList& rowValues : rowsToFlush)
    {
        if (rowValues.size() < 5)
        {
            continue;
        }
        appendWmiEventRow(rowValues[1], rowValues[2], rowValues[3], rowValues[4]);

        QTableWidgetItem* tsItem = wmiEventTable_->item(wmiEventTable_->rowCount() - 1, 0);
        if (tsItem != nullptr)
        {
            tsItem->setText(rowValues[0]);
            tsItem->setToolTip(rowValues[0]);
        }
    }

    // Apply filters uniformly after each batch is flushed to avoid UI jitter caused by recalculating line by line.
    applyWmiEventFilter();

    KLogEvent event;
    dbg << event
        << "[MonitorDock] 批量刷新WMI事件到UI, flushCount="
        << rowsToFlush.size()
        << ", tableRowCount="
        << wmiEventTable_->rowCount()
        << eol;
}

void MonitorDock::appendWmiEventRow(
    const QString& providerName,
    const QString& className,
    const QString& pidAndName,
    const QString& detailText)
{
    const int kRow = wmiEventTable_->rowCount();
    wmiEventTable_->insertRow(kRow);

    const QString kTs = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));

    QTableWidgetItem* tsItem = new QTableWidgetItem(kTs);
    QTableWidgetItem* providerItem = new QTableWidgetItem(providerName);
    QTableWidgetItem* classItem = new QTableWidgetItem(className);
    QTableWidgetItem* pidItem = new QTableWidgetItem(pidAndName);
    QTableWidgetItem* detailItem = new QTableWidgetItem(detailText);

    tsItem->setToolTip(kTs);
    providerItem->setToolTip(providerName);
    classItem->setToolTip(className);
    pidItem->setToolTip(pidAndName);
    detailItem->setToolTip(detailText);

    wmiEventTable_->setItem(kRow, 0, tsItem);
    wmiEventTable_->setItem(kRow, 1, providerItem);
    wmiEventTable_->setItem(kRow, 2, classItem);
    wmiEventTable_->setItem(kRow, 3, pidItem);
    wmiEventTable_->setItem(kRow, 4, detailItem);

    while (wmiEventTable_->rowCount() > 6000)
    {
        wmiEventTable_->removeRow(0);
    }
}
