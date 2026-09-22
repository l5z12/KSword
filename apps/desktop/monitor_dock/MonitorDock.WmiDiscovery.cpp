#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::refreshWmiProvidersAsync()
{
    KLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新WMI Provider。"
        << eol;

    wmiProviderStatusLabel_->setText(QStringLiteral("● 刷新中..."));
    ks::ui::applyStatusRole(wmiProviderStatusLabel_, ks::ui::StatusRole::kInfo);

    if (wmiProviderRefreshProgressPid_ == 0)
    {
        wmiProviderRefreshProgressPid_ = kPro.addReusable(this, "监控", "刷新WMI Provider");
    }
    kPro.set(wmiProviderRefreshProgressPid_, "开始枚举WMI Provider", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<WmiProviderEntry> providers;
        QString errorText;

        if (!initCom(&errorText))
        {
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->wmiProviderStatusLabel_->setText(QStringLiteral("● 初始化失败"));
                ks::ui::applyStatusRole(guardThis->wmiProviderStatusLabel_, ks::ui::StatusRole::kError);
                if (guardThis->wmiProviderRefreshProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiProviderRefreshProgressPid_, "WMI Provider刷新失败", 0, 100.0f);
                    guardThis->wmiProviderRefreshProgressPid_ = 0;
                }

                KLogEvent event;
                err << event << "[MonitorDock] WMI Provider初始化失败:" << errorText.toStdString() << eol;
            }, Qt::QueuedConnection);
            return;
        }

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            QMetaObject::invokeMethod(qApp, [guardThis, errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->wmiProviderStatusLabel_->setText(QStringLiteral("● 连接失败"));
                ks::ui::applyStatusRole(guardThis->wmiProviderStatusLabel_, ks::ui::StatusRole::kError);
                if (guardThis->wmiProviderRefreshProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiProviderRefreshProgressPid_, "WMI Provider刷新失败", 0, 100.0f);
                    guardThis->wmiProviderRefreshProgressPid_ = 0;
                }

                KLogEvent event;
                err << event << "[MonitorDock] WMI连接失败:" << errorText.toStdString() << eol;
            }, Qt::QueuedConnection);
            return;
        }

        CComPtr<IEnumWbemClassObject> enumerator;
        const HRESULT kQueryResult = service->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM __Win32Provider"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &enumerator);

        if (SUCCEEDED(kQueryResult) && enumerator != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT kNextResult = enumerator->Next(100, 1, &item, &count);
                if (FAILED(kNextResult) || count == 0 || item == nullptr)
                {
                    break;
                }

                VARIANT nameValue;
                VARIANT clsidValue;
                VARIANT hostingValue;
                ::VariantInit(&nameValue);
                ::VariantInit(&clsidValue);
                ::VariantInit(&hostingValue);

                item->Get(L"Name", 0, &nameValue, nullptr, nullptr);
                item->Get(L"CLSID", 0, &clsidValue, nullptr, nullptr);
                item->Get(L"HostingModel", 0, &hostingValue, nullptr, nullptr);

                WmiProviderEntry entry;
                entry.providerName = variantToText(nameValue);
                entry.nameSpaceText = QStringLiteral("ROOT\\CIMV2");
                entry.clsidText = variantToText(clsidValue);
                entry.eventClassCount = 0;
                entry.subscribable = !entry.providerName.trimmed().isEmpty()
                    && !variantToText(hostingValue).contains(QStringLiteral("Decoupled"), Qt::CaseInsensitive);

                providers.push_back(entry);

                ::VariantClear(&nameValue);
                ::VariantClear(&clsidValue);
                ::VariantClear(&hostingValue);
            }
        }

        int classCount = 0;
        CComPtr<IEnumWbemClassObject> classEnum;
        const HRESULT kClassQueryResult = service->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM meta_class WHERE __CLASS LIKE 'Win32\\_%Event'"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &classEnum);
        if (SUCCEEDED(kClassQueryResult) && classEnum != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT kNextResult = classEnum->Next(100, 1, &item, &count);
                if (FAILED(kNextResult) || count == 0 || item == nullptr)
                {
                    break;
                }
                ++classCount;
            }
        }

        for (WmiProviderEntry& entry : providers)
        {
            entry.eventClassCount = classCount;
        }

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis, providers]() {
            const auto kCommitProviders = [guardThis, providers]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->wmiProviders_ = providers;
                guardThis->wmiProviderModel_->removeRows(0, guardThis->wmiProviderModel_->rowCount());

                for (const WmiProviderEntry& entry : guardThis->wmiProviders_)
                {
                    QList<QStandardItem*> rowItems;
                    rowItems << new QStandardItem(entry.providerName)
                        << new QStandardItem(entry.nameSpaceText)
                        << new QStandardItem(entry.clsidText)
                        << new QStandardItem(QString::number(entry.eventClassCount))
                        << new QStandardItem(ks::i18n::sourceText(entry.subscribable
                            ? QStringLiteral("可订阅")
                            : QStringLiteral("受限")));
                    guardThis->wmiProviderModel_->appendRow(rowItems);
                }

                guardThis->applyWmiProviderFilter();
                guardThis->wmiProviderStatusLabel_->setText(
                    QStringLiteral("● 已刷新 %1 项").arg(guardThis->wmiProviders_.size()));
                ks::ui::applyStatusRole(guardThis->wmiProviderStatusLabel_, ks::ui::StatusRole::kSuccess);
                if (guardThis->wmiProviderRefreshProgressPid_ != 0)
                {
                    kPro.set(guardThis->wmiProviderRefreshProgressPid_, "WMI Provider完成", 0, 100.0f);
                    guardThis->wmiProviderRefreshProgressPid_ = 0;
                }

                KLogEvent event;
                info << event
                    << "[MonitorDock] WMI Provider刷新完成, providerCount="
                    << guardThis->wmiProviders_.size()
                    << eol;
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-wmi-provider-apply"),
                { guardThis->wmiProviderTableView_ },
                kCommitProviders))
            {
                return;
            }
            kCommitProviders();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::refreshWmiEventClassesAsync()
{
    // This refresh first clears the table, then repopulates the entire table with background results; when the menu is open, even the startup phase is deferred.
    const QPointer<MonitorDock> kDeferredGuard(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-wmi-event-class-refresh-start"),
        { wmiEventClassTable_ },
        [kDeferredGuard]()
        {
            if (!kDeferredGuard.isNull())
            {
                kDeferredGuard->refreshWmiEventClassesAsync();
            }
        }))
    {
        return;
    }

    KLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新WMI事件类。"
        << eol;

    wmiEventClassTable_->setRowCount(0);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<QString> classes;
        QString errorText;

        if (!initCom(&errorText))
        {
            KLogEvent event;
            err << event
                << "[MonitorDock] WMI事件类刷新失败：COM初始化失败, error="
                << errorText.toStdString()
                << eol;
            return;
        }

        CComPtr<IWbemServices> service;
        if (!connectWmi(&service, &errorText) || service == nullptr)
        {
            ::CoUninitialize();
            KLogEvent event;
            err << event
                << "[MonitorDock] WMI事件类刷新失败：连接失败, error="
                << errorText.toStdString()
                << eol;
            return;
        }

        CComPtr<IEnumWbemClassObject> classEnum;
        const HRESULT kEnumResult = service->CreateClassEnum(
            _bstr_t(L"__Event"),
            WBEM_FLAG_DEEP | WBEM_FLAG_FORWARD_ONLY,
            nullptr,
            &classEnum);

        if (SUCCEEDED(kEnumResult) && classEnum != nullptr)
        {
            while (true)
            {
                CComPtr<IWbemClassObject> item;
                ULONG count = 0;
                const HRESULT kNextResult = classEnum->Next(100, 1, &item, &count);
                if (FAILED(kNextResult) || count == 0 || item == nullptr)
                {
                    break;
                }

                VARIANT classValue;
                ::VariantInit(&classValue);
                item->Get(L"__CLASS", 0, &classValue, nullptr, nullptr);
                const QString kClassText = variantToText(classValue).trimmed();
                ::VariantClear(&classValue);

                if (!kClassText.isEmpty())
                {
                    classes.push_back(kClassText);
                }
            }
        }

        std::sort(classes.begin(), classes.end(), [](const QString& a, const QString& b) {
            return QString::compare(a, b, Qt::CaseInsensitive) < 0;
        });
        classes.erase(
            std::unique(classes.begin(), classes.end(), [](const QString& a, const QString& b) {
                return QString::compare(a, b, Qt::CaseInsensitive) == 0;
            }),
            classes.end());

        ::CoUninitialize();

        QMetaObject::invokeMethod(qApp, [guardThis, classes]() {
            const auto kCommitClasses = [guardThis, classes]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->wmiEventClassTable_->setRowCount(static_cast<int>(classes.size()));
                for (int row = 0; row < static_cast<int>(classes.size()); ++row)
                {
                    const QString kClassName = classes[static_cast<std::size_t>(row)];

                    QTableWidgetItem* checkItem = new QTableWidgetItem();
                    checkItem->setFlags(checkItem->flags() | Qt::ItemIsUserCheckable);
                    checkItem->setCheckState(kClassName.startsWith(QStringLiteral("Win32_"), Qt::CaseInsensitive)
                        ? Qt::Checked
                        : Qt::Unchecked);

                    guardThis->wmiEventClassTable_->setItem(row, 0, checkItem);
                    guardThis->wmiEventClassTable_->setItem(row, 1, new QTableWidgetItem(kClassName));
                    guardThis->wmiEventClassTable_->setItem(
                        row,
                        2,
                        new QTableWidgetItem(kClassName.startsWith(
                            QStringLiteral("Win32_"), Qt::CaseInsensitive)
                            ? QStringLiteral("Win32")
                            : ks::i18n::sourceText(QStringLiteral("其他"))));
                }
                // Recalculate the target height of the collapsed page after the event class refreshes to ensure the 'WMI Subscription' page does not overflow the collapsed bar due to row count changes.
                guardThis->updateWmiSubscribePanelCompactLayout();

                KLogEvent event;
                info << event
                    << "[MonitorDock] WMI事件类刷新完成, classCount="
                    << classes.size()
                    << eol;
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-wmi-event-class-apply"),
                { guardThis->wmiEventClassTable_ },
                kCommitClasses))
            {
                return;
            }
            kCommitClasses();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::applyWmiProviderFilter()
{
    const QString kKeyword = wmiProviderFilterEdit_->text().trimmed();
    wmiProviderProxyModel_->setFilterFixedString(kKeyword);

    KLogEvent event;
    dbg << event
        << "[MonitorDock] 应用WMI Provider过滤, keyword="
        << kKeyword.toStdString()
        << eol;
}

void MonitorDock::applyWmiEventFilter()
{
    if (wmiEventTable_ == nullptr)
    {
        return;
    }

    const QString kGlobalKeyword = wmiEventGlobalFilterEdit_ != nullptr
        ? wmiEventGlobalFilterEdit_->text().trimmed()
        : QString();
    const QString kProviderKeyword = wmiEventProviderFilterEdit_ != nullptr
        ? wmiEventProviderFilterEdit_->text().trimmed()
        : QString();
    const QString kClassKeyword = wmiEventClassFilterEdit_ != nullptr
        ? wmiEventClassFilterEdit_->text().trimmed()
        : QString();
    const QString kPidKeyword = wmiEventPidFilterEdit_ != nullptr
        ? wmiEventPidFilterEdit_->text().trimmed()
        : QString();
    const QString kDetailKeyword = wmiEventDetailFilterEdit_ != nullptr
        ? wmiEventDetailFilterEdit_->text().trimmed()
        : QString();
    const bool kUseRegex = wmiEventRegexCheck_ != nullptr && wmiEventRegexCheck_->isChecked();
    const bool kInvertMatch = wmiEventInvertCheck_ != nullptr && wmiEventInvertCheck_->isChecked();
    const Qt::CaseSensitivity kCaseSensitivity =
        (wmiEventCaseCheck_ != nullptr && wmiEventCaseCheck_->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    int visibleCount = 0;
    const int kTotalCount = wmiEventTable_->rowCount();
    for (int row = 0; row < kTotalCount; ++row)
    {
        const QString kTsText = wmiEventTable_->item(row, 0) != nullptr
            ? wmiEventTable_->item(row, 0)->text()
            : QString();
        const QString kProviderText = wmiEventTable_->item(row, 1) != nullptr
            ? wmiEventTable_->item(row, 1)->text()
            : QString();
        const QString kClassText = wmiEventTable_->item(row, 2) != nullptr
            ? wmiEventTable_->item(row, 2)->text()
            : QString();
        const QString kPidText = wmiEventTable_->item(row, 3) != nullptr
            ? wmiEventTable_->item(row, 3)->text()
            : QString();
        const QString kDetailText = wmiEventTable_->item(row, 4) != nullptr
            ? wmiEventTable_->item(row, 4)->text()
            : QString();

        const QString kMergedText = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(kTsText, kProviderText, kClassText, kPidText, kDetailText);
        const bool kGlobalMatch = textMatch(kMergedText, kGlobalKeyword, kUseRegex, kCaseSensitivity);
        const bool kProviderMatch = textMatch(kProviderText, kProviderKeyword, kUseRegex, kCaseSensitivity);
        const bool kClassMatch = textMatch(kClassText, kClassKeyword, kUseRegex, kCaseSensitivity);
        const bool kPidMatch = textMatch(kPidText, kPidKeyword, kUseRegex, kCaseSensitivity);
        const bool kDetailMatch = textMatch(kDetailText, kDetailKeyword, kUseRegex, kCaseSensitivity);
        bool showRow = kGlobalMatch && kProviderMatch && kClassMatch && kPidMatch && kDetailMatch;
        if (kInvertMatch)
        {
            showRow = !showRow;
        }

        wmiEventTable_->setRowHidden(row, !showRow);
        if (showRow)
        {
            ++visibleCount;
        }
    }

    if (wmiEventFilterStatusLabel_ != nullptr)
    {
        wmiEventFilterStatusLabel_->setText(QStringLiteral("可见: %1 / %2").arg(visibleCount).arg(kTotalCount));
    }
    if (wmiEventKeepBottomCheck_ != nullptr && wmiEventKeepBottomCheck_->isChecked())
    {
        wmiEventTable_->scrollToBottom();
    }

    KLogEvent event;
    dbg << event
        << "[MonitorDock] 应用WMI事件筛选, total="
        << kTotalCount
        << ", visible="
        << visibleCount
        << ", regex="
        << (kUseRegex ? "true" : "false")
        << ", invert="
        << (kInvertMatch ? "true" : "false")
        << eol;
}

void MonitorDock::clearWmiEventFilter()
{
    if (wmiEventGlobalFilterEdit_ != nullptr) wmiEventGlobalFilterEdit_->clear();
    if (wmiEventProviderFilterEdit_ != nullptr) wmiEventProviderFilterEdit_->clear();
    if (wmiEventClassFilterEdit_ != nullptr) wmiEventClassFilterEdit_->clear();
    if (wmiEventPidFilterEdit_ != nullptr) wmiEventPidFilterEdit_->clear();
    if (wmiEventDetailFilterEdit_ != nullptr) wmiEventDetailFilterEdit_->clear();
    if (wmiEventRegexCheck_ != nullptr) wmiEventRegexCheck_->setChecked(false);
    if (wmiEventCaseCheck_ != nullptr) wmiEventCaseCheck_->setChecked(false);
    if (wmiEventInvertCheck_ != nullptr) wmiEventInvertCheck_->setChecked(false);

    applyWmiEventFilter();

    KLogEvent event;
    info << event
        << "[MonitorDock] 已清空WMI事件筛选条件。"
        << eol;
}
