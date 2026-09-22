#include "NetworkDock.InternalCommon.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"
#include "../internationalization/LanguageManager.h"

#include "../ui/CodeEditorWidget.h"
#include <QDir>

using namespace network_dock_detail;

namespace
{
    constexpr quint32 kInfiniteRouteLifetime = std::numeric_limits<quint32>::max();

    QString routeAddressText(const SOCKADDR_INET& address)
    {
        wchar_t textBuffer[INET6_ADDRSTRLEN]{};
        if (address.si_family == AF_INET &&
            InetNtopW(AF_INET, &address.Ipv4.sin_addr, textBuffer, ARRAYSIZE(textBuffer)) != nullptr)
        {
            return QString::fromWCharArray(textBuffer);
        }
        if (address.si_family == AF_INET6 &&
            InetNtopW(AF_INET6, &address.Ipv6.sin6_addr, textBuffer, ARRAYSIZE(textBuffer)) != nullptr)
        {
            return QString::fromWCharArray(textBuffer);
        }
        return QString();
    }

    bool routeAddressFromText(const int addressFamily, const QString& text, SOCKADDR_INET* addressOut)
    {
        if (addressOut == nullptr || (addressFamily != AF_INET && addressFamily != AF_INET6))
        {
            return false;
        }
        *addressOut = SOCKADDR_INET{};
        addressOut->si_family = static_cast<ADDRESS_FAMILY>(addressFamily);
        const QString kNormalizedText = text.trimmed();
        if (kNormalizedText.isEmpty())
        {
            return true;
        }
        const std::wstring kWideText = kNormalizedText.toStdWString();
        if (addressFamily == AF_INET)
        {
            return InetPtonW(AF_INET, kWideText.c_str(), &addressOut->Ipv4.sin_addr) == 1;
        }
        return InetPtonW(AF_INET6, kWideText.c_str(), &addressOut->Ipv6.sin6_addr) == 1;
    }

    QString routeInterfaceName(const quint32 interfaceIndex)
    {
        MIB_IF_ROW2 interfaceRow{};
        interfaceRow.InterfaceIndex = interfaceIndex;
        if (GetIfEntry2(&interfaceRow) == NO_ERROR)
        {
            const QString kAlias = QString::fromWCharArray(interfaceRow.Alias).trimmed();
            if (!kAlias.isEmpty())
            {
                return kAlias;
            }
            const QString kDescription = QString::fromWCharArray(interfaceRow.Description).trimmed();
            if (!kDescription.isEmpty())
            {
                return kDescription;
            }
        }
        return QStringLiteral("ifIndex %1").arg(interfaceIndex);
    }

    QString routeProtocolText(const quint32 protocol)
    {
        switch (protocol)
        {
        case MIB_IPPROTO_LOCAL: return QStringLiteral("本地");
        case MIB_IPPROTO_NETMGMT: return QStringLiteral("手动");
        case MIB_IPPROTO_NT_STATIC: return QStringLiteral("NT 静态");
        case MIB_IPPROTO_NT_AUTOSTATIC: return QStringLiteral("NT 自动静态");
        default: return QStringLiteral("协议 %1").arg(protocol);
        }
    }

    QString routeOriginText(const quint32 origin)
    {
        switch (static_cast<NL_ROUTE_ORIGIN>(origin))
        {
        case NlroManual: return QStringLiteral("手动");
        case NlroWellKnown: return QStringLiteral("系统");
        case NlroDHCP: return QStringLiteral("DHCP");
        case NlroRouterAdvertisement: return QStringLiteral("路由通告");
        case Nlro6to4: return QStringLiteral("6to4");
        default: return QStringLiteral("来源 %1").arg(origin);
        }
    }

    QString routeLifetimeText(const quint32 lifetime)
    {
        return lifetime == kInfiniteRouteLifetime ? QStringLiteral("无限") : QString::number(lifetime);
    }

    bool parseRouteLifetime(const QString& text, quint32* lifetimeOut)
    {
        if (lifetimeOut == nullptr)
        {
            return false;
        }
        const QString kNormalizedText = text.trimmed();
        if (kNormalizedText.compare(QStringLiteral("infinite"), Qt::CaseInsensitive) == 0 ||
            kNormalizedText == QStringLiteral("无限"))
        {
            *lifetimeOut = kInfiniteRouteLifetime;
            return true;
        }
        bool parseOk = false;
        const quint32 kLifetime = kNormalizedText.toUInt(&parseOk, 10);
        if (!parseOk)
        {
            return false;
        }
        *lifetimeOut = kLifetime;
        return true;
    }

    bool routeRecordToNativeRow(
        const NetworkDock::RouteRecord& record,
        MIB_IPFORWARD_ROW2* rowOut,
        QString* errorTextOut)
    {
        if (rowOut == nullptr || (record.addressFamily != AF_INET && record.addressFamily != AF_INET6) ||
            record.interfaceIndex == 0U || record.prefixLength < 0 ||
            record.prefixLength > (record.addressFamily == AF_INET ? 32 : 128))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("地址族、前缀长度或接口索引无效。");
            }
            return false;
        }

        if (record.destinationAddress.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("目的网络或下一跳地址格式不正确。");
            }
            return false;
        }

        SOCKADDR_INET destination{};
        SOCKADDR_INET nextHop{};
        if (!routeAddressFromText(record.addressFamily, record.destinationAddress, &destination) ||
            !routeAddressFromText(record.addressFamily, record.nextHopAddress, &nextHop))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("目的网络或下一跳地址格式不正确。");
            }
            return false;
        }

        InitializeIpForwardEntry(rowOut);
        rowOut->InterfaceIndex = record.interfaceIndex;
        const DWORD kLuidStatus = ConvertInterfaceIndexToLuid(record.interfaceIndex, &rowOut->InterfaceLuid);
        if (kLuidStatus != NO_ERROR)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("接口索引 %1 无法转换为 LUID，错误码=%2。")
                    .arg(record.interfaceIndex).arg(kLuidStatus);
            }
            return false;
        }
        rowOut->DestinationPrefix.Prefix = destination;
        rowOut->DestinationPrefix.PrefixLength = static_cast<UINT8>(record.prefixLength);
        rowOut->NextHop = nextHop;
        rowOut->SitePrefixLength = record.sitePrefixLength;
        rowOut->Metric = record.metric;
        rowOut->Protocol = static_cast<NL_ROUTE_PROTOCOL>(record.protocol == 0U ? MIB_IPPROTO_NETMGMT : record.protocol);
        rowOut->Origin = static_cast<NL_ROUTE_ORIGIN>(record.origin == 0U ? NlroManual : record.origin);
        rowOut->Publish = record.publish;
        rowOut->Immortal = record.immortal;
        rowOut->ValidLifetime = record.validLifetime;
        rowOut->PreferredLifetime = record.preferredLifetime;
        return true;
    }

    NetworkDock::RouteRecord routeRecordFromNativeRow(const MIB_IPFORWARD_ROW2& row)
    {
        NetworkDock::RouteRecord record;
        record.addressFamily = row.DestinationPrefix.Prefix.si_family;
        record.destinationAddress = routeAddressText(row.DestinationPrefix.Prefix);
        record.prefixLength = row.DestinationPrefix.PrefixLength;
        record.nextHopAddress = routeAddressText(row.NextHop);
        record.interfaceIndex = row.InterfaceIndex;
        record.interfaceName = routeInterfaceName(row.InterfaceIndex);
        record.metric = row.Metric;
        record.protocol = static_cast<quint32>(row.Protocol);
        record.origin = static_cast<quint32>(row.Origin);
        record.publish = row.Publish != FALSE;
        record.immortal = row.Immortal != FALSE;
        record.age = row.Age;
        record.validLifetime = row.ValidLifetime;
        record.preferredLifetime = row.PreferredLifetime;
        record.sitePrefixLength = row.SitePrefixLength;
        return record;
    }

    bool sameRouteIdentity(const NetworkDock::RouteRecord& left, const NetworkDock::RouteRecord& right)
    {
        return left.addressFamily == right.addressFamily &&
            left.destinationAddress.compare(right.destinationAddress, Qt::CaseInsensitive) == 0 &&
            left.prefixLength == right.prefixLength &&
            left.nextHopAddress.compare(right.nextHopAddress, Qt::CaseInsensitive) == 0 &&
            left.interfaceIndex == right.interfaceIndex;
    }

    bool isHighRiskRoute(const NetworkDock::RouteRecord& record)
    {
        return record.prefixLength == 0 ||
            record.origin != static_cast<quint32>(NlroManual) ||
            record.protocol == static_cast<quint32>(MIB_IPPROTO_LOCAL);
    }

    QString routeSummaryText(const NetworkDock::RouteRecord& record)
    {
        return QStringLiteral("%1/%2\n下一跳：%3\n接口：%4 (%5)\nMetric：%6\n协议：%7\n来源：%8")
            .arg(record.destinationAddress)
            .arg(record.prefixLength)
            .arg(record.nextHopAddress.isEmpty() ? QStringLiteral("On-link") : record.nextHopAddress)
            .arg(record.interfaceName)
            .arg(record.interfaceIndex)
            .arg(record.metric)
            .arg(routeProtocolText(record.protocol))
            .arg(routeOriginText(record.origin));
    }

    bool runNetshRouteCommand(
        const QString& verb,
        const NetworkDock::RouteRecord& record,
        QString* errorTextOut)
    {
        const QString kFamilyToken = record.addressFamily == AF_INET ? QStringLiteral("ipv4") : QStringLiteral("ipv6");
        QProcess process;
        process.setProgram(QStringLiteral("netsh.exe"));
        process.setProcessChannelMode(QProcess::MergedChannels);
        QStringList arguments{
            QStringLiteral("interface"), kFamilyToken, verb,
            QStringLiteral("prefix=%1/%2").arg(record.destinationAddress).arg(record.prefixLength),
            QStringLiteral("interface=%1").arg(record.interfaceIndex)
        };
        if (!record.nextHopAddress.trimmed().isEmpty())
        {
            arguments.push_back(QStringLiteral("nexthop=%1").arg(record.nextHopAddress));
        }
        if (verb != QStringLiteral("delete"))
        {
            arguments.push_back(QStringLiteral("metric=%1").arg(record.metric));
            arguments.push_back(QStringLiteral("publish=%1").arg(record.publish ? QStringLiteral("yes") : QStringLiteral("no")));
            arguments.push_back(QStringLiteral("validlifetime=%1").arg(routeLifetimeText(record.validLifetime).replace(QStringLiteral("无限"), QStringLiteral("infinite"))));
            arguments.push_back(QStringLiteral("preferredlifetime=%1").arg(routeLifetimeText(record.preferredLifetime).replace(QStringLiteral("无限"), QStringLiteral("infinite"))));
        }
        arguments.push_back(QStringLiteral("store=persistent"));
        process.setArguments(arguments);
        process.start();
        if (!process.waitForStarted(2000) || !process.waitForFinished(8000) ||
            process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            if (errorTextOut != nullptr)
            {
                const QString kOutput = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
                *errorTextOut = QStringLiteral("netsh %1 失败：%2")
                    .arg(verb, kOutput.isEmpty()
                        ? (process.error() == QProcess::UnknownError
                            ? QStringLiteral("退出码=%1").arg(process.exitCode())
                            : process.errorString())
                        : kOutput);
            }
            return false;
        }
        return true;
    }

    bool editRouteRecordDialog(
        QWidget* parent,
        NetworkDock::RouteRecord* recordInOut,
        bool* persistentOut,
        const bool editing)
    {
        if (recordInOut == nullptr || persistentOut == nullptr)
        {
            return false;
        }
        QDialog dialog(parent);
        dialog.setWindowTitle(editing ? QStringLiteral("编辑路由") : QStringLiteral("新增路由"));
        QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
        QFormLayout* formLayout = new QFormLayout();
        QComboBox* familyCombo = new QComboBox(&dialog);
        familyCombo->addItem(QStringLiteral("IPv4"), AF_INET);
        familyCombo->addItem(QStringLiteral("IPv6"), AF_INET6);
        familyCombo->setCurrentIndex(recordInOut->addressFamily == AF_INET6 ? 1 : 0);
        QLineEdit* destinationEdit = new QLineEdit(recordInOut->destinationAddress, &dialog);
        QSpinBox* prefixSpin = new QSpinBox(&dialog);
        prefixSpin->setRange(0, recordInOut->addressFamily == AF_INET6 ? 128 : 32);
        prefixSpin->setValue(recordInOut->prefixLength);
        QLineEdit* nextHopEdit = new QLineEdit(recordInOut->nextHopAddress, &dialog);
        QComboBox* interfaceCombo = new QComboBox(&dialog);
        PMIB_IF_TABLE2 interfaceTable = nullptr;
        if (GetIfTable2(&interfaceTable) == NO_ERROR && interfaceTable != nullptr)
        {
            for (ULONG index = 0; index < interfaceTable->NumEntries; ++index)
            {
                const MIB_IF_ROW2& interfaceRow = interfaceTable->Table[index];
                const QString kAlias = QString::fromWCharArray(interfaceRow.Alias).trimmed();
                interfaceCombo->addItem(
                    QStringLiteral("%1 (%2)").arg(kAlias.isEmpty() ? routeInterfaceName(interfaceRow.InterfaceIndex) : kAlias).arg(interfaceRow.InterfaceIndex),
                    static_cast<quint32>(interfaceRow.InterfaceIndex));
            }
            FreeMibTable(interfaceTable);
        }
        const int kInterfaceIndex = interfaceCombo->findData(recordInOut->interfaceIndex);
        if (kInterfaceIndex >= 0)
        {
            interfaceCombo->setCurrentIndex(kInterfaceIndex);
        }
        QSpinBox* metricSpin = new QSpinBox(&dialog);
        metricSpin->setRange(0, std::numeric_limits<int>::max());
        metricSpin->setValue(static_cast<int>(std::min<quint32>(recordInOut->metric, std::numeric_limits<int>::max())));
        QLineEdit* validLifetimeEdit = new QLineEdit(routeLifetimeText(recordInOut->validLifetime), &dialog);
        QLineEdit* preferredLifetimeEdit = new QLineEdit(routeLifetimeText(recordInOut->preferredLifetime), &dialog);
        QCheckBox* publishCheck = new QCheckBox(QStringLiteral("发布路由"), &dialog);
        publishCheck->setChecked(recordInOut->publish);
        QCheckBox* immortalCheck = new QCheckBox(QStringLiteral("Immortal"), &dialog);
        immortalCheck->setChecked(recordInOut->immortal);
        QCheckBox* persistentCheck = new QCheckBox(QStringLiteral("同步写入持久路由"), &dialog);
        persistentCheck->setChecked(false);
        persistentCheck->setToolTip(QStringLiteral("默认仅写入活动路由表；勾选后同时调用 Windows netsh 写入持久存储。"));
        formLayout->addRow(QStringLiteral("地址族"), familyCombo);
        formLayout->addRow(QStringLiteral("目的网络"), destinationEdit);
        formLayout->addRow(QStringLiteral("前缀长度"), prefixSpin);
        formLayout->addRow(QStringLiteral("下一跳（空=On-link）"), nextHopEdit);
        formLayout->addRow(QStringLiteral("接口"), interfaceCombo);
        formLayout->addRow(QStringLiteral("Metric"), metricSpin);
        formLayout->addRow(QStringLiteral("有效期（秒或 infinite）"), validLifetimeEdit);
        formLayout->addRow(QStringLiteral("首选期（秒或 infinite）"), preferredLifetimeEdit);
        formLayout->addRow(publishCheck);
        formLayout->addRow(immortalCheck);
        formLayout->addRow(persistentCheck);
        rootLayout->addLayout(formLayout);
        QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        rootLayout->addWidget(buttons);
        QObject::connect(familyCombo, qOverload<int>(&QComboBox::currentIndexChanged), &dialog, [familyCombo, prefixSpin](int) {
            prefixSpin->setMaximum(familyCombo->currentData().toInt() == AF_INET6 ? 128 : 32);
        });
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return false;
        }
        quint32 validLifetime = 0;
        quint32 preferredLifetime = 0;
        if (!parseRouteLifetime(validLifetimeEdit->text(), &validLifetime) ||
            !parseRouteLifetime(preferredLifetimeEdit->text(), &preferredLifetime))
        {
            QMessageBox::warning(parent, QStringLiteral("路由"), QStringLiteral("有效期和首选期必须是秒数或 infinite。"));
            return false;
        }
        recordInOut->addressFamily = familyCombo->currentData().toInt();
        recordInOut->destinationAddress = destinationEdit->text().trimmed();
        recordInOut->prefixLength = prefixSpin->value();
        recordInOut->nextHopAddress = nextHopEdit->text().trimmed();
        recordInOut->interfaceIndex = interfaceCombo->currentData().toUInt();
        recordInOut->interfaceName = interfaceCombo->currentText();
        recordInOut->metric = static_cast<quint32>(metricSpin->value());
        recordInOut->publish = publishCheck->isChecked();
        recordInOut->immortal = immortalCheck->isChecked();
        recordInOut->validLifetime = validLifetime;
        recordInOut->preferredLifetime = preferredLifetime;
        *persistentOut = persistentCheck->isChecked();
        return true;
    }
}
// ============================================================
// NetworkDock.NetworkDiagnostics.cpp
// Purpose:
// - ARP cache display and editing;
// - DNS cache display and editing;
// - Live host discovery (ICMP scan).
// - hosts file editing.
// ============================================================

void NetworkDock::initializeRouteTableTab()
{
    routeTablePage_ = new QWidget(this);
    routeTableLayout_ = new QVBoxLayout(routeTablePage_);
    routeTableLayout_->setContentsMargins(6, 6, 6, 6);
    routeTableLayout_->setSpacing(6);
    routeTableControlLayout_ = new QHBoxLayout();
    routeTableControlLayout_->setSpacing(6);

    refreshRouteButton_ = new QPushButton(routeTablePage_);
    refreshRouteButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshRouteButton_->setToolTip(QStringLiteral("刷新 IPv4/IPv6 路由表"));
    addRouteButton_ = new QPushButton(routeTablePage_);
    addRouteButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    addRouteButton_->setToolTip(QStringLiteral("新增路由，默认仅在本次启动有效"));
    editRouteButton_ = new QPushButton(routeTablePage_);
    editRouteButton_->setIcon(QIcon(":/Icon/process_details.svg"));
    editRouteButton_->setToolTip(QStringLiteral("编辑选中路由"));
    removeRouteButton_ = new QPushButton(routeTablePage_);
    removeRouteButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    removeRouteButton_->setToolTip(QStringLiteral("删除选中活动路由及其同名持久副本"));
    routeStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), routeTablePage_);
    routeStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    routeTableControlLayout_->addWidget(refreshRouteButton_);
    routeTableControlLayout_->addWidget(addRouteButton_);
    routeTableControlLayout_->addWidget(editRouteButton_);
    routeTableControlLayout_->addWidget(removeRouteButton_);
    routeTableControlLayout_->addWidget(routeStatusLabel_, 1);
    routeTableLayout_->addLayout(routeTableControlLayout_);

    routeTable_ = new ks::ui::VisibleTableWidget(routeTablePage_);
    routeTable_->setColumnCount(13);
    routeTable_->setHorizontalHeaderLabels({
        QStringLiteral("地址族"), QStringLiteral("目的网络"), QStringLiteral("下一跳"),
        QStringLiteral("接口"), QStringLiteral("Metric"), QStringLiteral("协议"),
        QStringLiteral("来源"), QStringLiteral("发布"), QStringLiteral("Immortal"),
        QStringLiteral("Age"), QStringLiteral("有效期"), QStringLiteral("首选期"),
        QStringLiteral("站点前缀")
        });
    routeTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    routeTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    routeTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    routeTable_->verticalHeader()->setVisible(false);
    routeTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    routeTable_->horizontalHeader()->setStretchLastSection(true);
    installCopyCurrentRowMenu(routeTable_);
    routeTableLayout_->addWidget(routeTable_, 1);
    sideTabWidget_->addTab(routeTablePage_, QIcon(":/Icon/process_tree.svg"), QStringLiteral("路由表"));

    connect(refreshRouteButton_, &QPushButton::clicked, this, [this]() { refreshRouteTable(); });
    connect(addRouteButton_, &QPushButton::clicked, this, [this]() { addRouteEntry(); });
    connect(editRouteButton_, &QPushButton::clicked, this, [this]() { editSelectedRouteEntry(); });
    connect(removeRouteButton_, &QPushButton::clicked, this, [this]() { deleteSelectedRouteEntry(); });
    refreshRouteTable();
}

void NetworkDock::refreshRouteTable()
{
    if (routeTable_ == nullptr)
    {
        return;
    }
    PMIB_IPFORWARD_TABLE2 routeTable = nullptr;
    const DWORD kQueryStatus = GetIpForwardTable2(AF_UNSPEC, &routeTable);
    if (kQueryStatus != NO_ERROR || routeTable == nullptr)
    {
        if (routeStatusLabel_ != nullptr)
        {
            routeStatusLabel_->setText(QStringLiteral("状态：读取路由表失败，错误码=%1").arg(kQueryStatus));
        }
        return;
    }

    routeRecordCache_.clear();
    routeRecordCache_.reserve(routeTable->NumEntries);
    routeTable_->setUpdatesEnabled(false);
    routeTable_->setRowCount(0);
    for (ULONG index = 0; index < routeTable->NumEntries; ++index)
    {
        const RouteRecord kRecord = routeRecordFromNativeRow(routeTable->Table[index]);
        if (kRecord.addressFamily != AF_INET && kRecord.addressFamily != AF_INET6)
        {
            continue;
        }
        const int kCacheIndex = static_cast<int>(routeRecordCache_.size());
        routeRecordCache_.push_back(kRecord);
        const int kRow = routeTable_->rowCount();
        routeTable_->insertRow(kRow);
        const QStringList kFields{
            kRecord.addressFamily == AF_INET ? QStringLiteral("IPv4") : QStringLiteral("IPv6"),
            QStringLiteral("%1/%2").arg(kRecord.destinationAddress).arg(kRecord.prefixLength),
            kRecord.nextHopAddress.isEmpty() ? QStringLiteral("On-link") : kRecord.nextHopAddress,
            QStringLiteral("%1 (%2)").arg(kRecord.interfaceName).arg(kRecord.interfaceIndex),
            QString::number(kRecord.metric), routeProtocolText(kRecord.protocol), routeOriginText(kRecord.origin),
            kRecord.publish ? QStringLiteral("是") : QStringLiteral("否"),
            kRecord.immortal ? QStringLiteral("是") : QStringLiteral("否"),
            QString::number(kRecord.age), routeLifetimeText(kRecord.validLifetime),
            routeLifetimeText(kRecord.preferredLifetime), QString::number(kRecord.sitePrefixLength)
        };
        for (int column = 0; column < kFields.size(); ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(kFields.at(column));
            item->setData(Qt::UserRole, kCacheIndex);
            routeTable_->setItem(kRow, column, item);
        }
    }
    routeTable_->setUpdatesEnabled(true);
    FreeMibTable(routeTable);
    if (routeStatusLabel_ != nullptr)
    {
        routeStatusLabel_->setText(QStringLiteral("状态：路由项 %1").arg(routeRecordCache_.size()));
    }
}

void NetworkDock::addRouteEntry()
{
    RouteRecord record;
    record.addressFamily = AF_INET;
    record.prefixLength = 24;
    record.protocol = MIB_IPPROTO_NETMGMT;
    record.origin = NlroManual;
    record.validLifetime = kInfiniteRouteLifetime;
    record.preferredLifetime = kInfiniteRouteLifetime;
    bool persistent = false;
    if (!editRouteRecordDialog(this, &record, &persistent, false))
    {
        return;
    }
    MIB_IPFORWARD_ROW2 nativeRow{};
    QString errorText;
    if (!routeRecordToNativeRow(record, &nativeRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("新增路由"), errorText);
        return;
    }
    if (isHighRiskRoute(record) && QMessageBox::question(
        this, QStringLiteral("新增高风险路由"),
        QStringLiteral("将新增以下路由：\n%1\n\n该路由可能影响系统网络连接，是否继续？").arg(routeSummaryText(record)),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    const DWORD kCreateStatus = CreateIpForwardEntry2(&nativeRow);
    if (kCreateStatus != NO_ERROR)
    {
        // privilegePromptHandled: Skip the old error box when a structured error triggers a recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("新增系统路由"),
            kCreateStatus);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增路由"),
                QStringLiteral("CreateIpForwardEntry2 失败，错误码=%1").arg(kCreateStatus));
        }
        return;
    }
    if (persistent && !runNetshRouteCommand(QStringLiteral("add"), record, &errorText))
    {
        // privilegePromptHandled: Active routes still require rollback, but no duplicate popup is shown after the privilege prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("持久化新增路由"),
            errorText);
        (void)DeleteIpForwardEntry2(&nativeRow);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增路由"),
                QStringLiteral("持久化写入失败，已回滚活动路由。\n%1").arg(errorText));
        }
        return;
    }
    refreshRouteTable();
}

void NetworkDock::editSelectedRouteEntry()
{
    if (routeTable_ == nullptr || routeTable_->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("编辑路由"), QStringLiteral("请先选择一条路由。"));
        return;
    }
    QTableWidgetItem* sourceItem = routeTable_->item(routeTable_->currentRow(), 0);
    const int kCacheIndex = sourceItem != nullptr ? sourceItem->data(Qt::UserRole).toInt() : -1;
    if (kCacheIndex < 0 || kCacheIndex >= static_cast<int>(routeRecordCache_.size()))
    {
        return;
    }
    const RouteRecord kOriginal = routeRecordCache_.at(static_cast<std::size_t>(kCacheIndex));
    RouteRecord target = kOriginal;
    bool persistent = false;
    if (!editRouteRecordDialog(this, &target, &persistent, true))
    {
        return;
    }
    if (isHighRiskRoute(kOriginal) || isHighRiskRoute(target))
    {
        const QString kConfirmationText = QStringLiteral("原路由：\n%1\n\n修改后：\n%2\n\n是否继续？")
            .arg(routeSummaryText(kOriginal), routeSummaryText(target));
        if (QMessageBox::question(this, QStringLiteral("修改高风险路由"), kConfirmationText,
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }
    }
    MIB_IPFORWARD_ROW2 originalRow{};
    MIB_IPFORWARD_ROW2 targetRow{};
    QString errorText;
    if (!routeRecordToNativeRow(kOriginal, &originalRow, &errorText) || !routeRecordToNativeRow(target, &targetRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("编辑路由"), errorText);
        return;
    }
    DWORD operationStatus = NO_ERROR;
    if (sameRouteIdentity(kOriginal, target))
    {
        operationStatus = SetIpForwardEntry2(&targetRow);
    }
    else
    {
        operationStatus = CreateIpForwardEntry2(&targetRow);
        if (operationStatus == NO_ERROR)
        {
            operationStatus = DeleteIpForwardEntry2(&originalRow);
        }
    }
    if (operationStatus != NO_ERROR)
    {
        // privilegePromptHandled: Skip the old error box when a structured error triggers a recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("编辑系统路由"),
            operationStatus);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("编辑路由"),
                QStringLiteral("更新活动路由失败，错误码=%1").arg(operationStatus));
        }
        return;
    }
    if (persistent)
    {
        if (!sameRouteIdentity(kOriginal, target))
        {
            (void)runNetshRouteCommand(QStringLiteral("delete"), kOriginal, nullptr);
            if (!runNetshRouteCommand(QStringLiteral("add"), target, &errorText))
            {
                // privilegePromptHandled: Continue page refresh without stacking the old generic failure dialog.
                const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("持久化编辑路由"),
                    errorText);
                if (!kPrivilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        QStringLiteral("编辑路由"),
                        QStringLiteral("活动路由已更新，但持久化写入失败：%1").arg(errorText));
                }
            }
        }
        else if (!runNetshRouteCommand(QStringLiteral("set"), target, &errorText) &&
                 !runNetshRouteCommand(QStringLiteral("add"), target, &errorText))
        {
            // privilegePromptHandled: Continue page refresh without stacking the old generic failure dialog.
            const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("持久化编辑路由"),
                errorText);
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("编辑路由"),
                    QStringLiteral("活动路由已更新，但持久化写入失败：%1").arg(errorText));
            }
        }
    }
    else
    {
        (void)runNetshRouteCommand(QStringLiteral("delete"), kOriginal, nullptr);
    }
    refreshRouteTable();
}

void NetworkDock::deleteSelectedRouteEntry()
{
    if (routeTable_ == nullptr || routeTable_->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("删除路由"), QStringLiteral("请先选择一条路由。"));
        return;
    }
    QTableWidgetItem* sourceItem = routeTable_->item(routeTable_->currentRow(), 0);
    const int kCacheIndex = sourceItem != nullptr ? sourceItem->data(Qt::UserRole).toInt() : -1;
    if (kCacheIndex < 0 || kCacheIndex >= static_cast<int>(routeRecordCache_.size()))
    {
        return;
    }
    const RouteRecord kRecord = routeRecordCache_.at(static_cast<std::size_t>(kCacheIndex));
    if (isHighRiskRoute(kRecord) && QMessageBox::question(
        this, QStringLiteral("删除高风险路由"),
        QStringLiteral("将删除活动路由及同名持久副本：\n%1\n\n是否继续？").arg(routeSummaryText(kRecord)),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    MIB_IPFORWARD_ROW2 nativeRow{};
    QString errorText;
    if (!routeRecordToNativeRow(kRecord, &nativeRow, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("删除路由"), errorText);
        return;
    }
    const DWORD kDeleteStatus = DeleteIpForwardEntry2(&nativeRow);
    if (kDeleteStatus != NO_ERROR)
    {
        // privilegePromptHandled: Skip the old error box when a structured error triggers a recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("删除系统路由"),
            kDeleteStatus);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("删除路由"),
                QStringLiteral("DeleteIpForwardEntry2 失败，错误码=%1").arg(kDeleteStatus));
        }
        return;
    }
    (void)runNetshRouteCommand(QStringLiteral("delete"), kRecord, nullptr);
    refreshRouteTable();
}

void NetworkDock::initializeArpCacheTab()
{
    arpCachePage_ = new QWidget(this);
    arpCacheLayout_ = new QVBoxLayout(arpCachePage_);
    arpCacheLayout_->setContentsMargins(6, 6, 6, 6);
    arpCacheLayout_->setSpacing(6);

    arpCacheControlLayout_ = new QHBoxLayout();
    arpCacheControlLayout_->setSpacing(6);

    refreshArpButton_ = new QPushButton(arpCachePage_);
    refreshArpButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshArpButton_->setToolTip(QStringLiteral("刷新 ARP 缓存列表"));

    addArpButton_ = new QPushButton(arpCachePage_);
    addArpButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    addArpButton_->setToolTip(QStringLiteral("新增静态 ARP 缓存项"));

    removeArpButton_ = new QPushButton(arpCachePage_);
    removeArpButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    removeArpButton_->setToolTip(QStringLiteral("删除选中的 ARP 缓存项"));

    flushArpButton_ = new QPushButton(arpCachePage_);
    flushArpButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    flushArpButton_->setToolTip(QStringLiteral("清空全部 ARP 缓存"));

    arpStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), arpCachePage_);
    arpStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    arpCacheControlLayout_->addWidget(refreshArpButton_);
    arpCacheControlLayout_->addWidget(addArpButton_);
    arpCacheControlLayout_->addWidget(removeArpButton_);
    arpCacheControlLayout_->addWidget(flushArpButton_);
    arpCacheControlLayout_->addWidget(arpStatusLabel_, 1);
    arpCacheLayout_->addLayout(arpCacheControlLayout_);

    arpTable_ = new ks::ui::VisibleTableWidget(arpCachePage_);
    arpTable_->setColumnCount(4);
    arpTable_->setHorizontalHeaderLabels({
        QStringLiteral("IPv4地址"),
        QStringLiteral("MAC地址"),
        QStringLiteral("类型"),
        QStringLiteral("接口索引")
        });
    arpTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    arpTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    arpTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    arpTable_->verticalHeader()->setVisible(false);
    arpTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Horizontal scrollbar is not forcibly closed: by default, it is pushed into the viewport by global column width adaptation; it appears as needed after the user widens a column.
    installCopyCurrentRowMenu(arpTable_);
    arpCacheLayout_->addWidget(arpTable_, 1);

    sideTabWidget_->addTab(arpCachePage_, QIcon(":/Icon/process_tree.svg"), QStringLiteral("ARP缓存"));
}

void NetworkDock::initializeDnsCacheTab()
{
    dnsCachePage_ = new QWidget(this);
    dnsCacheLayout_ = new QVBoxLayout(dnsCachePage_);
    dnsCacheLayout_->setContentsMargins(6, 6, 6, 6);
    dnsCacheLayout_->setSpacing(6);

    dnsCacheControlLayout_ = new QHBoxLayout();
    dnsCacheControlLayout_->setSpacing(6);

    refreshDnsButton_ = new QPushButton(QStringLiteral("刷新"), dnsCachePage_);
    refreshDnsButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshDnsButton_->setToolTip(QStringLiteral("刷新 DNS 缓存列表"));

    dnsEntryEdit_ = new QLineEdit(dnsCachePage_);
    dnsEntryEdit_->setPlaceholderText(QStringLiteral("输入要删除的 DNS 域名，或先在表格里选择"));
    dnsEntryEdit_->setToolTip(QStringLiteral("删除指定域名的 DNS 缓存条目"));

    removeDnsButton_ = new QPushButton(QStringLiteral("删除"), dnsCachePage_);
    removeDnsButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    removeDnsButton_->setToolTip(QStringLiteral("删除输入框域名或表格选中的 DNS 缓存条目，支持多选"));

    flushDnsButton_ = new QPushButton(QStringLiteral("清空"), dnsCachePage_);
    flushDnsButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    flushDnsButton_->setToolTip(QStringLiteral("清空 DNS 缓存"));

    dnsStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), dnsCachePage_);
    dnsStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    dnsCacheControlLayout_->addWidget(refreshDnsButton_);
    dnsCacheControlLayout_->addWidget(dnsEntryEdit_, 1);
    dnsCacheControlLayout_->addWidget(removeDnsButton_);
    dnsCacheControlLayout_->addWidget(flushDnsButton_);
    dnsCacheControlLayout_->addWidget(dnsStatusLabel_, 1);
    dnsCacheLayout_->addLayout(dnsCacheControlLayout_);

    dnsTable_ = new ks::ui::VisibleTableWidget(dnsCachePage_);
    dnsTable_->setColumnCount(3);
    dnsTable_->setHorizontalHeaderLabels({
        QStringLiteral("域名"),
        QStringLiteral("记录类型"),
        QStringLiteral("标志")
        });
    dnsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    dnsTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    dnsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dnsTable_->verticalHeader()->setVisible(false);
    dnsTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Horizontal scrollbar is not forcibly closed: by default, it is pushed into the viewport by global column width adaptation; it appears as needed after the user widens a column.
    installCopyCurrentRowMenu(dnsTable_);
    dnsCacheLayout_->addWidget(dnsTable_, 1);

    sideTabWidget_->addTab(dnsCachePage_, QIcon(":/Icon/process_list.svg"), QStringLiteral("DNS缓存"));
}

void NetworkDock::initializeAliveHostScanTab()
{
    aliveScanPage_ = new QWidget(this);
    aliveScanLayout_ = new QVBoxLayout(aliveScanPage_);
    aliveScanLayout_->setContentsMargins(6, 6, 6, 6);
    aliveScanLayout_->setSpacing(6);

    aliveScanControlLayout_ = new QHBoxLayout();
    aliveScanControlLayout_->setSpacing(6);

    QLabel* startIpLabel = new QLabel(QStringLiteral("起始IP:"), aliveScanPage_);
    aliveScanStartIpEdit_ = new QLineEdit(aliveScanPage_);
    aliveScanStartIpEdit_->setPlaceholderText(QStringLiteral("例如 192.168.1.1"));
    aliveScanStartIpEdit_->setText(QStringLiteral("192.168.1.1"));

    QLabel* endIpLabel = new QLabel(QStringLiteral("结束IP:"), aliveScanPage_);
    aliveScanEndIpEdit_ = new QLineEdit(aliveScanPage_);
    aliveScanEndIpEdit_->setPlaceholderText(QStringLiteral("例如 192.168.1.254"));
    aliveScanEndIpEdit_->setText(QStringLiteral("192.168.1.254"));

    QLabel* timeoutLabel = new QLabel(QStringLiteral("超时ms:"), aliveScanPage_);
    aliveScanTimeoutSpin_ = new QSpinBox(aliveScanPage_);
    aliveScanTimeoutSpin_->setRange(50, 3000);
    aliveScanTimeoutSpin_->setValue(220);

    startAliveScanButton_ = new QPushButton(aliveScanPage_);
    startAliveScanButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    startAliveScanButton_->setToolTip(QStringLiteral("开始扫描指定 IP 段的存活主机"));

    stopAliveScanButton_ = new QPushButton(aliveScanPage_);
    stopAliveScanButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    stopAliveScanButton_->setToolTip(QStringLiteral("停止当前主机扫描任务"));
    stopAliveScanButton_->setEnabled(false);

    aliveScanControlLayout_->addWidget(startIpLabel);
    aliveScanControlLayout_->addWidget(aliveScanStartIpEdit_);
    aliveScanControlLayout_->addWidget(endIpLabel);
    aliveScanControlLayout_->addWidget(aliveScanEndIpEdit_);
    aliveScanControlLayout_->addWidget(timeoutLabel);
    aliveScanControlLayout_->addWidget(aliveScanTimeoutSpin_);
    aliveScanControlLayout_->addWidget(startAliveScanButton_);
    aliveScanControlLayout_->addWidget(stopAliveScanButton_);
    aliveScanLayout_->addLayout(aliveScanControlLayout_);

    aliveScanProgressBar_ = new QProgressBar(aliveScanPage_);
    aliveScanProgressBar_->setRange(0, 100);
    aliveScanProgressBar_->setValue(0);
    aliveScanProgressBar_->setFormat(QStringLiteral("0%"));
    aliveScanLayout_->addWidget(aliveScanProgressBar_);

    aliveScanStatusLabel_ = new QLabel(QStringLiteral("状态：待机"), aliveScanPage_);
    aliveScanLayout_->addWidget(aliveScanStatusLabel_);

    aliveScanTable_ = new ks::ui::VisibleTableWidget(aliveScanPage_);
    aliveScanTable_->setColumnCount(4);
    aliveScanTable_->setHorizontalHeaderLabels({
        QStringLiteral("IP"),
        QStringLiteral("状态"),
        QStringLiteral("RTT(ms)"),
        QStringLiteral("详情")
        });
    aliveScanTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    aliveScanTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    aliveScanTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    aliveScanTable_->verticalHeader()->setVisible(false);
    aliveScanTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // Horizontal scrollbar is not forcibly closed: by default, it is pushed into the viewport by global column width adaptation; it appears as needed after the user widens a column.
    installCopyCurrentRowMenu(aliveScanTable_);
    aliveScanLayout_->addWidget(aliveScanTable_, 1);

    sideTabWidget_->addTab(aliveScanPage_, QIcon(":/Icon/process_main.svg"), QStringLiteral("存活主机"));
}

void NetworkDock::initializeHostsFileEditorTab()
{
    hostsFileEditorPage_ = new QWidget(this);
    hostsFileEditorLayout_ = new QVBoxLayout(hostsFileEditorPage_);
    hostsFileEditorLayout_->setContentsMargins(0, 0, 0, 0);
    hostsFileEditorLayout_->setSpacing(0);

    hostsFileEditor_ = new CodeEditorWidget(hostsFileEditorPage_);
    hostsFileEditor_->setReadOnly(false);
    hostsFileEditorLayout_->addWidget(hostsFileEditor_, 1);

    QString windowsDirectory = qEnvironmentVariable("WINDIR").trimmed();
    if (windowsDirectory.isEmpty())
    {
        windowsDirectory = QStringLiteral("C:/Windows");
    }
    const QString kHostsFilePath = QDir(windowsDirectory)
        .absoluteFilePath(QStringLiteral("System32/drivers/etc/hosts"));

    if (hostsFileEditor_->openLocalFile(kHostsFilePath))
    {
        KLogEvent openHostsEvent;
        info << openHostsEvent
            << "[NetworkDock] hosts文件编辑页已加载, path="
            << kHostsFilePath.toStdString()
            << eol;
    }
    else
    {
        hostsFileEditor_->setCurrentFilePath(kHostsFilePath);
        // The hosts file body must remain unchanged; only translate the read failure message generated by this program.
        const QString kHostsReadFailureText =
            ks::i18n::sourceText(QStringLiteral("# hosts 文件读取失败。\n"))
            + ks::i18n::sourceText(QStringLiteral("# 目标路径: %1\n")).arg(kHostsFilePath)
            + ks::i18n::sourceText(QStringLiteral("# 如需直接保存系统 hosts，请以管理员权限运行程序。"));
        hostsFileEditor_->setRawText(kHostsReadFailureText);

        KLogEvent openHostsFailEvent;
        warn << openHostsFailEvent
            << "[NetworkDock] hosts文件编辑页加载失败, path="
            << kHostsFilePath.toStdString()
            << eol;
    }

    sideTabWidget_->addTab(hostsFileEditorPage_, QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("hosts文件编辑"));
}

void NetworkDock::refreshArpCacheTable()
{
    if (arpTable_ == nullptr)
    {
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[NetworkDock] 开始刷新ARP缓存表。"
            << eol;
    }

    ULONG tableSize = 0;
    if (GetIpNetTable(nullptr, &tableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER)
    {
        arpStatusLabel_->setText(QStringLiteral("状态：读取ARP缓存失败"));
        KLogEvent event;
        err << event
            << "[NetworkDock] ARP缓存刷新失败：首次获取缓冲区大小失败。"
            << eol;
        return;
    }

    std::vector<std::uint8_t> buffer(tableSize, 0);
    PMIB_IPNETTABLE netTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
    if (GetIpNetTable(netTable, &tableSize, FALSE) != NO_ERROR)
    {
        arpStatusLabel_->setText(QStringLiteral("状态：读取ARP缓存失败"));
        KLogEvent event;
        err << event
            << "[NetworkDock] ARP缓存刷新失败：GetIpNetTable读取失败。"
            << eol;
        return;
    }

    arpTable_->setRowCount(0);
    for (DWORD index = 0; index < netTable->dwNumEntries; ++index)
    {
        const MIB_IPNETROW& row = netTable->table[index];
        const QString kIpText = toQString(ks::network::formatIpv4HostOrder(ntohl(row.dwAddr)));
        const QString kMacText = toQString(ks::network::formatHardwareAddress(
            reinterpret_cast<const std::uint8_t*>(row.bPhysAddr),
            static_cast<std::size_t>(row.dwPhysAddrLen)));
        const QString kTypeText = toQString(ks::network::arpEntryTypeToString(row.dwType));

        const int kTableRow = arpTable_->rowCount();
        arpTable_->insertRow(kTableRow);
        arpTable_->setItem(kTableRow, 0, new QTableWidgetItem(kIpText));
        arpTable_->setItem(kTableRow, 1, new QTableWidgetItem(kMacText));
        arpTable_->setItem(kTableRow, 2, new QTableWidgetItem(kTypeText));
        arpTable_->setItem(kTableRow, 3, new QTableWidgetItem(QString::number(row.dwIndex)));
    }

    arpStatusLabel_->setText(QString("状态：ARP缓存项 %1").arg(arpTable_->rowCount()));

    KLogEvent event;
    info << event
        << "[NetworkDock] ARP缓存刷新完成, rowCount="
        << arpTable_->rowCount()
        << eol;
}

void NetworkDock::addArpCacheEntry()
{
    KLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 用户触发新增ARP缓存项。"
        << eol;

    bool ok = false;
    const QString kIpText = QInputDialog::getText(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("IPv4地址:"),
        QLineEdit::Normal,
        QString(),
        &ok).trimmed();
    if (!ok || kIpText.isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入IPv4地址。"
            << eol;
        return;
    }

    const QString kMacText = QInputDialog::getText(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("MAC地址(AA-BB-CC-DD-EE-FF):"),
        QLineEdit::Normal,
        QString(),
        &ok).trimmed();
    if (!ok || kMacText.isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入MAC地址。"
            << eol;
        return;
    }

    const int kInterfaceIndex = QInputDialog::getInt(
        this,
        QStringLiteral("新增ARP"),
        QStringLiteral("接口索引(ifIndex):"),
        1,
        1,
        INT_MAX,
        1,
        &ok);
    if (!ok)
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 新增ARP取消：未输入接口索引。"
            << eol;
        return;
    }

    std::uint32_t ipHostOrder = 0;
    if (!tryParseIpv4Text(kIpText, ipHostOrder))
    {
        KLogEvent event;
        warn << event
            << "[NetworkDock] 新增ARP失败：IPv4格式非法, ip="
            << kIpText.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("新增ARP"), QStringLiteral("IPv4 地址格式不正确。"));
        return;
    }

    std::vector<std::uint8_t> macBytes;
    std::string macParseErrorText;
    if (!ks::network::tryParseMacAddressText(kMacText.toStdString(), &macBytes, &macParseErrorText))
    {
        KLogEvent event;
        warn << event
            << "[NetworkDock] 新增ARP失败：MAC格式非法, mac="
            << kMacText.toStdString()
            << ", reason="
            << macParseErrorText
            << eol;
        QMessageBox::warning(this, QStringLiteral("新增ARP"), QStringLiteral("MAC 地址格式不正确。"));
        return;
    }

    MIB_IPNETROW row{};
    row.dwIndex = static_cast<DWORD>(kInterfaceIndex);
    row.dwAddr = htonl(ipHostOrder);
    row.dwType = MIB_IPNET_TYPE_STATIC;
    row.dwPhysAddrLen = static_cast<DWORD>(macBytes.size());
    for (std::size_t segmentIndex = 0; segmentIndex < macBytes.size(); ++segmentIndex)
    {
        row.bPhysAddr[segmentIndex] = static_cast<BYTE>(macBytes[segmentIndex]);
    }

    const DWORD kCreateResult = CreateIpNetEntry(&row);
    if (kCreateResult != NO_ERROR)
    {
        // privilegePromptHandled: Only retain error logs when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增 ARP 项"), kCreateResult);
        KLogEvent event;
        err << event
            << "[NetworkDock] 新增ARP失败, errorCode="
            << kCreateResult
            << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("新增ARP"),
                QString("CreateIpNetEntry 失败，错误码=%1").arg(kCreateResult));
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[NetworkDock] 新增ARP成功, ip="
        << kIpText.toStdString()
        << ", interfaceIndex="
        << kInterfaceIndex
        << eol;

    refreshArpCacheTable();
}

void NetworkDock::removeSelectedArpCacheEntry()
{
    if (arpTable_ == nullptr || arpTable_->currentRow() < 0)
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 删除ARP取消：未选中行。"
            << eol;
        return;
    }

    const int kSelectedRow = arpTable_->currentRow();
    const QString kIpText = arpTable_->item(kSelectedRow, 0) != nullptr
        ? arpTable_->item(kSelectedRow, 0)->text().trimmed()
        : QString();
    const QString kIndexText = arpTable_->item(kSelectedRow, 3) != nullptr
        ? arpTable_->item(kSelectedRow, 3)->text().trimmed()
        : QString();

    std::uint32_t ipHostOrder = 0;
    bool indexOk = false;
    const DWORD kInterfaceIndex = static_cast<DWORD>(kIndexText.toUInt(&indexOk));
    if (!tryParseIpv4Text(kIpText, ipHostOrder) || !indexOk)
    {
        KLogEvent event;
        warn << event
            << "[NetworkDock] 删除ARP失败：选中行解析失败, ip="
            << kIpText.toStdString()
            << ", index="
            << kIndexText.toStdString()
            << eol;
        return;
    }

    MIB_IPNETROW deleteRow{};
    deleteRow.dwAddr = htonl(ipHostOrder);
    deleteRow.dwIndex = kInterfaceIndex;
    const DWORD kDeleteResult = DeleteIpNetEntry(&deleteRow);
    if (kDeleteResult != NO_ERROR)
    {
        // privilegePromptHandled: Only retain error logs when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除 ARP 项"), kDeleteResult);
        KLogEvent event;
        err << event
            << "[NetworkDock] 删除ARP失败, ip="
            << kIpText.toStdString()
            << ", errorCode="
            << kDeleteResult
            << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("删除ARP"),
                QString("DeleteIpNetEntry 失败，错误码=%1").arg(kDeleteResult));
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[NetworkDock] 删除ARP成功, ip="
        << kIpText.toStdString()
        << ", interfaceIndex="
        << kInterfaceIndex
        << eol;
    refreshArpCacheTable();
}

void NetworkDock::flushArpCache()
{
    if (arpTable_ == nullptr)
    {
        return;
    }

    KLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 开始清空ARP缓存。"
        << eol;

    std::unordered_set<DWORD> interfaceIndexSet;
    for (int row = 0; row < arpTable_->rowCount(); ++row)
    {
        bool indexOk = false;
        const DWORD kInterfaceIndex = static_cast<DWORD>(
            arpTable_->item(row, 3)->text().toUInt(&indexOk));
        if (indexOk)
        {
            interfaceIndexSet.insert(kInterfaceIndex);
        }
    }

    for (DWORD interfaceIndex : interfaceIndexSet)
    {
        FlushIpNetTable(interfaceIndex);
    }

    KLogEvent event;
    info << event
        << "[NetworkDock] 清空ARP缓存完成, interfaceCount="
        << interfaceIndexSet.size()
        << eol;
    refreshArpCacheTable();
}

void NetworkDock::refreshDnsCacheTable()
{
    if (dnsTable_ == nullptr)
    {
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[NetworkDock] 开始刷新DNS缓存表。"
            << eol;
    }

    using DnsGetCacheDataTableFn = BOOL(WINAPI*)(PVOID);
    struct DnsCacheEntryRecord
    {
        DnsCacheEntryRecord* next = nullptr;
        PWSTR name = nullptr;
        WORD type = 0;
        WORD dataLength = 0;
        DWORD flags = 0;
    };

    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        dnsStatusLabel_->setText(QStringLiteral("状态：dnsapi.dll 不可用"));
        KLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：dnsapi.dll不可用。"
            << eol;
        return;
    }

    auto dnsGetCacheDataTable = reinterpret_cast<DnsGetCacheDataTableFn>(
        GetProcAddress(dnsapiModule, "DnsGetCacheDataTable"));
    if (dnsGetCacheDataTable == nullptr)
    {
        dnsStatusLabel_->setText(QStringLiteral("状态：DnsGetCacheDataTable 不可用"));
        KLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：DnsGetCacheDataTable不可用。"
            << eol;
        return;
    }

    DnsCacheEntryRecord rootEntry{};
    const BOOL kQueryOk = dnsGetCacheDataTable(&rootEntry);
    if (kQueryOk == FALSE)
    {
        dnsStatusLabel_->setText(QStringLiteral("状态：读取DNS缓存失败"));
        KLogEvent event;
        err << event
            << "[NetworkDock] DNS缓存刷新失败：读取缓存表失败。"
            << eol;
        return;
    }

    dnsTable_->setRowCount(0);
    int count = 0;
    for (DnsCacheEntryRecord* node = rootEntry.next; node != nullptr; node = node->next)
    {
        const int kRow = dnsTable_->rowCount();
        dnsTable_->insertRow(kRow);
        const QString kNameText = node->name != nullptr ? QString::fromWCharArray(node->name) : QStringLiteral("<null>");
        dnsTable_->setItem(kRow, 0, new QTableWidgetItem(kNameText));
        dnsTable_->setItem(kRow, 1, new QTableWidgetItem(QString::number(node->type)));
        dnsTable_->setItem(kRow, 2, new QTableWidgetItem(toQString(ks::network::formatDnsFlags(node->flags))));
        ++count;
    }

    dnsStatusLabel_->setText(QString("状态：DNS缓存项 %1").arg(count));

    KLogEvent event;
    info << event
        << "[NetworkDock] DNS缓存刷新完成, rowCount="
        << count
        << eol;
}

void NetworkDock::removeDnsCacheEntry()
{
    QStringList entryNameList;
    const QString kTypedEntryName = dnsEntryEdit_ != nullptr ? dnsEntryEdit_->text().trimmed() : QString();
    if (dnsEntryEdit_ != nullptr && dnsEntryEdit_->hasFocus() && !kTypedEntryName.isEmpty())
    {
        entryNameList.push_back(kTypedEntryName);
    }
    if (entryNameList.isEmpty() && dnsTable_ != nullptr)
    {
        // Delete using the selected table set as priority:
        // - When deleting multiple items, the input box is typically synchronized by selectionChanged to the first row's domain name.
        // - If input boxes are still prioritized here, it degrades to only allowing deletion of a single entry.
        // - Exception: If the user focus is still within the input field, prioritize the manually entered single domain name.
        const QList<QTableWidgetItem*> kSelectedItems = dnsTable_->selectedItems();
        std::set<int> selectedRowSet;
        for (QTableWidgetItem* item : kSelectedItems)
        {
            if (item != nullptr)
            {
                selectedRowSet.insert(item->row());
            }
        }
        if (selectedRowSet.empty() && dnsTable_->currentRow() >= 0)
        {
            selectedRowSet.insert(dnsTable_->currentRow());
        }

        for (const int kRow : selectedRowSet)
        {
            QTableWidgetItem* hostItem = dnsTable_->item(kRow, 0);
            if (hostItem == nullptr)
            {
                continue;
            }

            const QString kRowEntryName = hostItem->text().trimmed();
            if (!kRowEntryName.isEmpty() && !entryNameList.contains(kRowEntryName, Qt::CaseInsensitive))
            {
                entryNameList.push_back(kRowEntryName);
            }
        }
    }
    if (entryNameList.isEmpty())
    {
        if (!kTypedEntryName.isEmpty())
        {
            entryNameList.push_back(kTypedEntryName);
        }
    }
    if (entryNameList.isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 删除DNS缓存取消：未指定域名。"
            << eol;
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[NetworkDock] 尝试删除DNS缓存项, count="
            << entryNameList.size()
            << eol;
    }

    using DnsFlushResolverCacheEntryFn = DNS_STATUS(WINAPI*)(PCWSTR);
    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        KLogEvent event;
        err << event
            << "[NetworkDock] 删除DNS缓存失败：dnsapi.dll不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("删除DNS缓存"), QStringLiteral("dnsapi.dll 不可用。"));
        return;
    }

    auto dnsFlushResolverCacheEntry = reinterpret_cast<DnsFlushResolverCacheEntryFn>(
        GetProcAddress(dnsapiModule, "DnsFlushResolverCacheEntry_W"));
    if (dnsFlushResolverCacheEntry == nullptr)
    {
        KLogEvent event;
        err << event
            << "[NetworkDock] 删除DNS缓存失败：按项删除API不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("删除DNS缓存"), QStringLiteral("当前系统不支持按项删除 DNS 缓存。"));
        return;
    }

    QStringList failedEntryList;
    for (const QString& entryName : entryNameList)
    {
        const DNS_STATUS kFlushStatus = dnsFlushResolverCacheEntry(reinterpret_cast<PCWSTR>(entryName.utf16()));
        if (kFlushStatus != 0)
        {
            failedEntryList.push_back(QStringLiteral("%1（错误码=%2）").arg(entryName).arg(kFlushStatus));
        }
    }

    KLogEvent event;
    if (!failedEntryList.isEmpty())
    {
        warn << event
            << "[NetworkDock] 删除DNS缓存部分失败, requestCount="
            << entryNameList.size()
            << ", failedCount="
            << failedEntryList.size()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("删除DNS缓存"),
            QStringLiteral("部分 DNS 缓存删除失败：\n%1").arg(failedEntryList.join(QStringLiteral("\n"))));
    }
    else
    {
        info << event
            << "[NetworkDock] 删除DNS缓存成功, count="
            << entryNameList.size()
            << eol;
    }
    refreshDnsCacheTable();
}

void NetworkDock::flushDnsCache()
{
    KLogEvent startEvent;
    info << startEvent
        << "[NetworkDock] 尝试清空DNS缓存。"
        << eol;

    using DnsFlushResolverCacheFn = BOOL(WINAPI*)();
    HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
    if (dnsapiModule == nullptr)
    {
        dnsapiModule = LoadLibraryW(L"dnsapi.dll");
    }
    if (dnsapiModule == nullptr)
    {
        KLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败：dnsapi.dll不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QStringLiteral("dnsapi.dll 不可用。"));
        return;
    }

    auto dnsFlushResolverCache = reinterpret_cast<DnsFlushResolverCacheFn>(
        GetProcAddress(dnsapiModule, "DnsFlushResolverCache"));
    if (dnsFlushResolverCache == nullptr)
    {
        KLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败：API不可用。"
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QStringLiteral("当前系统不支持清空 DNS 缓存 API。"));
        return;
    }

    // DnsFlushResolverCache returns BOOL: non-0 indicates success, 0 indicates failure.
    // Legacy code treated the return value as DNS_STATUS, causing the 'flush failed' branch to be taken on success, making the button appear unresponsive.
    const BOOL kFlushOk = dnsFlushResolverCache();
    if (kFlushOk == FALSE)
    {
        const DWORD kLastError = GetLastError();
        KLogEvent event;
        err << event
            << "[NetworkDock] 清空DNS缓存失败, errorCode="
            << kLastError
            << eol;
        QMessageBox::warning(this, QStringLiteral("清空DNS缓存"), QString("清空失败，错误码=%1").arg(kLastError));
        return;
    }

    KLogEvent event;
    info << event
        << "[NetworkDock] 清空DNS缓存成功。"
        << eol;
    refreshDnsCacheTable();
}

void NetworkDock::startAliveHostScan()
{
    if (aliveScanRunning_.load())
    {
        KLogEvent event;
        dbg << event
            << "[NetworkDock] 忽略存活主机扫描启动：扫描已在进行中。"
            << eol;
        return;
    }

    std::uint32_t startIpHostOrder = 0;
    std::uint32_t endIpHostOrder = 0;
    if (!tryParseIpv4Text(aliveScanStartIpEdit_->text().trimmed(), startIpHostOrder) ||
        !tryParseIpv4Text(aliveScanEndIpEdit_->text().trimmed(), endIpHostOrder))
    {
        KLogEvent event;
        warn << event
            << "[NetworkDock] 启动存活主机扫描失败：IP地址格式非法, start="
            << aliveScanStartIpEdit_->text().trimmed().toStdString()
            << ", end="
            << aliveScanEndIpEdit_->text().trimmed().toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("存活主机扫描"), QStringLiteral("请输入正确的起止 IPv4 地址。"));
        return;
    }
    const ks::network::Ipv4ScanRange kScanRange =
        ks::network::normalizeIpv4ScanRange(startIpHostOrder, endIpHostOrder, 4096);
    startIpHostOrder = kScanRange.beginHostOrder;
    endIpHostOrder = kScanRange.endHostOrder;
    const std::uint64_t kHostCount = kScanRange.hostCount;
    if (!kScanRange.withinLimit)
    {
        KLogEvent event;
        warn << event
            << "[NetworkDock] 启动存活主机扫描失败：扫描范围过大, hostCount="
            << kHostCount
            << eol;
        QMessageBox::warning(this, QStringLiteral("存活主机扫描"), QStringLiteral("扫描范围过大，请控制在 4096 个主机以内。"));
        return;
    }

    aliveScanTable_->setRowCount(0);
    aliveScanProgressBar_->setValue(0);
    aliveScanStatusLabel_->setText(QString("状态：正在扫描 %1 个主机").arg(kHostCount));
    startAliveScanButton_->setEnabled(false);
    stopAliveScanButton_->setEnabled(true);

    if (aliveScanProgressPid_ == 0)
    {
        aliveScanProgressPid_ = kPro.addReusable(this, "网络", "存活主机扫描");
    }
    kPro.set(aliveScanProgressPid_, "开始ICMP探测", 0, 0.0f);

    aliveScanRunning_.store(true);
    aliveScanCancel_.store(false);
    const std::shared_ptr<AliveScanTaskState> kTaskState = aliveScanTaskState_;
    kTaskState->cancelRequested.store(false);
    {
        std::lock_guard<std::mutex> lock(kTaskState->mutex);
        ++kTaskState->activeTaskCount;
    }
    const int kTimeoutMs = aliveScanTimeoutSpin_->value();

    {
        KLogEvent event;
        info << event
            << "[NetworkDock] 开始存活主机扫描, startIp="
            << formatIpv4HostOrder(startIpHostOrder).toStdString()
            << ", endIp="
            << formatIpv4HostOrder(endIpHostOrder).toStdString()
            << ", hostCount="
            << kHostCount
            << ", timeoutMs="
            << kTimeoutMs
            << eol;
    }

    QPointer<NetworkDock> guardThis(this);
    auto* scanTask = QRunnable::create([guardThis, kTaskState, startIpHostOrder, endIpHostOrder, kTimeoutMs]()
        {
            const auto kFinishAliveScanTask = [kTaskState]()
            {
                std::lock_guard<std::mutex> lock(kTaskState->mutex);
                if (kTaskState->activeTaskCount > 0)
                {
                    --kTaskState->activeTaskCount;
                }
                if (kTaskState->activeTaskCount == 0)
                {
                    kTaskState->completion.notify_all();
                }
            };
            const std::uint64_t kTotalCount =
                static_cast<std::uint64_t>(endIpHostOrder) - startIpHostOrder + 1;
            std::atomic<std::uint64_t> nextIpHostOrder{ startIpHostOrder };
            std::atomic<std::uint64_t> finishedCount{ 0 };
            std::atomic<std::uint64_t> aliveCount{ 0 };
            std::atomic<std::uint32_t> icmpHandleFailCount{ 0 };

            unsigned int workerCount = std::thread::hardware_concurrency();
            if (workerCount == 0)
            {
                workerCount = 8;
            }
            workerCount = std::clamp(workerCount, 2u, 32u);

            std::vector<std::thread> workers;
            workers.reserve(workerCount);
            for (unsigned int workerIndex = 0; workerIndex < workerCount; ++workerIndex)
            {
                workers.emplace_back([guardThis,
                    kTaskState,
                    endIpHostOrder,
                    kTimeoutMs,
                    kTotalCount,
                    &nextIpHostOrder,
                    &finishedCount,
                    &aliveCount,
                    &icmpHandleFailCount]()
                    {
                        HANDLE icmpHandle = IcmpCreateFile();
                        if (icmpHandle == INVALID_HANDLE_VALUE)
                        {
                            ++icmpHandleFailCount;
                            return;
                        }

                        char sendData[] = "KSWORD";
                        while (true)
                        {
                            if (guardThis == nullptr || kTaskState->cancelRequested.load())
                            {
                                break;
                            }

                            const std::uint64_t kCurrentIpTicket = nextIpHostOrder.fetch_add(1);
                            if (kCurrentIpTicket > endIpHostOrder)
                            {
                                break;
                            }
                            const std::uint32_t kCurrentIpHostOrder = static_cast<std::uint32_t>(kCurrentIpTicket);

                            std::uint8_t replyBuffer[sizeof(ICMP_ECHO_REPLY) + 64] = {};
                            const DWORD kReplyCount = IcmpSendEcho(
                                icmpHandle,
                                htonl(kCurrentIpHostOrder),
                                sendData,
                                static_cast<WORD>(sizeof(sendData)),
                                nullptr,
                                replyBuffer,
                                static_cast<DWORD>(sizeof(replyBuffer)),
                                static_cast<DWORD>(kTimeoutMs));

                            bool alive = false;
                            std::uint32_t rttMs = 0;
                            QString detailText = QStringLiteral("Timeout");
                            if (kReplyCount > 0)
                            {
                                const auto* echoReply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer);
                                alive = (echoReply->Status == IP_SUCCESS);
                                rttMs = echoReply->RoundTripTime;
                                detailText = toQString(ks::network::formatIcmpEchoDetail(
                                    alive,
                                    echoReply->Status,
                                    echoReply->Options.Ttl));
                            }

                            const std::uint64_t kDoneCount = finishedCount.fetch_add(1) + 1;
                            const std::uint64_t kAliveNow = alive
                                ? (aliveCount.fetch_add(1) + 1)
                                : aliveCount.load();
                            const QString kIpText = toQString(ks::network::formatIpv4HostOrder(kCurrentIpHostOrder));
                            QMetaObject::invokeMethod(
                                guardThis,
                                [guardThis, kTaskState, kIpText, alive, rttMs, detailText, kDoneCount, kTotalCount, kAliveNow]()
                                {
                                    if (guardThis == nullptr || kTaskState->cancelRequested.load())
                                    {
                                        return;
                                    }
                                    // The result list displays only live hosts; down hosts are excluded.
                                    if (alive)
                                    {
                                        guardThis->appendAliveHostRow(kIpText, true, rttMs, detailText);
                                    }
                                    const int kProgressValue = ks::network::calculateIntegerProgressPercent(kDoneCount, kTotalCount);
                                    guardThis->aliveScanProgressBar_->setValue(kProgressValue);
                                    guardThis->aliveScanProgressBar_->setFormat(QString("%1%").arg(kProgressValue));
                                    guardThis->aliveScanStatusLabel_->setText(
                                        QString("状态：扫描中 %1/%2，存活 %3")
                                        .arg(kDoneCount)
                                        .arg(kTotalCount)
                                        .arg(kAliveNow));
                                    kPro.set(guardThis->aliveScanProgressPid_, "ICMP探测中", 0, static_cast<float>(kProgressValue));
                                },
                                Qt::QueuedConnection);
                        }

                        IcmpCloseHandle(icmpHandle);
                    });
            }

            for (std::thread& workerThread : workers)
            {
                if (workerThread.joinable())
                {
                    workerThread.join();
                }
            }

            const std::uint64_t kFinishedCountValue = finishedCount.load();
            const std::uint64_t kAliveCountValue = aliveCount.load();
            const std::uint32_t kIcmpHandleFailCountValue = icmpHandleFailCount.load();

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTaskState, kTotalCount, kFinishedCountValue, kAliveCountValue, kIcmpHandleFailCountValue, workerCount]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->aliveScanRunning_.store(false);
                    guardThis->startAliveScanButton_->setEnabled(true);
                    guardThis->stopAliveScanButton_->setEnabled(false);
                    const bool kCanceled = kTaskState->cancelRequested.load() || guardThis->aliveScanCancel_.load();
                    const int kProgressValue = ks::network::calculateIntegerProgressPercent(
                        kFinishedCountValue,
                        kTotalCount);
                    guardThis->aliveScanProgressBar_->setValue(kProgressValue);
                    guardThis->aliveScanProgressBar_->setFormat(QString("%1%").arg(kProgressValue));

                    QString statusText;
                    if (kIcmpHandleFailCountValue >= workerCount)
                    {
                        statusText = QStringLiteral("状态：ICMP句柄创建失败，扫描未执行");
                    }
                    else if (kCanceled)
                    {
                        statusText = QString("状态：已停止，已探测 %1/%2，存活 %3")
                            .arg(kFinishedCountValue)
                            .arg(kTotalCount)
                            .arg(kAliveCountValue);
                    }
                    else
                    {
                        statusText = QString("状态：扫描完成，存活 %1 台").arg(kAliveCountValue);
                    }
                    guardThis->aliveScanStatusLabel_->setText(statusText);
                    kPro.set(
                        guardThis->aliveScanProgressPid_,
                        kCanceled ? "ICMP扫描已停止" : "ICMP扫描完成",
                        0,
                        kCanceled ? static_cast<float>(kProgressValue) : 100.0f);

                    KLogEvent event;
                    info << event
                        << "[NetworkDock] 存活主机扫描结束, resultRowCount="
                        << guardThis->aliveScanTable_->rowCount()
                        << ", finished="
                        << kFinishedCountValue
                        << ", total="
                        << kTotalCount
                        << ", alive="
                        << kAliveCountValue
                        << ", icmpHandleFailCount="
                        << kIcmpHandleFailCountValue
                        << ", canceled="
                        << (kCanceled ? "true" : "false")
                        << eol;
                },
                Qt::QueuedConnection);
            kFinishAliveScanTask();
        });
    aliveScanThreadPool_.start(scanTask);
}

void NetworkDock::stopAliveHostScan()
{
    aliveScanCancel_.store(true);
    aliveScanTaskState_->cancelRequested.store(true);
    aliveScanStatusLabel_->setText(QStringLiteral("状态：正在停止扫描..."));

    KLogEvent event;
    info << event
        << "[NetworkDock] 用户请求停止存活主机扫描。"
        << eol;
}

void NetworkDock::cancelAndWaitForAliveHostScan()
{
    aliveScanCancel_.store(true);
    const std::shared_ptr<AliveScanTaskState> kTaskState = aliveScanTaskState_;
    kTaskState->cancelRequested.store(true);

    std::unique_lock<std::mutex> lock(kTaskState->mutex);
    kTaskState->completion.wait(lock, [kTaskState]()
    {
        return kTaskState->activeTaskCount == 0;
    });
}

void NetworkDock::appendAliveHostRow(
    const QString& ipText,
    const bool alive,
    const std::uint32_t rttMs,
    const QString& detailText)
{
    if (aliveScanTable_ == nullptr)
    {
        return;
    }
    if (!alive)
    {
        // The result table retains only Alive items; Down/Timeout entries are not written to the list.
        return;
    }

    const int kRow = aliveScanTable_->rowCount();
    aliveScanTable_->insertRow(kRow);
    aliveScanTable_->setItem(kRow, 0, new QTableWidgetItem(ipText));
    auto* stateItem = new QTableWidgetItem(QStringLiteral("Alive"));
    stateItem->setForeground(ksword_theme::successColor());
    stateItem->setTextAlignment(Qt::AlignCenter);
    aliveScanTable_->setItem(kRow, 1, stateItem);
    aliveScanTable_->setItem(kRow, 2, new QTableWidgetItem(QString::number(rttMs)));
    aliveScanTable_->setItem(kRow, 3, new QTableWidgetItem(detailText));
}
