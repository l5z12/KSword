#include "VirtualLocationPage.h"

#include "../../internationalization/LanguageManager.h"
#include "../../Theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QEvent>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QVBoxLayout>

#include <thread>
#include <utility>

namespace
{
    using ks::misc::virtual_location::CoordinateSystem;
    using ks::misc::virtual_location::GeoCoordinate;
    using ks::misc::virtual_location::RegistryBackend;

    // kLiveFixTimeoutMilliseconds：
    // System may need network lookup for initial location; set timeout to 12 seconds.
    constexpr unsigned long kLiveFixTimeoutMilliseconds = 12000UL;

    // backendText：
    // - Input backend: A channel through which a single registry access operation succeeds.
    // - Purpose: Inform the user whether the operation is performed by R3 or the driver.
    // - Returns: The channel description text.
    QString backendText(const RegistryBackend backend)
    {
        switch (backend) {
        case RegistryBackend::kWin32:
            return QStringLiteral("R3 直接写入");
        case RegistryBackend::kDriver:
            return QStringLiteral("R0 驱动写入");
        case RegistryBackend::kNone:
        default:
            break;
        }
        return QStringLiteral("无可用通道");
    }

    // formatCoordinate：
    // - Input coordinate: a set of coordinates.
    // - Purpose: Format as 'latitude, longitude' with fixed 6 decimal places, approximating meter-level precision.
    // - Returns: a single-line text.
    QString formatCoordinate(const GeoCoordinate& coordinate)
    {
        return QStringLiteral("%1, %2")
            .arg(coordinate.latitude, 0, 'f', 6)
            .arg(coordinate.longitude, 0, 'f', 6);
    }

    // showOpaqueMessage：
    // - Purpose: Display a non-transparent themed message box to avoid inheriting the semi-transparent background from the parent chain.
    // - Returns: Nothing.
    void showOpaqueMessage(
        QWidget* const parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksVirtualLocationMessageBox"));
        dialog.setStyleSheet(ksword_theme::opaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }

    // askConfirmation：
    // - Purpose: Require explicit confirmation for a system-wide toggle.
    // - Return: true indicates the user chose to continue.
    bool askConfirmation(
        QWidget* const parent,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksVirtualLocationConfirmBox"));
        dialog.setStyleSheet(ksword_theme::opaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(QMessageBox::Warning);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        dialog.setDefaultButton(QMessageBox::No);
        return dialog.exec() == QMessageBox::Yes;
    }
}

namespace ks::misc
{
    VirtualLocationPage::VirtualLocationPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        updateConversionPreview();
        updateButtons();
    }

    void VirtualLocationPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
    }

    void VirtualLocationPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyScopeBannerStyle();
        }
    }

    // applyScopeBannerStyle:
    // - Input: None. Reads semantic colors of the current theme.
    // - Handling: Apply effective scope banner style; follows the same path during construction and after theme switching.
    // - Return: None. Silently skip if the banner has not been created.
    void VirtualLocationPage::applyScopeBannerStyle()
    {
        if (scopeLabel_ == nullptr)
        {
            return;
        }
        scopeLabel_->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;}")
                .arg(ksword_theme::warningHex())
                .arg(ksword_theme::themeColorName(ksword_theme::warningBackgroundColor()))
                .arg(ksword_theme::textPrimaryHex()));
    }

    void VirtualLocationPage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // ===================== Scope Effectiveness Description =====================
        scopeLabel_ = new QLabel(this);
        scopeLabel_->setWordWrap(true);
        applyScopeBannerStyle();
        language.bindText(
            scopeLabel_,
            QStringLiteral("misc.virtual_location.scope"),
            QStringLiteral(
                "本页把坐标写成 Windows 的“系统默认位置”，只对通过 Windows 位置服务取位置的程序生效，"
                "而且要在系统拿不到更精确的定位源时才会被采用。浏览器网页定位、自带 IP 库或自建定位 SDK 的应用不受影响。"
                "修改只落在注册表上，随时可以用“清除虚拟定位”还原。"));
        rootLayout->addWidget(scopeLabel_);

        // ===================== Current Status =====================
        auto* statusGroup = new QGroupBox(this);
        language.bindText(
            statusGroup,
            QStringLiteral("misc.virtual_location.status.title"),
            QStringLiteral("当前状态"));
        auto* statusLayout = new QVBoxLayout(statusGroup);
        statusLayout->setSpacing(6);

        serviceLabel_ = new QLabel(statusGroup);
        serviceLabel_->setWordWrap(true);
        serviceLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusLayout->addWidget(serviceLabel_);

        policyLabel_ = new QLabel(statusGroup);
        policyLabel_->setWordWrap(true);
        policyLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        policyLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        statusLayout->addWidget(policyLabel_);

        currentLocationLabel_ = new QLabel(statusGroup);
        currentLocationLabel_->setWordWrap(true);
        currentLocationLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        currentLocationLabel_->setStyleSheet(
            QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
        statusLayout->addWidget(currentLocationLabel_);

        rawValueEdit_ = new QPlainTextEdit(statusGroup);
        rawValueEdit_->setObjectName(QStringLiteral("ksVirtualLocationRawView"));
        rawValueEdit_->setReadOnly(true);
        rawValueEdit_->setMaximumHeight(96);
        rawValueEdit_->setLineWrapMode(QPlainTextEdit::NoWrap);
        language.bindToolTip(
            rawValueEdit_,
            QStringLiteral("misc.virtual_location.raw.tooltip"),
            QStringLiteral("默认位置键下读到的原始值，方括号里标着这一条是 R3 还是 R0 读出来的。"));
        statusLayout->addWidget(rawValueEdit_);

        liveFixLabel_ = new QLabel(statusGroup);
        liveFixLabel_->setWordWrap(true);
        liveFixLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            liveFixLabel_,
            QStringLiteral("misc.virtual_location.livefix.idle"),
            QStringLiteral("实况定位：尚未读取。"));
        statusLayout->addWidget(liveFixLabel_);

        auto* statusButtonLayout = new QHBoxLayout();
        refreshButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QString(),
            statusGroup);
        liveFixButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
            QString(),
            statusGroup);
        language.bindText(
            refreshButton_,
            QStringLiteral("misc.virtual_location.refresh"),
            QStringLiteral("刷新状态"));
        language.bindText(
            liveFixButton_,
            QStringLiteral("misc.virtual_location.livefix.query"),
            QStringLiteral("读取实况定位"));
        language.bindToolTip(
            liveFixButton_,
            QStringLiteral("misc.virtual_location.livefix.tooltip"),
            QStringLiteral(
                "向 Windows 位置服务要一次坐标。返回来源显示“默认位置”，就说明虚拟定位已经被采纳。"));
        statusButtonLayout->addWidget(refreshButton_);
        statusButtonLayout->addWidget(liveFixButton_);
        statusButtonLayout->addStretch(1);
        statusLayout->addLayout(statusButtonLayout);
        rootLayout->addWidget(statusGroup);

        // ===================== Virtual Coordinates =====================
        auto* inputGroup = new QGroupBox(this);
        language.bindText(
            inputGroup,
            QStringLiteral("misc.virtual_location.input.title"),
            QStringLiteral("虚拟坐标"));
        auto* inputLayout = new QGridLayout(inputGroup);
        inputLayout->setHorizontalSpacing(10);
        inputLayout->setVerticalSpacing(8);

        auto* systemLabel = new QLabel(inputGroup);
        language.bindText(
            systemLabel,
            QStringLiteral("misc.virtual_location.input.system"),
            QStringLiteral("坐标系："));
        coordinateSystemCombo_ = new QComboBox(inputGroup);
        coordinateSystemCombo_->setObjectName(
            QStringLiteral("ksVirtualLocationSystemCombo"));
        coordinateSystemCombo_->addItem(QStringLiteral("WGS-84（GPS / Windows 原始坐标）"));
        coordinateSystemCombo_->addItem(QStringLiteral("GCJ-02（高德 / 腾讯地图坐标）"));
        coordinateSystemCombo_->addItem(QStringLiteral("BD-09（百度地图坐标）"));
        language.bindToolTip(
            coordinateSystemCombo_,
            QStringLiteral("misc.virtual_location.input.system.tooltip"),
            QStringLiteral(
                "从国内地图复制来的坐标多半是 GCJ-02 或 BD-09；选对坐标系后会自动换算成 WGS-84 再写入系统。"));
        inputLayout->addWidget(systemLabel, 0, 0);
        inputLayout->addWidget(coordinateSystemCombo_, 0, 1, 1, 3);

        auto* presetLabel = new QLabel(inputGroup);
        language.bindText(
            presetLabel,
            QStringLiteral("misc.virtual_location.input.preset"),
            QStringLiteral("预设点："));
        presetCombo_ = new QComboBox(inputGroup);
        presetCombo_->setObjectName(QStringLiteral("ksVirtualLocationPresetCombo"));
        presetCombo_->addItem(QStringLiteral("（不使用预设点）"));
        int presetCount = 0;
        const virtual_location::PresetLocation* const kPresets =
            virtual_location::presetLocations(&presetCount);
        for (int presetIndex = 0; presetIndex < presetCount; ++presetIndex) {
            presetCombo_->addItem(
                ks::i18n::text(
                    QString::fromLatin1(kPresets[presetIndex].nameKey),
                    QString::fromUtf8(kPresets[presetIndex].nameText)));
        }
        inputLayout->addWidget(presetLabel, 1, 0);
        inputLayout->addWidget(presetCombo_, 1, 1, 1, 3);

        auto* latitudeLabel = new QLabel(inputGroup);
        language.bindText(
            latitudeLabel,
            QStringLiteral("misc.virtual_location.input.latitude"),
            QStringLiteral("纬度："));
        latitudeSpin_ = new QDoubleSpinBox(inputGroup);
        latitudeSpin_->setObjectName(QStringLiteral("ksVirtualLocationLatitudeSpin"));
        latitudeSpin_->setDecimals(8);
        latitudeSpin_->setRange(-90.0, 90.0);
        latitudeSpin_->setSingleStep(0.0001);
        latitudeSpin_->setValue(39.909187);

        auto* longitudeLabel = new QLabel(inputGroup);
        language.bindText(
            longitudeLabel,
            QStringLiteral("misc.virtual_location.input.longitude"),
            QStringLiteral("经度："));
        longitudeSpin_ = new QDoubleSpinBox(inputGroup);
        longitudeSpin_->setObjectName(QStringLiteral("ksVirtualLocationLongitudeSpin"));
        longitudeSpin_->setDecimals(8);
        longitudeSpin_->setRange(-180.0, 180.0);
        longitudeSpin_->setSingleStep(0.0001);
        longitudeSpin_->setValue(116.397451);

        inputLayout->addWidget(latitudeLabel, 2, 0);
        inputLayout->addWidget(latitudeSpin_, 2, 1);
        inputLayout->addWidget(longitudeLabel, 2, 2);
        inputLayout->addWidget(longitudeSpin_, 2, 3);

        auto* altitudeLabel = new QLabel(inputGroup);
        language.bindText(
            altitudeLabel,
            QStringLiteral("misc.virtual_location.input.altitude"),
            QStringLiteral("海拔："));
        altitudeSpin_ = new QDoubleSpinBox(inputGroup);
        altitudeSpin_->setObjectName(QStringLiteral("ksVirtualLocationAltitudeSpin"));
        altitudeSpin_->setDecimals(2);
        altitudeSpin_->setRange(-1000.0, 100000.0);
        altitudeSpin_->setValue(44.0);
        // LanguageManager::bindSuffix only accepts QSpinBox. Since both are QDoubleSpinBox, fetch
        // the string once and set it directly. Unit switching will follow the next page rebuild.
        altitudeSpin_->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        auto* accuracyLabel = new QLabel(inputGroup);
        language.bindText(
            accuracyLabel,
            QStringLiteral("misc.virtual_location.input.accuracy"),
            QStringLiteral("误差半径："));
        accuracySpin_ = new QDoubleSpinBox(inputGroup);
        accuracySpin_->setObjectName(QStringLiteral("ksVirtualLocationAccuracySpin"));
        accuracySpin_->setDecimals(1);
        accuracySpin_->setRange(0.0, 100000.0);
        accuracySpin_->setValue(50.0);
        accuracySpin_->setSuffix(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.input.meter.suffix"),
                QStringLiteral(" 米")));

        inputLayout->addWidget(altitudeLabel, 3, 0);
        inputLayout->addWidget(altitudeSpin_, 3, 1);
        inputLayout->addWidget(accuracyLabel, 3, 2);
        inputLayout->addWidget(accuracySpin_, 3, 3);

        conversionLabel_ = new QLabel(inputGroup);
        conversionLabel_->setWordWrap(true);
        conversionLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        conversionLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        inputLayout->addWidget(conversionLabel_, 4, 0, 1, 4);

        inputLayout->setColumnStretch(1, 1);
        inputLayout->setColumnStretch(3, 1);
        rootLayout->addWidget(inputGroup);

        // ===================== Operations =====================
        auto* actionGroup = new QGroupBox(this);
        language.bindText(
            actionGroup,
            QStringLiteral("misc.virtual_location.action.title"),
            QStringLiteral("操作"));
        auto* actionLayout = new QVBoxLayout(actionGroup);
        actionLayout->setSpacing(8);

        forceProviderCheck_ = new QCheckBox(actionGroup);
        language.bindText(
            forceProviderCheck_,
            QStringLiteral("misc.virtual_location.action.force_provider"),
            QStringLiteral("同时禁用 Windows 位置提供程序，强制定位回落到默认位置（影响全系统）"));
        language.bindToolTip(
            forceProviderCheck_,
            QStringLiteral("misc.virtual_location.action.force_provider.tooltip"),
            QStringLiteral(
                "写入组策略 DisableWindowsLocationProvider=1，关掉 Windows 自带的网络定位。"
                "关掉之后依赖真实定位的程序（地图、天气、查找我的设备）都会失去精确位置，取消勾选即可还原。"));
        actionLayout->addWidget(forceProviderCheck_);

        auto* buttonLayout = new QHBoxLayout();
        applyButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
            QString(),
            actionGroup);
        clearButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
            QString(),
            actionGroup);
        useLiveFixButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QString(),
            actionGroup);
        restartServiceButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QString(),
            actionGroup);
        language.bindText(
            applyButton_,
            QStringLiteral("misc.virtual_location.action.apply"),
            QStringLiteral("应用虚拟定位"));
        language.bindText(
            clearButton_,
            QStringLiteral("misc.virtual_location.action.clear"),
            QStringLiteral("清除虚拟定位"));
        language.bindText(
            useLiveFixButton_,
            QStringLiteral("misc.virtual_location.action.use_livefix"),
            QStringLiteral("用实况定位填入"));
        language.bindText(
            restartServiceButton_,
            QStringLiteral("misc.virtual_location.action.restart_service"),
            QStringLiteral("重启位置服务"));
        language.bindToolTip(
            restartServiceButton_,
            QStringLiteral("misc.virtual_location.action.restart_service.tooltip"),
            QStringLiteral(
                "停止 lfsvc 让它丢掉进程内缓存。服务是按需触发启动的，下一次有程序请求定位会自动拉起。"));
        for (QPushButton* const kButton :
             { refreshButton_, liveFixButton_, applyButton_, clearButton_,
               useLiveFixButton_, restartServiceButton_ }) {
            kButton->setStyleSheet(ksword_theme::themedButtonStyle());
        }
        buttonLayout->addWidget(applyButton_);
        buttonLayout->addWidget(clearButton_);
        buttonLayout->addWidget(useLiveFixButton_);
        buttonLayout->addWidget(restartServiceButton_);
        buttonLayout->addStretch(1);
        actionLayout->addLayout(buttonLayout);

        resultLabel_ = new QLabel(actionGroup);
        resultLabel_->setWordWrap(true);
        resultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            resultLabel_,
            QStringLiteral("misc.virtual_location.action.idle"),
            QStringLiteral("尚未执行任何操作。"));
        actionLayout->addWidget(resultLabel_);
        rootLayout->addWidget(actionGroup);

        rootLayout->addStretch(1);
    }

    void VirtualLocationPage::initializeConnections()
    {
        connect(
            refreshButton_,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            liveFixButton_,
            &QPushButton::clicked,
            this,
            [this]() { requestLiveFix(false); });
        connect(
            useLiveFixButton_,
            &QPushButton::clicked,
            this,
            [this]() { requestLiveFix(true); });
        connect(
            applyButton_,
            &QPushButton::clicked,
            this,
            [this]() { applyVirtualLocation(); });
        connect(
            clearButton_,
            &QPushButton::clicked,
            this,
            [this]() { clearVirtualLocation(); });
        connect(
            restartServiceButton_,
            &QPushButton::clicked,
            this,
            [this]() { restartLocationService(); });
        connect(
            forceProviderCheck_,
            &QCheckBox::toggled,
            this,
            [this](const bool checked) { toggleProviderPolicy(checked); });
        connect(
            presetCombo_,
            &QComboBox::currentIndexChanged,
            this,
            [this](const int index) { applyPreset(index - 1); });

        // When switching coordinate systems, keep the 'same location' by converting the current input to the new coordinate system and filling it back.
        connect(
            coordinateSystemCombo_,
            &QComboBox::currentIndexChanged,
            this,
            [this](const int index) {
                if (updatingInputs_) {
                    return;
                }
                static const CoordinateSystem kSystems[] = {
                    CoordinateSystem::kWgs84,
                    CoordinateSystem::kGcj02,
                    CoordinateSystem::kBd09,
                };
                const int kPreviousIndex = lastCoordinateSystemIndex_;
                lastCoordinateSystemIndex_ = index;
                if (kPreviousIndex < 0 || kPreviousIndex > 2 || index < 0 || index > 2) {
                    updateConversionPreview();
                    return;
                }
                GeoCoordinate previous;
                previous.latitude = latitudeSpin_->value();
                previous.longitude = longitudeSpin_->value();
                previous.altitude = altitudeSpin_->value();
                previous.errorRadiusMeters = accuracySpin_->value();
                setInputCoordinate(
                    virtual_location::convertCoordinate(
                        previous, kSystems[kPreviousIndex], kSystems[index]));
                updateConversionPreview();
            });

        for (QDoubleSpinBox* const kSpinBox :
             { latitudeSpin_, longitudeSpin_, altitudeSpin_, accuracySpin_ }) {
            connect(
                kSpinBox,
                &QDoubleSpinBox::valueChanged,
                this,
                [this](double) {
                    if (updatingInputs_) {
                        return;
                    }
                    updateConversionPreview();
                });
        }
    }

    void VirtualLocationPage::refreshStatus()
    {
        if (busy_) {
            return;
        }
        setBusy(true);

        const virtual_location::ServiceSnapshot kServiceSnapshot =
            virtual_location::readServiceSnapshot();
        const virtual_location::DefaultLocationSnapshot kLocationSnapshot =
            virtual_location::readDefaultLocation();

        serviceLabel_->setText(
            QStringLiteral("位置服务：%1；系统位置开关：%2；桌面应用位置：%3")
                .arg(kServiceSnapshot.serviceStateText)
                .arg(
                    kServiceSnapshot.consentReadable
                        ? (kServiceSnapshot.locationAllowed
                               ? QStringLiteral("已允许")
                               : QStringLiteral("已拒绝"))
                        : QStringLiteral("读取失败"))
                .arg(
                    kServiceSnapshot.desktopAppAllowed
                        ? QStringLiteral("已允许")
                        : QStringLiteral("已拒绝")));

        providerDisabled_ = kServiceSnapshot.providerDisabledByPolicy;
        policyLabel_->setText(
            QStringLiteral("组策略：%1%2")
                .arg(kServiceSnapshot.policyDetailText)
                .arg(
                    kServiceSnapshot.locationDisabledByPolicy
                        ? QStringLiteral("（定位已被策略整体关闭，虚拟坐标同样读不到）")
                        : QString()));
        {
            const QSignalBlocker kBlocker(forceProviderCheck_);
            forceProviderCheck_->setChecked(providerDisabled_);
        }

        defaultLocationPresent_ = kLocationSnapshot.present;
        if (!kLocationSnapshot.readable) {
            currentLocationLabel_->setText(
                QStringLiteral("默认位置：读取失败。%1").arg(kLocationSnapshot.failureText));
            currentLocationLabel_->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(ksword_theme::errorHex()));
        }
        else if (!kLocationSnapshot.present) {
            currentLocationLabel_->setText(QStringLiteral("默认位置：未设置。"));
            currentLocationLabel_->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(ksword_theme::textSecondaryHex()));
        }
        else {
            const GeoCoordinate kGcj = virtual_location::convertCoordinate(
                kLocationSnapshot.coordinate,
                CoordinateSystem::kWgs84,
                CoordinateSystem::kGcj02);
            currentLocationLabel_->setText(
                QStringLiteral("默认位置：WGS-84 %1；GCJ-02 %2；海拔 %3 米；误差 %4 米")
                    .arg(formatCoordinate(kLocationSnapshot.coordinate))
                    .arg(formatCoordinate(kGcj))
                    .arg(kLocationSnapshot.coordinate.altitude, 0, 'f', 1)
                    .arg(kLocationSnapshot.coordinate.errorRadiusMeters, 0, 'f', 1));
            currentLocationLabel_->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:650;color:%1;")
                    .arg(ksword_theme::successHex()));
        }

        rawValueEdit_->setPlainText(
            kLocationSnapshot.rawValueLines.isEmpty()
                ? QStringLiteral("%1\n（该键下没有默认位置相关的值）")
                      .arg(virtual_location::defaultLocationKeyPath())
                : QStringLiteral("%1\n%2")
                      .arg(virtual_location::defaultLocationKeyPath())
                      .arg(kLocationSnapshot.rawValueLines.join(QStringLiteral("\n"))));

        setBusy(false);
    }

    void VirtualLocationPage::applyVirtualLocation()
    {
        if (busy_) {
            return;
        }

        // The value written to the registry must be WGS-84: Windows Location Service does not recognize domestic offset coordinate systems.
        const GeoCoordinate kWgsCoordinate = virtual_location::convertCoordinate(
            inputCoordinate(), currentCoordinateSystem(), CoordinateSystem::kWgs84);

        setBusy(true);
        const virtual_location::OperationResult kWriteResult =
            virtual_location::applyDefaultLocation(kWgsCoordinate);
        setBusy(false);

        if (!kWriteResult.ok) {
            setResultText(
                QStringLiteral("应用失败：%1").arg(kWriteResult.detailText),
                true);
            KLogEvent applyEvent;
            err << applyEvent << "[VirtualLocationPage] 写入系统默认位置失败。" << eol;
            refreshStatus();
            return;
        }

        // Immediately re-read: if the registry value type or path deviates from expectations, this will expose it immediately.
        const virtual_location::DefaultLocationSnapshot kVerifySnapshot =
            virtual_location::readDefaultLocation();
        const bool kVerified = kVerifySnapshot.present &&
            qAbs(kVerifySnapshot.coordinate.latitude - kWgsCoordinate.latitude) < 1e-5 &&
            qAbs(kVerifySnapshot.coordinate.longitude - kWgsCoordinate.longitude) < 1e-5;

        setResultText(
            kVerified
                ? QStringLiteral("已写入并回读校验通过：WGS-84 %1（%2）。要让已经在跑的程序拿到新位置，"
                                 "通常还需要重启位置服务或重启该程序。")
                      .arg(formatCoordinate(kWgsCoordinate))
                      .arg(backendText(kWriteResult.backend))
                : QStringLiteral("已写入（%1），但回读校验没通过，请检查下方原始值清单。")
                      .arg(backendText(kWriteResult.backend)),
            !kVerified);

        KLogEvent applyEvent;
        info << applyEvent << "[VirtualLocationPage] 系统默认位置已更新。" << eol;
        refreshStatus();
    }

    void VirtualLocationPage::clearVirtualLocation()
    {
        if (busy_) {
            return;
        }
        setBusy(true);
        const virtual_location::OperationResult kClearResult =
            virtual_location::clearDefaultLocation();
        setBusy(false);

        setResultText(
            kClearResult.ok
                ? QStringLiteral("已清除系统默认位置（%1）。").arg(backendText(kClearResult.backend))
                : QStringLiteral("清除失败：%1").arg(kClearResult.detailText),
            !kClearResult.ok);
        refreshStatus();
    }

    void VirtualLocationPage::toggleProviderPolicy(const bool disabled)
    {
        if (updatingInputs_) {
            return;
        }
        if (disabled == providerDisabled_) {
            return;
        }

        if (disabled &&
            !askConfirmation(
                this,
                ks::i18n::text(
                    QStringLiteral("misc.virtual_location.title"),
                    QStringLiteral("虚拟定位")),
                ks::i18n::text(
                    QStringLiteral("misc.virtual_location.action.force_provider.confirm"),
                    QStringLiteral(
                        "将写入组策略 DisableWindowsLocationProvider=1，关闭 Windows 自带的网络定位。\n\n"
                        "关闭后所有依赖真实定位的程序都只能拿到默认位置，部分系统功能（天气、地图、查找我的设备）"
                        "会失去精确位置。取消勾选即可还原。\n\n确定继续吗？")))) {
            const QSignalBlocker kBlocker(forceProviderCheck_);
            forceProviderCheck_->setChecked(false);
            return;
        }

        setBusy(true);
        const virtual_location::OperationResult kPolicyResult =
            virtual_location::setLocationProviderDisabled(disabled);
        setBusy(false);

        if (!kPolicyResult.ok) {
            setResultText(
                QStringLiteral("组策略修改失败：%1").arg(kPolicyResult.detailText),
                true);
            const QSignalBlocker kBlocker(forceProviderCheck_);
            forceProviderCheck_->setChecked(providerDisabled_);
            return;
        }

        providerDisabled_ = disabled;
        setResultText(
            disabled
                ? QStringLiteral("已禁用 Windows 位置提供程序（%1）。策略要在位置服务下次启动后才完全生效。")
                      .arg(backendText(kPolicyResult.backend))
                : QStringLiteral("已恢复 Windows 位置提供程序（%1）。")
                      .arg(backendText(kPolicyResult.backend)),
            false);
        refreshStatus();
    }

    void VirtualLocationPage::restartLocationService()
    {
        if (busy_) {
            return;
        }
        setBusy(true);
        const virtual_location::OperationResult kRestartResult =
            virtual_location::restartLocationService();
        setBusy(false);

        setResultText(
            kRestartResult.ok
                ? QStringLiteral("位置服务已停止，下一次有程序请求定位时会自动重新启动并读取新的默认位置。")
                : QStringLiteral("重启位置服务失败：%1").arg(kRestartResult.detailText),
            !kRestartResult.ok);
        refreshStatus();
    }

    void VirtualLocationPage::requestLiveFix(const bool fillInputs)
    {
        if (liveFixRunning_) {
            return;
        }
        liveFixRunning_ = true;
        updateButtons();
        liveFixLabel_->setText(
            ks::i18n::text(
                QStringLiteral("misc.virtual_location.livefix.running"),
                QStringLiteral("实况定位：正在向 Windows 位置服务请求坐标…")));

        const QPointer<VirtualLocationPage> kGuardThis(this);
        std::thread([kGuardThis, fillInputs]() {
            const virtual_location::LiveFixResult kFixResult =
                virtual_location::queryLiveFix(kLiveFixTimeoutMilliseconds);
            if (kGuardThis == nullptr) {
                return;
            }
            QMetaObject::invokeMethod(
                qApp,
                [kGuardThis, fillInputs, kFixResult]() {
                    if (kGuardThis == nullptr) {
                        return;
                    }
                    kGuardThis->applyLiveFixResult(kFixResult, fillInputs);
                });
        }).detach();
    }

    void VirtualLocationPage::applyLiveFixResult(
        const virtual_location::LiveFixResult& fixResult,
        const bool fillInputs)
    {
        liveFixRunning_ = false;

        if (!fixResult.ok) {
            liveFixLabel_->setText(
                QStringLiteral("实况定位：读取失败。%1").arg(fixResult.failureText));
            liveFixLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::errorHex()));
            updateButtons();
            return;
        }

        liveFixLabel_->setText(
            QStringLiteral("实况定位：WGS-84 %1；海拔 %2 米；误差 %3 米；来源 %4")
                .arg(formatCoordinate(fixResult.coordinate))
                .arg(fixResult.coordinate.altitude, 0, 'f', 1)
                .arg(fixResult.coordinate.errorRadiusMeters, 0, 'f', 1)
                .arg(fixResult.sourceText));
        liveFixLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::successHex()));

        if (fillInputs) {
            // Live readings are in WGS-84; convert to the current input coordinate system first, then write back to avoid showing users offset values.
            setInputCoordinate(
                virtual_location::convertCoordinate(
                    fixResult.coordinate,
                    CoordinateSystem::kWgs84,
                    currentCoordinateSystem()));
            updateConversionPreview();
        }
        updateButtons();
    }

    void VirtualLocationPage::applyPreset(const int presetIndex)
    {
        if (presetIndex < 0) {
            return;
        }
        int presetCount = 0;
        const virtual_location::PresetLocation* const kPresets =
            virtual_location::presetLocations(&presetCount);
        if (presetIndex >= presetCount) {
            return;
        }

        GeoCoordinate wgsCoordinate;
        wgsCoordinate.latitude = kPresets[presetIndex].latitude;
        wgsCoordinate.longitude = kPresets[presetIndex].longitude;
        wgsCoordinate.altitude = kPresets[presetIndex].altitude;
        wgsCoordinate.errorRadiusMeters = accuracySpin_->value();
        setInputCoordinate(
            virtual_location::convertCoordinate(
                wgsCoordinate, CoordinateSystem::kWgs84, currentCoordinateSystem()));
        updateConversionPreview();
    }

    void VirtualLocationPage::updateConversionPreview()
    {
        const GeoCoordinate kCurrent = inputCoordinate();
        const CoordinateSystem kSystem = currentCoordinateSystem();
        const GeoCoordinate kWgs =
            virtual_location::convertCoordinate(kCurrent, kSystem, CoordinateSystem::kWgs84);
        const GeoCoordinate kGcj =
            virtual_location::convertCoordinate(kCurrent, kSystem, CoordinateSystem::kGcj02);
        const GeoCoordinate kBd =
            virtual_location::convertCoordinate(kCurrent, kSystem, CoordinateSystem::kBd09);
        conversionLabel_->setText(
            QStringLiteral("换算预览：WGS-84 %1｜GCJ-02 %2｜BD-09 %3（写入系统的是 WGS-84）")
                .arg(formatCoordinate(kWgs))
                .arg(formatCoordinate(kGcj))
                .arg(formatCoordinate(kBd)));
    }

    virtual_location::CoordinateSystem VirtualLocationPage::currentCoordinateSystem() const
    {
        switch (coordinateSystemCombo_->currentIndex()) {
        case 1:
            return CoordinateSystem::kGcj02;
        case 2:
            return CoordinateSystem::kBd09;
        case 0:
        default:
            break;
        }
        return CoordinateSystem::kWgs84;
    }

    virtual_location::GeoCoordinate VirtualLocationPage::inputCoordinate() const
    {
        GeoCoordinate coordinate;
        coordinate.latitude = latitudeSpin_->value();
        coordinate.longitude = longitudeSpin_->value();
        coordinate.altitude = altitudeSpin_->value();
        coordinate.errorRadiusMeters = accuracySpin_->value();
        coordinate.altitudeAccuracyMeters = accuracySpin_->value();
        return coordinate;
    }

    void VirtualLocationPage::setInputCoordinate(const GeoCoordinate& coordinate)
    {
        updatingInputs_ = true;
        latitudeSpin_->setValue(coordinate.latitude);
        longitudeSpin_->setValue(coordinate.longitude);
        altitudeSpin_->setValue(coordinate.altitude);
        if (coordinate.errorRadiusMeters > 0.0) {
            accuracySpin_->setValue(coordinate.errorRadiusMeters);
        }
        updatingInputs_ = false;
    }

    void VirtualLocationPage::setResultText(const QString& text, const bool isError)
    {
        resultLabel_->setText(text);
        resultLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(isError ? ksword_theme::errorHex() : ksword_theme::successHex()));
    }

    void VirtualLocationPage::setBusy(const bool busy)
    {
        busy_ = busy;
        updateButtons();
    }

    void VirtualLocationPage::updateButtons()
    {
        const bool kIdle = !busy_ && !liveFixRunning_;
        refreshButton_->setEnabled(kIdle);
        applyButton_->setEnabled(kIdle);
        clearButton_->setEnabled(kIdle && defaultLocationPresent_);
        liveFixButton_->setEnabled(kIdle);
        useLiveFixButton_->setEnabled(kIdle);
        restartServiceButton_->setEnabled(kIdle);
        forceProviderCheck_->setEnabled(kIdle);
    }
}
