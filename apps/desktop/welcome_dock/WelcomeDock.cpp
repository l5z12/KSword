#include "WelcomeDock.h"

#include "../hardware_dock/HardwareDock.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/PerformanceNavCard.h"
#include "../ui/styles/UiStyleSheet.h"
#include "../Theme.h"

#include <QColor>
#include <QDateTime>
#include <QDesktopServices>
#include <QEvent>
#include <QFrame>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHideEvent>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QStorageInfo>
#include <QSysInfo>
#include <QTimer>
#include <QToolButton>
#include <QThread>
#include <QUrl>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>

namespace
{
    struct ContributorLink
    {
        QString displayName;
        QString targetUrl;
    };

    // contributorEntries purpose: Centralizes the list of developers and contributors at the beginning of the source file to avoid scattering the list throughout layout code.
    // Each person can register up to two links; if a link is empty, the data bit is retained but the corresponding button is not displayed.
    struct ContributorEntry
    {
        QString displayName;
        QString description;
        QString avatarResourcePath;
        ContributorLink firstLink;
        ContributorLink secondLink;
    };

    const std::array<ContributorEntry, 2> kContributorEntries = {{
        {QStringLiteral("WangWei_CM."), QStringLiteral("一个臭写C++的"),
         QStringLiteral(":/Image/Resource/Logo/WangWei_CM..jpg"),
         {QStringLiteral("网站 ->"), QString()}, {QStringLiteral("Bilibili ->"), QString("https://space.bilibili.com/1627165457?spm_id_from=333.337.0.0")}},
        {QStringLiteral("OB_BUFF"), QString(),
         QStringLiteral(":/Image/Resource/Logo/OB_BUFF.png"),
         {QStringLiteral("网站 ->"), QString()}, {QStringLiteral("Bilibili ->"), QString("https://b23.tv/IBNf1DA")}},
    }};

    // donorNames purpose: Centralize the public acknowledgment list; adding new donors later requires modifying only this location.
    const std::array<QString, 11> kDonorNames = {{
        QStringLiteral("长空落日"), QStringLiteral("Extrella_Explorer"),
        QStringLiteral("Txt Text"), QStringLiteral("Mapleleaf"),
        QStringLiteral("存钱买油条（云舟API）"), QStringLiteral("Solicom"),
        QStringLiteral("東雪蓮可爱捏"), QStringLiteral("JIAN2486"),
        QStringLiteral("NtKrnl64"), QStringLiteral("一花一树叶"), QStringLiteral("hzh")
    }};

    const QString kReleaseVersionText = QStringLiteral("5.1.4.3-Pre"); // RELEASE_META_VERSION_MARKER
    const QString kReleaseBuildTimeText = QStringLiteral("2026-08-17 22:41:10.119 +08:00"); // RELEASE_META_BUILD_TIME_MARKER
    const QString kQQGroupInviteUrl = QStringLiteral("https://qm.qq.com/q/5tWNPfIxkk");
    const QString kPplControlRepositoryUrl = QStringLiteral("https://github.com/itm4n/PPLcontrol");
    const QString kSystemInformerRepositoryUrl = QStringLiteral("https://github.com/winsiderss/systeminformer");
    const QString kSkt64RepositoryUrl = QStringLiteral("https://github.com/PspExitThread/SKT64");

    QString welcomeLogoResourcePath()
    {
        const QString kLanguageId = ks::i18n::LanguageManager::instance().currentLanguageId();
        return kLanguageId.startsWith(QStringLiteral("zh"), Qt::CaseInsensitive)
            ? QStringLiteral(":/Image/Resource/Logo/KswordHome-ZH.png")
            : QStringLiteral(":/Image/Resource/Logo/KswordHome-En.png");
    }

    QString formatRate(const double bytesPerSec)
    {
        const double kValue = std::max(0.0, bytesPerSec);
        if (kValue >= 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 GB/s").arg(kValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
        }
        if (kValue >= 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(kValue / (1024.0 * 1024.0), 0, 'f', 1);
        }
        if (kValue >= 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(kValue / 1024.0, 0, 'f', 1);
        }
        return QStringLiteral("%1 B/s").arg(kValue, 0, 'f', 0);
    }

    QString formatGiB(const quint64 bytes)
    {
        return QStringLiteral("%1 GB").arg(
            static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }

    QStringList overviewSectionValues(const QString& overviewText, const QString& sectionName)
    {
        QStringList values;
        const QStringList kLines = overviewText.split(QChar('\n'));
        const QString kSectionMarker = QStringLiteral("[%1]").arg(sectionName);
        bool inSection = false;
        for (const QString& rawLine : kLines)
        {
            // PowerShell Format-Table uses tabs and consecutive spaces as column separators. The welcome page is not
            // a table; retaining these spaces would stretch a single hardware name into misaligned 'fake columns'.
            const QString kLine = rawLine.simplified();
            if (kLine == kSectionMarker)
            {
                inSection = true;
                continue;
            }
            if (inSection && kLine.startsWith(QChar('[')))
            {
                break;
            }
            if (!inSection || kLine.isEmpty() || kLine.startsWith(QChar('<')))
            {
                continue;
            }
            // The field names and separators in Format-Table output are not hardware values; the BIOS/Motherboard/GPU
            // shown in the screenshot appeared as Manufacturer/Name headers because the old logic retrieved this line.
            if (kLine.startsWith(QStringLiteral("---")) ||
                kLine.contains(QStringLiteral("Manufacturer"), Qt::CaseInsensitive) ||
                kLine.contains(QStringLiteral("SMBIOSBIOSVersion"), Qt::CaseInsensitive) ||
                kLine.contains(QStringLiteral("AdapterRAM"), Qt::CaseInsensitive) ||
                kLine.contains(QStringLiteral("VideoProcessor"), Qt::CaseInsensitive) ||
                kLine.contains(QStringLiteral("DriverVersion"), Qt::CaseInsensitive) ||
                (sectionName == QStringLiteral("网卡设备(物理)") &&
                    kLine.startsWith(QStringLiteral("Name"), Qt::CaseInsensitive) &&
                    kLine.contains(QStringLiteral("AdapterType"), Qt::CaseInsensitive)))
            {
                continue;
            }
            values.push_back(kLine);
        }
        return values;
    }

    QString firstOverviewValue(const QString& overviewText, const QString& sectionName)
    {
        const QStringList kValues = overviewSectionValues(overviewText, sectionName);
        return kValues.isEmpty() ? QStringLiteral("N/A") : kValues.front();
    }

    QString secondOverviewValue(const QString& overviewText, const QString& sectionName)
    {
        const QStringList kValues = overviewSectionValues(overviewText, sectionName);
        return kValues.size() > 1 ? kValues.at(1) : QStringLiteral("N/A");
    }

    QString welcomeOutlineButtonStyle()
    {
        return QStringLiteral(
            "QPushButton{background:transparent;color:%1;border:1px solid #409EFF;"
            "border-radius:5px;padding:7px 12px;}"
            "QPushButton:hover{background:transparent;border-color:#64B5F6;}"
            "QPushButton:pressed{background:transparent;border-color:#1976D2;}")
            .arg(ksword_theme::textPrimaryHex());
    }

    class WelcomeRgbBorderButton final : public QPushButton
    {
    public:
        using QPushButton::QPushButton;

        void setBorderColor(const QColor& borderColor)
        {
            if (borderColor_ == borderColor)
            {
                return;
            }
            borderColor_ = borderColor;
            update();
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            QPushButton::paintEvent(event);
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(borderColor_, 3.0));
            painter.drawRoundedRect(
                QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5), 9.0, 9.0);
        }

    private:
        QColor borderColor_ = QColor::fromHsv(0, 255, 255);
    };
}

WelcomeDock::WelcomeDock(QWidget* parent)
    : QWidget(parent)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumSize(0, 0);

    const auto kWelcomeText = [](const char* key, const QString& sourceText) {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    };

    mLeftImage = new QLabel(this);
    mLeftImage->setAlignment(Qt::AlignCenter);
    mLeftImage->setMinimumSize(0, 0);
    mLeftImage->setMaximumSize(655, 250);
    mLeftImage->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    mLeftImage->setScaledContents(true);

    mLanguageSettingsBtn = new WelcomeRgbBorderButton(this);
    mLanguageSettingsBtn->setObjectName(QStringLiteral("welcomeLanguageSettingsButton"));
    mLanguageSettingsBtn->setMinimumSize(0, 48);
    mLanguageSettingsBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    mLanguageSettingsBtn->setCursor(Qt::PointingHandCursor);
    initializeLanguageButtonStyle();

    mLanguageButtonColorTimer = new QTimer(this);
    mLanguageButtonColorTimer->setInterval(80);
    connect(mLanguageButtonColorTimer, &QTimer::timeout, this, [this]() {
        mLanguageButtonHue = (mLanguageButtonHue + 4) % 360;
        updateLanguageButtonRgbBorder();
    });

    mCopyright = new QLabel(this);
    mCopyright->setWordWrap(true);
    mCopyright->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    mCopyright->setTextInteractionFlags(Qt::TextSelectableByMouse);

    mContributors = new QLabel(this);
    mReferenceTitle = new QLabel(this);
    mDonors = new QLabel(this);
    // Compatible with legacy public fields; actual display is handled by the collapsible scrollable area on the right to prevent unlayouted QLabel from overlaying the new interface.
    mContributors->setVisible(false);
    mReferenceTitle->setVisible(false);
    mDonors->setVisible(false);

    const QString kButtonStyle = welcomeOutlineButtonStyle();
    const auto kMakeButton = [this, &kButtonStyle](QPushButton** buttonOut) {
        QPushButton* button = new QPushButton(this);
        button->setStyleSheet(kButtonStyle);
        button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        button->setMinimumSize(0, 42);
        if (buttonOut != nullptr)
        {
            *buttonOut = button;
        }
        return button;
    };
    kMakeButton(&mGithubBtn);
    kMakeButton(&mQqBtn);
    kMakeButton(&mPplControlBtn);
    kMakeButton(&mSystemInformerBtn);
    kMakeButton(&mSkt64Btn);

    mBtnLayout = new QHBoxLayout();
    mBtnLayout->setContentsMargins(0, 0, 0, 0);
    mBtnLayout->setSpacing(8);
    mBtnLayout->addWidget(mQqBtn, 1);
    mBtnLayout->addWidget(mGithubBtn, 1);

    mReferenceLayout = new QHBoxLayout();
    mReferenceLayout->setContentsMargins(0, 0, 0, 0);
    mReferenceLayout->setSpacing(8);
    mReferenceLayout->addWidget(mPplControlBtn, 1);
    mReferenceLayout->addWidget(mSystemInformerBtn, 1);
    mReferenceLayout->addWidget(mSkt64Btn, 1);

    mLeftLayout = new QVBoxLayout();
    mLeftLayout->setContentsMargins(0, 0, 0, 0);
    mLeftLayout->addWidget(mLeftImage, 1);

    mMainLayout = new QHBoxLayout();
    mMainLayout->setContentsMargins(0, 0, 0, 0);
    mMainLayout->setSpacing(18);
    mMainLayout->addLayout(mLeftLayout, 1);
    QVBoxLayout* headerRightLayout = new QVBoxLayout();
    headerRightLayout->setContentsMargins(0, 0, 0, 0);
    headerRightLayout->setSpacing(8);
    headerRightLayout->addWidget(mCopyright, 1);
    headerRightLayout->addWidget(mLanguageSettingsBtn, 0);
    mMainLayout->addLayout(headerRightLayout, 1);

    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(16, 14, 16, 14);
    rootLayout->setSpacing(12);
    rootLayout->addLayout(mMainLayout, 0);

    initializePerformanceCards();
    rootLayout->addLayout(mPerformanceLayout, 0);

    QHBoxLayout* lowerLayout = new QHBoxLayout();
    lowerLayout->setContentsMargins(0, 0, 0, 0);
    lowerLayout->setSpacing(18);

    // Compatible with old fields but no longer uses a single newline text for layout; system summary is now a two-column grid of project name and content.
    mSystemInfo = new QLabel(this);
    mSystemInfo->setVisible(false);
    mSystemInfoPanel = new QWidget(this);
    mSystemInfoPanel->setAttribute(Qt::WA_TranslucentBackground, true);
    mSystemInfoPanel->setStyleSheet(QStringLiteral("background:transparent;"));
    // The panel itself fills the bottom-left area, while the grid content is fixed to the top; otherwise, when dynamically adding fields,
    // sizeHint is calculated only based on the initial few rows, causing subsequent fields to be clipped or pushed to abnormal positions.
    mSystemInfoPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    mSystemInfoLayout = new QGridLayout(mSystemInfoPanel);
    mSystemInfoLayout->setContentsMargins(0, 0, 0, 0);
    mSystemInfoLayout->setHorizontalSpacing(14);
    mSystemInfoLayout->setVerticalSpacing(4);
    mSystemInfoLayout->setAlignment(Qt::AlignTop);
    mSystemInfoLayout->setColumnMinimumWidth(0, 144);
    mSystemInfoLayout->setColumnStretch(0, 0);
    mSystemInfoLayout->setColumnStretch(1, 1);
    lowerLayout->addWidget(mSystemInfoPanel, 1);

    QVBoxLayout* rightLayout = new QVBoxLayout();
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(8);
    rightLayout->addLayout(mBtnLayout);
    rightLayout->addLayout(mReferenceLayout);
    initializeContributorCollapse();
    rightLayout->addWidget(mContributorsCollapse);
    rightLayout->addWidget(mContributorsScroll, 1);
    rightLayout->addWidget(mDonorsCollapse);
    rightLayout->addWidget(mDonorsScroll, 1);
    lowerLayout->addLayout(rightLayout, 1);
    rootLayout->addLayout(lowerLayout, 1);

    connect(mLanguageSettingsBtn, &QPushButton::clicked, this, &WelcomeDock::languageSettingsRequested);
    connect(mGithubBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://github.com/WangWei-CM/KSword")));
    });
    connect(mQqBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kQQGroupInviteUrl));
    });
    connect(mPplControlBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kPplControlRepositoryUrl));
    });
    connect(mSystemInformerBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kSystemInformerRepositoryUrl));
    });
    connect(mSkt64Btn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kSkt64RepositoryUrl));
    });

    retranslateUi();
    updateCollapseState(true);
    // The first screen relies only on information immediately available via Win32/Qt. After the hardware Dock completes its asynchronous
    // static sampling, it fills in BIOS, motherboard, GPU, and physical NIC details, preventing a blank welcome screen for several seconds.
    updateSystemInfoFromHardwareText(QString());
}

void WelcomeDock::initializePerformanceCards()
{
    mPerformanceLayout = new QHBoxLayout();
    mPerformanceLayout->setContentsMargins(0, 0, 0, 0);
    mPerformanceLayout->setSpacing(10);

    const std::array<ksword_theme::PerformanceRole, 5> kRoles = {{
        ksword_theme::PerformanceRole::kCpu,
        ksword_theme::PerformanceRole::kMemory,
        ksword_theme::PerformanceRole::kGpu,
        ksword_theme::PerformanceRole::kDisk,
        ksword_theme::PerformanceRole::kNetwork
    }};
    for (const auto kRole : kRoles)
    {
        PerformanceNavCard* card = new PerformanceNavCard(this);
        card->setMinimumSize(0, 84);
        card->setMaximumHeight(118);
        card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        card->setAccentColor(ksword_theme::performanceColor(kRole));
        mPerformanceCards.push_back(card);
        mPerformanceLayout->addWidget(card, 1);
    }
}

void WelcomeDock::initializeContributorCollapse()
{
    const QString kHeaderStyle = QStringLiteral(
        "QToolButton{background:transparent;color:%1;border:1px solid #409EFF;padding:7px 12px;"
        "font-size:16px;font-weight:600;text-align:center;}"
        "QToolButton:hover{background:transparent;border-color:#64B5F6;}"
        "QToolButton:checked{background:transparent;border-color:#409EFF;}")
        .arg(ksword_theme::textPrimaryHex());

    mContributorsCollapse = new QToolButton(this);
    mContributorsCollapse->setCheckable(true);
    mContributorsCollapse->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    mContributorsCollapse->setStyleSheet(kHeaderStyle);
    mContributorsCollapse->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    mDonorsCollapse = new QToolButton(this);
    mDonorsCollapse->setCheckable(true);
    mDonorsCollapse->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    mDonorsCollapse->setStyleSheet(kHeaderStyle);
    mDonorsCollapse->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    mContributorsBody = new QWidget(this);
    mContributorsBody->setAttribute(Qt::WA_TranslucentBackground, true);
    mContributorsBody->setStyleSheet(QStringLiteral("background:transparent;"));
    QVBoxLayout* contributorsLayout = new QVBoxLayout(mContributorsBody);
    contributorsLayout->setContentsMargins(4, 4, 4, 4);
    contributorsLayout->setSpacing(6);
    for (const ContributorEntry& entry : kContributorEntries)
    {
        QWidget* row = new QWidget(mContributorsBody);
        row->setAttribute(Qt::WA_TranslucentBackground, true);
        row->setStyleSheet(QStringLiteral("background:transparent;"));
        QHBoxLayout* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        rowLayout->setSpacing(8);

        QLabel* avatar = new QLabel(row);
        avatar->setText(QStringLiteral("头像"));
        avatar->setAlignment(Qt::AlignCenter);
        constexpr int kAvatarSize = 64;
        avatar->setFixedSize(kAvatarSize, kAvatarSize);
        avatar->setStyleSheet(QStringLiteral(
            "border:2px solid %1;border-radius:32px;color:%2;background:%3;")
            .arg(ksword_theme::borderHex(), ksword_theme::textPrimaryHex(), ksword_theme::surfaceAltHex()));
        const QPixmap kSourceAvatar(entry.avatarResourcePath);
        if (!kSourceAvatar.isNull())
        {
            QPixmap circularAvatar(kAvatarSize, kAvatarSize);
            circularAvatar.fill(Qt::transparent);
            QPainter avatarPainter(&circularAvatar);
            avatarPainter.setRenderHint(QPainter::Antialiasing);
            QPainterPath circularClip;
            circularClip.addEllipse(0, 0, kAvatarSize, kAvatarSize);
            avatarPainter.setClipPath(circularClip);
            avatarPainter.drawPixmap(0, 0, kSourceAvatar.scaled(
                kAvatarSize, kAvatarSize, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation));
            avatar->setPixmap(circularAvatar);
            avatar->setText(QString());
        }
        rowLayout->addWidget(avatar, 0, Qt::AlignTop);

        QVBoxLayout* detailLayout = new QVBoxLayout();
        detailLayout->setContentsMargins(0, 0, 0, 0);
        detailLayout->setSpacing(2);
        QLabel* nameLabel = new QLabel(entry.displayName, row);
        nameLabel->setStyleSheet(QStringLiteral("font-size:15px;font-weight:600;"));
        detailLayout->addWidget(nameLabel);
        if (!entry.description.isEmpty())
        {
            detailLayout->addWidget(new QLabel(entry.description, row));
        }
        // Links are arranged as a separate right-side button column so that the name and signature will not be pushed to the next line by the buttons.
        QVBoxLayout* linksLayout = new QVBoxLayout();
        linksLayout->setContentsMargins(0, 0, 0, 0);
        linksLayout->setSpacing(6);
        const std::array<ContributorLink, 2> kLinks = {{entry.firstLink, entry.secondLink}};
        for (const ContributorLink& link : kLinks)
        {
            QPushButton* linkButton = new QPushButton(link.displayName, row);
            linkButton->setStyleSheet(welcomeOutlineButtonStyle());
            linkButton->setVisible(!link.targetUrl.trimmed().isEmpty());
            linkButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
            linksLayout->addWidget(linkButton);
            if (!link.targetUrl.trimmed().isEmpty())
            {
                const QUrl kTargetUrl(link.targetUrl);
                connect(linkButton, &QPushButton::clicked, row, [kTargetUrl]() {
                    QDesktopServices::openUrl(kTargetUrl);
                });
            }
        }
        rowLayout->addLayout(detailLayout, 1);
        rowLayout->addLayout(linksLayout, 0);
        contributorsLayout->addWidget(row);
    }
    contributorsLayout->addStretch(1);

    mDonorsBody = new QWidget(this);
    mDonorsBody->setAttribute(Qt::WA_TranslucentBackground, true);
    mDonorsBody->setStyleSheet(QStringLiteral("background:transparent;"));
    QVBoxLayout* donorsLayout = new QVBoxLayout(mDonorsBody);
    donorsLayout->setContentsMargins(8, 6, 8, 6);
    donorsLayout->setSpacing(3);
    for (const QString& donorName : kDonorNames)
    {
        donorsLayout->addWidget(new QLabel(donorName, mDonorsBody));
    }
    donorsLayout->addStretch(1);

    const auto kMakeScrollArea = [](QWidget* body, QWidget* parent) {
        QScrollArea* scrollArea = new QScrollArea(parent);
        scrollArea->setAttribute(Qt::WA_TranslucentBackground, true);
        scrollArea->viewport()->setAttribute(Qt::WA_TranslucentBackground, true);
        scrollArea->setWidget(body);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setStyleSheet(QStringLiteral(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollArea > QWidget{background:transparent;}"));
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        return scrollArea;
    };
    mContributorsScroll = kMakeScrollArea(mContributorsBody, this);
    mDonorsScroll = kMakeScrollArea(mDonorsBody, this);

    connect(mContributorsCollapse, &QToolButton::clicked, this, [this]() {
        updateCollapseState(true);
    });
    connect(mDonorsCollapse, &QToolButton::clicked, this, [this]() {
        updateCollapseState(false);
    });
}

void WelcomeDock::updateCollapseState(const bool contributorsExpanded)
{
    if (mContributorsCollapse == nullptr || mDonorsCollapse == nullptr)
    {
        return;
    }
    mContributorsCollapse->setChecked(contributorsExpanded);
    mDonorsCollapse->setChecked(!contributorsExpanded);
    mContributorsCollapse->setArrowType(contributorsExpanded ? Qt::DownArrow : Qt::RightArrow);
    mDonorsCollapse->setArrowType(contributorsExpanded ? Qt::RightArrow : Qt::DownArrow);
    if (mContributorsScroll != nullptr)
    {
        mContributorsScroll->setVisible(contributorsExpanded);
    }
    if (mDonorsScroll != nullptr)
    {
        mDonorsScroll->setVisible(!contributorsExpanded);
    }
}

void WelcomeDock::setHardwareDock(HardwareDock* hardwareDock)
{
    if (mHardwareDock == hardwareDock)
    {
        return;
    }
    if (mHardwareDock != nullptr)
    {
        disconnect(mHardwareDock, nullptr, this, nullptr);
    }
    mHardwareDock = hardwareDock;
    if (mHardwareDock == nullptr)
    {
        return;
    }
    connect(mHardwareDock, &HardwareDock::performanceSnapshotChanged,
        this, &WelcomeDock::updatePerformanceSnapshot);
    connect(mHardwareDock, &HardwareDock::staticOverviewChanged,
        this, &WelcomeDock::updateSystemInfoFromHardwareText);
    // The welcome page only requires user-mode performance cards; it must not trigger R0 health queries requiring the KswordARK driver on the first screen.
    mHardwareDock->startPerformanceSampling(false);
}

void WelcomeDock::updatePerformanceSnapshot(
    const double cpuUsagePercent, const double memoryUsagePercent,
    const double diskReadBytesPerSec, const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec, const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (mPerformanceCards.size() < 5)
    {
        return;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);
    const double kUsedMemoryGiB = static_cast<double>(
        memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
    const double kTotalMemoryGiB = static_cast<double>(memoryStatus.ullTotalPhys) /
        (1024.0 * 1024.0 * 1024.0);

    mPerformanceCards[0]->setSubtitleText(QStringLiteral("%1%").arg(cpuUsagePercent, 0, 'f', 0));
    mPerformanceCards[0]->appendSample(cpuUsagePercent);
    mPerformanceCards[1]->setSubtitleText(QStringLiteral("用 %1/%2 GB / 余 %3%")
        .arg(kUsedMemoryGiB, 0, 'f', 1).arg(kTotalMemoryGiB, 0, 'f', 1)
        .arg(std::clamp(100.0 - memoryUsagePercent, 0.0, 100.0), 0, 'f', 0));
    mPerformanceCards[1]->appendSample(memoryUsagePercent);
    mPerformanceCards[2]->setSubtitleText(QStringLiteral("%1% 综合").arg(gpuUsagePercent, 0, 'f', 0));
    mPerformanceCards[2]->appendSample(gpuUsagePercent);

    const double kDiskTotal = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
    mDiskDisplayScale = std::max(1024.0 * 1024.0,
        std::max(mDiskDisplayScale * 0.92, kDiskTotal * 1.25));
    mPerformanceCards[3]->setSubtitleText(QStringLiteral("读 %1 / 写 %2")
        .arg(formatRate(diskReadBytesPerSec), formatRate(diskWriteBytesPerSec)));
    mPerformanceCards[3]->appendSample(std::clamp(kDiskTotal / mDiskDisplayScale * 100.0, 0.0, 100.0));

    const double kNetworkTotal = std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec);
    mNetworkDisplayScale = std::max(1024.0 * 1024.0,
        std::max(mNetworkDisplayScale * 0.92, kNetworkTotal * 1.25));
    mPerformanceCards[4]->setSubtitleText(QStringLiteral("下 %1 / 上 %2")
        .arg(formatRate(networkRxBytesPerSec), formatRate(networkTxBytesPerSec)));
    mPerformanceCards[4]->appendSample(std::clamp(kNetworkTotal / mNetworkDisplayScale * 100.0, 0.0, 100.0));
}

void WelcomeDock::updateSystemInfoFromHardwareText(const QString& overviewText)
{
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);
    const QStorageInfo kSystemStorage = QStorageInfo::root();
    const QString kMonitorText = QGuiApplication::primaryScreen() != nullptr
        ? QStringLiteral("%1 (%2 x %3)")
            .arg(QGuiApplication::primaryScreen()->name())
            .arg(QGuiApplication::primaryScreen()->size().width())
            .arg(QGuiApplication::primaryScreen()->size().height())
        : QStringLiteral("N/A");
    const QString kCpuText = firstOverviewValue(overviewText, QStringLiteral("处理器"));
    const QString kBoardText = firstOverviewValue(overviewText, QStringLiteral("主板"));
    const QString kBiosText = firstOverviewValue(overviewText, QStringLiteral("BIOS"));
    const QString kGpuText = firstOverviewValue(overviewText, QStringLiteral("显卡设备"));
    const QString kSecondGpuText = secondOverviewValue(overviewText, QStringLiteral("显卡设备"));
    const QString kNetworkText = firstOverviewValue(overviewText, QStringLiteral("网卡设备(物理)"));
    const QString kLogicalProcessorText = QString::number(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const QString kBootTimeText = QDateTime::fromMSecsSinceEpoch(
        QDateTime::currentMSecsSinceEpoch() - static_cast<qint64>(::GetTickCount64()))
        .toString(Qt::ISODate);
    struct SystemInfoRow
    {
        QString label;
        QString value;
    };
    const auto kTranslatedLabel = [](const QString& key, const QString& fallback) {
        return ks::i18n::contextText(key, fallback);
    };
    const QString kPendingCollection = ks::i18n::contextText(
        QStringLiteral("待采集"), QStringLiteral("待采集"));
    const std::array<SystemInfoRow, 18> kRows = {{
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.system_version"), QStringLiteral("系统版本：")), QSysInfo::prettyProductName()},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.internal_version"), QStringLiteral("内部版本：")), QSysInfo::kernelVersion()},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.cpu"), QStringLiteral("CPU：")), kCpuText == QStringLiteral("N/A") ? kPendingCollection : kCpuText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.cpu_threads"), QStringLiteral("CPU核心/线程：")), kLogicalProcessorText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.memory_usage"), QStringLiteral("内存：")), QStringLiteral("%1%").arg(memoryStatus.dwMemoryLoad)},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.memory_total"), QStringLiteral("物理内存总量：")), formatGiB(memoryStatus.ullTotalPhys)},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.bios"), QStringLiteral("BIOS：")), kBiosText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.motherboard"), QStringLiteral("主板：")), kBoardText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.gpu0"), QStringLiteral("显卡0：")), kGpuText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.gpu1"), QStringLiteral("显卡1：")), kSecondGpuText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.monitor"), QStringLiteral("显示器：")), kMonitorText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.system_drive"), QStringLiteral("系统盘：")), QStringLiteral("%1  %2/%3 GB").arg(kSystemStorage.rootPath()).arg(formatGiB(kSystemStorage.bytesAvailable())).arg(formatGiB(kSystemStorage.bytesTotal()))},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.network"), QStringLiteral("网络接口：")), kNetworkText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.computer_name"), QStringLiteral("计算机名：")), QSysInfo::machineHostName()},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.kernel_type"), QStringLiteral("内核类型：")), QSysInfo::kernelType()},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.system_architecture"), QStringLiteral("系统架构：")), QSysInfo::currentCpuArchitecture()},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.system_boot"), QStringLiteral("系统启动：")), kBootTimeText},
        {kTranslatedLabel(QStringLiteral("welcome.hardware.field.qt_version"), QStringLiteral("Qt版本：")), QStringLiteral(QT_VERSION_STR)},
    }};
    if (mSystemInfo != nullptr)
    {
        QStringList compatibilityLines;
        compatibilityLines.reserve(static_cast<qsizetype>(kRows.size()));
        for (const SystemInfoRow& row : kRows)
        {
            compatibilityLines.append(QStringLiteral("%1 %2").arg(row.label, row.value));
        }
        mSystemInfo->setText(compatibilityLines.join(QChar('\n')));
    }
    if (mSystemInfoLayout != nullptr)
    {
        while (QLayoutItem* item = mSystemInfoLayout->takeAt(0))
        {
            if (QWidget* widget = item->widget())
            {
                delete widget;
            }
            delete item;
        }

        int rowIndex = 0;
        for (const SystemInfoRow& row : kRows)
        {
            QLabel* nameLabel = new QLabel(row.label, mSystemInfoPanel);
            nameLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            nameLabel->setContentsMargins(0, 0, 0, 0);
            nameLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
            nameLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;")
                .arg(ksword_theme::textSecondaryHex()));
            QLabel* valueLabel = new QLabel(row.value, mSystemInfoPanel);
            // Asynchronous hardware details are much longer than the placeholder value on the first screen. If line wrapping were allowed, the arrival
            // of details would suddenly expand the bottom-left info area. Fixing the single-line height preserves the full text via a tooltip.
            valueLabel->setWordWrap(false);
            valueLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            valueLabel->setContentsMargins(0, 0, 0, 0);
            valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            valueLabel->setToolTip(row.value);
            valueLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
            valueLabel->setStyleSheet(QStringLiteral("color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
            const int kRowHeight = std::max(nameLabel->fontMetrics().height(),
                valueLabel->fontMetrics().height()) + 2;
            nameLabel->setFixedHeight(kRowHeight);
            valueLabel->setFixedHeight(kRowHeight);
            // Do not set AlignLeft for grid cells: it causes QLabel to occupy only the content width, preventing the right column from
            // receiving the remaining width in the lower-left area, which leads to premature line wrapping of the hardware model.
            // The text is already left-aligned via QLabel::setAlignment; the cell should fill horizontally.
            mSystemInfoLayout->addWidget(nameLabel, rowIndex, 0, Qt::AlignTop);
            mSystemInfoLayout->addWidget(valueLabel, rowIndex, 1, Qt::AlignTop);
            ++rowIndex;
        }
        mSystemInfoLayout->invalidate();
        mSystemInfoPanel->updateGeometry();
    }
}

void WelcomeDock::initializeLanguageButtonStyle()
{
    if (mLanguageSettingsBtn == nullptr)
    {
        return;
    }
    mLanguageSettingsBtn->setStyleSheet(QStringLiteral(
        "QPushButton#welcomeLanguageSettingsButton{background:transparent;color:%1;border:3px solid transparent;"
        "border-radius:10px;padding:8px 16px;font-size:16px;font-weight:700;}"
        "QPushButton#welcomeLanguageSettingsButton:hover{background:transparent;}"
        "QPushButton#welcomeLanguageSettingsButton:pressed{background:transparent;}")
        .arg(ksword_theme::textPrimaryHex()));
}

void WelcomeDock::updateLanguageButtonRgbBorder()
{
    if (mLanguageSettingsBtn != nullptr)
    {
        static_cast<WelcomeRgbBorderButton*>(mLanguageSettingsBtn)->setBorderColor(
            QColor(QStringLiteral("#409EFF")));
    }
}

void WelcomeDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void WelcomeDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    updateLanguageButtonRgbBorder();
    if (mLanguageButtonColorTimer != nullptr && !mLanguageButtonColorTimer->isActive())
    {
        mLanguageButtonColorTimer->start();
    }
}

void WelcomeDock::hideEvent(QHideEvent* event)
{
    if (mLanguageButtonColorTimer != nullptr)
    {
        mLanguageButtonColorTimer->stop();
    }
    QWidget::hideEvent(event);
}

void WelcomeDock::retranslateUi()
{
    const auto kWelcomeText = [](const char* key, const QString& sourceText) {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    };
    if (mLeftImage != nullptr)
    {
        const QPixmap kLogo(welcomeLogoResourcePath());
        if (!kLogo.isNull())
        {
            mLeftImage->setPixmap(kLogo);
        }
        else
        {
            mLeftImage->setText(kWelcomeText("welcome.logo_fallback", QStringLiteral("左侧图片区域")));
        }
    }
    if (mCopyright != nullptr)
    {
        mCopyright->setText(kWelcomeText(
            "welcome.release_info",
            QStringLiteral(
                "Ksword Dev 卡利剑ARK工具开发团队 保留所有权利。<br>"
                "<span style='font-size:22px;font-weight:700;'>当前版本：%1</span><br>"
                "<span style='font-size:14px;'>编译时间：%2</span>"))
            .arg(kReleaseVersionText, kReleaseBuildTimeText));
    }
    if (mLanguageSettingsBtn != nullptr)
    {
        mLanguageSettingsBtn->setText(kWelcomeText("welcome.language_settings", QStringLiteral("Language Settings ->")));
        mLanguageSettingsBtn->setToolTip(kWelcomeText(
            "welcome.language_settings.tooltip", QStringLiteral("打开设置中的语言设置")));
    }
    if (mGithubBtn != nullptr)
    {
        mGithubBtn->setText(kWelcomeText("welcome.github", QStringLiteral("Github仓库 ->")));
        mGithubBtn->setToolTip(kWelcomeText(
            "welcome.github.tooltip", QStringLiteral("打开项目 Github 仓库主页")));
    }
    if (mQqBtn != nullptr)
    {
        mQqBtn->setText(kWelcomeText("welcome.qq_group", QStringLiteral("QQ群 ->")));
        mQqBtn->setToolTip(kWelcomeText("welcome.qq_group.tooltip", QStringLiteral("加入项目 QQ 交流群")));
    }
    if (mPplControlBtn != nullptr)
    {
        mPplControlBtn->setText(QStringLiteral("PPLcontrol"));
        mPplControlBtn->setToolTip(kWelcomeText(
            "welcome.pplcontrol.tooltip", QStringLiteral("打开 PPLcontrol 参考项目仓库")));
    }
    if (mSystemInformerBtn != nullptr)
    {
        mSystemInformerBtn->setText(QStringLiteral("System Informer"));
        mSystemInformerBtn->setToolTip(kWelcomeText(
            "welcome.system_informer.tooltip", QStringLiteral("打开 System Informer 参考项目仓库")));
    }
    if (mSkt64Btn != nullptr)
    {
        mSkt64Btn->setText(QStringLiteral("SKT64"));
        mSkt64Btn->setToolTip(kWelcomeText(
            "welcome.skt64.tooltip", QStringLiteral("打开 SKT64 参考项目仓库")));
    }
    if (mContributorsCollapse != nullptr)
    {
        mContributorsCollapse->setText(kWelcomeText("welcome.contributors.header", QStringLiteral("贡献者")));
    }
    if (mDonorsCollapse != nullptr)
    {
        mDonorsCollapse->setText(kWelcomeText("welcome.donors.header", QStringLiteral("捐赠者")));
    }
    if (mPerformanceCards.size() >= 5)
    {
        mPerformanceCards[0]->setTitleText(kWelcomeText("hardware.utilization.card.cpu", QStringLiteral("CPU")));
        mPerformanceCards[1]->setTitleText(kWelcomeText("hardware.utilization.card.memory", QStringLiteral("内存")));
        mPerformanceCards[2]->setTitleText(kWelcomeText("hardware.utilization.card.gpu", QStringLiteral("GPU")));
        mPerformanceCards[3]->setTitleText(kWelcomeText("hardware.utilization.card.disk.prefix", QStringLiteral("磁盘")));
        mPerformanceCards[4]->setTitleText(kWelcomeText("hardware.utilization.card.network.prefix", QStringLiteral("以太网")));
    }
}
