#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QVector>
#include <QDesktopServices>
#include <QUrl>

class QEvent;
class QGridLayout;
class QHideEvent;
class QScrollArea;
class QShowEvent;
class QTimer;
class QToolButton;
class HardwareDock;
class PerformanceNavCard;

class WelcomeDock : public QWidget
{
    Q_OBJECT
public:

    explicit WelcomeDock(QWidget* parent = nullptr);

    QLabel* mLeftImage;       // Left image: displays the main logo on the welcome page.
    QPushButton* mLanguageSettingsBtn; // Language settings button: opens the language tab in the settings dialog.
    QLabel* mCopyright;       // Copyright information: displays copyright, version number, and build time.
    QLabel* mContributors;    // Contributor info: Displays the current list of participants.
    QLabel* mReferenceTitle;  // Reference project title: Indicates that the buttons below are entry points to external reference repositories.
    QLabel* mDonors;          // Donor information: display the list of currently publicly thanked donors.
    QPushButton* mGithubBtn;  // GitHub button: Opens the project repository entry.
    QPushButton* mQqBtn;      // QQ group button: Retain entry point for project discussion group.
    QPushButton* mPplControlBtn;      // PPLcontrol button: opens the PPLcontrol reference repository.
    QPushButton* mSystemInformerBtn;  // System Informer button: opens the System Informer reference repository.
    QPushButton* mSkt64Btn;           // SKT64 button: Opens the SKT64 reference repository.

    // Layout manager: The welcome page retains only the main content area and displays contributors and reference projects below the main entry.
    QHBoxLayout* mMainLayout;      // Main layout: Holds the main content of the welcome page.
    QVBoxLayout* mLeftLayout;      // Left vertical layout: arranged as Logo, release info, button area, and extended info.
    QHBoxLayout* mBtnLayout;       // Horizontal button layout: for GitHub and QQ group buttons.
    QHBoxLayout* mReferenceLayout; // Reference project layout: Horizontal arrangement of external reference repository buttons.

    // Layout control dedicated to the welcome page. All dimensions allow compression to prevent ADS from creating scrollbars at the Dock level.
    QHBoxLayout* mPerformanceLayout = nullptr;
    QLabel* mSystemInfo = nullptr;
    QWidget* mSystemInfoPanel = nullptr;
    QGridLayout* mSystemInfoLayout = nullptr;
    QToolButton* mContributorsCollapse = nullptr;
    QToolButton* mDonorsCollapse = nullptr;
    QScrollArea* mContributorsScroll = nullptr;
    QScrollArea* mDonorsScroll = nullptr;
    QWidget* mContributorsBody = nullptr;
    QWidget* mDonorsBody = nullptr;
    QVector<PerformanceNavCard*> mPerformanceCards;

    // WelcomeDock reuses real-time sampling results from HardwareDock; the Hardware Dock starts sampling even if not yet opened by the main window.
    HardwareDock* mHardwareDock = nullptr;
    double mDiskDisplayScale = 1024.0 * 1024.0;
    double mNetworkDisplayScale = 1024.0 * 1024.0;

signals:
    // languageSettingsRequested: Notifies the main window to open the settings dialog and navigate to the Language tab.
    void languageSettingsRequested();

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void retranslateUi();
    void initializeLanguageButtonStyle();
    void updateLanguageButtonRgbBorder();
    void initializePerformanceCards();
    void initializeContributorCollapse();
    void updateCollapseState(bool contributorsExpanded);
    void updatePerformanceSnapshot(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateSystemInfoFromHardwareText(const QString& overviewText);

public:
    // setHardwareDock: Connects WelcomeDock to the already-created HardwareDock sample source of the main window.
    void setHardwareDock(HardwareDock* hardwareDock);

    int mLanguageButtonHue = 0; // Current hue of the RGB animation, range 0~359.
    QTimer* mLanguageButtonColorTimer = nullptr; // Language button animation timer: runs only when WelcomeDock is visible.
};
