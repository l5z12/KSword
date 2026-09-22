#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <mutex>
#include <thread>
#include <vector>

class QEvent;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTabWidget;
class QTableWidget;

// KernelPlatformAuditTab：
// - Hal mode provides four distinct HAL sub-tabs.
// - WDF mode provides the KMDF function table and this driver's callback table.
// - Queries remain read-only; the four HAL sub-table pages and the WDF function page can be repositioned,
//   snapshot-validated, and have their function slots edited with atomic CAS constraints via ArkDriverClient.
// - WDF callback pages list compile-time addresses within the driver's .text section; there are no writable slots, so it is always read-only.
class KernelPlatformAuditTab final : public QWidget
{
public:
    enum class Mode
    {
        kHal,
        kWdf
    };

    explicit KernelPlatformAuditTab(Mode mode, QWidget* parent = nullptr);
    ~KernelPlatformAuditTab() override;

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    struct Page
    {
        unsigned long scope = 0;
        QTableWidget* table = nullptr;
    };

    void initializeUi();
    void retranslateUi();
    void addPage(unsigned long scope, const QString& title);
    void refreshAsync();
    void applyResult(ksword::ark::PlatformAuditResult result);
    void populatePage(Page& page, const ksword::ark::PlatformAuditResult& result);
    void showContextMenu(QTableWidget* table, unsigned long scope, const QPoint& position);
    void editFunctionSlot(KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry);
    bool confirmSlotEdit(
        const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry,
        unsigned long long newAddress);
    // The editability criterion follows scope only: WDF callback pages and other read-only rows in Wdf mode are excluded.
    static bool scopeIsEditable(unsigned long scope);
    QString tableFamilyName() const;
    void setColumnGroup(int groupIndex);
    void applyColumnGroup();
    void updateColumnGroupButtons();
    void applyFilter();

    static QString fixedWide(const wchar_t* text, int capacity);
    static QString addressText(unsigned long long address);
    static QString statusText(unsigned long status, long lastStatus);
    static QString hookText(unsigned long hookStatus);
    static QString signatureText(unsigned long signatureId);
    static QString detailText(const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry);
    static QString companyNameForModule(const QString& modulePath);
    static QString controlStatusText(unsigned long status, long lastStatus);
    static bool parseAddress(const QString& text, unsigned long long& addressOut);

    Mode mode_;
    QTabWidget* innerTabs_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* columnGroupAButton_ = nullptr;
    QPushButton* columnGroupBButton_ = nullptr;
    QPushButton* columnGroupCButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    std::vector<Page> pages_;
    ksword::ark::PlatformAuditResult lastResult_;
    std::thread refreshThread_;
    std::mutex refreshMutex_;
    bool closing_ = false;
    bool firstRefreshStarted_ = false;
    bool refreshRunning_ = false;
    bool hasResult_ = false;
    int columnGroupIndex_ = 0;
};
