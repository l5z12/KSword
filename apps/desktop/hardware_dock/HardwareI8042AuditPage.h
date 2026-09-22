#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <mutex>
#include <thread>

class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;

// HardwareI8042AuditPage：
// - Only calls the dedicated i8042prt audit protocol, does not splice global CallbackEnum or replay internal IOCTLs;
// - All versions display public I/O manager device enumeration; precise descriptors only control private extension reads.
// - Only display endpoint pointers and ownership; do not read key presses, scan codes, mouse movement, or HID reports.
class HardwareI8042AuditPage final : public QWidget
{
public:
    explicit HardwareI8042AuditPage(QWidget* parent = nullptr);
    ~HardwareI8042AuditPage() override;

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void retranslateUi();
    void refreshAsync();
    void applyResult(ksword::ark::I8042AuditResult result);
    void renderResult(const ksword::ark::I8042AuditResult& result);
    void appendEntry(const KSWORD_ARK_I8042_AUDIT_ENTRY& entry);
    void setColumnGroup(int groupIndex);
    void applyColumnGroup();
    void updateColumnGroupButtons();
    void applyFilter();

    static QString fixedWide(const wchar_t* text, int capacity);
    static QString addressText(std::uint64_t address);
    static QString deviceKindText(std::uint32_t value);
    static QString endpointText(std::uint32_t value);
    static QString yesNoText(bool value, bool present);
    static QString verdictText(std::uint32_t value);
    static QString statusText(std::uint32_t value, std::int32_t lastStatus);
    static QString detailText(const KSWORD_ARK_I8042_AUDIT_ENTRY& entry);

    QPushButton* refreshButton_ = nullptr;
    QPushButton* columnGroupAButton_ = nullptr;
    QPushButton* columnGroupBButton_ = nullptr;
    QPushButton* columnGroupCButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    std::thread refreshThread_;
    std::mutex refreshMutex_;
    bool closing_ = false;
    bool firstRefreshStarted_ = false;
    bool refreshRunning_ = false;
    bool hasResult_ = false;
    int columnGroupIndex_ = 0;
    ksword::ark::I8042AuditResult lastResult_;
};
