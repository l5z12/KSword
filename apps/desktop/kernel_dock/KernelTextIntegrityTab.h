#pragma once

#include "KernelCleanImageBaseline.h"

#include <QWidget>

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;

// Kernel executable section integrity tab.
//
// It performs a full byte-by-byte comparison between the executable section content of each loaded module and the relocated disk raw image.
// Regardless of how the code page became writable, any modification to .text will leave a difference interval here.
//
// Differences fall into two categories: those occurring at PE dynamic relocation sites (import optimization / retpoline, which are
// normal rewrites during boot), and those that cannot be explained by any known mechanism. The latter are particularly severe on
// machines where HVCI is actively enforcing integrity—under such an environment, kernel code pages should not be writable at all.
class KernelTextIntegrityTab final : public QWidget
{
public:
    explicit KernelTextIntegrityTab(QWidget* parent = nullptr);
    ~KernelTextIntegrityTab() override;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void startScan();
    void cancelScan();
    void appendModuleResult(const ks::kernel::KernelTextIntegrityResult& result);
    void finishScan(bool cancelled);
    void rebuildRangeTable();
    void updateVerdict();

    static QString originText(ks::kernel::KernelTextDiffRange::Origin origin);
    static QString byteText(const std::vector<std::uint8_t>& bytes);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);

    QLabel* verdictLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLineEdit* moduleFilterEdit_ = nullptr;
    QCheckBox* unexplainedOnlyCheck_ = nullptr;
    QPushButton* scanButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QTableWidget* moduleTable_ = nullptr;
    QTableWidget* rangeTable_ = nullptr;

    std::vector<ks::kernel::KernelTextIntegrityResult> results_;
    std::shared_ptr<std::atomic_bool> cancelFlag_;
    bool firstScanStarted_ = false;
    bool scanRunning_ = false;
    // Whether HVCI is in enforcing mode, which determines the severity level of 'unexplained discrepancies'.
    bool hvciEnforcing_ = false;
    bool hvciEvidenceUsable_ = false;
};
