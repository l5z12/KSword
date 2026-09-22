#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTextEdit;

// VBS/HVCI real posture tab.
//
// This page addresses the specific issue of 'HVCI appears enabled but is not actually running': the policy
// bit (HVCI_KMCI_ENABLED in SystemCodeIntegrityInformation) only indicates configuration intent; actual
// enforcement requires VBS to be present, a hypervisor to exist, and securekernel/skci to be loaded.
// The page places these two types of evidence side by side. If either side is missing, a definitive conclusion is given, and
// downgrade items that weaken CI—such as Audit Mode, Test Signature, CI Debug Mode, and Kernel Debugger—are listed separately.
class KernelVbsPostureTab final : public QWidget
{
public:
    explicit KernelVbsPostureTab(QWidget* parent = nullptr);
    ~KernelVbsPostureTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    // Single-factor severity determines table coloring and inclusion in the downgrade list.
    enum class Severity : int
    {
        kGood = 0,
        kNeutral,
        kWarning,
        kBad
    };

    struct PostureRow
    {
        QString item;
        QString observed;
        QString verdict;
        QString source;
        Severity severity = Severity::kNeutral;
        bool downgrade = false;
    };

    struct Snapshot
    {
        ksword::ark::SecurityStatusAuditResult security;
        ksword::ark::HyperVSummaryAuditResult hyperV;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTable(const QList<PostureRow>& rows);
    void applyVerdictBanner(const Snapshot& snapshot, const QList<PostureRow>& rows);

    static QList<PostureRow> buildRows(const Snapshot& snapshot);
    static QString buildDetail(const Snapshot& snapshot);
    static QString codeIntegrityOptionText(std::uint32_t options);
    static QString moduleStateText(std::uint32_t state);
    static QString boolText(std::uint32_t value);
    static QString ntStatusText(long status);
    static QString fixedWide(const wchar_t* text, std::size_t capacity);

    QLabel* verdictLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* downgradeLabel_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QTableWidget* table_ = nullptr;
    QTextEdit* detailEdit_ = nullptr;
    bool firstRefreshStarted_ = false;
    bool queryRunning_ = false;
};
