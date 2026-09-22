#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTextEdit;

// KernelHvmTab presents VT-x/EPT capability, reversible resource preparation,
// per-CPU VMX validation, a one-shot VMCALL guest, VM-exit evidence, and teardown.
class KernelHvmTab final : public QWidget
{
public:
    enum class FeatureArea
    {
        kKept,
        kNestedVmx,
        kEvmcs
    };

    explicit KernelHvmTab(QWidget* parent = nullptr);
    KernelHvmTab(FeatureArea featureArea, QWidget* parent);
    ~KernelHvmTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyStatus(ksword::ark::HvmStatusResult result);
    void runControlAsync(
        unsigned long command,
        bool force,
        bool enableEptEvents = false,
        bool enableNestedVmx = false,
        bool enableEvmcs = false);
    void applyControl(
        unsigned long command,
        ksword::ark::HvmControlResult control,
        ksword::ark::HvmStatusResult status);
    void prepareBackend();
    void selfTestBackend();
    void launchControlledGuest();
    void teardownBackend();
    void startResident();
    void stopResident();
    void validateNested();
    void validateEvmcs();
    void addEptRule();
    void queryEptRule();
    void removeEptRule();
    void clearEptRules();
    void queryEvents();
    void clearEvents();
    void runEptRuleAsync(
        unsigned long operation,
        unsigned long ruleId,
        unsigned long deniedAccess,
        std::uint64_t physicalAddress,
        std::uint64_t pageCount,
        bool log,
        bool allowOnce);
    void applyEptRule(
        unsigned long operation,
        ksword::ark::HvmEptRuleResult result,
        ksword::ark::HvmStatusResult status);
    void runEventQueryAsync(bool clear);
    void applyEvents(
        bool clear,
        ksword::ark::HvmEventResult result);
    bool confirmTyped(const QString& warning, const QString& phrase);
    void updateButtons();
    QString buildDetail(
        const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const;
    static QString featureText(std::uint64_t flags);
    static QString stateText(std::uint32_t flags);
    static QString implementationText(std::uint32_t implementation);
    static QString nestedStateText(std::uint32_t state);
    // executionStageText: Execution stage per CPU. Used for the 'Execution State' column on the AMD
    // side—the driver reports an index from 0 to 7; displaying a raw number conveys no information.
    static QString executionStageText(std::uint32_t stage);
    static QString ntStatusText(long status);
    static QString fixedAscii(const char* text, int capacity);

    QLabel* statusLabel_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* prepareButton_ = nullptr;
    QPushButton* selfTestButton_ = nullptr;
    QPushButton* launchButton_ = nullptr;
    QPushButton* teardownButton_ = nullptr;
    QPushButton* startResidentButton_ = nullptr;
    QPushButton* stopResidentButton_ = nullptr;
    QPushButton* featureActionButton_ = nullptr;
    QTableWidget* cpuTable_ = nullptr;
    QTextEdit* detailEdit_ = nullptr;
    FeatureArea featureArea_ = FeatureArea::kKept;
    KSWORD_ARK_QUERY_HVM_RESPONSE snapshot_{};
    bool firstRefreshStarted_ = false;
    bool operationRunning_ = false;
    bool supported_ = false;
};
