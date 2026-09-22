#pragma once

// ============================================================
// TamperDetectionPage.h
// Purpose:
// - Read the same memory region via multiple independent paths, compare page-by-page to
//   find pages where 'what the CPU reads' differs from 'the actual content in memory'.
//
// Why this page is needed (it is not the same as existing memory comparison):
// - Comparing memory against disk images (ImageDiff / injection scanning) can catch standard inline hooks,
//   but **cannot detect SLAT/EPT-level hiding**: such hiding causes the processor to fetch instructions from
//   the real page while reading data from a shadow page containing the original bytes from disk. Consequently,
//   the "memory vs. disk" comparison yields a perfect match, which is exactly the effect the hider seeks.
// - The only way to bypass it is a read path that does not go through the CPU page tables. In this project, that path is DDMA
//   (Disk Controller Bus Master DMA): data is moved directly by the HBA into the specified physical page, unconstrained by SLAT/EPT.
//   If the CPU side and the DMA side give different answers for the same physical page, that is the criterion for redirection.
//
// Key design (all are criteria, not implementation details):
// - **Physical addresses must be translated only once**. R0 physical reads and DDMA reads must fall within the same physical page;
//   otherwise, any changes between the two translations will be incorrectly flagged as content differences, resulting in a false read.
// - **Multi-round sampling.** Memory may be legitimately written at any time (self-modifying code, hot patches, data pages); a single
//   inconsistency cannot be distinguished from tampering in one round. Only consistent inconsistencies across every round elevate to a conclusion.
// - **Read failure does not mean "clean"**. If any path fails, is unavailable, or is not covered, the page's
//   conclusion must be "Unable to determine". It is strictly forbidden to benignly classify it as "No issues found".
// - The decision matrix and four-state semantics are defined in shared/evidence/MemoryTamperCrossView.h (Qt-free) and exhaustively
//   covered by the offline suite. This page is responsible only for data collection and display, not for drawing conclusions.
// ============================================================

#include "MemoryAccessBackend.h"

#include "../../../shared/evidence/MemoryTamperCrossView.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;

namespace ks::ui
{
    class VisibleTableWidget;
}

namespace ksword::memory_dock
{
    // TamperPageResult: collection and conclusion for one page.
    struct TamperPageResult
    {
        std::uint64_t virtualAddress = 0;
        std::uint64_t physicalAddress = 0;
        bool physicalAddressValid = false;
        QString translateFailureText;
        ksword::evidence::TamperFinding finding;
    };

    // TamperScanRequest: all inputs for a single scan, copied to the worker thread, containing no Qt controls.
    struct TamperScanRequest
    {
        std::uint32_t processId = 0;
        std::uint64_t startAddress = 0;
        std::uint64_t pageCount = 0;
        int roundCount = 3;
        bool useUserMode = true;
        bool useKernelVirtual = true;
        bool useKernelPhysical = true;
        bool useHvm = true;
        bool useDma = true;
        // Two static references. They do not reflect the current memory state but answer "what this page should have been originally".
        // Therefore, they belong to a different group than the live path, and cross-group discrepancies carry different meanings.
        bool useImageSection = false;
        bool useOnDiskImage = false;
        // Disk image normalization requires loading the base address and file path: bytes of the same file differ at different
        // base addresses (due to relocation). Comparing the raw file against every normal load would falsely report differences.
        std::uint64_t moduleBaseAddress = 0;
        QString moduleFilePath;
        ksword::memory_backend::DdmaSession ddmaSession;
    };

    // No Q_OBJECT: This page declares no own signals/slots; it uses only lambdas with connect(this, ...),
    // consistent with DdmaPage and SystemMemoryAuditPage in the same directory, avoiding an extra moc pass.
    class TamperDetectionPage final : public QWidget
    {
    public:
        explicit TamperDetectionPage(QWidget* parent = nullptr);
        ~TamperDetectionPage() override;

        // setAttachedProcess: Synchronized from MemoryDock upon attach/detach.
        void setAttachedProcess(std::uint32_t processId, const QString& processName);

        // setModuleCandidates: Synchronize the current process's module list for use by the target dropdown.
        // Each item is (display text, base address, size).
        struct ModuleCandidate
        {
            QString displayText;
            QString filePath;
            std::uint64_t baseAddress = 0;
            std::uint64_t sizeBytes = 0;
        };
        void setModuleCandidates(const std::vector<ModuleCandidate>& candidates);

        // refreshChannelAvailability: Called by MemoryDock when DDMA session changes.
        void refreshChannelAvailability();

    private:
        void buildUi();
        void wireSignals();
        void startScan();
        void applyScanResults(const std::vector<TamperPageResult>& results);
        void renderSelectedDetail();
        void updateRunButtonState();
        bool parseScanRange(std::uint64_t& startOut, std::uint64_t& pageCountOut, QString& errorOut) const;

        std::uint32_t attachedPid_ = 0;
        QString attachedProcessName_;
        std::vector<ModuleCandidate> moduleCandidates_;
        std::vector<TamperPageResult> results_;
        bool scanInFlight_ = false;
        std::uint64_t scanGeneration_ = 0;

        QComboBox* targetCombo_ = nullptr;
        QLineEdit* rangeStartEdit_ = nullptr;  // Start address when the target is set to "Custom Range".
        QCheckBox* useUserModeCheck_ = nullptr;
        QCheckBox* useKernelVirtualCheck_ = nullptr;
        QCheckBox* useKernelPhysicalCheck_ = nullptr;
        QCheckBox* useHvmCheck_ = nullptr;
        QCheckBox* useDmaCheck_ = nullptr;
        QCheckBox* useImageSectionCheck_ = nullptr;
        QCheckBox* useOnDiskImageCheck_ = nullptr;
        QSpinBox* roundSpin_ = nullptr;
        QSpinBox* maxPageSpin_ = nullptr;
        QPushButton* runButton_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QLabel* channelHintLabel_ = nullptr;
        ks::ui::VisibleTableWidget* resultTable_ = nullptr;
        QPlainTextEdit* detailText_ = nullptr;
    };
}
