#pragma once

// ============================================================
// DmaProcessOpPage.h
// Purpose:
// - Writes bytes into the target process's physical pages via DDMA: injecting payloads, or writing UD2 to crash the target.
//
// Relationship with the R-1 injection (IOCTL_KSWORD_ARK_HVM_INJECT): **Not a backend swap.**
//
// R-1: Injection places the payload in shadow pages, installs an execution view (execution goes through shadow pages, read/write accesses the real
// pages), and arms a trigger point. The real pages remain unmodified from start to finish, so any scanner reading them sees the original state.
//
// DMA does nothing else. It only has 'write bytes to physical pages', so:
//   * **The real page was truly modified**; any read path can see it, including this tool's own R3/R0/HVM paths.
//   * **No trigger point**: The payload lies dormant waiting for the target to execute
//     it. Writing to a location that will never be executed is equivalent to doing nothing.
//   * **Restoration is our responsibility**: this page enforces backing up first and keeping the backup visible on the interface.
//
// Regarding the 'terminate' via UD2: DMA cannot call PsTerminateProcess. Writing a UD2 into the code the target is about to execute forces
// an exit via an unhandled exception. This is the only method that does not rely on kernel structure offsets. **It is not a reliable
// terminate**: the target may have an exception handler that swallows the #UD, success depends on whether that code segment is executed,
// and it leaves a crash dump. The UI must explain these caveats instead of offering a button simply labeled 'Terminate Process'.
//
// Criteria and plans are entirely in shared/evidence/DmaProcessOpPlan.h, Qt-free, covering offline kits.
// This page is solely responsible for collecting page content, initiating writes, and faithfully displaying the results of read-back verification.
// ============================================================

#include "MemoryAccessBackend.h"

#include "../../../shared/evidence/DmaProcessOpPlan.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

namespace ksword::memory_dock
{
    // DmaOpRecord: A committed write that must be retained for restoration.
    struct DmaOpRecord
    {
        std::uint64_t virtualAddress = 0;
        std::uint64_t physicalAddress = 0;
        std::size_t offsetInPage = 0;
        std::vector<std::uint8_t> writtenBytes;
        std::vector<std::uint8_t> originalBytes;
        QString description;
        bool verified = false;
    };

    // No Q_OBJECT: Consistent with other pages in the same directory; all use lambda + connect(this, ...).
    class DmaProcessOpPage final : public QWidget
    {
    public:
        explicit DmaProcessOpPage(QWidget* parent = nullptr);
        ~DmaProcessOpPage() override;

        void setAttachedProcess(std::uint32_t processId, const QString& processName);
        void refreshChannelAvailability();

    private:
        void buildUi();
        void wireSignals();
        void updateActionState();

        // performWrite: All three steps are completed here without splitting them for the caller; splitting
        // would create call sequences like 'written but not verified' or 'written without backup'.
        void performWrite(bool injectPayload);
        void restoreLastWrite();
        void appendLog(const QString& line);

        // evaluateSharing: Compare physical addresses across processes to determine if the target page is shared.
        // This is the most severe check on this page: DMA writes to physical pages, while Copy-On-Write relies on page
        // faults. Since DMA does not trigger page faults, writing to a shared image page affects every process mapping it.
        ksword::evidence::DmaTargetSharing evaluateSharing(
            std::uint64_t pageVirtualAddress,
            std::uint64_t pagePhysical,
            QString& evidenceOut);

        bool resolveTargetPage(
            std::uint64_t& virtualAddressOut,
            std::uint64_t& pagePhysicalOut,
            std::vector<std::uint8_t>& pageBytesOut,
            QString& errorOut);

        std::uint32_t attachedPid_ = 0;
        QString attachedProcessName_;
        std::vector<DmaOpRecord> records_;

        QLabel* targetLabel_ = nullptr;
        QLineEdit* addressEdit_ = nullptr;
        QLineEdit* payloadEdit_ = nullptr;
        QCheckBox* forceCheck_ = nullptr;
        QCheckBox* acknowledgeCheck_ = nullptr;
        // Only check this box if sharing status cannot be confirmed; pages confirmed as shared cannot be unlocked by any switch.
        QCheckBox* unknownSharingCheck_ = nullptr;
        QPushButton* injectButton_ = nullptr;
        QPushButton* ud2Button_ = nullptr;
        QPushButton* restoreButton_ = nullptr;
        QLabel* channelHintLabel_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QPlainTextEdit* logText_ = nullptr;
    };
}
