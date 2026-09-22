#pragma once

// KvmWatchPanel: R-1 memory monitoring (first-access attribution) page.
//
// It answers a question that no other page in this ARK can answer. Snapshot-based detection can tell the user
// that "SSDT / DriverObject / callbacks / kernel code is currently wrong," but cannot answer **who changed it,
// from which instruction, or when the first change occurred**—because the moment of change has already passed.
// This page reframes the question: watch the target, wait for the next access, and capture the context at that moment.
//
// There are three things on the UI that must be explicitly stated, as they all fall into the category of 'looks correct but is misunderstood':
//
// - The monitoring unit is a 4 KiB physical page, not the few bytes selected by the user. EPT permissions are page-granular.
//   The user builds a watch from an 8-byte field in DriverObject->MajorFunction[14], but the hardware
//   still monitors the entire page. Therefore, the requested range and the actual monitored page must
//   be displayed side-by-side; it must never be described as an "8-byte hardware breakpoint."
// - **The requested access type may differ from the actually effective one.** EPT does not allow W=1 with
//   R=0, so "monitor read only" necessarily monitors writes as well in hardware. Both columns are retained.
// - **This is not protection.** After a hit, the original access proceeds normally; the target can simply remap that page to a different
//   physical page to leave the monitored set; DMA does not go through the CPU EPT. It is observation and attribution, not an inescapable guard.
//
// Another state easily misinterpreted as negative: a hit occurred but the event loop failed to catch it. At that moment, 'no
// event' and 'never accessed' appear identical in the event list, yet their conclusions are opposite. Therefore, this page
// uses the watch's own hitCount and lastHitStatus to distinguish them, rather than relying on whether the event row exists.

#include <QHash>
#include <QWidget>

#include <functional>

// Process attribution structures must be stored by value in the member table, not merely forward-declared.
#include "KvmControl.h"

class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;

class KvmWatchPanel final : public QWidget
{
public:
    explicit KvmWatchPanel(QWidget* parent = nullptr);

    // onBusyChanged: Serialized callback shared with other KVM entry points.
    // Both installation and removal must exclusively hold the driver-side status lock; concurrent commands cannot proceed while others are in flight.
    std::function<void(bool)> onBusyChanged;

    // refreshAsync: Reads the watch table once in the background. The query is a blocking IOCTL and cannot be called directly from the UI thread.
    void refreshAsync();

protected:
    void showEvent(QShowEvent* event) override;

private:
    void buildUi();
    void setBusy(bool busy);
    void updateEnabledState();
    // applyWatches: Populates the table with a single snapshot and performs virtual address remapping checks.
    void applyWatches(const QVector<ksword::kvm::KvmWatchEntry>& watches);
    // selectedWatch: Returns the snapshot corresponding to the currently selected row; returns false if nothing is selected.
    bool selectedWatch(ksword::kvm::KvmWatchEntry* entryOut) const;
    void showDetail(const ksword::kvm::KvmWatchEntry& entry);

    void startAdd();
    void startRearm();
    void startRemove();
    void openWriterDisassembly();
    // openTargetMemory: Opens the monitored page within the memory page.
    void openTargetMemory();
    // openWriterModule: Locate the module file belonging to the writer in File Explorer.
    void openWriterModule();
    // resolveHitProcess: Map the CR3 of the hit site to a specific process.
    //
    // This is a standalone button rather than an automatic trigger on details: it must attach and iterate through all
    // processes, involving hundreds of kernel transitions. Attaching to selection row changes would freeze the machine just
    // by scanning the table with arrow keys, and a delay of a few seconds for this step does not affect any conclusions.
    void resolveHitProcess();
    void copyEvidence();
    // exportEvidence: Writes the entire table to a text file.
    //
    // The distinction from 'Copy Evidence' lies not in scope but in purpose: copying is for pasting into a message,
    // while exporting is for archiving. Thus, it writes all entries, including those not yet matched (e.g., 'these
    // targets were flagged but not acted upon' is also a conclusion) and those matched but missed by the event loop.
    void exportEvidence();

    QLabel* hintLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    QTextEdit* detail_ = nullptr;
    QLabel* statusLabel_ = nullptr;

    QPushButton* addButton_ = nullptr;
    QPushButton* rearmButton_ = nullptr;
    QPushButton* removeButton_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* disassembleButton_ = nullptr;
    QPushButton* memoryButton_ = nullptr;
    QPushButton* moduleButton_ = nullptr;
    QPushButton* processButton_ = nullptr;
    QPushButton* copyButton_ = nullptr;
    QPushButton* exportButton_ = nullptr;

    // Process attribution cached by CR3.
    //
    // Group by CR3, not by watchId: when multiple watches collide on the same address space, the answer is identical.
    // Re-running a traversal of hundreds of processes is wasteful. Since the cache is a snapshot, the display must
    // include the qualifier 'this was resolved later' and cannot be presented as the fact at the moment of the hit.
    QHash<quint64, ksword::kvm::KvmProcessAttribution> processAttribution_;

    bool busy_ = false;
    bool queryInFlight_ = false;
};
