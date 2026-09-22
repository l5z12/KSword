#pragma once

// KvmMemoryDialog: KVM (Layer-1) memory operation panel.
//
// Opened via the right-click menu of the KVM button in the title bar. It performs a single task: expose the R-1
// memory channel (private page table window) to allow manual read, write, and translation operations, and
// accurately display whether this access traverses the private window or the degraded MmCopyMemory path—the latter
// can still read data but no longer bypasses kernel-level hooks. This distinction must be visible to the user.
//
// All IOCTLs execute on a background thread; writes are additionally constrained by the write permission gate in KvmControl.

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;

class KvmMemoryDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmMemoryDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // updateEnabledState: Refresh control availability based on current mode, write permissions, and busy status.
    void updateEnabledState();
    // startRead/startWrite/startTranslate: Initiates a background operation.
    void startRead();
    void startWrite();
    void startTranslate();
    // parseAddress: Parses a hexadecimal address input; returns false on failure and writes the status line.
    bool parseAddress(const QLineEdit* field, unsigned long long* valueOut,
        const QString& fieldName);
    // setBusy: Enter or exit busy state; disable all action buttons while busy.
    void setBusy(bool busy);
    // showHexDump: Renders the read bytes into a hex view with offsets.
    void showHexDump(unsigned long long baseAddress, const QByteArray& data);
    // isVirtualMode: Whether the current mode is virtual address mode.
    bool isVirtualMode() const;

    QComboBox* modeBox_ = nullptr;
    QLineEdit* addressEdit_ = nullptr;
    QLineEdit* directoryBaseEdit_ = nullptr;
    QSpinBox* lengthBox_ = nullptr;
    QPlainTextEdit* dataView_ = nullptr;
    QLineEdit* writeEdit_ = nullptr;
    QPushButton* readButton_ = nullptr;
    QPushButton* writeButton_ = nullptr;
    QPushButton* translateButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* windowLabel_ = nullptr;
    bool busy_ = false;
};
