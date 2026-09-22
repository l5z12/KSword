#pragma once

// KvmWatchDialog: Installation dialog for memory monitoring and a unified entry point for other pages.
//
// This exists because of the statement in Section 14 of issue #195: functionality must not remain confined to the HVM experimental page.
// Authors of the SSDT page, DriverObject page, memory page, and disassembly page should
// not and need not understand GPA, EPT leaf entries, or ruleId. They only need 'an address
// and a human-readable description', which is exactly all the input openHvmWatch requires.
//
// This layer assumes three responsibilities that callers should not worry about:
// - Address translation and page alignment (EPT is page-granular; the user-selected 8 bytes must be displayed aligned to the full page);
// - Preconditions: write authorization is granted, the resident hypervisor is stopped, and no other EPT mechanism occupies the target page;
// Result explanation (when conflict occurs, specify the occupant rather than returning a protocol status code).

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;

namespace ksword::kvm
{
    struct KvmWatchTarget;
}

namespace ks::ui
{
    // HvmWatchRequest: A monitoring request originating from another page.
    struct HvmWatchRequest
    {
        // Address is a kernel virtual address (true) or a physical address (false).
        bool virtualAddress = true;
        quint64 address = 0;
        // Byte count of actual interest to the caller. 0 indicates the entire page.
        //
        // It does not change the hardware monitoring range; it only determines whether, upon a hit, the access can be judged
        // to fall within the few bytes of interest to the caller. An SSDT entry is 4 or 8 bytes, and a MajorFunction entry is
        // 8 bytes—filling them correctly ensures that 'other offsets in the same page' and 'your target' can be distinguished.
        quint64 length = 0;
        // Combination of KSWORD_ARK_HVM_EPT_ACCESS_* flags, used as initial checkboxes in the dialog.
        unsigned long access = 0;
        // Human-readable description for the target, displayed directly to the user, e.g.
        // "\Driver\Foo MajorFunction[IRP_MJ_DEVICE_CONTROL]"。
        QString label;
    };

    // openHvmWatch: opens the installation dialog with the target pre-filled; installation proceeds upon user confirmation.
    //
    // Non-blocking semantics match other KVM panels: the dialog is modal (the user is acting on a specific
    // target and should not click elsewhere at this moment). The installation itself runs in a background thread
    // because it involves a blocking IOCTL. The installation result is reported via a single message box.
    void openHvmWatch(QWidget* parent, const HvmWatchRequest& request);
}

// KvmWatchAddDialog: Installation form.
//
// The memory monitoring page shares the same form as the entry above, rather than having separate forms:
// the two forms would gradually drift apart in the 'page granularity' and 'requested access vs. actual
// access' descriptions, which are precisely the areas where this feature is most easily misunderstood.
class KvmWatchAddDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmWatchAddDialog(QWidget* parent = nullptr);

    // prefill: Pre-fill the target from a unified entry point. If the label is non-empty, display "Monitoring:
    // <label>" at the top and set the address field to read-only—the caller has already computed the address; allowing
    // the user to modify it here would cause the on-screen description to mismatch the actual monitored target.
    void prefill(const ks::ui::HvmWatchRequest& request);

    ksword::kvm::KvmWatchTarget target() const;
    bool addressValid() const;

private:
    void updateGranularity();

    QLabel* targetLabel_ = nullptr;
    QComboBox* addressKind_ = nullptr;
    QLineEdit* address_ = nullptr;
    QLineEdit* length_ = nullptr;
    QCheckBox* read_ = nullptr;
    QCheckBox* write_ = nullptr;
    QCheckBox* execute_ = nullptr;
    QLabel* granularity_ = nullptr;
};
