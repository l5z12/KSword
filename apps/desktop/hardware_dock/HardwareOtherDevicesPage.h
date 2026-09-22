#pragma once

// ============================================================
// HardwareOtherDevicesPage.h
// Purpose:
// 1) Provide a 'Other Devices' side tab within the hardware page to host hardware inventory beyond CPU, memory, and GPU;
// 2) Collect motherboard, BIOS, storage, USB, audio, display, and HID information via background PowerShell/CIM;
// 3) Use a read-only text view to display detailed enumeration results to avoid blocking the main window and the existing HardwareDock.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic> // std::atomic_bool: Prevents redundant startup of the hardware inventory refresh thread.

class CodeEditorWidget;
class QLabel;
class QPushButton;
class QVBoxLayout;

// HardwareOtherDevicesPage:
// - Input: Qt parent object;
// - Processing logic: initializes the top status bar and read-only text area, and performs device enumeration in the background;
// - Return behavior: No business return value. Collection results are displayed in the UI.
class HardwareOtherDevicesPage final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent is the Qt parent widget;
    // - Trigger an asynchronous refresh immediately after UI initialization.
    explicit HardwareOtherDevicesPage(QWidget* parent = nullptr);

    // Destructor:
    // - The current class does not hold any thread-blocking handles;
    // - Background back-casting uses QPointer to prevent access after object destruction.
    ~HardwareOtherDevicesPage() override = default;

private:
    // initializeUi:
    // - Create status label, refresh button, and read-only text editor;
    // - Logic only operates on Qt controls;
    // - No return value.
    void initializeUi();

    // initializeConnections:
    // - Connect refresh button to async collection entry;
    // - No input parameters;
    // - No return value.
    void initializeConnections();

    // refreshDeviceInventoryAsync:
    // - Perform PowerShell/CIM device enumeration in the background.
    // - forceRefresh: indicates that user-initiated refresh overwrites the status text;
    // - No return value; results are returned to the UI via queued connection.
    void refreshDeviceInventoryAsync(bool forceRefresh);

    // buildDeviceInventoryTextSnapshot:
    // - Build the complete hardware device inventory text in the worker thread.
    // - Do not access any QWidget.
    // - Returns device inventory or error diagnostic text.
    static QString buildDeviceInventoryTextSnapshot();

private:
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Root layout within the page.
    QLabel* statusLabel_ = nullptr;          // m_statusLabel: Display refresh status and time.
    QPushButton* refreshButton_ = nullptr;   // m_refreshButton: Manual refresh button.
    CodeEditorWidget* inventoryEditor_ = nullptr; // m_inventoryEditor: Read-only device inventory text area.
    std::atomic_bool refreshing_{ false };   // m_refreshing: Asynchronous refresh mutex flag.
};
