#pragma once

// ============================================================
// HardwareDeviceManagerPage.h
// Purpose:
// 1) Provide a PnP device tree page in the System Informer style;
// 2) By default, display only currently existing devices; allow switching to show all devices and highlight abnormal ones;
// 3) Read device properties via SetupAPI/CfgMgr without relying on PowerShell.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic> // std::atomic_bool: Mutex for background refresh.
#include <vector> // std::vector: stores device snapshots and supports tree reconstruction.

class QCheckBox;
class QLabel;
class QLineEdit;
class QMenu;
class QPoint;
class QPushButton;
class QSplitter;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class CodeEditorWidget;

// HardwareDeviceManagerPage:
// - Input: Qt parent control;
// - Processing: enumerate PnP devices asynchronously and build a tree using parent and child InstanceId values;
// - Return behavior: The page class has no business return value; results are rendered directly to the tree and detail areas.
class HardwareDeviceManagerPage final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent control;
    // - Processing: start the initial enumeration of current devices after initializing the UI.
    explicit HardwareDeviceManagerPage(QWidget* parent = nullptr);

    // Destructor:
    // - Processing: Background thread uses QPointer for back-casting; UI updates are automatically dropped after page destruction.
    // - Returns: Nothing.
    ~HardwareDeviceManagerPage() override = default;

public:
    // DeviceEntry：
    // - Purpose: Save a PnP device node and its display fields.
    // - Processing logic: Background thread populates data; UI thread builds the tree based on instanceId/parentInstanceId;
    // - Return behavior: Pure data structure, no function return.
    struct DeviceEntry
    {
        QString nameText;             // nameText: FriendlyName or DeviceDesc.
        QString manufacturerText;     // manufacturerText: Device manufacturer.
        QString serviceText;          // serviceText: Associated service name.
        QString classText;            // classText: Device class name.
        QString enumeratorText;       // enumeratorText: Enumerator, e.g., PCI/USB/ROOT.
        QString installedText;        // installedText: Installation time.
        QString instanceIdText;       // instanceIdText：PnP Instance ID。
        QString parentInstanceIdText; // parentInstanceIdText: Parent device Instance ID.
        QString classGuidText;        // classGuidText: Device class GUID.
        QString driverText;           // driverText: Driver registry key or INF-related field.
        QString driverInfPathText;    // driverInfPathText: INF name or path currently used by the device.
        QString driverProviderText;   // driverProviderText: Driver provider.
        QString driverVersionText;    // driverVersionText: Driver version.
        QString driverDateText;       // driverDateText: Driver date.
        QString driverRegistryPathText; // driverRegistryPathText: The driver key path under HKLM\SYSTEM\CCS\Control\Class.
        QString serviceImagePathText; // serviceImagePathText: Service ImagePath, typically pointing to a .sys driver file.
        QString locationText;         // locationText: Location description.
        QString hardwareIdsText;      // hardwareIdsText: Hardware ID list.
        QString compatibleIdsText;    // compatibleIdsText: List of compatible IDs.
        QString problemText;          // problemText: Exception code summary.
        QString statusText;           // statusText: DevNode status summary.
        unsigned long problemCode = 0; // problemCode: CM_PROB_*; 0 indicates no error.
        bool hasProblem = false;      // hasProblem: Whether highlighting is required.
        bool isPresent = true;        // isPresent: whether currently present.
    };

private:
    // initializeUi:
    // - Create the top toolbar, device tree, and details panel.
    // - No input parameters;
    // - No return value.
    void initializeUi();

    // initializeConnections:
    // - Handles interactions for refresh, show all, search, and tree selection.
    // - No input parameters;
    // - No return value.
    void initializeConnections();

    // refreshDevicesAsync:
    // - enumerate devices in a background thread;
    // - forceRefresh indicates a user-initiated refresh;
    // - No return value; results are returned to the UI via queued connection.
    void refreshDevicesAsync(bool forceRefresh);

    // applyDeviceSnapshot:
    // - Atomically replace device cache and rebuild tree on the GUI thread;
    // - Delays the full snapshot when opening the device tree context menu to avoid stale cache pointers held by old items.
    void applyDeviceSnapshot(
        std::vector<DeviceEntry> deviceList,
        bool includeAllDevices);

    // rebuildDeviceTree:
    // - Input: Device snapshot list;
    // - Processing: Build tree by Parent InstanceId; apply search filtering and exception highlighting.
    // - No return value.
    void rebuildDeviceTree(const std::vector<DeviceEntry>& deviceList);

    // applyFilterToTree:
    // - Hide nodes that do not match the search box content.
    // - If a parent node has matching child nodes, keep it visible;
    // - Returns: Whether the current node or its descendants match.
    bool applyFilterToTree(QTreeWidgetItem* itemPointer, const QString& filterText);

    // updateDetailForItem:
    // - Input: currently selected tree item;
    // - Processing: Display the DeviceEntry associated with the node in the details area.
    // - No return value.
    void updateDetailForItem(QTreeWidgetItem* itemPointer);

    // showDeviceContextMenu:
    // - Input: device tree local coordinates;
    // - Processing: Construct right-click menu for properties, driver details, unload, and driver package removal based on the currently selected device;
    // - Return value: None.
    void showDeviceContextMenu(const QPoint& localPosition);

    // showSelectedDeviceProperties:
    // - Input: Device currently selected in the tree;
    // - Processing: Open a read-only properties dialog to display SetupAPI/CfgMgr enumerated fields.
    // - Return value: None.
    void showSelectedDeviceProperties();

    // showSelectedDeviceDriverDetails:
    // - Input: Device currently selected in the tree;
    // - Processing: Open a read-only driver details dialog to display fields such as INF, Provider, Version, and service ImagePath.
    // - Return value: None.
    void showSelectedDeviceDriverDetails();

    // copySelectedDeviceInstanceId:
    // - Input: Device currently selected in the tree;
    // - Processing: Copy Instance ID to clipboard.
    // - Return value: None.
    void copySelectedDeviceInstanceId();

    // uninstallSelectedDevice:
    // - Input: Device currently selected in the tree;
    // - Handling: Uninstall the device node via SetupAPI DIF_REMOVE after secondary confirmation.
    // - Return value: None.
    void uninstallSelectedDevice();

    // deleteSelectedDeviceDriverPackage:
    // - Input: Device currently selected in the tree;
    // - Handling: Delete the OEM INF driver package via SetupUninstallOEMInf after secondary confirmation.
    // - Return value: None.
    void deleteSelectedDeviceDriverPackage();

    // selectedDeviceEntry:
    // - Input: Currently selected tree item;
    // - Processing: Retrieve the DeviceEntry pointer from Qt::UserRole.
    // - Return: On success, returns the current device pointer; otherwise returns nullptr.
    const DeviceEntry* selectedDeviceEntry() const;

    // enumerateDevicesSnapshot:
    // - Input: When includeAllDevices is true, enumerate historical/non-current devices.
    // - Processing: Call SetupAPI/CfgMgr to read device properties.
    // - Returns: Device snapshot ready for rendering.
    static std::vector<DeviceEntry> enumerateDevicesSnapshot(bool includeAllDevices);

private:
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Page root layout.
    QLabel* statusLabel_ = nullptr;          // m_statusLabel: Refresh status text.
    QPushButton* refreshButton_ = nullptr;   // m_refreshButton: Refresh button.
    QCheckBox* showAllDevicesCheck_ = nullptr; // m_showAllDevicesCheck: Whether to show all devices.
    QCheckBox* showProblemOnlyCheck_ = nullptr; // m_showProblemOnlyCheck: Whether to show only problematic devices.
    QLineEdit* searchEdit_ = nullptr;        // m_searchEdit: Tree filter input box.
    QSplitter* splitter_ = nullptr;          // m_splitter: Device tree/details splitter.
    QTreeWidget* deviceTree_ = nullptr;      // m_deviceTree: System Informer-style device tree.
    CodeEditorWidget* detailEditor_ = nullptr; // m_detailEditor: Selected device details.
    std::vector<DeviceEntry> deviceList_;    // m_deviceList: Most recent full snapshot.
    std::atomic_bool refreshing_{ false };   // m_refreshing: Refresh mutex flag.
};
