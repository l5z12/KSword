#pragma once

#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QTableWidget;
class QTabWidget;
class QPushButton;

// KernelIoctlAuditTab：
// - Project DriverObject, DeviceObject, and MajorFunction collectively based on the \\Driver object.
// - Displays KswordARK unified dispatch registry separately.
// - All pages contain read-only evidence, supporting unified text filtering and row/full-table copy.
class KernelIoctlAuditTab final : public QWidget
{
public:
    explicit KernelIoctlAuditTab(QWidget* parent = nullptr);
    ~KernelIoctlAuditTab() override = default;

    // requestInitialRefresh：
    // - Initiates an R0 query only when the user first navigates to the "IOCTL Dispatch Table" sub-page.
    // - Prevent background prefetching during construction from triggering the 'R0 not enabled' prompt.
    // - Repeated calls remain idempotent and do not affect manual toolbar refreshes;
    void requestInitialRefresh();

private:
    struct DriverRow
    {
        QString driverName;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t driverStart = 0;
        std::uint32_t driverSize = 0;
        std::uint32_t driverFlags = 0;
        std::uint32_t majorFunctionCount = 0;
        std::uint32_t returnedDeviceCount = 0;
        std::uint32_t totalDeviceCount = 0;
        std::uint32_t queryStatus = 0;
        std::int32_t lastStatus = 0;
        QString status;
    };

    struct DeviceRow
    {
        QString driverName;
        QString deviceName;
        std::uint32_t relationDepth = 0;
        std::uint32_t deviceType = 0;
        std::uint32_t flags = 0;
        std::uint32_t characteristics = 0;
        std::uint32_t stackSize = 0;
        std::int32_t nameStatus = 0;
        std::uint64_t rootDeviceObjectAddress = 0;
        std::uint64_t deviceObjectAddress = 0;
        std::uint64_t nextDeviceObjectAddress = 0;
        std::uint64_t attachedDeviceObjectAddress = 0;
        std::uint64_t ownerDriverObjectAddress = 0;
    };

    struct DispatchRow
    {
        QString driverName;
        std::uint64_t driverObjectAddress = 0;
        std::uint32_t majorFunction = 0;
        std::uint64_t dispatchAddress = 0;
        std::uint64_t moduleBase = 0;
        QString moduleName;
        std::uint32_t flags = 0;
    };

    struct Snapshot
    {
        std::vector<DriverRow> driverRows;
        std::vector<DeviceRow> deviceRows;
        std::vector<DispatchRow> dispatchRows;
        std::vector<ksword::ark::IoctlRegistryEntry> registryRows;
        QString errorText;
        std::uint32_t queryFailureCount = 0;
        std::uint32_t partialDriverCount = 0;
        std::uint32_t registryTotal = 0;
        std::uint32_t registryDuplicate = 0;
        bool registryOk = false;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTables();
    void applyFilter();
    void showCopyMenu(QTableWidget* table, const QPoint& position);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString majorFunctionName(std::uint32_t value);
    static QString tableRowText(QTableWidget* table, int row, bool includeHeader);

    QTabWidget* innerTabs_ = nullptr;
    QWidget* driverPage_ = nullptr;
    QWidget* devicePage_ = nullptr;
    QWidget* dispatchPage_ = nullptr;
    QWidget* registryPage_ = nullptr;
    QTableWidget* driverTable_ = nullptr;
    QTableWidget* deviceTable_ = nullptr;
    QTableWidget* dispatchTable_ = nullptr;
    QTableWidget* registryTable_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QPushButton* clearFilterButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    std::vector<DriverRow> driverRows_;
    std::vector<DeviceRow> deviceRows_;
    std::vector<DispatchRow> dispatchRows_;
    std::vector<ksword::ark::IoctlRegistryEntry> registryRows_;
    std::uint32_t queryFailureCount_ = 0;
    std::uint32_t partialDriverCount_ = 0;
    std::uint32_t registryTotal_ = 0;
    std::uint32_t registryDuplicate_ = 0;
    QString errorText_;
    bool registryOk_ = false;
    bool refreshRunning_ = false;
    bool initialRefreshRequested_ = false;
};
