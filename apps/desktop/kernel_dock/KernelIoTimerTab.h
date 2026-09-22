#pragma once

// ============================================================
// KernelIoTimerTab.h
// Purpose:
// 1) enumerate the DriverObject in the object namespace and query its DeviceObject via ArkDriverClient;
// 2) Display the IoTimer list formed by the WDK public DEVICE_OBJECT.Timer field;
// 3) After double confirmation, R0 re-verifies DriverObject/DeviceObject/PIO_TIMER, then
//    calls the public IoStartTimer/IoStopTimer; do not dereference private IO_TIMER layouts.
// ============================================================

#include <QWidget>

#include <atomic>  // std::atomic_bool: Mutual exclusion for the first round/manual refresh.
#include <cstdint> // std::uintXX_t: Fixed-width addresses and counters.
#include <vector>  // std::vector: stores background snapshots and UI row cache.

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;

// KernelIoTimerTab: secure equivalent implementation of the legacy SKT64 IoTimer view.
class KernelIoTimerTab final : public QWidget
{
public:
    explicit KernelIoTimerTab(QWidget* parent = nullptr);

    // requestInitialRefresh: triggers an expensive full DriverObject query only when the user first opens the sub-page.
    void requestInitialRefresh();

protected:
    void changeEvent(QEvent* event) override;

private:
    enum class Column
    {
        kTimerAddress = 0,
        kDeviceObject,
        kDriverObject,
        kDriverName,
        kDeviceName,
        kNamespacePath,
        kQueryStatus,
        kCount
    };

    // IoTimerRow: A snapshot of a device object with a non-null DEVICE_OBJECT.Timer.
    struct IoTimerRow
    {
        std::uint64_t timerAddress = 0;
        std::uint64_t deviceObjectAddress = 0;
        std::uint64_t driverObjectAddress = 0;
        QString driverName;
        QString deviceName;
        QString namespacePath;
        QString imagePath;
        QString queryStatus;
        std::uint32_t queryProtocolVersion = 0;
        std::uint32_t queryFieldFlags = 0;
    };

    // Snapshot: Background full-query results and integrity statistics.
    struct Snapshot
    {
        std::vector<IoTimerRow> rows;
        QString namespaceError;
        std::uint32_t driverObjectsDiscovered = 0;
        std::uint32_t driverObjectsQueried = 0;
        std::uint32_t queryFailures = 0;
        std::uint32_t partialQueries = 0;
        std::uint32_t duplicateTimersSkipped = 0;
    };

    void initializeUi();
    void applyTranslatedText();
    void refreshAsync();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();
    void updateControlActions();
    void showContextMenu(const QPoint& localPosition);
    void runControlAction(std::uint32_t action);

    const IoTimerRow* selectedRow() const;

    static Snapshot collectSnapshot();
    static QString pointerText(std::uint64_t address);
    static QString normalizedCellText(const QString& text);

    QPushButton* refreshButton_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    CodeEditorWidget* detailEditor_ = nullptr;

    std::vector<IoTimerRow> rows_;
    Snapshot lastSnapshot_;
    std::atomic_bool refreshRunning_{ false };
    bool initialRefreshRequested_ = false;
    std::uint64_t refreshTicket_ = 0;
};
