#pragma once

// ============================================================
// KernelCallbackMonitorWidget.h
// Purpose:
// 1) Display six categories of R0 kernel callback telemetry in MonitorDock.
// 2) Uses an independent cursor for background reading without modifying callback rules or AskUser state;
// 3) Provides bounded caching, real-time filtering, pause, details, and export.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QWidget>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSortFilterProxyModel;
class QSpinBox;
class QTimer;
class QVBoxLayout;

namespace ks::ui
{
    class TableActionTableView;
}

class KernelCallbackEventModel;
class KernelCallbackFilterModel;

class KernelCallbackMonitorWidget final : public QWidget
{
public:
    explicit KernelCallbackMonitorWidget(QWidget* parent = nullptr);
    ~KernelCallbackMonitorWidget() override;

private:
    void initializeUi();
    void initializeConnections();
    void startCapture();
    void stopCapture(bool destroying = false);
    void setPaused(bool paused);
    void clearLocalEvents();
    void workerMain();
    void flushPendingEvents();
    void applyFilters();
    void updateActionState();
    void updateStatusLabel();
    void updateDetailPanel();
    void exportVisibleRows();
    unsigned long selectedCategoryMask() const;
    void recordWorkerFailure(const std::string& message, bool unsupported);

    QVBoxLayout* rootLayout_ = nullptr;
    QCheckBox* processCheck_ = nullptr;
    QCheckBox* threadCheck_ = nullptr;
    QCheckBox* imageCheck_ = nullptr;
    QCheckBox* registryCheck_ = nullptr;
    QCheckBox* objectCheck_ = nullptr;
    QCheckBox* fileCheck_ = nullptr;
    QSpinBox* maxRowsSpin_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* pauseButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QPushButton* exportButton_ = nullptr;
    QComboBox* categoryFilterCombo_ = nullptr;
    QLineEdit* operationFilterEdit_ = nullptr;
    QLineEdit* pidFilterEdit_ = nullptr;
    QLineEdit* processFilterEdit_ = nullptr;
    QLineEdit* pathFilterEdit_ = nullptr;
    QLineEdit* resultFilterEdit_ = nullptr;
    QCheckBox* regexCheck_ = nullptr;
    QCheckBox* keepBottomCheck_ = nullptr;
    QLabel* filterStatusLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    ks::ui::TableActionTableView* eventTable_ = nullptr;
    QPlainTextEdit* detailEdit_ = nullptr;
    KernelCallbackEventModel* eventModel_ = nullptr;
    KernelCallbackFilterModel* filterModel_ = nullptr;
    QTimer* uiTimer_ = nullptr;

    std::atomic_bool workerStop_{ false };
    std::atomic_bool captureRunning_{ false };
    std::atomic_bool driverCaptureActive_{ false };
    std::atomic_bool paused_{ false };
    std::atomic_bool cursorResetRequested_{ false };
    std::atomic_uint64_t cursorResetValue_{ 0 };
    std::atomic_uint64_t readerGeneration_{ 0 };
    std::atomic_uint64_t latestSequence_{ 0 };
    std::atomic_uint64_t r0DroppedCount_{ 0 };
    std::atomic_uint64_t cursorLostCount_{ 0 };
    std::atomic_uint64_t r3DroppedCount_{ 0 };
    std::atomic_uint32_t runtimeFlags_{ 0 };
    std::atomic_uint32_t activeCategoryMask_{ 0 };
    std::atomic_uint32_t ringCapacity_{ 0 };
    std::atomic_int pendingLimit_{ 20000 };
    std::thread worker_;
    std::mutex pendingMutex_;
    std::condition_variable workerWake_;
    std::deque<ksword::ark::CallbackMonitorEventRow> pendingEvents_;
    std::string workerError_;
    bool workerUnsupported_ = false;
    QString lastDisplayedError_;
};
