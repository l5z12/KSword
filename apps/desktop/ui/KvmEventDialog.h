#pragma once

// KvmEventDialog: HVM real-time event stream.
//
// The driver-side event ring continuously records events, but no UI consumes them
// beforehand—EPT view flips, rule hits, and MSR intercepts are all blind. This panel reads new
// events after the afterSequence in the ring at fixed intervals and appends them to the table.
//
// The ring buffer is bounded: when consumption lags, the driver reports droppedRows. This
// number must be displayed; otherwise, the event stream seen by the user will have silent gaps.

#include <QDialog>

class QCheckBox;
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;

class KvmEventDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmEventDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // poll: Read one new event and append it to the table.
    void poll();
    // trimRows: Truncate the table to the upper limit to prevent memory exhaustion during long-term observation.
    void trimRows();

    QTableWidget* eventTable_ = nullptr;
    QCheckBox* followCheck_ = nullptr;
    QPushButton* pauseButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTimer* pollTimer_ = nullptr;
    // m_afterSequence: Fetch only events with a sequence number greater than this value next time.
    unsigned long long afterSequence_ = 0;
    // m_droppedTotal: Cumulative count of dropped rows, accumulated across multiple polls.
    unsigned long long droppedTotal_ = 0;
    bool paused_ = false;
    bool pollInFlight_ = false;
};
