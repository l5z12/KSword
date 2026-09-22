#pragma once

#include "../Framework.h"
#include "KernelDock.CallbackIntercept.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QDialog>
#include <QPointer>

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

class QLabel;
class QPushButton;
class QTimer;
class QWidget;
class QCloseEvent;
class QEvent;

class CallbackPromptManager final : public QObject
{
    Q_OBJECT

public:
    static CallbackPromptManager* ensureGlobalManager(QWidget* hostWindow = nullptr);
    static CallbackPromptManager* globalManager();
    static void shutdownGlobalManager();

    explicit CallbackPromptManager(QWidget* hostWindow = nullptr, QObject* parent = nullptr);
    ~CallbackPromptManager() override;

    void setHostWindow(QWidget* hostWindow);
    void start();
    void stop();

signals:
    void logLineGenerated(const QString& logText);

private:
    class DecisionPopupDialog final : public QDialog
    {
    public:
        explicit DecisionPopupDialog(CallbackPromptManager* owner, QWidget* parent = nullptr);

    protected:
        void closeEvent(QCloseEvent* event) override;

    private:
        CallbackPromptManager* owner_ = nullptr;
    };

    struct WaitWorkerContext
    {
        int workerTag = 0;
        std::atomic_bool running{ false };
        std::unique_ptr<std::thread> thread;
        std::mutex ioMutex;
        ksword::ark::DriverHandle deviceHandle;
    };

private:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void applyPopupTheme();
    void initializePopupUi();
    void initializePopupConnections();
    void appendManagerLog(const QString& logText);
    void startWorkersIfNeeded();
    void stopWorkersIfNeeded();
    void runWaitWorkerLoop(int workerTag);
    void onEventArrivedOnUiThread(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket);
    void enqueueEvent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket);
    bool shouldAutoAllowByRegex(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket) const;
    void tryShowNextEvent();
    void updatePopupContent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket);
    void updateCountdownLabel();
    void finishCurrentEventWithDecision(quint32 decision, bool fromTimeoutOrClose);
    void onPopupClosedByUser();
    bool sendAnswerToDriver(const KSWORD_ARK_GUID128& eventGuid, quint32 decision);
    void cancelAllPendingDecisionsBestEffort();
    quint64 currentUtc100ns() const;
    quint32 currentSessionId() const;
    void movePopupToBottomRight();

private:
    QWidget* hostWindow_ = nullptr;
    std::atomic_bool running_{ false };
    std::vector<std::unique_ptr<WaitWorkerContext>> workerList_;

    mutable std::mutex queueMutex_;
    std::deque<KSWORD_ARK_CALLBACK_EVENT_PACKET> eventQueue_;

    bool hasCurrentEvent_ = false;
    KSWORD_ARK_CALLBACK_EVENT_PACKET currentEvent_{};
    qint64 remainingTimeoutMs_ = 0;

    QPointer<DecisionPopupDialog> popupDialog_;
    QLabel* eventGuidValueLabel_ = nullptr;
    QLabel* callbackTypeValueLabel_ = nullptr;
    QLabel* operationValueLabel_ = nullptr;
    QLabel* targetValueLabel_ = nullptr;
    QLabel* initiatorIconLabel_ = nullptr;
    QLabel* initiatorValueLabel_ = nullptr;
    QLabel* sessionIdValueLabel_ = nullptr;
    QLabel* ruleValueLabel_ = nullptr;
    QPushButton* allowButton_ = nullptr;
    QPushButton* denyButton_ = nullptr;
    QPushButton* detailButton_ = nullptr;
    QTimer* countdownTimer_ = nullptr;
};
