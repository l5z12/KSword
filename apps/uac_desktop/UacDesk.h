#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <evntcons.h>
#include <evntrace.h>
#include <QDateTime>
#include <QFileInfo>
#include <QIcon>
#include <QMainWindow>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVector>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <thread>

class QLabel;
class QEvent;
class QMouseEvent;
class QPushButton;

struct ProcessIdentity
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD sessionId = 0;
    quint64 creationTime = 0;
    QString imagePath;
    QString commandLine;
    QString fileDescription;

    bool isValid() const { return pid != 0 && creationTime != 0 && !imagePath.isEmpty(); }
};

struct UacApplicationIdentity
{
    HWND consentWindow = nullptr;
    QRect windowRect;
    QString displayName;
    QString publisher;
    QString imagePath;
    QString matchText;
    QString evidence;
    quint64 observedAtMs = 0;
    bool exact = false;
    bool isUac = false;
};

struct UacOriginEvidence
{
    ProcessIdentity origin;
    QString targetPath;
    DWORD consentPid = 0;
    DWORD appInfoPid = 0;
    DWORD bufferLength = 0;
    quintptr requestAddress = 0;
    DWORD originPidOffset = 0;
    DWORD targetPathOffset = 0;
    quint64 observedAtMs = 0;

    bool isValid() const
    {
        return origin.isValid() && consentPid != 0 && appInfoPid != 0 &&
               bufferLength >= 0x70 && requestAddress != 0;
    }
};

struct ProcessActionState
{
    ProcessIdentity origin;
    bool originResolved = false;
    QIcon originIcon;
    QString launchChain;
    QString integrityLevel;
    QString elevationType;
    QString startTime;
    QString runDuration;
    QString originSignature;
    QString targetSignature;
    ProcessIdentity target;
    bool unique = false;
    bool protectedProcess = true;
    QString reason;
};

class ProcessInspector final
{
public:
    static bool query(DWORD pid, ProcessIdentity& identity, DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION);
    static bool queryCommandLine(DWORD pid, QString& commandLine);
    static bool identityStillMatches(const ProcessIdentity& expected);
    static bool isProtectedName(const QString& imagePath);
    static bool suspend(const ProcessIdentity& expected, QString& error);
    static bool resume(const ProcessIdentity& expected, QString& error);
    static bool terminate(const ProcessIdentity& expected, QString& error);
    static QString fileName(const QString& path);

private:
    static bool queryCommandLine(HANDLE process, QString& commandLine);
};

class PrivilegeStage final
{
public:
    static void writeDiagnosticLog(const QString& message);
    static bool isProcessElevated();
    static bool isSystem();
    static bool hasUiAccess();
    static bool launchAdminStage(const QString& executable, const QStringList& args, QString& error);
    static bool launchSystemStage(const QString& executable, const QStringList& args, const QString& desktop,
                                  DWORD targetSession, QString& error);
    static QString currentDesktopName();
    static DWORD currentSessionId();
};

class UacEventMonitor final : public QObject
{
public:
    explicit UacEventMonitor(QObject* parent = nullptr);
    ~UacEventMonitor() override;

    void start();
    void stop();
    bool etwAvailable() const { return etwAvailable_; }
    std::optional<UacOriginEvidence> readConsentOrigin(DWORD sessionId);
    std::optional<ProcessIdentity> takeUacOrigin(DWORD sessionId, quint64 uacObservedAtMs,
                                                  const QString& targetPath);

    std::function<void()> onDesktopChanged;

private:
    struct EventItem
    {
        GUID provider{};
        DWORD eventId = 0;
        USHORT task = 0;
        UCHAR opcode = 0;
        DWORD pid = 0;
        HWND hwnd = nullptr;
        quint64 eventTimeMs = 0;
    };

    static void WINAPI winEventCallback(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG objectId,
                                        LONG childId, DWORD eventThreadId, DWORD eventTime);
    static void WINAPI etwEventCallback(PEVENT_RECORD record);
    static void etwEventCallbackImpl(PEVENT_RECORD record);
    void observeAlpc(bool receive, DWORD pid, DWORD tid, ULONG messageId, quint64 eventTimeMs);
    void startEtw();
    void startAlpcEtw();
    void stopEtw();
    void stopAlpcEtw();
    void consumeEvents();
    void pushEvent(const EventItem& item);

    QTimer consumeTimer_;
    HWINEVENTHOOK winEventHook_ = nullptr;
    HWINEVENTHOOK objectEventHook_ = nullptr;
    QMutex queueMutex_;
    QQueue<EventItem> events_;
    struct AlpcSendItem
    {
        ULONG messageId = 0;
        DWORD pid = 0;
        DWORD tid = 0;
        quint64 eventTimeMs = 0;
        quint64 observedAtMs = 0;
    };
    struct UacOriginItem
    {
        ULONG messageId = 0;
        DWORD clientPid = 0;
        DWORD clientTid = 0;
        DWORD appInfoPid = 0;
        quint64 eventTimeMs = 0;
        quint64 observedAtMs = 0;
    };
    QMutex alpcMutex_;
    QQueue<AlpcSendItem> alpcSends_;
    QQueue<UacOriginItem> uacOrigins_;
    std::atomic<DWORD> appInfoPid_{0};
    std::atomic<DWORD> consentPid_{0};
    std::atomic<quint64> lastConsentDiscoveryMs_{0};
    QMutex consentMutex_;
    QString lastOriginKey_;
    quint64 lastAppInfoPidRefreshMs_ = 0;
    std::atomic_bool running_{false};
    std::atomic_bool etwStop_{false};
    std::thread etwThread_;
    ULONG64 traceSession_ = 0;
    TRACEHANDLE traceHandle_ = 0;
    QString traceName_;
    std::thread alpcThread_;
    std::atomic_bool alpcStop_{false};
    std::atomic<ULONG64> alpcSession_{0};
    std::atomic<TRACEHANDLE> alpcTraceHandle_{0};
    std::atomic<ULONG> alpcLastStatus_{ERROR_SUCCESS};
    QString alpcTraceName_;
    bool etwAvailable_ = false;
};

class UacWindowScanner final
{
public:
    static UacApplicationIdentity scan();
    static BOOL CALLBACK enumChildProc(HWND hwnd, LPARAM lParam);

private:
    static BOOL CALLBACK enumWindowProc(HWND hwnd, LPARAM lParam);
    static QString readUiAutomationName(HWND hwnd);
};

class UacDeskWindow final : public QMainWindow
{
public:
    explicit UacDeskWindow(QWidget* parent = nullptr);
    ~UacDeskWindow() override;

    void setParentWatch(HANDLE processHandle, quint64 creationTime);
    void setInitialStatus(const QString& status);
    void notifyUacActivity();
    void refreshNow();
    void refreshAppearance();

private:
    void refreshUacState();
    void applyScanResult(const UacApplicationIdentity& identity, const ProcessActionState& actionState);
    void adjustToContent();
    void repositionBesideUac(const UacApplicationIdentity& identity);
    void updateButtons();
    void showStatus(const QString& status, bool error = false);
    void launchMainOnSecureDesktop();
    void launchPowerShellOnSecureDesktop();
    void runProcessAction(int action);
    void checkParent();
    static bool isAlive(HANDLE process);
    bool eventFilter(QObject* watched, QEvent* event) override;
    void changeEvent(QEvent* event) override;

    QWidget* brandHeader_ = nullptr;
    QLabel* originIconLabel_ = nullptr;
    QLabel* identityLabel_ = nullptr;
    QLabel* processLabel_ = nullptr;
    QPushButton* suspendButton_ = nullptr;
    QPushButton* terminateButton_ = nullptr;
    QPushButton* powerShellButton_ = nullptr;
    QPushButton* launchMainButton_ = nullptr;
    QTimer refreshTimer_;
    QTimer parentTimer_;
    QWidget* dragHandle_ = nullptr;
    bool dragging_ = false;
    QPoint dragOffset_;
    HWND positionedUacWindow_ = nullptr;
    std::atomic_bool scanRunning_{false};
    std::atomic_bool scanStop_{false};
    std::atomic<quint64> scanGeneration_{0};
    std::thread scanThread_;
    std::atomic_bool actionRunning_{false};
    std::atomic_bool launchRunning_{false};
    std::atomic_bool parentCheckRunning_{false};
    std::thread actionThread_;
    std::thread launchThread_;
    std::thread parentCheckThread_;
    quint64 fastPollUntilMs_ = 0;
    HANDLE parentProcess_ = nullptr;
    quint64 parentCreationTime_ = 0;
    ProcessActionState actionState_;
    UacApplicationIdentity identity_;
};

QString formatFileTime(quint64 fileTime);
quint64 processCreationTime(HANDLE process);
QString quoteArgument(const QString& value);
