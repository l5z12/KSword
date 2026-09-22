#pragma once

// ============================================================
// ThreatBookScan.h
// Purpose:
// - Declare the ThreatBook (Webscan) file scanning class.
// - After the caller provides a local file path, the class reads the API Key from settings, uploads the sample, queries the report by SHA-256, and displays a popup.
// - Currently, only capabilities are prepared; do not actively connect to the main window menu or file list entry.
// ============================================================

#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;
class QWidget;

// ThreatBookScan：
// - Input: File path and optional parent window passed to scanFile;
// - Processing: Read threatbook_api_key from settings, and call ThreatBook file/upload and file/report.
// - Output: feedback is provided via a popup dialog upon completion or failure; no synchronous scan result is returned.
class ThreatBookScan final : public QObject
{
public:
    // Constructor purpose:
    // - Create the network access manager;
    // - Do not read the API Key or initiate requests.
    // Usage: Instances can be created by future file context menu items or buttons.
    // Input parameter parent: the Qt parent object, which may be null.
    explicit ThreatBookScan(QObject* parent = nullptr);

    // Destructor purpose:
    // - Release network objects via the QObject parent-child mechanism;
    // If requests remain, Qt will disconnect callbacks upon object destruction.
    ~ThreatBookScan() override;

    // scanFile:
    // - Read the ThreatBook API Key from settings and upload the specified file.
    // - Poll for the report by SHA-256 after upload; display the result window upon completion.
    // Usage: scanner->scanFile(path, parentWidget).
    // Input filePath: Local file path.
    // Input dialogParent: parent control for the popup, may be null.
    // Return: None; asynchronous flow uses pop-up dialogs and kPro feedback.
    void scanFile(const QString& filePath, QWidget* dialogParent = nullptr);

    // scanFileAndAutoDelete:
    // - For convenient heap object creation, with automatic deleteLater after scanning completes;
    // - If the future UI entry does not wish to store member pointers, it can call this directly.
    // Invocation: ThreatBookScan::scanFileAndAutoDelete(path, parent).
    // Input filePath: Local file path.
    // Input dialogParent: parent control for the popup, may be null.
    // Returns: Nothing.
    static void scanFileAndAutoDelete(const QString& filePath, QWidget* dialogParent = nullptr);

private:
    // uploadFile:
    // - Use multipart/form-data to call ThreatBook file/upload;
    // - Continue querying the report by resource after a successful upload.
    // Return: None; asynchronous callback handleUploadReply.
    void uploadFile();

    // handleUploadReply:
    // - Parse file/upload response.
    // - Enter report polling upon success or if the sample already exists.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleUploadReply(QNetworkReply* reply);

    // scheduleReportPoll:
    // - Schedule the next file/report query.
    // - The initial query is also scheduled uniformly via this function.
    // Input parameter delayMs: delay in milliseconds.
    // Returns: Nothing.
    void scheduleReportPoll(int delayMs);

    // requestReport:
    // - Call ThreatBook file/report query for a specific SHA-256 report;
    // - If the server is still analyzing, scheduleReportPoll will continue to be called.
    // Returns: Nothing.
    void requestReport();

    // handleReportReply:
    // - Parse report query response.
    // - Display results upon completion; otherwise, continue polling or fail on timeout.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleReportReply(QNetworkReply* reply);

    // finishWithError:
    // - Unify the failure termination flow: update kPro, display an error dialog, and self-delete if needed.
    // Input parameter titleText: dialog title.
    // Input detailText: Error details.
    // Returns: Nothing.
    void finishWithError(const QString& titleText, const QString& detailText);

    // finishWithResult:
    // - Unified success completion flow: update kPro and display scan results.
    // - The result dialog uses CodeEditorWidget to display the complete JSON.
    // Parameter reportObject: Root object of the ThreatBook report JSON.
    // Returns: Nothing.
    void finishWithResult(const QJsonObject& reportObject);

    // resetRuntimeState:
    // - Clears leftover file paths, SHA-256 hashes, and polling counts from the previous scan;
    // - Do not clear the network manager object
    // Returns: Nothing.
    void resetRuntimeState();

    // completeProgress:
    // - Advance the current kPro task to 100% and clear the PID.
    // - Avoid duplicating progress bar completion logic for success/failure paths.
    // Input parameter messageText: The final task status to display.
    // Returns: Nothing.
    void completeProgress(const QString& messageText);

    // buildResultSummary:
    // - Extract summary and multiengines summary from ThreatBook report JSON;
    // - Human-readable description displayed at the top of the result dialog.
    // Parameter reportObject: Root object of the ThreatBook report JSON.
    // Return: Summary text.
    QString buildResultSummary(const QJsonObject& reportObject) const;

    // reportDataObject:
    // - Compatible with two forms in ThreatBook report responses: data is either the report object directly or grouped by hash.
    // - Subsequent summary extraction will uniformly access this object.
    // Parameter reportObject: Root object of the ThreatBook report JSON.
    // Returns: extracted report data object; returns an empty object if missing.
    QJsonObject reportDataObject(const QJsonObject& reportObject) const;

private:
    QNetworkAccessManager* networkManager_ = nullptr; // Network request manager responsible for all ThreatBook HTTP calls.
    QPointer<QWidget> dialogParent_;                  // Dialog parent widget; prevents dangling references if the parent is destroyed early.
    QString filePath_;                                // Local file path currently pending upload.
    QString apiKey_;                                  // ThreatBook API Key read during the current scan.
    QString sha256Text_;                              // Current sample SHA-256, used for file/report resources.
    int progressPid_ = 0;                             // kPro task PID; 0 indicates no active progress task.
    int pollAttempt_ = 0;                             // Current polling count, used for timeout control.
    bool scanInProgress_ = false;                     // Whether a scan process is currently running for this object.
    bool autoDeleteWhenFinished_ = false;             // Whether to automatically call deleteLater after the scan completes.
};
