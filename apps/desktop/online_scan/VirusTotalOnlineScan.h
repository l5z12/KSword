#pragma once

// ============================================================
// VirusTotalOnlineScan.h
// Purpose:
// - Declare the VirusTotal multi-API online analysis console.
// - Caller passes local file path, source text, and initial API; the class reads the API Key from settings.
// - Standard analysis uploads samples and polls /analyses/{id}; other APIs query file profiles, IOCs, and sandbox behaviors locally using SHA256.
// - All results are displayed in a multi-tab popup and support exporting all raw API responses.
// ============================================================

#include <QByteArray>
#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QUrl>

#include <array>
#include <functional>

class QDialog;
class QGroupBox;
class QLabel;
class QLineEdit;
class QNetworkAccessManager;
class QNetworkReply;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTextBrowser;
class QTreeWidget;
class QWidget;
class CodeEditorWidget;

// VirusTotalOnlineScan：
// - Input: File path, source text, initial API, and optional parent window passed when calling scanFile;
// - Processing: Read the virustotal_api_key from settings and execute VirusTotal v3 API requests for upload, profiling, IOC, sandbox, and HTML report generation serially.
// - Output: Completion, no data, or failure are all reported in the multi-API result window; no synchronous scan result is returned.
class VirusTotalOnlineScan final : public QObject
{
public:
    // VtApiKind:
    // - Describe the top-level tabs of the VirusTotal multi-API console.
    // - Note: Callers use this enum to determine which analysis page to switch to after the window opens.
    enum class VtApiKind
    {
        kShallowAnalysis = 0, // Standard analysis: upload sample and poll /analyses/{id}.
        kFileProfile = 1,    // File profile: GET /files/{sha256}.
        kIoc = 2,            // IOC: Common relationships for GET /files/{sha256}/{relationship}.
        kSandbox = 3,        // Sandbox: behaviour_summary, behaviours, and HTML report.
        kAllApis = 4,        // Special entry: triggers all APIs sequentially, not corresponding to a fixed top-level tab.
    };

    // VtApiState:
    // - Records the current request state for each top-level tab.
    // - The UI displays 'Start Analysis', 'Running', 'Completed', 'No Data', or 'Failed' based on the status.
    enum class VtApiState
    {
        kNotStarted,
        kHashing,
        kRunning,
        kCompleted,
        kEmpty,
        kFailed,
    };

    // Constructor purpose:
    // - Create the network access manager;
    // - Do not read the API Key or initiate requests.
    // Usage: Instances can be created by future file context menu items or buttons.
    // Input parameter parent: the Qt parent object, which may be null.
    explicit VirusTotalOnlineScan(QObject* parent = nullptr);

    // Destructor purpose:
    // - Release network objects via the QObject parent-child mechanism;
    // If requests remain, Qt will disconnect callbacks upon object destruction.
    ~VirusTotalOnlineScan() override;

    // scanFile:
    // - Read the VirusTotal API Key from settings and upload the specified file.
    // - Open the real-time results window immediately upon receiving the upload response, and continuously append the raw JSON from analysis polling;
    // - sourceText identifies the caller, e.g., "Process List PID=1234".
    // Call pattern: scanner->scanFile(path, sourceText, parentWidget).
    // Input filePath: Local file path.
    // Parameter sourceText: upload source description; if empty, automatically use the generic source text.
    // Input dialogParent: parent control for the popup, may be null.
    // Return: None; the asynchronous flow uses the real-time results window and kPro feedback.
    void scanFile(const QString& filePath, const QString& sourceText, QWidget* dialogParent = nullptr);

    // scanFile:
    // - Multi-API entry version, additionally accepts initialApi.
    // - initialApi determines which top-level Tab the result window initially switches to, and which API starts automatically on the first run;
    // - AllApis starts ordinary analysis, file profiling, IOC detection, and sandboxing sequentially.
    // Input filePath/sourceText/dialogParent: same as the old overload.
    // Input parameter initialApi: initial analysis type.
    // Returns: Nothing.
    void scanFile(
        const QString& filePath,
        const QString& sourceText,
        VtApiKind initialApi,
        QWidget* dialogParent = nullptr);

    // scanFile:
    // - Maintain compatibility with legacy callers: when only the file path is provided, use the default source text.
    // Input filePath: Local file path.
    // Input dialogParent: parent control for the popup, may be null.
    // Returns: void; internally forwards to the overload with sourceText.
    void scanFile(const QString& filePath, QWidget* dialogParent = nullptr);

    // scanFileAndAutoDelete:
    // - For convenient heap object creation, with automatic deleteLater after scanning completes;
    // - If the future UI entry does not wish to store member pointers, it can call this directly.
    // Invocation: VirusTotalOnlineScan::scanFileAndAutoDelete(path, source, parent).
    // Input filePath: Local file path.
    // Input parameter sourceText: description of the upload source.
    // Input dialogParent: parent control for the popup, may be null.
    // Returns: Nothing.
    static void scanFileAndAutoDelete(
        const QString& filePath,
        const QString& sourceText,
        QWidget* dialogParent = nullptr);

    // scanFileAndAutoDelete:
    // - Multi-API entry version; object lifetime rules after completion are consistent with the old version.
    // Parameter initialApi: the API type to start or switch to after opening the window.
    // Returns: Nothing.
    static void scanFileAndAutoDelete(
        const QString& filePath,
        const QString& sourceText,
        VtApiKind initialApi,
        QWidget* dialogParent = nullptr);

    // scanFileAndAutoDelete:
    // - Maintain compatibility with legacy callers: when only the file path is provided, use the default source text.
    // Input filePath: Local file path.
    // Input dialogParent: parent control for the popup, may be null.
    // Returns: Nothing.
    static void scanFileAndAutoDelete(const QString& filePath, QWidget* dialogParent = nullptr);

private:
    // requestLargeUploadUrl:
    // - Request a VirusTotal one-time large file upload URL when the sample exceeds 32MB.
    // - Continue calling uploadFileToUrl upon success.
    // Return: None; asynchronous callback handleUploadUrlReply.
    void requestLargeUploadUrl();

    // uploadFileToUrl:
    // - Upload the current file to the specified URL using multipart/form-data;
    // - Use /api/v3/files for small files; use the upload_url return value for large files.
    // Input parameter uploadUrl: the target upload URL.
    // Return: None; asynchronous callback handleUploadReply.
    void uploadFileToUrl(const QUrl& uploadUrl);

    // handleUploadUrlReply:
    // - Parse the response from /api/v3/files/upload_url;
    // - Extracts the 'data' field as the actual upload URL.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleUploadUrlReply(QNetworkReply* reply);

    // handleUploadReply:
    // - Parse file upload response.
    // - Extracts the analysis ID and enters the polling phase.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleUploadReply(QNetworkReply* reply);

    // scheduleAnalysisPoll:
    // - Schedule the next analysis status poll.
    // - Schedule the initial poll through this function as well to avoid duplicate logic.
    // Input parameter delayMs: delay in milliseconds.
    // Returns: Nothing.
    void scheduleAnalysisPoll(int delayMs);

    // requestAnalysisStatus:
    // - Calls VirusTotal /api/v3/analyses/{id} to query analysis status;
    // - If the task is not completed, scheduleAnalysisPoll will continue to be called.
    // Returns: Nothing.
    void requestAnalysisStatus();

    // handleAnalysisReply:
    // - Parse analysis status response.
    // - Display results on completion; otherwise, continue polling or fail on timeout.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleAnalysisReply(QNetworkReply* reply);

    // ensureLocalHashes:
    // - Computes local MD5/SHA1/SHA256 for non-upload APIs;
    // - If a hash already exists, enter the target API directly; otherwise, place it in a background thread.
    // Parameter nextApi: The API to start after hash completion.
    // Returns: Nothing.
    void ensureLocalHashes(VtApiKind nextApi);

    // handleLocalHashesReady:
    // - Receive background hash calculation results and wake up waiting APIs;
    // - Mark waiting tabs as failed on error.
    // Input md5Text/sha1Text/sha256Text: computed hexadecimal hashes.
    // Input parameter errorText: reason for failure; empty indicates success.
    // Returns: Nothing.
    void handleLocalHashesReady(
        const QString& md5Text,
        const QString& sha1Text,
        const QString& sha256Text,
        const QString& errorText);

    // startApiAnalysis:
    // - Starts the corresponding VT API based on the primary Tab type.
    // - Standard analysis uses upload/polling; other APIs first ensure local SHA256.
    // Parameter apiKind: Target API.
    // Returns: Nothing.
    void startApiAnalysis(VtApiKind apiKind);

    // startAllApis:
    // - Start all APIs sequentially
    // - Avoid excessive concurrent requests in Public API scenarios.
    // Returns: Nothing.
    void startAllApis();

    // requestFileProfile:
    // - Note: Calls GET /api/v3/files/{sha256} to retrieve the file profile.
    // Returns: Nothing.
    void requestFileProfile();

    // handleFileProfileReply:
    // - Parses the file profile response and refreshes the 'File Profile' tab.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleFileProfileReply(QNetworkReply* reply);

    // requestNextIocRelationship:
    // - Serially request common IOC relationships.
    // - Continue to the next relationship after each response.
    // Returns: Nothing.
    void requestNextIocRelationship();

    // startSingleIocRelationship:
    // - Start a single relationship request from an item-specific button in the IOC report view;
    // - When another VT request is running, only record pending relationships without disrupting the currently executing full IOC queue.
    // Input relationshipText: VT files relationship name.
    // Returns: Nothing.
    void startSingleIocRelationship(const QString& relationshipText);

    // handleIocRelationshipReply:
    // - Save a single IOC relationship response and decide whether to continue.
    // Input parameter relationshipText: The current relationship name.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleIocRelationshipReply(const QString& relationshipText, QNetworkReply* reply);

    // requestSandboxSummary:
    // - Start sandbox behavior analysis: first request behaviour_summary, then request behaviours.
    // Returns: Nothing.
    void requestSandboxSummary();

    // handleSandboxSummaryReply:
    // - Save the behaviour_summary response and proceed to request behaviours.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleSandboxSummaryReply(QNetworkReply* reply);

    // requestSandboxBehaviours:
    // - Request GET /files/{sha256}/behaviours to retrieve the single sandbox list.
    // Returns: Nothing.
    void requestSandboxBehaviours();

    // handleSandboxBehavioursReply:
    // - Save the behaviours response and refresh the Sandbox tab.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleSandboxBehavioursReply(QNetworkReply* reply);

    // requestSandboxHtmlReport:
    // - Fetch the HTML report for a single file_behaviour;
    // - HTML content enters the sandbox Tab raw data and report tree summary.
    // Parameter behaviourId: the ID of the file_behaviour object.
    // Returns: Nothing.
    void requestSandboxHtmlReport(const QString& behaviourId);

    // requestNextSandboxHtmlReport:
    // - Serially fetch available HTML reports when "All APIs" or the button is triggered;
    // - End sandbox API when the queue is empty.
    // Returns: Nothing.
    void requestNextSandboxHtmlReport();

    // handleSandboxHtmlReply:
    // - Save the HTML report response.
    // Parameter behaviourId: the ID of the file_behaviour object.
    // Input reply: Qt network response object.
    // Returns: Nothing.
    void handleSandboxHtmlReply(const QString& behaviourId, QNetworkReply* reply);

    // finishWithError:
    // - Unified failure termination flow: update kPro, write to the real-time results window, and self-delete if needed.
    // Input parameter titleText: dialog title.
    // Input detailText: Error details.
    // Returns: Nothing.
    void finishWithError(const QString& titleText, const QString& detailText);

    // finishWithResult:
    // - Unify the success completion flow: update kPro and refresh the real-time result window summary.
    // - The original JSON is appended to the window upon each response arrival.
    // Parameter analysisObject: the root object of the VirusTotal analysis JSON.
    // Returns: Nothing.
    void finishWithResult(const QJsonObject& analysisObject);

    // ensureResultDialog:
    // - Ensure the real-time results dialog is created and displayed.
    // - Upload response, analysis response, and error response all call this function first before appending content.
    // Returns: Nothing.
    void ensureResultDialog();

    // selectApiTab:
    // - Switch the primary tab to the specified API.
    // - AllApis switches to the standard analysis tab.
    // Parameter apiKind: Target API.
    // Returns: Nothing.
    void selectApiTab(VtApiKind apiKind);

    // setApiState:
    // - Update the state of a top-level tab and refresh the visibility of the Start button;
    // - All API start, completion, and failure states converge UI state through this function.
    // Parameters apiKind/apiState/statusText: target API, state, and optional status text.
    // Returns: Nothing.
    void setApiState(VtApiKind apiKind, VtApiState apiState, const QString& statusText = QString());

    // refreshApiPlaceholder:
    // - Refresh the report view placeholder content when not started, running, empty, or failed.
    // - Overridden by specific refreshXxxResult functions upon completion.
    // Parameters apiKind/statusText: target API and status text.
    // Returns: Nothing.
    void refreshApiPlaceholder(VtApiKind apiKind, const QString& statusText = QString());

    // hasActiveApiOperation:
    // - Check if a VT API request or local hash task is currently running.
    // - When the user manually clicks other APIs, this triggers entry into a serial wait queue to avoid overwhelming the Public API with concurrent calls.
    // Returns: true if at least one API is running or computing a hash; false if the next item can be started immediately.
    bool hasActiveApiOperation() const;

    // startNextQueuedAllApi:
    // - serial queue driver function for "pass all APIs" and user-manually queued APIs;
    // - Called after the current API completes or fails to start the next queued item.
    // Returns: Nothing.
    void startNextQueuedAllApi();

    // scheduleRetryAfterRateLimit:
    // - Unified serial retry for VirusTotal 429/quota rate-limit responses.
    // - Reads the Retry-After response header; uses a conservative default wait time if missing.
    // - Keep the corresponding API Pane in the Running state during retries to prevent other VT requests from interleaving concurrently.
    // Input parameter apiKind: the rate-limited level-1 API.
    // Input retryKey: a stable endpoint key used for counting to prevent infinite retries on the same endpoint.
    // Input parameter reply: The network response containing the HTTP status and Retry-After header.
    // Input statusText: throttling wait description displayed in the report view.
    // Input retryAction: callback to reissue the same request when the scheduled time arrives.
    // Returns: true = retry scheduled; false = not rate-limited or retry limit exceeded.
    bool scheduleRetryAfterRateLimit(
        VtApiKind apiKind,
        const QString& retryKey,
        QNetworkReply* reply,
        const QString& statusText,
        std::function<void()> retryAction);

    // appendRawJsonSection:
    // - Append a raw VirusTotal JSON response to the real-time window;
    // - titleText is used to label stages such as upload_url, upload, analysis, and error.
    // Input parameter titleText: section title.
    // Input parameter jsonObject: The raw JSON object.
    // Returns: Nothing.
    void appendRawJsonSection(const QString& titleText, const QJsonObject& jsonObject);

    // appendRawJsonSection:
    // - For multiple API versions, append the response to the 'Response Details / Raw Data' tab of the specified top-level tab.
    // - In older versions, this is appended to the standard analysis tab by default.
    // Input parameter apiKind: target top-level tab.
    // Parameters titleText/jsonObject: response title and JSON.
    // Returns: Nothing.
    void appendRawJsonSection(VtApiKind apiKind, const QString& titleText, const QJsonObject& jsonObject);

    // appendRawJsonSection:
    // - Handle: Include HTTP metadata version; write fields such as http_status and retry_after into the exported JSON.
    // - The JSON body maintains the original VT structure without mixing HTTP metadata into the body itself.
    // Input parameter responseMetadata: HTTP metadata generated by replyHttpMetadataObject, which may be null.
    // Returns: Nothing.
    void appendRawJsonSection(
        VtApiKind apiKind,
        const QString& titleText,
        const QJsonObject& jsonObject,
        const QJsonObject& responseMetadata);

    // appendRawTextSection:
    // - Append non-JSON error details or local diagnostics to the live window;
    // - Used for network errors, parsing errors, and timeout details.
    // Input parameter titleText: section title.
    // Input parameter detailText: raw/diagnostic text.
    // Returns: Nothing.
    void appendRawTextSection(const QString& titleText, const QString& detailText);

    // appendRawTextSection:
    // - Multi-API version, appends text/errors to the specified top-level tab.
    // Input parameter apiKind: target top-level tab.
    // Returns: Nothing.
    void appendRawTextSection(VtApiKind apiKind, const QString& titleText, const QString& detailText);

    // appendRawTextSection:
    // - With HTTP metadata version; used for error text, HTML reports, and other non-JSON responses.
    // - Preserve the text body during export while separately saving the HTTP status.
    // Input parameter responseMetadata: HTTP metadata, which may be null.
    // Returns: Nothing.
    void appendRawTextSection(
        VtApiKind apiKind,
        const QString& titleText,
        const QString& detailText,
        const QJsonObject& responseMetadata);

    // appendRawReplyBodySection:
    // - Write the complete HTTP response body to the real-time window and exported JSON.
    // - If the response body is a JSON object, save it according to the JSON structure; otherwise, save it as UTF-8 text.
    // - Used for network error and parsing failure paths to avoid displaying only a truncated error summary.
    // Input titleText: section title, typically containing the API path and the semantics of 'raw response body'.
    // Parameter bodyBytes: the complete response body obtained via QNetworkReply::readAll().
    // Returns: None; empty response body is recorded with explicit placeholder text.
    void appendRawReplyBodySection(const QString& titleText, const QByteArray& bodyBytes);

    // appendRawReplyBodySection:
    // - Support multiple API versions; save HTTP raw response bodies as JSON or text.
    // Input parameter apiKind: target top-level tab.
    // Returns: Nothing.
    void appendRawReplyBodySection(VtApiKind apiKind, const QString& titleText, const QByteArray& bodyBytes);

    // appendRawReplyBodySection:
    // - Include HTTP metadata version; synchronously save the status code when the error response body is parsed as JSON or text;
    // - Enables each exported API response to be traced back to the HTTP layer result.
    // Input parameter responseMetadata: HTTP metadata, which may be null.
    // Returns: Nothing.
    void appendRawReplyBodySection(
        VtApiKind apiKind,
        const QString& titleText,
        const QByteArray& bodyBytes,
        const QJsonObject& responseMetadata);

    // updateResultSummary:
    // - Update the summary at the top of the live window;
    // - The result body is not lost; only the status text at the top of the window changes.
    // Input summaryText: new summary text.
    // Returns: Nothing.
    void updateResultSummary(const QString& summaryText);

    // buildRawExportJson:
    // - Package real-time window cumulative raw responses, error text, and upload context into UTF-8 JSON.
    // - The responses field preserves the raw content for each upload_url/upload/analysis/error.
    // - raw_text field retains the original text displayed in the window for character-by-character manual troubleshooting.
    // Returns: UTF-8 document bytes directly writable to a .json file.
    QByteArray buildRawExportJson() const;

    // finalizeAutoDeleteIfNeeded:
    // - Unified handling of the lifecycle of temporary objects created by scanFileAndAutoDelete after scan success or failure.
    // If the real-time results window is still displayed, wait for it to close before calling deleteLater to avoid accessing a released object in button callbacks.
    // Returns: None; only modifies object lifecycle markers.
    void finalizeAutoDeleteIfNeeded();

    // resetRuntimeState:
    // - Clean up file paths, analysis IDs, and polling counts left over from the previous scan.
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
    // - Extract stats summary from VirusTotal analysis JSON;
    // - Human-readable description displayed at the top of the result dialog.
    // Parameter analysisObject: the root object of the VirusTotal analysis JSON.
    // Return: Summary text.
    QString buildResultSummary(const QJsonObject& analysisObject) const;

    // refreshReadableResult:
    // - Convert VirusTotal's fixed-structure analysis response into a readable page.
    // - Refresh summary, file hash, statistics, and multi-engine detection tables without affecting the original JSON page.
    // Parameter analysisObject: the root object returned by /api/v3/analyses/{id}.
    // Returns: Nothing.
    void refreshReadableResult(const QJsonObject& analysisObject);

    // refreshFileProfileResult:
    // - Converts GET /files/{sha256} file profile to a report tree.
    // Parameter fileObject: VT file object JSON.
    // Returns: Nothing.
    void refreshFileProfileResult(const QJsonObject& fileObject);

    // refreshIocResult:
    // - Convert the requested IOC relationship results into a report tree.
    // Returns: Nothing.
    void refreshIocResult();

    // refreshSandboxResult:
    // - Convert sandbox summary, sandbox list, and HTML report status into a report tree;
    // Returns: Nothing.
    void refreshSandboxResult();

    // showSandboxHtmlPreview:
    // - Render the HTML report for the specified file_behaviour within the 'Sandbox -> Report View';
    // - Displays readable text when there is an error or no HTML, avoiding the need for users to inspect the raw data page for responses.
    // Parameter behaviourId: the ID of the file_behaviour object.
    // Returns: Nothing.
    void showSandboxHtmlPreview(const QString& behaviourId);

    // appendResponseTreeJsonSection:
    // - Append a JSON response to the 'Response Details' tree;
    // - Tree nodes are expandable to facilitate viewing VT response fields layer by layer.
    // Input titleText: the response phase title.
    // Input parameter timestampText: The UTC timestamp.
    // Input parameter jsonObject: The raw JSON object.
    // Returns: Nothing.
    void appendResponseTreeJsonSection(
        VtApiKind apiKind,
        const QString& titleText,
        const QString& timestampText,
        const QJsonObject& jsonObject);

    // appendResponseTreeTextSection:
    // - Append error text or non-JSON responses to the 'Response Details' tree;
    // - Used for network errors, parsing failures, and local validation errors.
    // Input titleText: the response phase title.
    // Input parameter timestampText: The UTC timestamp.
    // Input parameter detailText: error or response text.
    // Returns: Nothing.
    void appendResponseTreeTextSection(
        VtApiKind apiKind,
        const QString& titleText,
        const QString& timestampText,
        const QString& detailText);

private:
    static constexpr int kApiPaneCount = 4;

    // LocalHashContext:
    // - Save local sample hash and background calculation status;
    // - For non-upload APIs, use sha256 as the /files/{id} parameter.
    struct LocalHashContext
    {
        QString md5Text;
        QString sha1Text;
        QString sha256Text;
        bool ready = false;
        bool running = false;
    };

    // ApiPaneUi:
    // - Saves a second-level tab control within a first-level API tab;
    // - Each Pane statically includes the report view, response details, and raw data.
    struct ApiPaneUi
    {
        QPointer<QTabWidget> detailTabWidget;
        QPointer<QLabel> overviewLabel;
        QPointer<QPushButton> startButton;
        QPointer<QPushButton> sandboxHtmlButton;
        QPointer<QLineEdit> fileProfileFilterEdit;
        QPointer<QTableWidget> fileInfoTable;
        QPointer<QTableWidget> engineTable;
        QPointer<QTreeWidget> reportTree;
        QPointer<QGroupBox> sandboxHtmlPreviewGroup;
        QPointer<QTextBrowser> sandboxHtmlPreview;
        QPointer<QTreeWidget> responseTree;
        QPointer<CodeEditorWidget> rawEditor;
    };

    QNetworkAccessManager* networkManager_ = nullptr; // Network request manager responsible for all VirusTotal HTTP calls.
    QPointer<QWidget> dialogParent_;                  // Dialog parent widget; prevents dangling references if the parent is destroyed early.
    QPointer<QDialog> resultDialog_;                  // Real-time results window: displays immediately upon upload response arrival.
    QPointer<QLabel> resultSummaryLabel_;             // Real-time result summary label displaying source, file, status, and analysis ID.
    QPointer<QTabWidget> resultTabWidget_;            // Level-1 result tabs: Normal analysis, file profiling, IOC, and sandbox.
    QPointer<QLabel> readableOverviewLabel_;          // Readable page summary, displaying status, source, analysis ID, and conclusion.
    QPointer<QTableWidget> fileInfoTable_;            // Readable page file information table, displaying hash, size, and VT item links.
    QPointer<QTableWidget> engineTable_;              // Readable page engine details table, displaying classification and hit names for each engine.
    QPointer<QTreeWidget> staticAnalysisTree_;        // Read-only page static analysis tree displaying basic info, analysis tasks, and statistics fields.
    QPointer<QTreeWidget> responseTree_;              // Response detail page, expanding each VT response in a tree structure.
    QPointer<CodeEditorWidget> resultEditor_;         // Real-time result raw data editor displaying all responses and error text.
    std::array<ApiPaneUi, kApiPaneCount> apiPanes_;    // UI controls for multi-API level-1 tabs.
    std::array<VtApiState, kApiPaneCount> apiStates_{}; // Multiple API states, all defaulting to NotStarted.
    std::array<QString, kApiPaneCount> apiRawText_;    // Raw text for each API Tab.
    std::array<QJsonArray, kApiPaneCount> apiRawSections_; // Structured raw response for each API tab.
    QString filePath_;                                // Local file path currently pending upload.
    QString sourceText_;                              // Current upload source description, used for result window summary and export context.
    QString resultRawText_;                           // Accumulated raw response/error text for display and export.
    QJsonArray resultRawSections_;                    // Currently accumulated structured raw response/error sections, provided for JSON export.
    LocalHashContext localHashes_;                     // Local sample hashes; reused by upper-layer APIs.
    QList<VtApiKind> pendingHashApis_;                 // APIs to be started after hash completion.
    QList<VtApiKind> allApiQueue_;                     // Serial queue for 'pass all APIs'.
    QList<VtApiKind> deferredApiQueue_;                // API queue deferred by manual user click due to an existing VT request running.
    QStringList deferredSingleIocRelationships_;       // Queue of IOC items manually clicked by the user, independent of the full IOC queue.
    QJsonObject fileProfileObject_;                    // GET /files/{sha256} latest response.
    QJsonObject iocRelationshipObjects_;               // relationship -> Original response.
    QStringList iocRelationshipQueue_;                 // IOC relationship serialization request queue.
    QJsonObject sandboxSummaryObject_;                 // behaviour_summary: Latest response.
    QJsonObject sandboxBehavioursObject_;              // behaviours: Latest response.
    QJsonObject sandboxHtmlReports_;                   // behaviour_id -> HTML text/error metadata.
    QStringList sandboxHtmlQueue_;                     // Queue of file_behaviour HTML IDs to be fetched.
    bool sandboxHtmlFetchQueued_ = false;              // Indicates whether the HTML report fetch is deferred due to an active VT request.
    QHash<QString, int> vtRateLimitRetryCounts_;       // VT 429 retry count, keyed by API/endpoint, to prevent infinite retries.
    QString apiKey_;                                  // VirusTotal API Key read during the current scan.
    QString settingsJsonPath_;                         // Path to the settings file containing the API Key read at runtime, used for security diagnostics only.
    QString analysisId_;                              // The analysis ID returned after upload, used for polling results.
    int progressPid_ = 0;                             // kPro task PID; 0 indicates no active progress task.
    int pollAttempt_ = 0;                             // Current polling count, used for timeout control.
    bool scanInProgress_ = false;                     // Whether a scan process is currently running for this object.
    bool allApisMode_ = false;                         // Whether the serial flow is currently driven by 'pass all APIs'.
    bool dispatchingQueuedApi_ = false;                // Whether an API is currently being started by the internal serial queue to avoid re-queuing.
    bool autoDeleteWhenFinished_ = false;             // Whether to automatically call deleteLater after the scan completes.
    bool deleteAfterResultDialogClosed_ = false;      // Wait for the real-time result dialog to close before self-deleting after the scan finishes.
};
