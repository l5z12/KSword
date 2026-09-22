#pragma once

// ============================================================
// OnlineScanSupport.h
// Purpose:
// - Provides common UI, JSON, network error handling, and file utilities for VirusTotalOnlineScan and ThreatBookScan.
// - Unify the style of the scan result dialog to avoid transparency or black background issues when the theme changes in a standard QDialog.
// - Provides only stateless helper functions; does not initiate any network requests directly.
// ============================================================

#include <QByteArray>
#include <QJsonObject>
#include <QString>

class QNetworkReply;
class QWidget;

namespace ks::online_scan
{
    // kVirusTotalDirectUploadMaxBytes:
    // - The 32MB threshold for VirusTotal's official /api/v3/files direct upload interface;
    // - When exceeding this value, call /api/v3/files/upload_url to obtain a one-time upload URL.
    inline constexpr qint64 kVirusTotalDirectUploadMaxBytes = 32LL * 1024LL * 1024LL;

    // kVirusTotalLargeUploadMaxBytes:
    // - VirusTotal's official large file upload URL has a 650MB limit.
    // - If exceeded, the local system directly rejects the request to avoid initiating a request that is bound to fail.
    inline constexpr qint64 kVirusTotalLargeUploadMaxBytes = 650LL * 1024LL * 1024LL;

    // kThreatBookUploadMaxBytes:
    // - The official ThreatBook file/upload API requires single files to be no larger than 100MB.
    // - Validate this value before upload to avoid meaningless quota consumption and wait time.
    inline constexpr qint64 kThreatBookUploadMaxBytes = 100LL * 1024LL * 1024LL;

    // validateReadableFile:
    // - Validate that the input file path exists, is a regular file, and is readable; check the size limit if required.
    // - Called by the scan class before creating an upload task.
    // Parameter filePath: File path provided by the user.
    // Parameter maxBytes: maximum allowed bytes; values less than or equal to 0 indicate no upper limit check.
    // Parameter errorTextOut: Output for failure reason; may be null.
    // Returns: true = file is ready for upload; false = file is unreadable or exceeds the limit.
    bool validateReadableFile(const QString& filePath, qint64 maxBytes, QString* errorTextOut);

    // sanitizeFileNameForContentDisposition:
    // - Sanitize file names within multipart Content-Disposition headers;
    // - Prevent characters like quotes and slashes from corrupting HTTP form headers.
    // Parameter fileName: Original file name.
    // Returns: A filename safe to use in filename="...".
    QString sanitizeFileNameForContentDisposition(const QString& fileName);

    // parseJsonObjectFromBytes:
    // - Parse the HTTP response body into a JSON object;
    // - Returns an empty object on parse failure and writes the error text.
    // Input parameter bodyBytes: HTTP response body.
    // Parameter errorTextOut: Output for failure reason; may be null.
    // Returns: parsed JSON object; returns empty object on failure.
    QJsonObject parseJsonObjectFromBytes(const QByteArray& bodyBytes, QString* errorTextOut);

    // formatJsonObject:
    // - Format the JSON object into indented text;
    // - Used to display the raw scan results in the CodeEditorWidget.
    // Input parameter jsonObject: the object to be formatted.
    // Returns: UTF-8 JSON text.
    QString formatJsonObject(const QJsonObject& jsonObject);

    // networkReplyErrorText:
    // - Aggregate the HTTP status, Qt network error, and response body summary from QNetworkReply.
    // - Scan class reuses this for error dialogs and logs.
    // Input parameter reply: completed network response object.
    // Input parameter bodyBytes: The response body that has already been read.
    // Returns: An error message suitable for user reading.
    QString networkReplyErrorText(QNetworkReply* reply, const QByteArray& bodyBytes);

    // calculateSha256Hex:
    // - Streamingly compute the file's SHA-256 for use in ThreatBook query reports.
    // - Reads files in chunks even when large to avoid loading the entire sample into memory at once.
    // Input parameter filePath: file path to be hashed.
    // Parameter errorTextOut: Output for failure reason; may be null.
    // Returns: Lowercase hexadecimal SHA-256; returns an empty string on failure.
    QString calculateSha256Hex(const QString& filePath, QString* errorTextOut);

    // showMissingApiKeyDialog:
    // - If no corresponding API Key is set, show a dialog prompting the user to enter the Settings page to fill it in.
    // - Does not initiate any network requests.
    // Input parentWidget: parent window for the popup, may be null.
    // Parameter serviceName: service name, e.g., VirusTotal or ThreatBook.
    // Returns: Nothing.
    void showMissingApiKeyDialog(QWidget* parentWidget, const QString& serviceName);

    // showErrorDialog:
    // - Show online scan error with unified theme;
    // - Applicable to scenarios such as local verification, upload failure, and polling timeout.
    // Input parentWidget: parent window for the popup, may be null.
    // Input parameter titleText: dialog title.
    // Input parameter detailText: detailed error text.
    // Returns: Nothing.
    void showErrorDialog(QWidget* parentWidget, const QString& titleText, const QString& detailText);

    // showResultDialog:
    // - Display the online scan result JSON using the project's built-in CodeEditorWidget;
    // - Displays a summary at the top and the full raw response at the bottom for easy copying and searching.
    // Input parentWidget: parent window for the popup, may be null.
    // Input parameter titleText: dialog title.
    // Input summaryText: summary description text.
    // Parameter detailJsonText: formatted raw JSON text.
    // Returns: Nothing.
    void showResultDialog(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& summaryText,
        const QString& detailJsonText);
}
