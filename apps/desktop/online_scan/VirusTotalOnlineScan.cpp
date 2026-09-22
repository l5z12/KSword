#include "VirusTotalOnlineScan.h"
#include "../ui/VisibleTableWidget.h"

#include "OnlineScanSupport.h"
#include "../Framework.h"
#include "../settings_dock/AppearanceSettings.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHttpMultiPart>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScrollArea>
#include <QSizePolicy>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextBrowser>
#include <QThreadPool>
#include <QTabWidget>
#include <QTimer>
#include <QTimeZone>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <vector>

namespace
{
    // VirusTotal API constants: centrally maintain official v3 endpoints to avoid scattering them across business logic.
    constexpr const char* kVirusTotalFilesEndpoint = "https://www.virustotal.com/api/v3/files";
    constexpr const char* kVirusTotalFilesEndpointPrefix = "https://www.virustotal.com/api/v3/files/";
    constexpr const char* kVirusTotalLargeUploadUrlEndpoint = "https://www.virustotal.com/api/v3/files/upload_url";
    constexpr const char* kVirusTotalAnalysisEndpointPrefix = "https://www.virustotal.com/api/v3/analyses/";
    constexpr const char* kVirusTotalFileBehaviourEndpointPrefix = "https://www.virustotal.com/api/v3/file_behaviours/";
    constexpr int kInitialPollDelayMs = 15000;
    constexpr int kPollIntervalMs = 15000;
    constexpr int kMaxPollAttempts = 40;
    constexpr int kMaxRateLimitRetryAttempts = 2;
    constexpr int kDefaultRateLimitRetryDelayMs = 60000;
    constexpr int kMaxRateLimitRetryDelayMs = 300000;

    // setVirusTotalHeaders:
    // - Uniformly add API Key and User-Agent to VirusTotal requests;
    // - Content-Type is handled automatically by QHttpMultiPart or Qt and is not set here.
    // Input request: the request object to be modified.
    // Input parameter apiKey: the API Key configured by the user.
    // Returns: Nothing.
    void setVirusTotalHeaders(QNetworkRequest* request, const QString& apiKey)
    {
        if (request == nullptr)
        {
            return;
        }
        request->setRawHeader("x-apikey", apiKey.toUtf8());
        request->setRawHeader("User-Agent", "Ksword5.1-OnlineScan/1.0");
    }

    // replyHttpStatusCode:
    // - Read the HTTP status code from the Qt network response;
    // Unified handling of missing attribute scenarios to avoid repeating boilerplate code in each VT API handler.
    // Input reply: Completed QNetworkReply, may be null.
    // Returns: The HTTP status code; returns 0 if unknown.
    int replyHttpStatusCode(QNetworkReply* reply)
    {
        if (reply == nullptr)
        {
            return 0;
        }
        const QVariant kStatusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        return kStatusCodeVariant.isValid() ? kStatusCodeVariant.toInt() : 0;
    }

    // replyRetryAfterText:
    // - Read the Retry-After response header that may be returned by the VirusTotal/API gateway;
    // - Used to write executable wait information to the UI and exported JSON during 429 rate limiting.
    // Input reply: Completed QNetworkReply, may be null.
    // Returns: Raw Retry-After header text; empty string if the header is absent.
    QString replyRetryAfterText(QNetworkReply* reply)
    {
        if (reply == nullptr || !reply->hasRawHeader("Retry-After"))
        {
            return QString();
        }
        return QString::fromLatin1(reply->rawHeader("Retry-After")).trimmed();
    }

    // rateLimitRetryDelayMs:
    // - Convert the VirusTotal Retry-After header to milliseconds;
    // - Public APIs commonly return values in seconds; if parsing fails, use a conservative default wait time.
    // - Set a maximum wait limit to prevent the UI from appearing frozen for too long.
    // Input parameter reply: The completed 429 response, which may be null.
    // Returns: Wait time in milliseconds for QTimer.
    int rateLimitRetryDelayMs(QNetworkReply* reply)
    {
        const QString kRetryAfterText = replyRetryAfterText(reply);
        bool numberOk = false;
        const int kRetryAfterSeconds = kRetryAfterText.toInt(&numberOk);
        if (numberOk && kRetryAfterSeconds > 0)
        {
            return std::clamp(
                kRetryAfterSeconds * 1000,
                1000,
                kMaxRateLimitRetryDelayMs);
        }
        return kDefaultRateLimitRetryDelayMs;
    }

    // formatWaitSecondsText:
    // - Compress the millisecond wait time into UI status text.
    // - Returns at least 1 second to avoid displaying "Retry in 0 seconds".
    // Parameter delayMs: wait duration in milliseconds.
    // Returns: Chinese seconds text.
    QString formatWaitSecondsText(const int delayMs)
    {
        return QStringLiteral("%1 秒").arg(std::max(1, (delayMs + 999) / 1000));
    }

    // replyHttpMetadataObject:
    // - Archive HTTP layer status, Reason-Phrase, and Retry-After into structured JSON;
    // - Every VT API response is exported along with the raw data to facilitate troubleshooting rate limiting, authentication, 404, etc.
    // Input reply: Completed QNetworkReply, may be null.
    // Return: Object containing http_status/http_reason/retry_after; omit fields if unreadable.
    QJsonObject replyHttpMetadataObject(QNetworkReply* reply)
    {
        QJsonObject metadataObject;
        const int kStatusCode = replyHttpStatusCode(reply);
        if (kStatusCode > 0)
        {
            metadataObject.insert(QStringLiteral("http_status"), kStatusCode);
        }

        if (reply != nullptr)
        {
            const QVariant kReasonVariant = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
            const QString kReasonText = kReasonVariant.isValid()
                ? kReasonVariant.toString().trimmed()
                : QString();
            if (!kReasonText.isEmpty())
            {
                metadataObject.insert(QStringLiteral("http_reason"), kReasonText);
            }

            const QString kRetryAfterText = replyRetryAfterText(reply);
            if (!kRetryAfterText.isEmpty())
            {
                metadataObject.insert(QStringLiteral("retry_after"), kRetryAfterText);
            }
        }
        return metadataObject;
    }

    // virusTotalErrorObjectFromBody:
    // - Extract the error object from the VirusTotal v3 error response body;
    // - Only read the JSON object without modifying the original response body, facilitating subsequent exports that preserve the original VT structure.
    // Parameter bodyBytes: the complete response body read by QNetworkReply::readAll.
    // Returns: error object; if the response body is not JSON or lacks an error field, return an empty object.
    QJsonObject virusTotalErrorObjectFromBody(const QByteArray& bodyBytes)
    {
        if (bodyBytes.isEmpty())
        {
            return QJsonObject();
        }

        QJsonParseError parseError;
        const QJsonDocument kJsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
        if (parseError.error != QJsonParseError::NoError || !kJsonDocument.isObject())
        {
            return QJsonObject();
        }
        return kJsonDocument.object().value(QStringLiteral("error")).toObject();
    }

    // virusTotalResponseMetadataObject:
    // - Supplement VirusTotal error.code/message on top of HTTP metadata;
    // - The report page, response details, and exported JSON all directly display authentication, permission, and quota categories.
    // Input parameters reply/bodyBytes: completed network response and full response body.
    // Returns: An object containing HTTP fields and an optional vt_error field.
    QJsonObject virusTotalResponseMetadataObject(QNetworkReply* reply, const QByteArray& bodyBytes)
    {
        QJsonObject metadataObject = replyHttpMetadataObject(reply);
        const QJsonObject kErrorObject = virusTotalErrorObjectFromBody(bodyBytes);
        if (!kErrorObject.isEmpty())
        {
            metadataObject.insert(QStringLiteral("vt_error"), kErrorObject);
            const QString kErrorCode = kErrorObject.value(QStringLiteral("code")).toString().trimmed();
            if (!kErrorCode.isEmpty())
            {
                metadataObject.insert(QStringLiteral("vt_error_code"), kErrorCode);
            }
        }
        return metadataObject;
    }

    // maskedApiKeyText:
    // - Generate a secure diagnostic text for the API Key, exposing only its length and a few characters from the start and end.
    // - Never return the full key to prevent key leakage via logs, screenshots, or exported files.
    // Input parameter apiKey: The VirusTotal API Key read at runtime.
    // Returns: e.g., "length=64, masked=abcd...1234"; returns "empty" if null.
    QString maskedApiKeyText(const QString& apiKey)
    {
        const QString kTrimmedKey = apiKey.trimmed();
        if (kTrimmedKey.isEmpty())
        {
            return QStringLiteral("空");
        }
        if (kTrimmedKey.size() <= 8)
        {
            return QStringLiteral("长度=%1，掩码=<过短，已隐藏>").arg(kTrimmedKey.size());
        }
        return QStringLiteral("长度=%1，掩码=%2...%3")
            .arg(kTrimmedKey.size())
            .arg(kTrimmedKey.left(4), kTrimmedKey.right(4));
    }

    // virusTotalErrorDiagnosisText:
    // - Translate common VirusTotal error codes into actionable troubleshooting suggestions.
    // - Distinguish between 'Key error', 'Insufficient permissions/package', and 'Public API quota limit'.
    // Input parameter statusCode: The HTTP status code.
    // Input vtErrorCode: VT error.code, e.g., WrongCredentialsError.
    // Returns: Chinese diagnosis for UI; returns empty string if unable to determine.
    QString virusTotalErrorDiagnosisText(const int statusCode, const QString& vtErrorCode)
    {
        const QString kNormalizedCode = vtErrorCode.trimmed();
        if (kNormalizedCode == QStringLiteral("WrongCredentialsError"))
        {
            return QStringLiteral("诊断：VirusTotal 判定当前 x-apikey 无效。这通常不是免费版权限不足，而是 Key 输错、复制了旧 Key、账号/Key 被撤销，或程序读取到了错误配置文件。");
        }
        if (kNormalizedCode == QStringLiteral("AuthenticationRequiredError") || statusCode == 401)
        {
            return QStringLiteral("诊断：请求未通过 VirusTotal 认证。请确认设置中已保存 VT v3 API Key，并确认程序实际读取的是同一个配置文件。");
        }
        if (kNormalizedCode == QStringLiteral("ForbiddenError") || statusCode == 403)
        {
            return QStringLiteral("诊断：认证已到达服务端，但当前 Key 没有访问该端点的权限。Public/免费 Key 对部分 IOC、沙箱或高级行为接口可能不可用。");
        }
        if (kNormalizedCode == QStringLiteral("QuotaExceededError") ||
            kNormalizedCode == QStringLiteral("TooManyRequestsError") ||
            statusCode == 429)
        {
            return QStringLiteral("诊断：VirusTotal 配额或频率限制。Public API 常见限制较低，连续触发多个 API 时需要等待后重试。");
        }
        if (kNormalizedCode == QStringLiteral("NotFoundError") || statusCode == 404)
        {
            return QStringLiteral("诊断：VT 暂无该 hash/对象的数据，或该关系端点没有可返回结果。");
        }
        return QString();
    }

    // shouldAppendAuthDiagnostics:
    // - Determine whether the current VT error requires displaying the key mask and setting path.
    // - NotFoundError/404 indicates 'no data available' and should not be mixed into authentication diagnostics to avoid misleading users into thinking the key is invalid.
    // Input parameters statusCode/vtErrorCode: HTTP status code and VT error.code.
    // Returns: true = append authentication/quota diagnostics; false = do not append.
    bool shouldAppendAuthDiagnostics(const int statusCode, const QString& vtErrorCode)
    {
        const QString kNormalizedCode = vtErrorCode.trimmed();
        return statusCode == 401 ||
            statusCode == 403 ||
            statusCode == 429 ||
            kNormalizedCode == QStringLiteral("WrongCredentialsError") ||
            kNormalizedCode == QStringLiteral("AuthenticationRequiredError") ||
            kNormalizedCode == QStringLiteral("ForbiddenError") ||
            kNormalizedCode == QStringLiteral("QuotaExceededError") ||
            kNormalizedCode == QStringLiteral("TooManyRequestsError");
    }

    // virusTotalAuthDiagnosticsText:
    // - Generate an authentication context that does not leak the full key.
    // - Used for 401/403/429 and VT error responses to help locate which settings JSON was read.
    // Input parameters apiKey/settingsJsonPath: the key and settings file path read at runtime.
    // Returns: Multi-line diagnostic text.
    QString virusTotalAuthDiagnosticsText(const QString& apiKey, const QString& settingsJsonPath)
    {
        QStringList lines;
        lines << QStringLiteral("认证诊断：");
        lines << QStringLiteral("- 请求头：x-apikey");
        lines << QStringLiteral("- 当前 Key：%1").arg(maskedApiKeyText(apiKey));
        lines << QStringLiteral("- 设置读取路径：%1").arg(QDir::toNativeSeparators(settingsJsonPath));
        return lines.join(QChar('\n'));
    }

    // virusTotalNetworkErrorText:
    // - Wrap the generic network error text.
    // - Distinguish between Key errors, insufficient permissions, and Public API rate limits to avoid conflating 401/403/429 errors.
    // Input reply/bodyBytes: failed response and full response body.
    // Input parameters apiKey/settingsJsonPath: used for secure diagnostics; do not output the full key.
    // Return: Error details suitable for UI display and archival of raw data pages.
    QString virusTotalNetworkErrorText(
        QNetworkReply* reply,
        const QByteArray& bodyBytes,
        const QString& apiKey,
        const QString& settingsJsonPath)
    {
        QString errorText = ks::online_scan::networkReplyErrorText(reply, bodyBytes);
        const int kStatusCode = replyHttpStatusCode(reply);
        const QJsonObject kVtErrorObject = virusTotalErrorObjectFromBody(bodyBytes);
        const QString kVtErrorCode = kVtErrorObject.value(QStringLiteral("code")).toString().trimmed();
        const QString kVtErrorMessage = kVtErrorObject.value(QStringLiteral("message")).toString().trimmed();
        if (!kVtErrorCode.isEmpty())
        {
            errorText += QStringLiteral("\nVirusTotal 错误码：%1").arg(kVtErrorCode);
        }
        if (!kVtErrorMessage.isEmpty())
        {
            errorText += QStringLiteral("\nVirusTotal 错误消息：%1").arg(kVtErrorMessage);
        }

        const QString kDiagnosisText = virusTotalErrorDiagnosisText(kStatusCode, kVtErrorCode);
        if (!kDiagnosisText.isEmpty())
        {
            errorText += QLatin1Char('\n') + kDiagnosisText;
        }

        if (shouldAppendAuthDiagnostics(kStatusCode, kVtErrorCode))
        {
            errorText += QLatin1Char('\n') + virusTotalAuthDiagnosticsText(apiKey, settingsJsonPath);
        }

        if (kStatusCode == 429)
        {
            const QString kRetryAfterText = replyRetryAfterText(reply);
            errorText += QStringLiteral("\nVirusTotal 返回 429：请求被限流。");
            if (!kRetryAfterText.isEmpty())
            {
                errorText += QStringLiteral("\nRetry-After：%1").arg(kRetryAfterText);
            }
            else
            {
                errorText += QStringLiteral("\nRetry-After：响应头未提供。");
            }
        }
        return errorText;
    }

    // endpointTextFromTitle:
    // - Extract stable endpoint field from response section title;
    // - Exporting JSON requires an independent endpoint; subsequent scripts should not be required to parse it from a Chinese title.
    // Input parameter titleText: e.g., 'GET /api/v3/files/{sha256} File Profile'.
    // Returns: e.g., 'GET /api/v3/files/{sha256}'; returns the original title if unrecognized.
    QString endpointTextFromTitle(const QString& titleText)
    {
        const QString kTrimmedTitle = titleText.trimmed();
        static const QRegularExpression kEndpointExpression(QStringLiteral("^(GET|POST|PUT|PATCH|DELETE|HEAD)\\s+([^\\s]+)"));
        const QRegularExpressionMatch kEndpointMatch = kEndpointExpression.match(kTrimmedTitle);
        if (kEndpointMatch.hasMatch())
        {
            return kEndpointMatch.captured(1) + QLatin1Char(' ') + kEndpointMatch.captured(2);
        }
        return kTrimmedTitle;
    }

    // apiIndex:
    // - Map VtApiKind to array index;
    // - AllApis is not a real Pane; it is merged into the standard analysis index to avoid out-of-bounds access.
    // Parameter apiKind: API type.
    // Return value: Pane index in the range 0..3.
    int apiIndex(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::kFileProfile:
            return 1;
        case VirusTotalOnlineScan::VtApiKind::kIoc:
            return 2;
        case VirusTotalOnlineScan::VtApiKind::kSandbox:
            return 3;
        case VirusTotalOnlineScan::VtApiKind::kShallowAnalysis:
        case VirusTotalOnlineScan::VtApiKind::kAllApis:
        default:
            return 0;
        }
    }

    // paneApiKinds:
    // - Uniformly return the correct primary tab order.
    // - UI creation, export, and cleanup states all use this order.
    // Returns: A fixed set of 4 Pane APIs.
    std::array<VirusTotalOnlineScan::VtApiKind, 4> paneApiKinds()
    {
        return {
            VirusTotalOnlineScan::VtApiKind::kShallowAnalysis,
            VirusTotalOnlineScan::VtApiKind::kFileProfile,
            VirusTotalOnlineScan::VtApiKind::kIoc,
            VirusTotalOnlineScan::VtApiKind::kSandbox,
        };
    }

    // apiTitleText:
    // - Returns the human-readable name for the top-level tab and button.
    // Parameter apiKind: API type.
    // Returns: Chinese name.
    QString apiTitleText(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::kFileProfile:
            return QStringLiteral("文件画像");
        case VirusTotalOnlineScan::VtApiKind::kIoc:
            return QStringLiteral("IOC");
        case VirusTotalOnlineScan::VtApiKind::kSandbox:
            return QStringLiteral("沙箱");
        case VirusTotalOnlineScan::VtApiKind::kAllApis:
            return QStringLiteral("全部API");
        case VirusTotalOnlineScan::VtApiKind::kShallowAnalysis:
        default:
            return QStringLiteral("普通分析");
        }
    }

    // apiExportKey:
    // - Returns the stable API key from the exported JSON.
    // - Facilitates subsequent scripts reading by fixed key.
    // Parameter apiKind: API type.
    // Return: ASCII key.
    QString apiExportKey(const VirusTotalOnlineScan::VtApiKind apiKind)
    {
        switch (apiKind)
        {
        case VirusTotalOnlineScan::VtApiKind::kFileProfile:
            return QStringLiteral("file_profile");
        case VirusTotalOnlineScan::VtApiKind::kIoc:
            return QStringLiteral("ioc");
        case VirusTotalOnlineScan::VtApiKind::kSandbox:
            return QStringLiteral("sandbox");
        case VirusTotalOnlineScan::VtApiKind::kAllApis:
            return QStringLiteral("all_apis");
        case VirusTotalOnlineScan::VtApiKind::kShallowAnalysis:
        default:
            return QStringLiteral("shallow_analysis");
        }
    }

    // apiStateText:
    // - Convert internal state to report view hint text.
    // Input parameter apiState: current state.
    // Returns: Chinese status text.
    QString apiStateText(const VirusTotalOnlineScan::VtApiState apiState)
    {
        switch (apiState)
        {
        case VirusTotalOnlineScan::VtApiState::kHashing:
            return QStringLiteral("正在计算本地 Hash");
        case VirusTotalOnlineScan::VtApiState::kRunning:
            return QStringLiteral("正在请求 VirusTotal");
        case VirusTotalOnlineScan::VtApiState::kCompleted:
            return QStringLiteral("已完成");
        case VirusTotalOnlineScan::VtApiState::kEmpty:
            return QStringLiteral("VT 暂无该类数据");
        case VirusTotalOnlineScan::VtApiState::kFailed:
            return QStringLiteral("失败");
        case VirusTotalOnlineScan::VtApiState::kNotStarted:
        default:
            return QStringLiteral("未开始");
        }
    }

    // iocRelationships:
    // - Returns the default set of common IOC relationships.
    // - The order determines the report view display order and the serial request order.
    // Returns: a list of relationships.
    QStringList iocRelationships()
    {
        return QStringList()
            << QStringLiteral("contacted_ips")
            << QStringLiteral("contacted_domains")
            << QStringLiteral("contacted_urls")
            << QStringLiteral("dropped_files")
            << QStringLiteral("bundled_files")
            << QStringLiteral("execution_parents");
    }

    // relationshipDisplayText:
    // - Converts VT relationship keys to UI section names.
    // Input parameter relationshipText: VT relationship key.
    // Returns: Chinese partition name.
    QString relationshipDisplayText(const QString& relationshipText)
    {
        if (relationshipText == QStringLiteral("contacted_ips"))
        {
            return QStringLiteral("连接 IP");
        }
        if (relationshipText == QStringLiteral("contacted_domains"))
        {
            return QStringLiteral("连接域名");
        }
        if (relationshipText == QStringLiteral("contacted_urls"))
        {
            return QStringLiteral("连接 URL");
        }
        if (relationshipText == QStringLiteral("dropped_files"))
        {
            return QStringLiteral("释放文件");
        }
        if (relationshipText == QStringLiteral("bundled_files"))
        {
            return QStringLiteral("打包文件");
        }
        if (relationshipText == QStringLiteral("execution_parents"))
        {
            return QStringLiteral("执行父样本");
        }
        return relationshipText;
    }

    // jsonValueCompactText:
    // - Extract a single-line summary suitable for a table or tree node from any JSON value;
    // - IOC and sandbox lists must avoid embedding full objects into a single cell.
    // Parameter jsonValue: Source JSON value.
    // Returns: A one-line summary text.
    QString jsonValueCompactText(const QJsonValue& jsonValue)
    {
        if (jsonValue.isString())
        {
            return jsonValue.toString();
        }
        if (jsonValue.isDouble() || jsonValue.isBool() || jsonValue.isNull())
        {
            if (jsonValue.isBool())
            {
                return jsonValue.toBool() ? QStringLiteral("true") : QStringLiteral("false");
            }
            if (jsonValue.isDouble())
            {
                return QString::number(jsonValue.toDouble());
            }
            return QStringLiteral("null");
        }
        if (jsonValue.isObject())
        {
            const QJsonObject kObjectValue = jsonValue.toObject();
            const QString kIdText = kObjectValue.value(QStringLiteral("id")).toString();
            if (!kIdText.isEmpty())
            {
                return kIdText;
            }
            const QJsonObject kAttributesObject = kObjectValue.value(QStringLiteral("attributes")).toObject();
            const QString kNameText = kAttributesObject.value(QStringLiteral("meaningful_name")).toString();
            if (!kNameText.isEmpty())
            {
                return kNameText;
            }
            return QStringLiteral("{ %1 fields }").arg(kObjectValue.size());
        }
        if (jsonValue.isArray())
        {
            return QStringLiteral("[ %1 items ]").arg(jsonValue.toArray().size());
        }
        return QStringLiteral("-");
    }

    // jsonValueToInt:
    // - Safely read integer values from VirusTotal stats;
    // - Compatible with missing JSON fields or type anomalies.
    // Input parameter objectValue: The JSON object.
    // Input parameter keyText: the field name.
    // Returns: Integer value of the field; returns 0 if missing.
    int jsonValueToInt(const QJsonObject& objectValue, const QString& keyText)
    {
        return objectValue.value(keyText).toInt(0);
    }

    // utcTimestampText:
    // - Generate the timestamp for the original response section;
    // - Output uses ISO format for timeline analysis after exporting to JSON/TXT.
    // Returns: Current UTC time string.
    QString utcTimestampText()
    {
        return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    }

    // fileDisplayText:
    // - Generate the file description at the top of the real-time results window;
    // - Handle cases where the path is empty or QFileInfo cannot parse the filename.
    // Input filePath: Local sample path.
    // Returns: User-readable text combining the file name and path.
    QString fileDisplayText(const QString& filePath)
    {
        const QFileInfo kFileInfo(filePath);
        const QString kFileName = kFileInfo.fileName().isEmpty()
            ? QStringLiteral("<未知文件>")
            : kFileInfo.fileName();
        return QStringLiteral("%1\n%2").arg(kFileName, QDir::toNativeSeparators(filePath));
    }

    // formatByteCount:
    // - Convert VT/local file byte counts into compact human-readable text.
    // - The UI uses this for the headline and basic information table.
    // Input byteCount: raw byte count; negative means unknown.
    // Return: formatted size text, or "-" when unavailable.
    QString formatByteCount(const qint64 byteCount)
    {
        if (byteCount < 0)
        {
            return QStringLiteral("-");
        }
        if (byteCount < 1024)
        {
            return QStringLiteral("%1 B").arg(byteCount);
        }

        const double kKibValue = static_cast<double>(byteCount) / 1024.0;
        if (kKibValue < 1024.0)
        {
            return QStringLiteral("%1 KB").arg(kKibValue, 0, 'f', 2);
        }

        const double kMibValue = kKibValue / 1024.0;
        if (kMibValue < 1024.0)
        {
            return QStringLiteral("%1 MB").arg(kMibValue, 0, 'f', 2);
        }

        const double kGibValue = kMibValue / 1024.0;
        return QStringLiteral("%1 GB").arg(kGibValue, 0, 'f', 2);
    }

    // unixDateText:
    // - Format VT epoch seconds into local time text.
    // - Unknown or zero timestamps are rendered as "-".
    // Input secondsValue: seconds since Unix epoch.
    // Return: local date/time string.
    QString unixDateText(const qint64 secondsValue)
    {
        if (secondsValue <= 0)
        {
            return QStringLiteral("-");
        }
        return QDateTime::fromSecsSinceEpoch(secondsValue, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    }

    // jsonPrimitiveText:
    // - Convert a primitive JSON value into a short display string for tables/trees.
    // - Objects and arrays are represented by shape markers because children carry details.
    // Input jsonValue: VT JSON value.
    // Return: user-readable scalar value.
    QString jsonPrimitiveText(const QJsonValue& jsonValue)
    {
        if (jsonValue.isString())
        {
            return jsonValue.toString();
        }
        if (jsonValue.isBool())
        {
            return jsonValue.toBool() ? QStringLiteral("true") : QStringLiteral("false");
        }
        if (jsonValue.isDouble())
        {
            const double kNumberValue = jsonValue.toDouble();
            const qint64 kIntegerValue = static_cast<qint64>(kNumberValue);
            if (qFuzzyCompare(kNumberValue + 1.0, static_cast<double>(kIntegerValue) + 1.0))
            {
                return QString::number(kIntegerValue);
            }
            return QString::number(kNumberValue, 'f', 4);
        }
        if (jsonValue.isNull())
        {
            return QStringLiteral("null");
        }
        if (jsonValue.isUndefined())
        {
            return QStringLiteral("<undefined>");
        }
        if (jsonValue.isArray())
        {
            return QStringLiteral("[Array]");
        }
        if (jsonValue.isObject())
        {
            return QStringLiteral("{Object}");
        }
        return QString();
    }

    // categoryText:
    // - Localize VirusTotal engine result category into concise Chinese text.
    // - Unknown categories are preserved so new VT values remain visible.
    // Input categoryTextValue: VT category string.
    // Return: localized category label.
    QString categoryText(const QString& categoryTextValue)
    {
        const QString kNormalizedText = categoryTextValue.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("malicious"))
        {
            return QStringLiteral("恶意");
        }
        if (kNormalizedText == QStringLiteral("suspicious"))
        {
            return QStringLiteral("可疑");
        }
        if (kNormalizedText == QStringLiteral("harmless"))
        {
            return QStringLiteral("无害");
        }
        if (kNormalizedText == QStringLiteral("undetected"))
        {
            return QStringLiteral("无检出");
        }
        if (kNormalizedText == QStringLiteral("timeout"))
        {
            return QStringLiteral("超时");
        }
        if (kNormalizedText == QStringLiteral("confirmed-timeout"))
        {
            return QStringLiteral("确认超时");
        }
        if (kNormalizedText == QStringLiteral("failure"))
        {
            return QStringLiteral("失败");
        }
        if (kNormalizedText == QStringLiteral("type-unsupported"))
        {
            return QStringLiteral("类型不支持");
        }
        return categoryTextValue.trimmed().isEmpty() ? QStringLiteral("-") : categoryTextValue.trimmed();
    }

    // categoryPriority:
    // - Sort engine rows by analyst importance.
    // - Detections appear first, then weak/unknown states, then clean results.
    // Input categoryTextValue: VT category string.
    // Return: lower value sorts earlier.
    int categoryPriority(const QString& categoryTextValue)
    {
        const QString kNormalizedText = categoryTextValue.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("malicious"))
        {
            return 0;
        }
        if (kNormalizedText == QStringLiteral("suspicious"))
        {
            return 1;
        }
        if (kNormalizedText == QStringLiteral("failure") ||
            kNormalizedText == QStringLiteral("timeout") ||
            kNormalizedText == QStringLiteral("confirmed-timeout"))
        {
            return 2;
        }
        if (kNormalizedText == QStringLiteral("undetected"))
        {
            return 3;
        }
        if (kNormalizedText == QStringLiteral("harmless"))
        {
            return 4;
        }
        return 5;
    }

    // categoryColor:
    // - Map VT categories to visible semantic colors.
    // - Colors are used only as foreground hints and keep table text readable.
    // Input categoryTextValue: VT category string.
    // Return: QColor; invalid color means default palette foreground.
    QColor categoryColor(const QString& categoryTextValue)
    {
        const QString kNormalizedText = categoryTextValue.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("malicious"))
        {
            return ksword_theme::errorColor();
        }
        if (kNormalizedText == QStringLiteral("suspicious"))
        {
            return ksword_theme::warningColor();
        }
        if (kNormalizedText == QStringLiteral("failure") ||
            kNormalizedText == QStringLiteral("timeout") ||
            kNormalizedText == QStringLiteral("confirmed-timeout"))
        {
            return ksword_theme::warningColor();
        }
        if (kNormalizedText == QStringLiteral("undetected") ||
            kNormalizedText == QStringLiteral("harmless"))
        {
            return ksword_theme::successColor();
        }
        return QColor();
    }

    // engineDetectionText:
    // - Compress VirusTotal single-engine category/result into short text suitable for a two-engine layout on the report page.
    // - Malicious/Suspicious items uniformly display 'Detected: XXX'; Undetected/Safe items display a short status; Exceptional states retain diagnostic semantics.
    // Input categoryTextValue: the category field returned by VT.
    // Input parameter resultTextValue: the 'result' field returned by VT.
    // Returns: Short text for the 'Multi-Engine Detection' result column.
    QString engineDetectionText(const QString& categoryTextValue, const QString& resultTextValue)
    {
        const QString kNormalizedText = categoryTextValue.trimmed().toLower();
        const QString kTrimmedResultText = resultTextValue.trimmed();
        if (kNormalizedText == QStringLiteral("malicious") ||
            kNormalizedText == QStringLiteral("suspicious"))
        {
            return QStringLiteral("检出：%1").arg(kTrimmedResultText.isEmpty()
                ? categoryText(categoryTextValue)
                : kTrimmedResultText);
        }
        if (kNormalizedText == QStringLiteral("undetected"))
        {
            return QStringLiteral("未检出");
        }
        if (kNormalizedText == QStringLiteral("harmless"))
        {
            return QStringLiteral("安全");
        }
        if (kNormalizedText == QStringLiteral("timeout") ||
            kNormalizedText == QStringLiteral("confirmed-timeout"))
        {
            return QStringLiteral("超时");
        }
        if (kNormalizedText == QStringLiteral("failure"))
        {
            return QStringLiteral("失败");
        }
        if (kNormalizedText == QStringLiteral("type-unsupported"))
        {
            return QStringLiteral("不支持");
        }
        return kTrimmedResultText.isEmpty() ? categoryText(categoryTextValue) : kTrimmedResultText;
    }

    struct ReportVerdict
    {
        QString labelText;     // One of the four conclusion categories displayed at the top of the report.
        QString iconPath;      // Path to the SVG icon in qrc.
        QColor accentColor;    // Text accent color.
    };

    // reportVerdictFromStats:
    // - Compress VirusTotal stats into the four user-requested verdict categories: Threat, Suspicious, Safe, and Not Detected.
    // - Malicious takes highest priority, followed by suspicious; if neither malicious nor suspicious but harmless is present, it is considered safe; otherwise, it is undetected.
    // Input parameters maliciousCount/suspiciousCount/harmlessCount: corresponding counts from VT stats.
    // Returns: Copy, icon, and accent color used at the top of the report.
    ReportVerdict reportVerdictFromStats(
        const int maliciousCount,
        const int suspiciousCount,
        const int harmlessCount)
    {
        if (maliciousCount > 0)
        {
            return {
                QStringLiteral("威胁"),
                QStringLiteral(":/Icon/vt_status_threat.svg"),
                ksword_theme::errorColor(),
            };
        }
        if (suspiciousCount > 0)
        {
            return {
                QStringLiteral("可疑"),
                QStringLiteral(":/Icon/vt_status_suspicious.svg"),
                ksword_theme::warningColor(),
            };
        }
        if (harmlessCount > 0)
        {
            return {
                QStringLiteral("安全"),
                QStringLiteral(":/Icon/vt_status_safe.svg"),
                ksword_theme::successColor(),
            };
        }
        return {
            QStringLiteral("未检出"),
            QStringLiteral(":/Icon/vt_status_undetected.svg"),
            ksword_theme::infoColor(),
        };
    }

    // createReadOnlyTableItem:
    // - Create a non-editable table item with optional semantic color.
    // - All result tables are display-only, so this helper centralizes flags/tooltips.
    // Input textValue: cell text.
    // Input foregroundColor: optional foreground color.
    // Return: newly allocated QTableWidgetItem owned by the table after setItem().
    QTableWidgetItem* createReadOnlyTableItem(const QString& textValue, const QColor& foregroundColor = QColor())
    {
        QTableWidgetItem* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(textValue);
        if (foregroundColor.isValid())
        {
            item->setForeground(QBrush(foregroundColor));
        }
        return item;
    }

    // configureReadOnlyTable:
    // - Apply common read-only behavior to VT result tables.
    // - Keeps interaction predictable across overview, engine and detail tables.
    // Input table: table widget to configure.
    // Return: no value.
    void configureReadOnlyTable(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setHighlightSections(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setWordWrap(false);
    }

    // configureBorderlessInfoTable:
    // - Adjust QTableWidget to achieve the 'text info block' effect for the report page.
    // - Hide the header, grid lines, and border, keeping only the two columns for fields and values.
    // Input table: target table.
    // Returns: Nothing.
    void configureBorderlessInfoTable(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        ks::ui::setTableActionBarMode(table, ks::ui::TableActionBarMode::kNone);
        configureReadOnlyTable(table);
        table->setFrameShape(QFrame::NoFrame);
        table->setShowGrid(false);
        table->setFocusPolicy(Qt::NoFocus);
        table->horizontalHeader()->setVisible(false);
        table->verticalHeader()->setVisible(false);
        table->verticalHeader()->setDefaultSectionSize(18);
        table->verticalHeader()->setMinimumSectionSize(16);
        table->setSelectionMode(QAbstractItemView::NoSelection);
        table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    }

    // fitTableHeightToRows:
    // - Calculate the minimum/maximum height of the QTableWidget based on the current row height;
    // - Used for compact text blocks like basic information to prevent whitespace from making line spacing appear loose.
    // Input table: Table requiring height compression.
    // Returns: Nothing.
    void fitTableHeightToRows(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        int totalHeight = table->frameWidth() * 2 + 2;
        if (table->horizontalHeader() != nullptr && table->horizontalHeader()->isVisible())
        {
            totalHeight += table->horizontalHeader()->height();
        }
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            totalHeight += table->rowHeight(rowIndex);
        }
        table->setMinimumHeight(totalHeight);
        table->setMaximumHeight(totalHeight);
    }

    // setTableRow:
    // - Write a two-column key/value row into a QTableWidget.
    // - It grows the table when needed and keeps cells read-only.
    // Input table: target table.
    // Input rowIndex: target row.
    // Input keyText: left column label.
    // Input valueText: right column value.
    // Return: no value.
    void setTableRow(QTableWidget* table, const int rowIndex, const QString& keyText, const QString& valueText)
    {
        if (table == nullptr)
        {
            return;
        }
        if (table->rowCount() <= rowIndex)
        {
            table->setRowCount(rowIndex + 1);
        }
        table->setItem(rowIndex, 0, createReadOnlyTableItem(keyText));
        table->setItem(rowIndex, 1, createReadOnlyTableItem(valueText));
        table->setRowHeight(rowIndex, 18);
    }

    // visibleTableRowText:
    // - Concatenate all visible columns of the current table row into TSV.
    // - Preserve column order when copying via right-click for easy pasting into tickets, Excel, or text records.
    // Input parameter table: the source table.
    // Input rowIndex: Row index to copy.
    // Returns: TSV text; returns an empty string if the input is invalid.
    QString visibleTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList cellTexts;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (table->isColumnHidden(columnIndex))
            {
                continue;
            }
            QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            cellTexts << (item == nullptr ? QString() : item->text());
        }
        return cellTexts.join(QChar('\t'));
    }

    // visibleTreeItemText:
    // - Concatenate all visible columns of the current tree node row into TSV;
    // - Both report details and response details use a tree control; this function ensures consistent copy behavior;
    // Input tree: source tree control.
    // Input parameter item: the node to copy.
    // Returns: TSV text; returns an empty string if the input is invalid.
    QString visibleTreeItemText(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        if (tree == nullptr || item == nullptr)
        {
            return QString();
        }

        QStringList cellTexts;
        for (int columnIndex = 0; columnIndex < tree->columnCount(); ++columnIndex)
        {
            if (tree->isColumnHidden(columnIndex))
            {
                continue;
            }
            cellTexts << item->text(columnIndex);
        }
        return cellTexts.join(QChar('\t'));
    }

    // treeItemContainsFilterText:
    // - Check if all columns of the tree item contain the filter text.
    // - The file profile page filter matches both 'fields' and 'values' to avoid missing results when users only know PE field values.
    // Input parameter item: The tree node to be checked.
    // Parameter filterText: The filter text has already been trimmed.
    // Returns: true if any column of the current node matches; false if the current node does not match.
    bool treeItemContainsFilterText(QTreeWidgetItem* item, const QString& filterText)
    {
        if (item == nullptr || filterText.isEmpty())
        {
            return filterText.isEmpty();
        }

        const QTreeWidget* tree = item->treeWidget();
        const int kColumnCount = tree != nullptr ? tree->columnCount() : item->columnCount();
        for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
        {
            if (item->text(columnIndex).contains(filterText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // applyTreeItemFilter:
    // - Recursively filter tree nodes, retaining matched nodes and their parent chains.
    // - Automatically expands parent nodes when a child matches, ensuring filter results are immediately visible.
    // Input parameter item: the current tree node.
    // Input parameter filterText: already trimmed filter text; if empty, restore display.
    // Return value: true if the current node or any child node is visible; false if the entire subtree does not match.
    bool applyTreeItemFilter(QTreeWidgetItem* item, const QString& filterText)
    {
        if (item == nullptr)
        {
            return false;
        }

        bool childVisible = false;
        for (int childIndex = 0; childIndex < item->childCount(); ++childIndex)
        {
            childVisible = applyTreeItemFilter(item->child(childIndex), filterText) || childVisible;
        }

        const bool kSelfVisible = treeItemContainsFilterText(item, filterText);
        const bool kVisible = filterText.isEmpty() || kSelfVisible || childVisible;
        item->setHidden(!kVisible);
        if (!filterText.isEmpty() && kVisible && childVisible)
        {
            item->setExpanded(true);
        }
        return kVisible;
    }

    // applyTreeFilter:
    // - Apply filtering to the top-level nodes of QTreeWidget;
    // - Control node visibility only without deleting original report nodes, allowing full restoration after clearing the filter.
    // Input tree: target report tree.
    // Input filterText: User-provided filter text.
    // Returns: Nothing.
    void applyTreeFilter(QTreeWidget* tree, const QString& filterText)
    {
        if (tree == nullptr)
        {
            return;
        }

        const QString kNormalizedFilterText = filterText.trimmed();
        for (int topIndex = 0; topIndex < tree->topLevelItemCount(); ++topIndex)
        {
            applyTreeItemFilter(tree->topLevelItem(topIndex), kNormalizedFilterText);
        }
    }

    // copyTextToClipboard:
    // - Copy the cell/row selected by the user via right-click in the VT report page to the system clipboard.
    // - Ignores empty text directly to avoid accidentally clearing existing clipboard content.
    // Input text: text to copy.
    // Returns: Nothing.
    void copyTextToClipboard(const QString& text)
    {
        if (text.isEmpty())
        {
            return;
        }
        QClipboard* clipboardObject = QApplication::clipboard();
        if (clipboardObject != nullptr)
        {
            clipboardObject->setText(text);
        }
    }

    // installTableCopyMenu:
    // - Install a right-click context menu for 'copy cell/copy current row' on the VT report page table.
    // - Only copy data, do not change the analysis status or trigger network requests.
    // Input table: target table.
    // Returns: Nothing.
    void installTableCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
            {
                QTableWidgetItem* clickedItem = table->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    table->setCurrentCell(clickedItem->row(), clickedItem->column());
                }

                QMenu contextMenu(table);
                contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
                QAction* copyCellAction = contextMenu.addAction(QStringLiteral("复制单元格"));
                QAction* copyRowAction = contextMenu.addAction(QStringLiteral("复制当前行"));
                const bool kHasItem = clickedItem != nullptr || table->currentItem() != nullptr;
                copyCellAction->setEnabled(kHasItem);
                copyRowAction->setEnabled(kHasItem);

                QAction* selectedAction = contextMenu.exec(table->viewport()->mapToGlobal(localPosition));
                QTableWidgetItem* currentItem = table->currentItem();
                if (selectedAction == copyCellAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text());
                }
                else if (selectedAction == copyRowAction && currentItem != nullptr)
                {
                    copyTextToClipboard(visibleTableRowText(table, currentItem->row()));
                }
            });
    }

    // installTreeCopyMenu:
    // - Install right-click menus for 'Copy Field', 'Copy Value', and 'Copy Current Row' on the VT report tree and response tree.
    // - Tree nodes store report evidence and original response summaries; right-click copy facilitates review and external archiving.
    // Input tree: target tree control.
    // Returns: Nothing.
    void installTreeCopyMenu(QTreeWidget* tree)
    {
        if (tree == nullptr)
        {
            return;
        }

        tree->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tree, &QTreeWidget::customContextMenuRequested, tree, [tree](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = tree->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    tree->setCurrentItem(clickedItem);
                }

                QMenu contextMenu(tree);
                contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
                QAction* copyFieldAction = contextMenu.addAction(QStringLiteral("复制字段"));
                QAction* copyValueAction = contextMenu.addAction(QStringLiteral("复制值"));
                QAction* copyRowAction = contextMenu.addAction(QStringLiteral("复制当前行"));
                const bool kHasItem = clickedItem != nullptr || tree->currentItem() != nullptr;
                copyFieldAction->setEnabled(kHasItem);
                copyValueAction->setEnabled(kHasItem);
                copyRowAction->setEnabled(kHasItem);

                QAction* selectedAction = contextMenu.exec(tree->viewport()->mapToGlobal(localPosition));
                QTreeWidgetItem* currentItem = tree->currentItem();
                if (selectedAction == copyFieldAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text(0));
                }
                else if (selectedAction == copyValueAction && currentItem != nullptr)
                {
                    copyTextToClipboard(currentItem->text(1));
                }
                else if (selectedAction == copyRowAction && currentItem != nullptr)
                {
                    copyTextToClipboard(visibleTreeItemText(tree, currentItem));
                }
            });
    }

    // addTreeLeaf:
    // - Add a simple key/value child item to a QTreeWidgetItem.
    // - Used by both readable static analysis tree and raw response tree.
    // Input parentItem: parent tree item.
    // Input keyText: field name.
    // Input valueText: field value.
    // Return: created child item, or nullptr if parent is missing.
    QTreeWidgetItem* addTreeLeaf(QTreeWidgetItem* parentItem, const QString& keyText, const QString& valueText)
    {
        if (parentItem == nullptr)
        {
            return nullptr;
        }
        QTreeWidgetItem* childItem = new QTreeWidgetItem(parentItem);
        childItem->setText(0, keyText);
        childItem->setText(1, valueText);
        childItem->setToolTip(0, keyText);
        childItem->setToolTip(1, valueText);
        return childItem;
    }

    // appendJsonValueToTree:
    // - Recursively project JSON objects/arrays into an expandable tree.
    // - Object and array nodes keep the structural marker in column 1; scalar leaves show values.
    // Input parentItem: parent tree item.
    // Input keyText: current field/index label.
    // Input jsonValue: current JSON value.
    // Return: no value.
    void appendJsonValueToTree(QTreeWidgetItem* parentItem, const QString& keyText, const QJsonValue& jsonValue)
    {
        if (parentItem == nullptr)
        {
            return;
        }

        QTreeWidgetItem* currentItem = new QTreeWidgetItem(parentItem);
        currentItem->setText(0, keyText);
        if (jsonValue.isObject())
        {
            const QJsonObject kObjectValue = jsonValue.toObject();
            currentItem->setText(1, QStringLiteral("{ %1 fields }").arg(kObjectValue.size()));
            for (auto iterator = kObjectValue.constBegin(); iterator != kObjectValue.constEnd(); ++iterator)
            {
                appendJsonValueToTree(currentItem, iterator.key(), iterator.value());
            }
            return;
        }
        if (jsonValue.isArray())
        {
            const QJsonArray kArrayValue = jsonValue.toArray();
            currentItem->setText(1, QStringLiteral("[ %1 items ]").arg(kArrayValue.size()));
            for (int index = 0; index < kArrayValue.size(); ++index)
            {
                appendJsonValueToTree(currentItem, QStringLiteral("[%1]").arg(index), kArrayValue.at(index));
            }
            return;
        }

        const QString kValueText = jsonPrimitiveText(jsonValue);
        currentItem->setText(1, kValueText);
        currentItem->setToolTip(0, keyText);
        currentItem->setToolTip(1, kValueText);
    }
}

VirusTotalOnlineScan::VirusTotalOnlineScan(QObject* parent)
    : QObject(parent)
    , networkManager_(new QNetworkAccessManager(this))
{
}

VirusTotalOnlineScan::~VirusTotalOnlineScan() = default;

void VirusTotalOnlineScan::scanFile(
    const QString& filePath,
    const QString& sourceText,
    QWidget* dialogParent)
{
    scanFile(filePath, sourceText, VtApiKind::kShallowAnalysis, dialogParent);
}

void VirusTotalOnlineScan::scanFile(
    const QString& filePath,
    const QString& sourceText,
    const VtApiKind initialApi,
    QWidget* dialogParent)
{
    if (scanInProgress_)
    {
        ks::online_scan::showErrorDialog(
            dialogParent,
            QStringLiteral("VirusTotal 在线扫描"),
            QStringLiteral("当前 VirusTotal 扫描仍在进行，请等待完成后再上传新文件。"));
        return;
    }

    resetRuntimeState();
    dialogParent_ = dialogParent;
    filePath_ = filePath.trimmed();
    sourceText_ = sourceText.trimmed().isEmpty()
        ? QStringLiteral("手动上传")
        : sourceText.trimmed();

    // settings: Read the API key from the unified settings JSON; if not configured, prompt the user to provide it.
    // m_settingsJsonPath purpose: Records the current read location; subsequent 401/403/429 errors display only the path and Key mask.
    settingsJsonPath_ = ks::settings::resolveSettingsJsonPathForRead();
    const ks::settings::AppearanceSettings kSettings = ks::settings::loadAppearanceSettings();
    apiKey_ = kSettings.virusTotalApiKey.trimmed();
    if (apiKey_.isEmpty())
    {
        ks::online_scan::showErrorDialog(
            dialogParent,
            QStringLiteral("在线扫描 API Key 未配置"),
            QStringLiteral("VirusTotal API Key 为空。\n\n请在“设置 -> 在线扫描”中填写 API Key，保存后重新上传文件。\n\n当前设置读取路径：%1")
                .arg(QDir::toNativeSeparators(settingsJsonPath_)));
        return;
    }

    QString fileErrorText;
    if (!ks::online_scan::validateReadableFile(
        filePath_,
        ks::online_scan::kVirusTotalLargeUploadMaxBytes,
        &fileErrorText))
    {
        ks::online_scan::showErrorDialog(dialogParent, QStringLiteral("VirusTotal 在线扫描"), fileErrorText);
        return;
    }

    ensureResultDialog();
    selectApiTab(initialApi);
    if (initialApi == VtApiKind::kAllApis)
    {
        startAllApis();
        return;
    }
    startApiAnalysis(initialApi);
}

void VirusTotalOnlineScan::scanFile(const QString& filePath, QWidget* dialogParent)
{
    scanFile(filePath, QStringLiteral("手动上传"), dialogParent);
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(
    const QString& filePath,
    const QString& sourceText,
    QWidget* dialogParent)
{
    scanFileAndAutoDelete(filePath, sourceText, VtApiKind::kShallowAnalysis, dialogParent);
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(
    const QString& filePath,
    const QString& sourceText,
    const VtApiKind initialApi,
    QWidget* dialogParent)
{
    VirusTotalOnlineScan* scanner = new VirusTotalOnlineScan(dialogParent);
    scanner->autoDeleteWhenFinished_ = true;
    scanner->scanFile(filePath, sourceText, initialApi, dialogParent);
    if (!scanner->scanInProgress_)
    {
        // Non-shallow analysis APIs may also issue asynchronous requests, but m_scanInProgress only indicates upload polling.
        // The result window cannot be immediately released if it has already been created, otherwise button/network callbacks would access a dangling object.
        if (scanner->resultDialog_.isNull())
        {
            scanner->deleteLater();
        }
        else
        {
            scanner->deleteAfterResultDialogClosed_ = true;
        }
    }
}

void VirusTotalOnlineScan::scanFileAndAutoDelete(const QString& filePath, QWidget* dialogParent)
{
    scanFileAndAutoDelete(filePath, QStringLiteral("手动上传"), dialogParent);
}

void VirusTotalOnlineScan::setApiState(
    const VtApiKind apiKind,
    const VtApiState apiState,
    const QString& statusText)
{
    // Input: new state for a top-level API Tab.
    // Processing: Write to the state array and refresh the placeholder text and 'Start Analysis' button for this pane.
    // Returns: Nothing.
    const int kIndex = apiIndex(apiKind);
    apiStates_[static_cast<std::size_t>(kIndex)] = apiState;

    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    if (!pane.startButton.isNull())
    {
        pane.startButton->setVisible(apiState == VtApiState::kNotStarted ||
            apiState == VtApiState::kEmpty ||
            apiState == VtApiState::kFailed);
        pane.startButton->setEnabled(apiState != VtApiState::kRunning &&
            apiState != VtApiState::kHashing);
    }
    refreshApiPlaceholder(apiKind, statusText);
}

void VirusTotalOnlineScan::refreshApiPlaceholder(const VtApiKind apiKind, const QString& statusText)
{
    // Input: target API and optional status text.
    // Processing: Provide a clear placeholder status for incomplete tabs; do not overwrite existing reports for completed tabs.
    // Returns: Nothing.
    const int kIndex = apiIndex(apiKind);
    const VtApiState kApiState = apiStates_[static_cast<std::size_t>(kIndex)];
    if (kApiState == VtApiState::kCompleted)
    {
        return;
    }

    const QString kDisplayText = statusText.trimmed().isEmpty()
        ? apiStateText(kApiState)
        : statusText.trimmed();
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    const QList<QAbstractItemView*> kItemViews{
        pane.fileInfoTable.data(),
        pane.engineTable.data(),
        pane.reportTree.data()
    };
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-api-placeholder-%1").arg(kIndex),
            kItemViews,
            [safeThis, apiKind, statusText]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshApiPlaceholder(apiKind, statusText);
                }
            }))
    {
        return;
    }
    if (!pane.overviewLabel.isNull())
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:18px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;'>%2</div>")
            .arg(apiTitleText(apiKind).toHtmlEscaped(), kDisplayText.toHtmlEscaped()));
    }
    if (!pane.reportTree.isNull())
    {
        pane.reportTree->clear();
        QTreeWidgetItem* item = new QTreeWidgetItem(pane.reportTree);
        item->setText(0, apiTitleText(apiKind));
        item->setText(1, kDisplayText);
        item->setExpanded(true);
    }
}

void VirusTotalOnlineScan::selectApiTab(const VtApiKind apiKind)
{
    if (resultTabWidget_.isNull())
    {
        return;
    }
    resultTabWidget_->setCurrentIndex(apiIndex(apiKind));
}

void VirusTotalOnlineScan::startApiAnalysis(const VtApiKind apiKind)
{
    ensureResultDialog();
    selectApiTab(apiKind);

    const int kIndex = apiIndex(apiKind);
    const VtApiState kCurrentState = apiStates_[static_cast<std::size_t>(kIndex)];
    if (kCurrentState == VtApiState::kRunning || kCurrentState == VtApiState::kHashing)
    {
        return;
    }
    if (!dispatchingQueuedApi_ && hasActiveApiOperation())
    {
        if (!deferredApiQueue_.contains(apiKind))
        {
            deferredApiQueue_.append(apiKind);
        }
        refreshApiPlaceholder(
            apiKind,
            QStringLiteral("已加入 VT 串行队列，等待当前 API 请求结束后自动开始。"));
        return;
    }

    if (apiKind == VtApiKind::kShallowAnalysis)
    {
        if (scanInProgress_)
        {
            return;
        }
        setApiState(apiKind, VtApiState::kRunning, QStringLiteral("正在上传样本并等待普通分析结果。"));
        scanInProgress_ = true;
        progressPid_ = kPro.add(this, "在线扫描", "VirusTotal 上传准备");
        kPro.set(progressPid_, "VirusTotal：准备上传样本", 0, 5.0f);

        const QFileInfo kFileInfo(filePath_);
        if (kFileInfo.size() > ks::online_scan::kVirusTotalDirectUploadMaxBytes)
        {
            requestLargeUploadUrl();
            return;
        }
        uploadFileToUrl(QUrl(QString::fromLatin1(kVirusTotalFilesEndpoint)));
        return;
    }

    ensureLocalHashes(apiKind);
}

void VirusTotalOnlineScan::startAllApis()
{
    ensureResultDialog();
    allApisMode_ = true;
    allApiQueue_.clear();
    allApiQueue_ << VtApiKind::kShallowAnalysis
        << VtApiKind::kFileProfile
        << VtApiKind::kIoc
        << VtApiKind::kSandbox;
    if (hasActiveApiOperation())
    {
        updateResultSummary(QStringLiteral(
            "来源：%1\n文件：%2\n状态：全部 API 已排队，等待当前 VT 请求结束后串行执行。")
            .arg(sourceText_, fileDisplayText(filePath_)));
        return;
    }
    startNextQueuedAllApi();
}

bool VirusTotalOnlineScan::hasActiveApiOperation() const
{
    if (scanInProgress_ || localHashes_.running)
    {
        return true;
    }
    for (const VtApiState kApiState : apiStates_)
    {
        if (kApiState == VtApiState::kRunning || kApiState == VtApiState::kHashing)
        {
            return true;
        }
    }
    return false;
}

void VirusTotalOnlineScan::startNextQueuedAllApi()
{
    while (!allApiQueue_.isEmpty())
    {
        const VtApiKind kNextApi = allApiQueue_.takeFirst();
        const VtApiState kQueuedState = apiStates_[static_cast<std::size_t>(apiIndex(kNextApi))];
        if (kQueuedState == VtApiState::kCompleted || kQueuedState == VtApiState::kEmpty)
        {
            continue;
        }
        dispatchingQueuedApi_ = true;
        startApiAnalysis(kNextApi);
        dispatchingQueuedApi_ = false;
        return;
    }

    allApisMode_ = false;
    if (sandboxHtmlFetchQueued_ && sandboxHtmlQueue_.isEmpty())
    {
        sandboxHtmlFetchQueued_ = false;
    }
    if (sandboxHtmlFetchQueued_ && !sandboxHtmlQueue_.isEmpty())
    {
        sandboxHtmlFetchQueued_ = false;
        requestNextSandboxHtmlReport();
        return;
    }
    if (!deferredSingleIocRelationships_.isEmpty())
    {
        const QString kRelationshipText = deferredSingleIocRelationships_.takeFirst();
        startSingleIocRelationship(kRelationshipText);
        return;
    }
    if (!deferredApiQueue_.isEmpty())
    {
        const VtApiKind kNextApi = deferredApiQueue_.takeFirst();
        dispatchingQueuedApi_ = true;
        startApiAnalysis(kNextApi);
        dispatchingQueuedApi_ = false;
        return;
    }

    finalizeAutoDeleteIfNeeded();
}

bool VirusTotalOnlineScan::scheduleRetryAfterRateLimit(
    const VtApiKind apiKind,
    const QString& retryKey,
    QNetworkReply* reply,
    const QString& statusText,
    std::function<void()> retryAction)
{
    // Input: A freshly received VT response and a retry callback.
    // Handling: Only retry serially with a delay based on Retry-After when HTTP 429 is received; if the limit is exceeded, return control to the caller for failure display.
    // Returns: true indicates this function has already scheduled a retry; the caller should not mark this API as failed.
    if (replyHttpStatusCode(reply) != 429 || !retryAction)
    {
        return false;
    }

    const QString kNormalizedRetryKey = retryKey.trimmed().isEmpty()
        ? apiTitleText(apiKind)
        : retryKey.trimmed();
    const int kRetryCount = vtRateLimitRetryCounts_.value(kNormalizedRetryKey, 0);
    if (kRetryCount >= kMaxRateLimitRetryAttempts)
    {
        return false;
    }

    const int kDelayMs = rateLimitRetryDelayMs(reply);
    vtRateLimitRetryCounts_.insert(kNormalizedRetryKey, kRetryCount + 1);
    const QString kWaitText = formatWaitSecondsText(kDelayMs);
    setApiState(
        apiKind,
        VtApiState::kRunning,
        QStringLiteral("%1\nVirusTotal 返回 429，%2 后自动重试（%3/%4）。")
            .arg(statusText.trimmed().isEmpty() ? apiTitleText(apiKind) : statusText.trimmed())
            .arg(kWaitText)
            .arg(kRetryCount + 1)
            .arg(kMaxRateLimitRetryAttempts));

    QPointer<VirusTotalOnlineScan> self(this);
    QTimer::singleShot(kDelayMs, this, [self, retryAction]()
        {
            if (self.isNull())
            {
                return;
            }
            retryAction();
        });
    return true;
}

void VirusTotalOnlineScan::ensureLocalHashes(const VtApiKind nextApi)
{
    if (localHashes_.ready)
    {
        if (nextApi == VtApiKind::kFileProfile)
        {
            requestFileProfile();
        }
        else if (nextApi == VtApiKind::kIoc)
        {
            if (iocRelationshipQueue_.isEmpty())
            {
                iocRelationshipQueue_ = iocRelationships();
                iocRelationshipObjects_ = QJsonObject();
            }
            setApiState(nextApi, VtApiState::kRunning, QStringLiteral("正在请求常用 IOC 关系。"));
            requestNextIocRelationship();
        }
        else if (nextApi == VtApiKind::kSandbox)
        {
            requestSandboxSummary();
        }
        return;
    }

    if (!pendingHashApis_.contains(nextApi))
    {
        pendingHashApis_.append(nextApi);
    }
    setApiState(nextApi, VtApiState::kHashing, QStringLiteral("正在计算本地 MD5/SHA1/SHA256。"));
    if (localHashes_.running)
    {
        return;
    }

    localHashes_.running = true;
    const QString kFilePath = filePath_;
    QPointer<VirusTotalOnlineScan> self(this);
    QRunnable* task = QRunnable::create([self, kFilePath]()
        {
            // Input: sample path.
            // Processing: Stream compute MD5/SHA1/SHA256 in the background to avoid blocking the UI with large files.
            // Returns: Via QueuedConnection back to the UI thread.
            QString errorText;
            QString md5Text;
            QString sha1Text;
            QString sha256Text;
            QFile inputFile(kFilePath);
            if (!inputFile.open(QIODevice::ReadOnly))
            {
                errorText = QStringLiteral("打开文件失败：%1").arg(inputFile.errorString());
            }
            else
            {
                QCryptographicHash md5Hasher(QCryptographicHash::Md5);
                QCryptographicHash sha1Hasher(QCryptographicHash::Sha1);
                QCryptographicHash sha256Hasher(QCryptographicHash::Sha256);
                while (!inputFile.atEnd())
                {
                    const QByteArray kChunkBytes = inputFile.read(1024 * 1024);
                    if (kChunkBytes.isEmpty() && inputFile.error() != QFile::NoError)
                    {
                        errorText = QStringLiteral("读取文件失败：%1").arg(inputFile.errorString());
                        break;
                    }
                    md5Hasher.addData(kChunkBytes);
                    sha1Hasher.addData(kChunkBytes);
                    sha256Hasher.addData(kChunkBytes);
                }
                if (errorText.isEmpty())
                {
                    md5Text = QString::fromLatin1(md5Hasher.result().toHex());
                    sha1Text = QString::fromLatin1(sha1Hasher.result().toHex());
                    sha256Text = QString::fromLatin1(sha256Hasher.result().toHex());
                }
            }

            if (!self.isNull())
            {
                QMetaObject::invokeMethod(
                    self.data(),
                    [self, md5Text, sha1Text, sha256Text, errorText]()
                    {
                        if (!self.isNull())
                        {
                            self->handleLocalHashesReady(md5Text, sha1Text, sha256Text, errorText);
                        }
                    },
                    Qt::QueuedConnection);
            }
        });
    QThreadPool::globalInstance()->start(task);
}

void VirusTotalOnlineScan::handleLocalHashesReady(
    const QString& md5Text,
    const QString& sha1Text,
    const QString& sha256Text,
    const QString& errorText)
{
    localHashes_.running = false;
    if (!errorText.trimmed().isEmpty() || sha256Text.trimmed().isEmpty())
    {
        const QString kFinalErrorText = errorText.trimmed().isEmpty()
            ? QStringLiteral("本地 SHA256 计算结果为空。")
            : errorText.trimmed();
        const QList<VtApiKind> kWaitingApis = pendingHashApis_;
        pendingHashApis_.clear();
        for (const VtApiKind kApiKind : kWaitingApis)
        {
            appendRawTextSection(kApiKind, QStringLiteral("本地 Hash 计算失败"), kFinalErrorText);
            setApiState(kApiKind, VtApiState::kFailed, kFinalErrorText);
        }
        startNextQueuedAllApi();
        return;
    }

    localHashes_.md5Text = md5Text;
    localHashes_.sha1Text = sha1Text;
    localHashes_.sha256Text = sha256Text;
    localHashes_.ready = true;

    const QList<VtApiKind> kWaitingApis = pendingHashApis_;
    pendingHashApis_.clear();
    for (const VtApiKind kApiKind : kWaitingApis)
    {
        ensureLocalHashes(kApiKind);
    }
}

void VirusTotalOnlineScan::requestFileProfile()
{
    setApiState(VtApiKind::kFileProfile, VtApiState::kRunning, QStringLiteral("正在请求文件完整画像。"));
    const QUrl kRequestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) + localHashes_.sha256Text);
    QNetworkRequest request(kRequestUrl);
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleFileProfileReply(reply);
        });
}

void VirusTotalOnlineScan::handleFileProfileReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const QVariant kStatusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    const int kStatusCode = kStatusCodeVariant.isValid() ? kStatusCodeVariant.toInt() : 0;
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
    const QString kTitleText = QStringLiteral("GET /api/v3/files/%1 文件画像").arg(localHashes_.sha256Text);

    if (!kNetworkOk)
    {
        if (kStatusCode == 404)
        {
            const QString kEmptyText = QStringLiteral("VT 暂无该文件画像。该 hash 目前没有 VirusTotal 文件对象记录；如需要画像，可先执行普通分析上传后稍后重试。");
            appendRawTextSection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 暂无数据"), kEmptyText, kResponseMetadata);
            appendRawReplyBodySection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 404 原始响应体"), kBodyBytes, kResponseMetadata);
            reply->deleteLater();
            setApiState(VtApiKind::kFileProfile, VtApiState::kEmpty, kEmptyText);
            startNextQueuedAllApi();
            return;
        }
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 请求失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kFileProfile,
            kTitleText,
            reply,
            QStringLiteral("文件画像请求被限流。"),
            [this]()
            {
                requestFileProfile();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        setApiState(
            VtApiKind::kFileProfile,
            VtApiState::kFailed,
            kErrorText);
        startNextQueuedAllApi();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kFileProfile, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        setApiState(VtApiKind::kFileProfile, VtApiState::kFailed, parseErrorText);
        startNextQueuedAllApi();
        return;
    }

    appendRawJsonSection(VtApiKind::kFileProfile, kTitleText, kRootObject, kResponseMetadata);
    fileProfileObject_ = kRootObject;
    const QJsonObject kAttributesObject = kRootObject.value(QStringLiteral("data")).toObject().value(QStringLiteral("attributes")).toObject();
    if (kAttributesObject.isEmpty())
    {
        setApiState(VtApiKind::kFileProfile, VtApiState::kEmpty, QStringLiteral("VT 文件画像为空。"));
    }
    else
    {
        setApiState(VtApiKind::kFileProfile, VtApiState::kCompleted);
        refreshFileProfileResult(kRootObject);
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestNextIocRelationship()
{
    if (iocRelationshipQueue_.isEmpty())
    {
        bool hasAnyData = false;
        for (const QString& relationshipText : iocRelationships())
        {
            const QJsonArray kDataArray = iocRelationshipObjects_
                .value(relationshipText)
                .toObject()
                .value(QStringLiteral("data"))
                .toArray();
            if (!kDataArray.isEmpty())
            {
                hasAnyData = true;
                break;
            }
        }
        setApiState(
            VtApiKind::kIoc,
            hasAnyData ? VtApiState::kCompleted : VtApiState::kEmpty,
            hasAnyData ? QString() : QStringLiteral("VT 暂无该文件的常用 IOC 关系数据。"));
        refreshIocResult();
        startNextQueuedAllApi();
        return;
    }

    const QString kRelationshipText = iocRelationshipQueue_.takeFirst();
    setApiState(
        VtApiKind::kIoc,
        VtApiState::kRunning,
        QStringLiteral("正在请求 %1。").arg(relationshipDisplayText(kRelationshipText)));
    const QUrl kRequestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        localHashes_.sha256Text +
        QLatin1Char('/') +
        kRelationshipText);
    QNetworkRequest request(kRequestUrl);
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, kRelationshipText, reply]()
        {
            handleIocRelationshipReply(kRelationshipText, reply);
        });
}

void VirusTotalOnlineScan::handleIocRelationshipReply(const QString& relationshipText, QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const int kStatusCode = replyHttpStatusCode(reply);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
    const QString kTitleText = QStringLiteral("GET /api/v3/files/%1/%2")
        .arg(localHashes_.sha256Text, relationshipText);
    if (!kNetworkOk)
    {
        if (kStatusCode == 404)
        {
            const QString kEmptyText = QStringLiteral("VT 暂无该类 IOC 数据。");
            appendRawTextSection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 暂无数据"), kEmptyText, kResponseMetadata);
            appendRawReplyBodySection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 404 原始响应体"), kBodyBytes, kResponseMetadata);
            QJsonObject emptyObject;
            emptyObject.insert(QStringLiteral("relationship"), relationshipText);
            emptyObject.insert(QStringLiteral("data"), QJsonArray());
            emptyObject.insert(QStringLiteral("empty_reason"), kEmptyText);
            emptyObject.insert(QStringLiteral("response_metadata"), kResponseMetadata);
            iocRelationshipObjects_.insert(relationshipText, emptyObject);
            reply->deleteLater();
            requestNextIocRelationship();
            return;
        }
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 请求失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kIoc,
            kTitleText,
            reply,
            QStringLiteral("IOC %1 请求被限流。").arg(relationshipDisplayText(relationshipText)),
            [this, relationshipText]()
            {
                iocRelationshipQueue_.prepend(relationshipText);
                requestNextIocRelationship();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        QJsonObject errorObject;
        errorObject.insert(QStringLiteral("error"), kErrorText);
        errorObject.insert(QStringLiteral("relationship"), relationshipText);
        errorObject.insert(QStringLiteral("response_metadata"), kResponseMetadata);
        iocRelationshipObjects_.insert(relationshipText, errorObject);
        requestNextIocRelationship();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kIoc, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        QJsonObject errorObject;
        errorObject.insert(QStringLiteral("error"), parseErrorText);
        errorObject.insert(QStringLiteral("relationship"), relationshipText);
        errorObject.insert(QStringLiteral("response_metadata"), kResponseMetadata);
        iocRelationshipObjects_.insert(relationshipText, errorObject);
        requestNextIocRelationship();
        return;
    }

    appendRawJsonSection(VtApiKind::kIoc, kTitleText, kRootObject, kResponseMetadata);
    iocRelationshipObjects_.insert(relationshipText, kRootObject);
    requestNextIocRelationship();
}

void VirusTotalOnlineScan::startSingleIocRelationship(const QString& relationshipText)
{
    // Input: a VT files relationship name.
    // Handling: Start only for this relationship; if a VT request is already running, queue it in a separate item to avoid overwriting the full IOC queue.
    // Returns: Nothing.
    const QString kTrimmedRelationship = relationshipText.trimmed();
    if (kTrimmedRelationship.isEmpty())
    {
        return;
    }

    ensureResultDialog();
    selectApiTab(VtApiKind::kIoc);
    if (!dispatchingQueuedApi_ && hasActiveApiOperation())
    {
        if (!deferredSingleIocRelationships_.contains(kTrimmedRelationship))
        {
            deferredSingleIocRelationships_.append(kTrimmedRelationship);
        }
        refreshApiPlaceholder(
            VtApiKind::kIoc,
            QStringLiteral("%1 已加入 VT 串行队列。").arg(relationshipDisplayText(kTrimmedRelationship)));
        return;
    }

    iocRelationshipQueue_.clear();
    iocRelationshipQueue_ << kTrimmedRelationship;
    ensureLocalHashes(VtApiKind::kIoc);
}

void VirusTotalOnlineScan::requestSandboxSummary()
{
    setApiState(VtApiKind::kSandbox, VtApiState::kRunning, QStringLiteral("正在请求沙箱行为汇总。"));
    const QUrl kRequestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        localHashes_.sha256Text +
        QStringLiteral("/behaviour_summary"));
    QNetworkRequest request(kRequestUrl);
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleSandboxSummaryReply(reply);
        });
}

void VirusTotalOnlineScan::handleSandboxSummaryReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const int kStatusCode = replyHttpStatusCode(reply);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
    const QString kTitleText = QStringLiteral("GET /api/v3/files/%1/behaviour_summary").arg(localHashes_.sha256Text);
    if (!kNetworkOk)
    {
        if (kStatusCode == 404)
        {
            const QString kEmptyText = QStringLiteral("VT 暂无该文件沙箱行为汇总。");
            appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 暂无数据"), kEmptyText, kResponseMetadata);
            appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 404 原始响应体"), kBodyBytes, kResponseMetadata);
            reply->deleteLater();
            sandboxSummaryObject_ = QJsonObject();
            requestSandboxBehaviours();
            return;
        }
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 请求失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kSandbox,
            kTitleText,
            reply,
            QStringLiteral("沙箱行为汇总请求被限流。"),
            [this]()
            {
                requestSandboxSummary();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        sandboxSummaryObject_ = QJsonObject();
        requestSandboxBehaviours();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        sandboxSummaryObject_ = QJsonObject();
        requestSandboxBehaviours();
        return;
    }

    appendRawJsonSection(VtApiKind::kSandbox, kTitleText, kRootObject, kResponseMetadata);
    sandboxSummaryObject_ = kRootObject;
    requestSandboxBehaviours();
}

void VirusTotalOnlineScan::requestSandboxBehaviours()
{
    setApiState(VtApiKind::kSandbox, VtApiState::kRunning, QStringLiteral("正在请求单沙箱报告列表。"));
    const QUrl kRequestUrl(QString::fromLatin1(kVirusTotalFilesEndpointPrefix) +
        localHashes_.sha256Text +
        QStringLiteral("/behaviours"));
    QNetworkRequest request(kRequestUrl);
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleSandboxBehavioursReply(reply);
        });
}

void VirusTotalOnlineScan::handleSandboxBehavioursReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const int kStatusCode = replyHttpStatusCode(reply);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
    const QString kTitleText = QStringLiteral("GET /api/v3/files/%1/behaviours").arg(localHashes_.sha256Text);
    if (!kNetworkOk)
    {
        if (kStatusCode == 404)
        {
            const QString kEmptyText = QStringLiteral("VT 暂无该文件沙箱报告列表。");
            appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 暂无数据"), kEmptyText, kResponseMetadata);
            appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 404 原始响应体"), kBodyBytes, kResponseMetadata);
            reply->deleteLater();
            sandboxBehavioursObject_ = QJsonObject();
            setApiState(
                VtApiKind::kSandbox,
                sandboxSummaryObject_.isEmpty() ? VtApiState::kEmpty : VtApiState::kCompleted,
                sandboxSummaryObject_.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
            refreshSandboxResult();
            startNextQueuedAllApi();
            return;
        }
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 请求失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kSandbox,
            kTitleText,
            reply,
            QStringLiteral("沙箱报告列表请求被限流。"),
            [this]()
            {
                requestSandboxBehaviours();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        sandboxBehavioursObject_ = QJsonObject();
        setApiState(
            VtApiKind::kSandbox,
            sandboxSummaryObject_.isEmpty() ? VtApiState::kEmpty : VtApiState::kCompleted,
            sandboxSummaryObject_.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
        refreshSandboxResult();
        startNextQueuedAllApi();
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        sandboxBehavioursObject_ = QJsonObject();
        setApiState(
            VtApiKind::kSandbox,
            sandboxSummaryObject_.isEmpty() ? VtApiState::kEmpty : VtApiState::kCompleted,
            sandboxSummaryObject_.isEmpty() ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
        refreshSandboxResult();
        startNextQueuedAllApi();
        return;
    }

    appendRawJsonSection(VtApiKind::kSandbox, kTitleText, kRootObject, kResponseMetadata);
    sandboxBehavioursObject_ = kRootObject;

    sandboxHtmlQueue_.clear();
    const QJsonArray kBehavioursArray = kRootObject.value(QStringLiteral("data")).toArray();
    for (const QJsonValue& behaviourValue : kBehavioursArray)
    {
        const QJsonObject kBehaviourObject = behaviourValue.toObject();
        const QJsonObject kAttributesObject = kBehaviourObject.value(QStringLiteral("attributes")).toObject();
        if (kAttributesObject.value(QStringLiteral("has_html_report")).toBool(false))
        {
            const QString kBehaviourId = kBehaviourObject.value(QStringLiteral("id")).toString();
            if (!kBehaviourId.isEmpty())
            {
                sandboxHtmlQueue_.append(kBehaviourId);
            }
        }
    }

    setApiState(
        VtApiKind::kSandbox,
        (sandboxSummaryObject_.isEmpty() && kBehavioursArray.isEmpty()) ? VtApiState::kEmpty : VtApiState::kCompleted,
        (sandboxSummaryObject_.isEmpty() && kBehavioursArray.isEmpty()) ? QStringLiteral("VT 暂无该文件沙箱行为数据。") : QString());
    refreshSandboxResult();
    if (allApisMode_ && !sandboxHtmlQueue_.isEmpty())
    {
        requestNextSandboxHtmlReport();
        return;
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestSandboxHtmlReport(const QString& behaviourId)
{
    const QString kTrimmedId = behaviourId.trimmed();
    if (kTrimmedId.isEmpty())
    {
        return;
    }
    if (!dispatchingQueuedApi_ && hasActiveApiOperation())
    {
        if (!sandboxHtmlQueue_.contains(kTrimmedId))
        {
            sandboxHtmlQueue_.append(kTrimmedId);
        }
        sandboxHtmlFetchQueued_ = true;
        refreshApiPlaceholder(
            VtApiKind::kSandbox,
            QStringLiteral("HTML 沙箱报告已加入 VT 串行队列：%1").arg(kTrimmedId));
        return;
    }
    setApiState(VtApiKind::kSandbox, VtApiState::kRunning, QStringLiteral("正在请求 HTML 沙箱报告：%1").arg(kTrimmedId));
    const QUrl kRequestUrl(QString::fromLatin1(kVirusTotalFileBehaviourEndpointPrefix) +
        kTrimmedId +
        QStringLiteral("/html"));
    QNetworkRequest request(kRequestUrl);
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, kTrimmedId, reply]()
        {
            handleSandboxHtmlReply(kTrimmedId, reply);
        });
}

void VirusTotalOnlineScan::requestNextSandboxHtmlReport()
{
    if (sandboxHtmlQueue_.isEmpty())
    {
        setApiState(VtApiKind::kSandbox, VtApiState::kCompleted);
        refreshSandboxResult();
        if (allApisMode_ && allApiQueue_.isEmpty())
        {
            allApisMode_ = false;
        }
        startNextQueuedAllApi();
        return;
    }
    requestSandboxHtmlReport(sandboxHtmlQueue_.takeFirst());
}

void VirusTotalOnlineScan::handleSandboxHtmlReply(const QString& behaviourId, QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const int kStatusCode = replyHttpStatusCode(reply);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
    const QString kTitleText = QStringLiteral("GET /api/v3/file_behaviours/%1/html").arg(behaviourId);
    QJsonObject htmlObject;
    htmlObject.insert(QStringLiteral("behaviour_id"), behaviourId);
    htmlObject.insert(QStringLiteral("timestamp_utc"), utcTimestampText());
    htmlObject.insert(QStringLiteral("response_metadata"), kResponseMetadata);
    if (!kNetworkOk)
    {
        if (kStatusCode == 404)
        {
            const QString kEmptyText = QStringLiteral("VT 暂无该 HTML 沙箱报告，可能已过期或当前 Key 无法访问该报告。");
            htmlObject.insert(QStringLiteral("empty_reason"), kEmptyText);
            appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 暂无数据"), kEmptyText, kResponseMetadata);
            appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 404 原始响应体"), kBodyBytes, kResponseMetadata);
            reply->deleteLater();
            sandboxHtmlReports_.insert(behaviourId, htmlObject);
            setApiState(VtApiKind::kSandbox, VtApiState::kCompleted);
            refreshSandboxResult();
            showSandboxHtmlPreview(behaviourId);
            if (!sandboxHtmlQueue_.isEmpty() || allApisMode_)
            {
                requestNextSandboxHtmlReport();
                return;
            }
            startNextQueuedAllApi();
            return;
        }
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        htmlObject.insert(QStringLiteral("error"), kErrorText);
        appendRawTextSection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 请求失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kSandbox, kTitleText + QStringLiteral(" 原始响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kSandbox,
            kTitleText,
            reply,
            QStringLiteral("HTML 沙箱报告请求被限流：%1").arg(behaviourId),
            [this, behaviourId]()
            {
                const bool kPreviousDispatchingState = dispatchingQueuedApi_;
                dispatchingQueuedApi_ = true;
                requestSandboxHtmlReport(behaviourId);
                dispatchingQueuedApi_ = kPreviousDispatchingState;
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
    }
    else
    {
        const QString kHtmlText = QString::fromUtf8(kBodyBytes);
        htmlObject.insert(QStringLiteral("html"), kHtmlText);
        appendRawTextSection(VtApiKind::kSandbox, kTitleText, kHtmlText, kResponseMetadata);
        reply->deleteLater();
    }
    sandboxHtmlReports_.insert(behaviourId, htmlObject);
    setApiState(VtApiKind::kSandbox, VtApiState::kCompleted);
    refreshSandboxResult();
    showSandboxHtmlPreview(behaviourId);
    if (!sandboxHtmlQueue_.isEmpty() || allApisMode_)
    {
        requestNextSandboxHtmlReport();
        return;
    }
    startNextQueuedAllApi();
}

void VirusTotalOnlineScan::requestLargeUploadUrl()
{
    QNetworkRequest request(QUrl(QString::fromLatin1(kVirusTotalLargeUploadUrlEndpoint)));
    setVirusTotalHeaders(&request, apiKey_);

    kPro.set(progressPid_, "VirusTotal：获取大文件上传地址", 0, 8.0f);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleUploadUrlReply(reply);
        });
}

void VirusTotalOnlineScan::uploadFileToUrl(const QUrl& uploadUrl)
{
    QFile* uploadFile = new QFile(filePath_);
    if (!uploadFile->open(QIODevice::ReadOnly))
    {
        const QString kErrorText = QStringLiteral("打开上传文件失败：%1").arg(uploadFile->errorString());
        uploadFile->deleteLater();
        finishWithError(QStringLiteral("VirusTotal 上传失败"), kErrorText);
        return;
    }

    // multiPart purpose: Construct the multipart/form-data request body required for VirusTotal v3 file upload.
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart filePart;
    const QString kSafeFileName = ks::online_scan::sanitizeFileNameForContentDisposition(QFileInfo(filePath_).fileName());
    filePart.setHeader(
        QNetworkRequest::ContentDispositionHeader,
        QVariant(QStringLiteral("form-data; name=\"file\"; filename=\"%1\"").arg(kSafeFileName)));
    filePart.setBodyDevice(uploadFile);
    uploadFile->setParent(multiPart);
    multiPart->append(filePart);

    QNetworkRequest request(uploadUrl);
    setVirusTotalHeaders(&request, apiKey_);

    kPro.set(progressPid_, "VirusTotal：上传样本", 0, 12.0f);
    QNetworkReply* reply = networkManager_->post(request, multiPart);
    multiPart->setParent(reply);

    connect(reply, &QNetworkReply::uploadProgress, this,
        [this](const qint64 sentBytes, const qint64 totalBytes)
        {
            if (progressPid_ == 0 || totalBytes <= 0)
            {
                return;
            }
            const float kUploadPercent = static_cast<float>(sentBytes) * 40.0f / static_cast<float>(totalBytes);
            kPro.set(progressPid_, "VirusTotal：上传样本", 0, 12.0f + std::min(kUploadPercent, 40.0f));
        });
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleUploadReply(reply);
        });
}

void VirusTotalOnlineScan::handleUploadUrlReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;

    if (!kNetworkOk)
    {
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kShallowAnalysis, QStringLiteral("获取大文件上传 URL 失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 错误响应体"), kBodyBytes, kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/files/upload_url"),
            reply,
            QStringLiteral("获取大文件上传 URL 被限流。"),
            [this]()
            {
                requestLargeUploadUrl();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 获取上传地址失败"),
            kErrorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(VtApiKind::kShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url"), kRootObject, kResponseMetadata);
    }
    else
    {
        appendRawTextSection(VtApiKind::kShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kShallowAnalysis, QStringLiteral("GET /api/v3/files/upload_url 原始响应体"), kBodyBytes, kResponseMetadata);
    }
    const QString kUploadUrlText = kRootObject.value(QStringLiteral("data")).toString().trimmed();
    if (!parseErrorText.isEmpty() || kUploadUrlText.isEmpty())
    {
        finishWithError(
            QStringLiteral("VirusTotal 获取上传地址失败"),
            parseErrorText.isEmpty() ? QStringLiteral("响应中缺少 data 上传 URL。") : parseErrorText);
        return;
    }

    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\n状态：已取得大文件上传 URL，正在上传样本。")
        .arg(sourceText_, fileDisplayText(filePath_)));
    uploadFileToUrl(QUrl(kUploadUrlText));
}

void VirusTotalOnlineScan::handleUploadReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;

    if (!kNetworkOk)
    {
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(VtApiKind::kShallowAnalysis, QStringLiteral("上传样本失败"), kErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kShallowAnalysis, QStringLiteral("POST /api/v3/files 错误响应体"), kBodyBytes, kResponseMetadata);
        const QUrl kUploadUrl = reply->url();
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("POST %1").arg(kUploadUrl.toString()),
            reply,
            QStringLiteral("上传样本请求被限流。"),
            [this, kUploadUrl]()
            {
                uploadFileToUrl(kUploadUrl);
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 上传失败"),
            kErrorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(VtApiKind::kShallowAnalysis, QStringLiteral("POST /api/v3/files 上传响应"), kRootObject, kResponseMetadata);
    }
    else
    {
        appendRawTextSection(VtApiKind::kShallowAnalysis, QStringLiteral("POST /api/v3/files 上传响应解析失败"), parseErrorText, kResponseMetadata);
        appendRawReplyBodySection(VtApiKind::kShallowAnalysis, QStringLiteral("POST /api/v3/files 原始响应体"), kBodyBytes, kResponseMetadata);
    }
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("VirusTotal 上传失败"), parseErrorText);
        return;
    }

    const QJsonObject kDataObject = kRootObject.value(QStringLiteral("data")).toObject();
    analysisId_ = kDataObject.value(QStringLiteral("id")).toString().trimmed();
    if (analysisId_.isEmpty())
    {
        finishWithError(
            QStringLiteral("VirusTotal 上传失败"),
            QStringLiteral("上传响应中缺少 analysis id。\n\n%1").arg(ks::online_scan::formatJsonObject(kRootObject)));
        return;
    }

    kPro.set(progressPid_, "VirusTotal：等待分析结果", 0, 55.0f);
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\nAnalysisId：%3\n状态：上传响应已返回，正在等待 VirusTotal 分析结果。")
        .arg(sourceText_, fileDisplayText(filePath_), analysisId_));
    scheduleAnalysisPoll(kInitialPollDelayMs);
}

void VirusTotalOnlineScan::scheduleAnalysisPoll(const int delayMs)
{
    QTimer::singleShot(delayMs, this, [this]()
        {
            requestAnalysisStatus();
        });
}

void VirusTotalOnlineScan::requestAnalysisStatus()
{
    if (!scanInProgress_ || analysisId_.isEmpty())
    {
        return;
    }

    ++pollAttempt_;
    const float kProgressValue = std::min(95.0f, 55.0f + static_cast<float>(pollAttempt_) * 1.0f);
    kPro.set(
        progressPid_,
        QStringLiteral("VirusTotal：轮询分析结果(%1/%2)").arg(pollAttempt_).arg(kMaxPollAttempts).toStdString(),
        0,
        kProgressValue);

    QNetworkRequest request(QUrl(QString::fromLatin1(kVirusTotalAnalysisEndpointPrefix) + analysisId_));
    setVirusTotalHeaders(&request, apiKey_);
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleAnalysisReply(reply);
        });
}

void VirusTotalOnlineScan::handleAnalysisReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const QJsonObject kResponseMetadata = virusTotalResponseMetadataObject(reply, kBodyBytes);
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;

    if (!kNetworkOk)
    {
        const QString kErrorText = virusTotalNetworkErrorText(reply, kBodyBytes, apiKey_, settingsJsonPath_);
        appendRawTextSection(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 查询失败").arg(analysisId_),
            kErrorText,
            kResponseMetadata);
        appendRawReplyBodySection(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 错误响应体").arg(analysisId_),
            kBodyBytes,
            kResponseMetadata);
        const bool kRetryScheduled = scheduleRetryAfterRateLimit(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1").arg(analysisId_),
            reply,
            QStringLiteral("查询分析结果被限流。"),
            [this]()
            {
                requestAnalysisStatus();
            });
        reply->deleteLater();
        if (kRetryScheduled)
        {
            return;
        }
        finishWithError(
            QStringLiteral("VirusTotal 查询失败"),
            kErrorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (parseErrorText.isEmpty())
    {
        appendRawJsonSection(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 第 %2 次响应")
                .arg(analysisId_)
                .arg(pollAttempt_),
            kRootObject,
            kResponseMetadata);
    }
    else
    {
        appendRawTextSection(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 解析失败").arg(analysisId_),
            parseErrorText,
            kResponseMetadata);
        appendRawReplyBodySection(
            VtApiKind::kShallowAnalysis,
            QStringLiteral("GET /api/v3/analyses/%1 原始响应体").arg(analysisId_),
            kBodyBytes,
            kResponseMetadata);
    }
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("VirusTotal 查询失败"), parseErrorText);
        return;
    }

    const QJsonObject kDataObject = kRootObject.value(QStringLiteral("data")).toObject();
    const QJsonObject kAttributesObject = kDataObject.value(QStringLiteral("attributes")).toObject();
    const QString kStatusText = kAttributesObject.value(QStringLiteral("status")).toString().trimmed().toLower();
    if (kStatusText == QStringLiteral("completed"))
    {
        finishWithResult(kRootObject);
        return;
    }

    if (pollAttempt_ >= kMaxPollAttempts)
    {
        finishWithError(
            QStringLiteral("VirusTotal 查询超时"),
            QStringLiteral("分析任务尚未完成，analysis id：%1\n最后状态：%2")
                .arg(analysisId_, kStatusText.isEmpty() ? QStringLiteral("未知") : kStatusText));
        return;
    }
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\nAnalysisId：%3\n状态：%4；已轮询 %5/%6 次。")
        .arg(sourceText_)
        .arg(fileDisplayText(filePath_))
        .arg(analysisId_)
        .arg(kStatusText.isEmpty() ? QStringLiteral("未知") : kStatusText)
        .arg(pollAttempt_)
        .arg(kMaxPollAttempts));
    scheduleAnalysisPoll(kPollIntervalMs);
}

void VirusTotalOnlineScan::finishWithError(const QString& titleText, const QString& detailText)
{
    completeProgress(QStringLiteral("VirusTotal：扫描失败"));
    scanInProgress_ = false;
    ensureResultDialog();
    setApiState(VtApiKind::kShallowAnalysis, VtApiState::kFailed, detailText);
    updateResultSummary(QStringLiteral(
        "来源：%1\n文件：%2\n状态：%3\n错误：%4")
        .arg(sourceText_, fileDisplayText(filePath_), titleText, detailText));
    if (!readableOverviewLabel_.isNull())
    {
        readableOverviewLabel_->setText(QStringLiteral(
            "<table cellspacing='0' cellpadding='0'>"
            "<tr>"
            "<td width='124'><img src=':/Icon/vt_status_threat.svg' width='104' height='104'/></td>"
            "<td>"
            "<div style='font-size:22px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;color:%4;font-size:18px;font-weight:700;'>威胁</div>"
            "<div style='margin-top:8px;'>状态：%2</div>"
            "<div style='margin-top:6px;'>错误详情：%3</div>"
            "</td>"
            "</tr>"
            "</table>")
            .arg(QFileInfo(filePath_).fileName().toHtmlEscaped().isEmpty()
                ? QStringLiteral("<未知文件>")
                : QFileInfo(filePath_).fileName().toHtmlEscaped())
            .arg(titleText.toHtmlEscaped())
            .arg(detailText.toHtmlEscaped())
            .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
    }
    if (!resultTabWidget_.isNull())
    {
        resultTabWidget_->setCurrentIndex(0);
    }
    appendRawTextSection(titleText, detailText);
    startNextQueuedAllApi();
    finalizeAutoDeleteIfNeeded();
}

void VirusTotalOnlineScan::finishWithResult(const QJsonObject& analysisObject)
{
    completeProgress(QStringLiteral("VirusTotal：扫描完成"));
    scanInProgress_ = false;

    const QString kSummaryText = buildResultSummary(analysisObject);
    ensureResultDialog();
    const QJsonObject kFileInfoObject = analysisObject
        .value(QStringLiteral("meta")).toObject()
        .value(QStringLiteral("file_info")).toObject();
    const QString kMd5Text = kFileInfoObject.value(QStringLiteral("md5")).toString().trimmed();
    const QString kSha1Text = kFileInfoObject.value(QStringLiteral("sha1")).toString().trimmed();
    const QString kSha256Text = kFileInfoObject.value(QStringLiteral("sha256")).toString().trimmed();
    if (!kSha256Text.isEmpty())
    {
        localHashes_.md5Text = kMd5Text;
        localHashes_.sha1Text = kSha1Text;
        localHashes_.sha256Text = kSha256Text;
        localHashes_.ready = true;
    }
    setApiState(VtApiKind::kShallowAnalysis, VtApiState::kCompleted);
    refreshReadableResult(analysisObject);
    updateResultSummary(QStringLiteral("来源：%1\n%2").arg(sourceText_, kSummaryText));

    startNextQueuedAllApi();
    finalizeAutoDeleteIfNeeded();
}

void VirusTotalOnlineScan::resetRuntimeState()
{
    dialogParent_.clear();
    resultDialog_.clear();
    resultSummaryLabel_.clear();
    resultTabWidget_.clear();
    readableOverviewLabel_.clear();
    fileInfoTable_.clear();
    engineTable_.clear();
    staticAnalysisTree_.clear();
    responseTree_.clear();
    resultEditor_.clear();
    for (ApiPaneUi& pane : apiPanes_)
    {
        pane.detailTabWidget.clear();
        pane.overviewLabel.clear();
        pane.startButton.clear();
        pane.sandboxHtmlButton.clear();
        pane.fileProfileFilterEdit.clear();
        pane.fileInfoTable.clear();
        pane.engineTable.clear();
        pane.reportTree.clear();
        pane.sandboxHtmlPreviewGroup.clear();
        pane.sandboxHtmlPreview.clear();
        pane.responseTree.clear();
        pane.rawEditor.clear();
    }
    for (VtApiState& apiState : apiStates_)
    {
        apiState = VtApiState::kNotStarted;
    }
    for (QString& rawText : apiRawText_)
    {
        rawText.clear();
    }
    for (QJsonArray& rawSections : apiRawSections_)
    {
        rawSections = QJsonArray();
    }
    filePath_.clear();
    sourceText_.clear();
    resultRawText_.clear();
    resultRawSections_ = QJsonArray();
    localHashes_ = LocalHashContext();
    pendingHashApis_.clear();
    allApiQueue_.clear();
    deferredApiQueue_.clear();
    deferredSingleIocRelationships_.clear();
    fileProfileObject_ = QJsonObject();
    iocRelationshipObjects_ = QJsonObject();
    iocRelationshipQueue_.clear();
    sandboxSummaryObject_ = QJsonObject();
    sandboxBehavioursObject_ = QJsonObject();
    sandboxHtmlReports_ = QJsonObject();
    sandboxHtmlQueue_.clear();
    sandboxHtmlFetchQueued_ = false;
    vtRateLimitRetryCounts_.clear();
    apiKey_.clear();
    settingsJsonPath_.clear();
    analysisId_.clear();
    pollAttempt_ = 0;
    scanInProgress_ = false;
    allApisMode_ = false;
    dispatchingQueuedApi_ = false;
    progressPid_ = 0;
    deleteAfterResultDialogClosed_ = false;
}

void VirusTotalOnlineScan::completeProgress(const QString& messageText)
{
    if (progressPid_ == 0)
    {
        return;
    }
    kPro.set(progressPid_, messageText.toStdString(), 0, 100.0f);
    progressPid_ = 0;
}

void VirusTotalOnlineScan::ensureResultDialog()
{
    if (!resultDialog_.isNull())
    {
        if (!resultDialog_->isVisible())
        {
            resultDialog_->show();
        }
        resultDialog_->raise();
        resultDialog_->activateWindow();
        return;
    }

    QDialog* resultDialog = new QDialog(dialogParent_.data());
    resultDialog->setAttribute(Qt::WA_DeleteOnClose, true);
    resultDialog->setObjectName(QStringLiteral("virusTotalLiveResultDialog"));
    resultDialog->setWindowTitle(QStringLiteral("VirusTotal 云沙箱上传结果"));
    resultDialog->resize(1180, 780);
    resultDialog->setStyleSheet(
        ksword_theme::opaqueDialogStyle(resultDialog->objectName()) +
        QStringLiteral(
            "QDialog#virusTotalLiveResultDialog QLabel#vtOverviewCard{"
            "  border:0;"
            "  padding:4px 0 12px 0;"
            "}"
            "QDialog#virusTotalLiveResultDialog QGroupBox{"
            "  border:0;"
            "  margin-top:12px;"
            "  padding-top:12px;"
            "}"
            "QDialog#virusTotalLiveResultDialog QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:0px;"
            "  padding:0 4px;"
            "  font-weight:600;"
            "}"
            "QDialog#virusTotalLiveResultDialog QTabWidget::pane{"
            "  border:1px solid palette(mid);"
            "}"
            "QDialog#virusTotalLiveResultDialog QTableWidget#vtFileInfoTable{"
            "  border:0;"
            "  background:transparent;"
            "}"
            "QDialog#virusTotalLiveResultDialog QTableWidget#vtFileInfoTable::item{"
            "  border:0;"
            "  padding:1px 8px 1px 0;"
            "}"));

    // dialogLayout:
    // - Place global API action buttons at the top;
    // - The middle section contains a Level 1 API Tab; each Level 1 Tab fixedly includes Level 2 Tabs for 'Report View', 'Response Details', and 'Raw Data'.
    // Only the close button is retained at the bottom; exports are unified via the top 'Export all API raw response data'.
    QVBoxLayout* dialogLayout = new QVBoxLayout(resultDialog);
    dialogLayout->setContentsMargins(0, 0, 0, 10);
    dialogLayout->setSpacing(0);

    QHBoxLayout* topButtonLayout = new QHBoxLayout();
    topButtonLayout->setContentsMargins(10, 8, 10, 8);
    QPushButton* runAllButton = new QPushButton(QStringLiteral("调用所有 API"), resultDialog);
    QPushButton* exportAllButton = new QPushButton(QStringLiteral("导出所有API原始响应数据"), resultDialog);
    topButtonLayout->addWidget(runAllButton, 0);
    topButtonLayout->addWidget(exportAllButton, 0);
    topButtonLayout->addStretch(1);
    dialogLayout->addLayout(topButtonLayout, 0);

    QTabWidget* resultTabWidget = new QTabWidget(resultDialog);
    resultTabWidget->setDocumentMode(false);
    dialogLayout->addWidget(resultTabWidget, 1);

    const auto kCreateCommonPane = [this, resultDialog, resultTabWidget](const VtApiKind apiKind) -> ApiPaneUi
        {
            ApiPaneUi pane;
            QWidget* apiPage = new QWidget(resultTabWidget);
            QVBoxLayout* apiLayout = new QVBoxLayout(apiPage);
            apiLayout->setContentsMargins(0, 0, 0, 0);
            apiLayout->setSpacing(0);

            QTabWidget* detailTabWidget = new QTabWidget(apiPage);
            pane.detailTabWidget = detailTabWidget;
            apiLayout->addWidget(detailTabWidget, 1);

            QWidget* reportPage = new QWidget(detailTabWidget);
            QVBoxLayout* reportPageLayout = new QVBoxLayout(reportPage);
            reportPageLayout->setContentsMargins(0, 0, 0, 0);
            QScrollArea* reportScrollArea = new QScrollArea(reportPage);
            reportScrollArea->setWidgetResizable(true);
            reportScrollArea->setFrameShape(QFrame::NoFrame);
            reportPageLayout->addWidget(reportScrollArea, 1);

            QWidget* reportContent = new QWidget(reportScrollArea);
            QVBoxLayout* reportLayout = new QVBoxLayout(reportContent);
            reportLayout->setContentsMargins(12, 12, 12, 12);
            reportLayout->setSpacing(10);

            QLabel* overviewLabel = new QLabel(reportContent);
            overviewLabel->setObjectName(QStringLiteral("vtOverviewCard"));
            overviewLabel->setTextFormat(Qt::RichText);
            overviewLabel->setWordWrap(true);
            pane.overviewLabel = overviewLabel;
            reportLayout->addWidget(overviewLabel, 0);

            QPushButton* startButton = new QPushButton(QStringLiteral("开始分析"), reportContent);
            pane.startButton = startButton;
            QObject::connect(startButton, &QPushButton::clicked, this, [this, apiKind]()
                {
                    startApiAnalysis(apiKind);
                });
            reportLayout->addWidget(startButton, 0);

            if (apiKind == VtApiKind::kShallowAnalysis)
            {
                QGroupBox* fileInfoGroup = new QGroupBox(QStringLiteral("基础信息 / HASH"), reportContent);
                QVBoxLayout* fileInfoLayout = new QVBoxLayout(fileInfoGroup);
                fileInfoLayout->setContentsMargins(0, 2, 0, 2);
                fileInfoLayout->setSpacing(0);
                QTableWidget* fileInfoTable = new ks::ui::VisibleTableWidget(fileInfoGroup);
                fileInfoTable->setObjectName(QStringLiteral("vtFileInfoTable"));
                fileInfoTable->setColumnCount(2);
                configureBorderlessInfoTable(fileInfoTable);
                installTableCopyMenu(fileInfoTable);
                fileInfoTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
                fileInfoTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
                setTableRow(fileInfoTable, 0, QStringLiteral("文件名"), QFileInfo(filePath_).fileName());
                setTableRow(fileInfoTable, 1, QStringLiteral("文件大小"), formatByteCount(QFileInfo(filePath_).size()));
                fitTableHeightToRows(fileInfoTable);
                fileInfoLayout->addWidget(fileInfoTable, 1);
                reportLayout->addWidget(fileInfoGroup, 0);
                pane.fileInfoTable = fileInfoTable;

                QGroupBox* engineGroup = new QGroupBox(QStringLiteral("多引擎检测"), reportContent);
                QVBoxLayout* engineLayout = new QVBoxLayout(engineGroup);
                QTableWidget* engineTable = new ks::ui::VisibleTableWidget(engineGroup);
                engineTable->setColumnCount(4);
                engineTable->setHorizontalHeaderLabels(QStringList()
                    << QStringLiteral("引擎")
                    << QStringLiteral("结果")
                    << QStringLiteral("引擎")
                    << QStringLiteral("结果"));
                configureReadOnlyTable(engineTable);
                installTableCopyMenu(engineTable);
                engineTable->horizontalHeader()->setVisible(false);
                engineTable->setSortingEnabled(false);
                engineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
                engineTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
                engineTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
                engineTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
                engineLayout->addWidget(engineTable, 1);
                reportLayout->addWidget(engineGroup, 3);
                pane.engineTable = engineTable;
            }
            else if (apiKind == VtApiKind::kIoc)
            {
                QGroupBox* iocButtonGroup = new QGroupBox(QStringLiteral("IOC 分项分析"), reportContent);
                QHBoxLayout* iocButtonLayout = new QHBoxLayout(iocButtonGroup);
                iocButtonLayout->setContentsMargins(0, 4, 0, 4);
                for (const QString& relationshipText : iocRelationships())
                {
                    QPushButton* relationshipButton = new QPushButton(
                        QStringLiteral("%1 开始分析").arg(relationshipDisplayText(relationshipText)),
                        iocButtonGroup);
                    QObject::connect(relationshipButton, &QPushButton::clicked, this, [this, relationshipText]()
                        {
                            // Input: User clicks an IOC relationship item button.
                            // Processing: Request only this relationship; if other VT requests are running, enter the independent execution queue.
                            // Returns: Nothing.
                            startSingleIocRelationship(relationshipText);
                        });
                    iocButtonLayout->addWidget(relationshipButton, 0);
                }
                iocButtonLayout->addStretch(1);
                reportLayout->addWidget(iocButtonGroup, 0);
            }

            QGroupBox* reportTreeGroup = new QGroupBox(
                apiKind == VtApiKind::kShallowAnalysis
                    ? QStringLiteral("静态分析 / 可展开详情")
                    : QStringLiteral("报告详情"),
                reportContent);
            QVBoxLayout* reportTreeLayout = new QVBoxLayout(reportTreeGroup);
            if (apiKind == VtApiKind::kFileProfile)
            {
                QLineEdit* fileProfileFilterEdit = new QLineEdit(reportTreeGroup);
                fileProfileFilterEdit->setClearButtonEnabled(true);
                fileProfileFilterEdit->setPlaceholderText(QStringLiteral("筛选文件画像字段/值，例如 pe_info、signature、section、tag、hash"));
                fileProfileFilterEdit->setToolTip(QStringLiteral("输入关键字后筛选文件画像树；匹配字段和值，保留命中节点的父级路径。"));
                reportTreeLayout->addWidget(fileProfileFilterEdit, 0);
                pane.fileProfileFilterEdit = fileProfileFilterEdit;
            }
            QTreeWidget* reportTree = new QTreeWidget(reportTreeGroup);
            reportTree->setColumnCount(2);
            reportTree->setHeaderLabels(QStringList() << QStringLiteral("字段") << QStringLiteral("值"));
            reportTree->setAlternatingRowColors(true);
            reportTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
            reportTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            reportTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
            installTreeCopyMenu(reportTree);
            reportTreeLayout->addWidget(reportTree, 1);
            reportLayout->addWidget(reportTreeGroup, 2);
            pane.reportTree = reportTree;
            if (apiKind == VtApiKind::kFileProfile && !pane.fileProfileFilterEdit.isNull())
            {
                QObject::connect(
                    pane.fileProfileFilterEdit,
                    &QLineEdit::textChanged,
                    reportTree,
                    [reportTree](const QString& filterText)
                    {
                        // Input: File profile filter text.
                        // Processing: Apply real-time filtering to report tree nodes, hiding only non-matching items without modifying original data.
                        // Returns: Nothing.
                        applyTreeFilter(reportTree, filterText);
                    });
            }

            if (apiKind == VtApiKind::kSandbox)
            {
                QObject::connect(reportTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int /*columnIndex*/)
                    {
                        // Input: Node with behaviour_id in the sandbox report tree.
                        // Processing: Fetch the corresponding HTML report when double-clicking the 'View HTML Report' node or its parent sandbox node.
                        // Return: None; if a report already exists, only switch to the raw data page for viewing.
                        if (item == nullptr)
                        {
                            return;
                        }
                        const QString kBehaviourId = item->data(0, Qt::UserRole).toString().trimmed();
                        if (kBehaviourId.isEmpty())
                        {
                            return;
                        }
                        selectApiTab(VtApiKind::kSandbox);
                        if (sandboxHtmlReports_.contains(kBehaviourId))
                        {
                            showSandboxHtmlPreview(kBehaviourId);
                            return;
                        }
                        requestSandboxHtmlReport(kBehaviourId);
                    });

                QGroupBox* htmlPreviewGroup = new QGroupBox(QStringLiteral("HTML 报告预览"), reportContent);
                QVBoxLayout* htmlPreviewLayout = new QVBoxLayout(htmlPreviewGroup);
                htmlPreviewLayout->setContentsMargins(0, 4, 0, 0);
                QTextBrowser* htmlPreviewBrowser = new QTextBrowser(htmlPreviewGroup);
                htmlPreviewBrowser->setReadOnly(true);
                htmlPreviewBrowser->setOpenExternalLinks(false);
                htmlPreviewBrowser->setOpenLinks(false);
                htmlPreviewBrowser->setMinimumHeight(260);
                htmlPreviewBrowser->setPlaceholderText(QStringLiteral("双击带 HTML 报告的沙箱行后在此处显示渲染结果。"));
                htmlPreviewLayout->addWidget(htmlPreviewBrowser, 1);
                htmlPreviewGroup->setVisible(false);
                reportLayout->addWidget(htmlPreviewGroup, 2);
                pane.sandboxHtmlPreviewGroup = htmlPreviewGroup;
                pane.sandboxHtmlPreview = htmlPreviewBrowser;

                QPushButton* htmlButton = new QPushButton(QStringLiteral("拉取可用HTML报告"), reportContent);
                htmlButton->setVisible(false);
                QObject::connect(htmlButton, &QPushButton::clicked, this, [this]()
                    {
                        if (sandboxHtmlQueue_.isEmpty())
                        {
                            const QJsonArray kBehavioursArray = sandboxBehavioursObject_.value(QStringLiteral("data")).toArray();
                            for (const QJsonValue& behaviourValue : kBehavioursArray)
                            {
                                const QJsonObject kBehaviourObject = behaviourValue.toObject();
                                const QJsonObject kAttributesObject = kBehaviourObject.value(QStringLiteral("attributes")).toObject();
                                const QString kBehaviourId = kBehaviourObject.value(QStringLiteral("id")).toString();
                                if (kAttributesObject.value(QStringLiteral("has_html_report")).toBool(false) &&
                                    !kBehaviourId.isEmpty() &&
                                    !sandboxHtmlReports_.contains(kBehaviourId))
                                {
                                    sandboxHtmlQueue_.append(kBehaviourId);
                                }
                            }
                        }
                        requestNextSandboxHtmlReport();
                    });
                reportLayout->addWidget(htmlButton, 0);
                pane.sandboxHtmlButton = htmlButton;
            }

            reportLayout->addStretch(0);
            reportScrollArea->setWidget(reportContent);

            QWidget* responsePage = new QWidget(detailTabWidget);
            QVBoxLayout* responseLayout = new QVBoxLayout(responsePage);
            responseLayout->setContentsMargins(8, 8, 8, 8);
            QTreeWidget* responseTree = new QTreeWidget(responsePage);
            responseTree->setColumnCount(3);
            responseTree->setHeaderLabels(QStringList()
                << QStringLiteral("字段 / 响应阶段")
                << QStringLiteral("值")
                << QStringLiteral("时间(UTC)"));
            responseTree->setAlternatingRowColors(true);
            responseTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
            responseTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
            responseTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
            responseTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
            installTreeCopyMenu(responseTree);
            responseLayout->addWidget(responseTree, 1);
            pane.responseTree = responseTree;

            QWidget* rawPage = new QWidget(detailTabWidget);
            QVBoxLayout* rawLayout = new QVBoxLayout(rawPage);
            rawLayout->setContentsMargins(8, 8, 8, 8);
            CodeEditorWidget* rawEditor = new CodeEditorWidget(resultDialog);
            rawEditor->setReadOnly(true);
            rawLayout->addWidget(rawEditor, 1);
            pane.rawEditor = rawEditor;

            detailTabWidget->addTab(reportPage, QStringLiteral("报告视图"));
            detailTabWidget->addTab(responsePage, QStringLiteral("响应详情"));
            detailTabWidget->addTab(rawPage, QStringLiteral("原始数据"));
            resultTabWidget->addTab(apiPage, apiTitleText(apiKind));
            return pane;
        };

    for (const VtApiKind kApiKind : paneApiKinds())
    {
        apiPanes_[static_cast<std::size_t>(apiIndex(kApiKind))] = kCreateCommonPane(kApiKind);
    }

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, resultDialog);

    QObject::connect(runAllButton, &QPushButton::clicked, this, [this]()
        {
            startAllApis();
        });
    QObject::connect(exportAllButton, &QPushButton::clicked, this, [this, resultDialog]()
        {
            // Input: Current cumulative raw response text, structured response array, and sample file name.
            // Processing: Show a save dialog and write a UTF-8 JSON file containing all APIs.
            // Returns: None; prompts user via dialog on failure.
            const QString kDefaultName = QStringLiteral("virustotal_%1_%2.json")
                .arg(QFileInfo(filePath_).completeBaseName().isEmpty()
                    ? QStringLiteral("sample")
                    : QFileInfo(filePath_).completeBaseName())
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
            const QString kSavePath = QFileDialog::getSaveFileName(
                resultDialog,
                QStringLiteral("导出 VirusTotal 全部 API 原始数据"),
                QDir(QDir::homePath()).absoluteFilePath(kDefaultName),
                QStringLiteral("JSON Files (*.json);;Text Files (*.txt);;All Files (*)"));
            if (kSavePath.isEmpty())
            {
                return;
            }

            QFile outputFile(kSavePath);
            if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
            {
                QMessageBox::warning(
                    resultDialog,
                    QStringLiteral("导出 VirusTotal 全部 API 原始数据"),
                    QStringLiteral("无法写入文件：%1\n%2").arg(kSavePath, outputFile.errorString()));
                return;
            }
            outputFile.write(buildRawExportJson());
            outputFile.close();
        });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, resultDialog, &QDialog::close);
    dialogLayout->addWidget(buttonBox, 0);

    resultDialog_ = resultDialog;
    resultSummaryLabel_.clear();
    resultTabWidget_ = resultTabWidget;
    ApiPaneUi& shallowPane = apiPanes_[static_cast<std::size_t>(apiIndex(VtApiKind::kShallowAnalysis))];
    readableOverviewLabel_ = shallowPane.overviewLabel;
    fileInfoTable_ = shallowPane.fileInfoTable;
    engineTable_ = shallowPane.engineTable;
    staticAnalysisTree_ = shallowPane.reportTree;
    responseTree_ = shallowPane.responseTree;
    resultEditor_ = shallowPane.rawEditor;
    for (const VtApiKind kApiKind : paneApiKinds())
    {
        refreshApiPlaceholder(kApiKind);
    }
    QObject::connect(resultDialog, &QObject::destroyed, this, [this]()
        {
            // Input: destroyed signal of the real-time results window.
            // Processing: Clear weak pointers and release the scan object in the scanFileAndAutoDelete scenario.
            // Returns: None; deleteLater is handled by the Qt event loop.
            resultDialog_.clear();
            resultSummaryLabel_.clear();
            resultTabWidget_.clear();
            readableOverviewLabel_.clear();
            fileInfoTable_.clear();
            engineTable_.clear();
            staticAnalysisTree_.clear();
            responseTree_.clear();
            resultEditor_.clear();
            for (ApiPaneUi& pane : apiPanes_)
            {
                pane.detailTabWidget.clear();
                pane.overviewLabel.clear();
                pane.startButton.clear();
                pane.sandboxHtmlButton.clear();
                pane.fileProfileFilterEdit.clear();
                pane.fileInfoTable.clear();
                pane.engineTable.clear();
                pane.reportTree.clear();
                pane.sandboxHtmlPreviewGroup.clear();
                pane.sandboxHtmlPreview.clear();
                pane.responseTree.clear();
                pane.rawEditor.clear();
            }
            if (deleteAfterResultDialogClosed_)
            {
                deleteAfterResultDialogClosed_ = false;
                deleteLater();
            }
        });
    resultDialog->show();
    resultDialog->raise();
    resultDialog->activateWindow();
}

void VirusTotalOnlineScan::appendRawJsonSection(const QString& titleText, const QJsonObject& jsonObject)
{
    appendRawJsonSection(VtApiKind::kShallowAnalysis, titleText, jsonObject);
}

void VirusTotalOnlineScan::appendRawJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QJsonObject& jsonObject)
{
    appendRawJsonSection(apiKind, titleText, jsonObject, QJsonObject());
}

void VirusTotalOnlineScan::appendRawJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QJsonObject& jsonObject,
    const QJsonObject& responseMetadata)
{
    ensureResultDialog();
    const QString kTimestampText = utcTimestampText();
    QJsonObject sectionObject;
    sectionObject.insert(QStringLiteral("timestamp_utc"), kTimestampText);
    sectionObject.insert(QStringLiteral("title"), titleText);
    sectionObject.insert(QStringLiteral("endpoint"), endpointTextFromTitle(titleText));
    sectionObject.insert(QStringLiteral("kind"), QStringLiteral("json"));
    sectionObject.insert(QStringLiteral("body"), jsonObject);
    if (!responseMetadata.isEmpty())
    {
        sectionObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        if (responseMetadata.contains(QStringLiteral("http_status")))
        {
            sectionObject.insert(QStringLiteral("http_status"), responseMetadata.value(QStringLiteral("http_status")));
        }
        if (responseMetadata.contains(QStringLiteral("retry_after")))
        {
            sectionObject.insert(QStringLiteral("retry_after"), responseMetadata.value(QStringLiteral("retry_after")));
        }
    }
    const int kIndex = apiIndex(apiKind);
    apiRawSections_[static_cast<std::size_t>(kIndex)].append(sectionObject);

    QString& rawText = apiRawText_[static_cast<std::size_t>(kIndex)];
    rawText += QStringLiteral("\n===== %1 | %2 =====\n")
        .arg(kTimestampText, titleText);
    if (!responseMetadata.isEmpty())
    {
        rawText += QStringLiteral("[HTTP] %1\n").arg(QString::fromUtf8(QJsonDocument(responseMetadata).toJson(QJsonDocument::Compact)));
    }
    rawText += ks::online_scan::formatJsonObject(jsonObject);
    rawText += QLatin1Char('\n');
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    if (!pane.rawEditor.isNull())
    {
        pane.rawEditor->setRawText(rawText);
    }
    QJsonObject treeObject = jsonObject;
    if (!responseMetadata.isEmpty())
    {
        treeObject.insert(QStringLiteral("_ksword_http"), responseMetadata);
    }
    appendResponseTreeJsonSection(apiKind, titleText, kTimestampText, treeObject);
}

void VirusTotalOnlineScan::appendRawTextSection(const QString& titleText, const QString& detailText)
{
    appendRawTextSection(VtApiKind::kShallowAnalysis, titleText, detailText);
}

void VirusTotalOnlineScan::appendRawTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& detailText)
{
    appendRawTextSection(apiKind, titleText, detailText, QJsonObject());
}

void VirusTotalOnlineScan::appendRawTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& detailText,
    const QJsonObject& responseMetadata)
{
    ensureResultDialog();
    const QString kTimestampText = utcTimestampText();
    QJsonObject sectionObject;
    sectionObject.insert(QStringLiteral("timestamp_utc"), kTimestampText);
    sectionObject.insert(QStringLiteral("title"), titleText);
    sectionObject.insert(QStringLiteral("endpoint"), endpointTextFromTitle(titleText));
    sectionObject.insert(QStringLiteral("kind"), QStringLiteral("text"));
    sectionObject.insert(QStringLiteral("body"), detailText);
    if (!responseMetadata.isEmpty())
    {
        sectionObject.insert(QStringLiteral("response_metadata"), responseMetadata);
        if (responseMetadata.contains(QStringLiteral("http_status")))
        {
            sectionObject.insert(QStringLiteral("http_status"), responseMetadata.value(QStringLiteral("http_status")));
        }
        if (responseMetadata.contains(QStringLiteral("retry_after")))
        {
            sectionObject.insert(QStringLiteral("retry_after"), responseMetadata.value(QStringLiteral("retry_after")));
        }
    }
    const int kIndex = apiIndex(apiKind);
    apiRawSections_[static_cast<std::size_t>(kIndex)].append(sectionObject);

    QString& rawText = apiRawText_[static_cast<std::size_t>(kIndex)];
    rawText += QStringLiteral("\n===== %1 | %2 =====\n")
        .arg(kTimestampText, titleText);
    if (!responseMetadata.isEmpty())
    {
        rawText += QStringLiteral("[HTTP] %1\n").arg(QString::fromUtf8(QJsonDocument(responseMetadata).toJson(QJsonDocument::Compact)));
    }
    rawText += detailText;
    rawText += QLatin1Char('\n');
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    if (!pane.rawEditor.isNull())
    {
        pane.rawEditor->setRawText(rawText);
    }
    appendResponseTreeTextSection(apiKind, titleText, kTimestampText, detailText);
}

void VirusTotalOnlineScan::appendRawReplyBodySection(const QString& titleText, const QByteArray& bodyBytes)
{
    appendRawReplyBodySection(VtApiKind::kShallowAnalysis, titleText, bodyBytes);
}

void VirusTotalOnlineScan::appendRawReplyBodySection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QByteArray& bodyBytes)
{
    appendRawReplyBodySection(apiKind, titleText, bodyBytes, QJsonObject());
}

void VirusTotalOnlineScan::appendRawReplyBodySection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QByteArray& bodyBytes,
    const QJsonObject& responseMetadata)
{
    // Input: Full HTTP response body, which may be a VirusTotal JSON error or plain text returned by a gateway/proxy.
    // Handling: prioritize saving as JSON object; if parsing fails, save as UTF-8 text, explicitly recording empty response bodies.
    // Returns: none; all data is appended to the live window and m_resultRawSections for JSON export.
    if (bodyBytes.isEmpty())
    {
        appendRawTextSection(apiKind, titleText, QStringLiteral("<空响应体>"), responseMetadata);
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
    if (parseError.error == QJsonParseError::NoError && kJsonDocument.isObject())
    {
        appendRawJsonSection(apiKind, titleText, kJsonDocument.object(), responseMetadata);
        return;
    }

    appendRawTextSection(apiKind, titleText, QString::fromUtf8(bodyBytes), responseMetadata);
}

QByteArray VirusTotalOnlineScan::buildRawExportJson() const
{
    // rootObject structure:
    // - metadata: context including upload source, sample file, analysis ID, and export time.
    // - local_hashes: Local sample hashes.
    // - apis: The raw JSON/text responses for each API Tab.
    // - legacy raw_text/responses are no longer top-level fields to avoid mixing data from multiple APIs.
    QJsonObject metadataObject;
    metadataObject.insert(QStringLiteral("service"), QStringLiteral("VirusTotal"));
    metadataObject.insert(QStringLiteral("source"), sourceText_);
    metadataObject.insert(QStringLiteral("file_path"), QDir::toNativeSeparators(filePath_));
    metadataObject.insert(QStringLiteral("file_name"), QFileInfo(filePath_).fileName());
    metadataObject.insert(QStringLiteral("analysis_id"), analysisId_);
    metadataObject.insert(QStringLiteral("poll_attempts"), pollAttempt_);
    metadataObject.insert(QStringLiteral("scan_in_progress"), scanInProgress_);
    metadataObject.insert(QStringLiteral("settings_json_path"), QDir::toNativeSeparators(settingsJsonPath_));
    metadataObject.insert(QStringLiteral("api_key_configured"), !apiKey_.trimmed().isEmpty());
    metadataObject.insert(QStringLiteral("exported_at_utc"), utcTimestampText());

    QJsonObject localHashesObject;
    localHashesObject.insert(QStringLiteral("md5"), localHashes_.md5Text);
    localHashesObject.insert(QStringLiteral("sha1"), localHashes_.sha1Text);
    localHashesObject.insert(QStringLiteral("sha256"), localHashes_.sha256Text);
    localHashesObject.insert(QStringLiteral("ready"), localHashes_.ready);

    QJsonObject apisObject;
    for (const VtApiKind kApiKind : paneApiKinds())
    {
        const int kIndex = apiIndex(kApiKind);
        QJsonObject apiObject;
        apiObject.insert(QStringLiteral("title"), apiTitleText(kApiKind));
        apiObject.insert(QStringLiteral("state"), apiStateText(apiStates_[static_cast<std::size_t>(kIndex)]));
        apiObject.insert(QStringLiteral("responses"), apiRawSections_[static_cast<std::size_t>(kIndex)]);
        apiObject.insert(QStringLiteral("raw_text"), apiRawText_[static_cast<std::size_t>(kIndex)]);
        apisObject.insert(apiExportKey(kApiKind), apiObject);
    }

    QJsonObject rootObject;
    rootObject.insert(QStringLiteral("metadata"), metadataObject);
    rootObject.insert(QStringLiteral("local_hashes"), localHashesObject);
    rootObject.insert(QStringLiteral("apis"), apisObject);
    return QJsonDocument(rootObject).toJson(QJsonDocument::Indented);
}

void VirusTotalOnlineScan::updateResultSummary(const QString& summaryText)
{
    ensureResultDialog();
    if (!resultSummaryLabel_.isNull())
    {
        resultSummaryLabel_->setText(summaryText);
    }
}

void VirusTotalOnlineScan::finalizeAutoDeleteIfNeeded()
{
    if (!autoDeleteWhenFinished_)
    {
        return;
    }
    if (hasActiveApiOperation() ||
        !allApiQueue_.isEmpty() ||
        !deferredApiQueue_.isEmpty() ||
        !deferredSingleIocRelationships_.isEmpty() ||
        sandboxHtmlFetchQueued_)
    {
        return;
    }

    // In the auto-delete scenario, the result window buttons still need to read m_resultRawText and m_filePath.
    // Therefore, as long as the window exists, extend the object's lifetime until the window closes; if the window has not been created or is already closed, release the object immediately.
    if (!resultDialog_.isNull())
    {
        deleteAfterResultDialogClosed_ = true;
        return;
    }

    deleteLater();
}

QString VirusTotalOnlineScan::buildResultSummary(const QJsonObject& analysisObject) const
{
    const QJsonObject kDataObject = analysisObject.value(QStringLiteral("data")).toObject();
    const QJsonObject kAttributesObject = kDataObject.value(QStringLiteral("attributes")).toObject();
    const QJsonObject kStatsObject = kAttributesObject.value(QStringLiteral("stats")).toObject();

    // Note: statsObject purpose: Carry VirusTotal multi-engine statistics; return the base analysis ID even if missing.
    const int kMaliciousCount = jsonValueToInt(kStatsObject, QStringLiteral("malicious"));
    const int kSuspiciousCount = jsonValueToInt(kStatsObject, QStringLiteral("suspicious"));
    const int kHarmlessCount = jsonValueToInt(kStatsObject, QStringLiteral("harmless"));
    const int kUndetectedCount = jsonValueToInt(kStatsObject, QStringLiteral("undetected"));
    const int kTimeoutCount = jsonValueToInt(kStatsObject, QStringLiteral("timeout"));
    const int kFailureCount = jsonValueToInt(kStatsObject, QStringLiteral("failure"));
    const int kUnsupportedCount = jsonValueToInt(kStatsObject, QStringLiteral("type-unsupported"));

    QStringList summaryLines;
    summaryLines << QStringLiteral("文件：%1").arg(QFileInfo(filePath_).fileName());
    summaryLines << QStringLiteral("AnalysisId：%1").arg(analysisId_);
    summaryLines << QStringLiteral("状态：%1").arg(kAttributesObject.value(QStringLiteral("status")).toString(QStringLiteral("未知")));
    summaryLines << QStringLiteral("恶意：%1，可疑：%2，无害：%3，未检出：%4")
        .arg(kMaliciousCount)
        .arg(kSuspiciousCount)
        .arg(kHarmlessCount)
        .arg(kUndetectedCount);
    summaryLines << QStringLiteral("超时：%1，失败：%2，不支持类型：%3")
        .arg(kTimeoutCount)
        .arg(kFailureCount)
        .arg(kUnsupportedCount);
    return summaryLines.join(QChar('\n'));
}

void VirusTotalOnlineScan::refreshReadableResult(const QJsonObject& analysisObject)
{
    // Input: Final JSON from VirusTotal /analyses/{id}.
    // Processing: Extract report view data from fixed fields data.attributes.stats/results and meta.file_info.
    //      Sort findings by malicious/suspicious priority; preserve expandable key raw fields in the static analysis tree.
    // Returns: nothing; only refreshes the already created report page controls.
    ensureResultDialog();

    const QList<QAbstractItemView*> kItemViews{
        fileInfoTable_.data(),
        engineTable_.data(),
        staticAnalysisTree_.data()
    };
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-readable-result"),
            kItemViews,
            [safeThis, analysisObject]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshReadableResult(analysisObject);
                }
            }))
    {
        return;
    }

    const QJsonObject kDataObject = analysisObject.value(QStringLiteral("data")).toObject();
    const QJsonObject kAttributesObject = kDataObject.value(QStringLiteral("attributes")).toObject();
    const QJsonObject kStatsObject = kAttributesObject.value(QStringLiteral("stats")).toObject();
    const QJsonObject kResultsObject = kAttributesObject.value(QStringLiteral("results")).toObject();
    const QJsonObject kMetaObject = analysisObject.value(QStringLiteral("meta")).toObject();
    const QJsonObject kFileInfoObject = kMetaObject.value(QStringLiteral("file_info")).toObject();
    const QJsonObject kLinksObject = kDataObject.value(QStringLiteral("links")).toObject();

    const int kMaliciousCount = jsonValueToInt(kStatsObject, QStringLiteral("malicious"));
    const int kSuspiciousCount = jsonValueToInt(kStatsObject, QStringLiteral("suspicious"));
    const int kHarmlessCount = jsonValueToInt(kStatsObject, QStringLiteral("harmless"));
    const int kUndetectedCount = jsonValueToInt(kStatsObject, QStringLiteral("undetected"));
    const int kTimeoutCount = jsonValueToInt(kStatsObject, QStringLiteral("timeout"));
    const int kConfirmedTimeoutCount = jsonValueToInt(kStatsObject, QStringLiteral("confirmed-timeout"));
    const int kFailureCount = jsonValueToInt(kStatsObject, QStringLiteral("failure"));
    const int kUnsupportedCount = jsonValueToInt(kStatsObject, QStringLiteral("type-unsupported"));
    const int kDetectedCount = kMaliciousCount + kSuspiciousCount;
    const int kEngineTotal = kMaliciousCount + kSuspiciousCount + kHarmlessCount + kUndetectedCount +
        kTimeoutCount + kConfirmedTimeoutCount + kFailureCount + kUnsupportedCount;

    const QString kStatusText = kAttributesObject.value(QStringLiteral("status")).toString(QStringLiteral("未知"));
    const QString kSha256Text = kFileInfoObject.value(QStringLiteral("sha256")).toString();
    const QString kSha1Text = kFileInfoObject.value(QStringLiteral("sha1")).toString();
    const QString kMd5Text = kFileInfoObject.value(QStringLiteral("md5")).toString();
    const qint64 kVtSizeBytes = static_cast<qint64>(kFileInfoObject.value(QStringLiteral("size")).toDouble(-1.0));
    const QFileInfo kLocalFileInfo(filePath_);
    const qint64 kDisplaySizeBytes = kVtSizeBytes >= 0 ? kVtSizeBytes : kLocalFileInfo.size();

    const ReportVerdict kVerdict = reportVerdictFromStats(kMaliciousCount, kSuspiciousCount, kHarmlessCount);

    if (!readableOverviewLabel_.isNull())
    {
        const QString kVerdictColorText = kVerdict.accentColor.isValid()
            ? kVerdict.accentColor.name(QColor::HexRgb)
            : ksword_theme::textPrimaryColorHex();
        readableOverviewLabel_->setText(QStringLiteral(
            "<table cellspacing='0' cellpadding='0'>"
            "<tr>"
            "<td width='124'><img src='%1' width='104' height='104'/></td>"
            "<td>"
            "<div style='font-size:22px;font-weight:700;'>%2</div>"
            "<div style='margin-top:6px;'>"
            "<span style='color:%3;font-size:18px;font-weight:700;'>%4</span>"
            "&nbsp;&nbsp; 检出率：<span style='color:%3;font-weight:700;'>%5 / %6</span>"
            "&nbsp;&nbsp; 状态：%7"
            "</div>"
            "<div style='margin-top:6px;'>AnalysisId：%8</div>"
            "</td>"
            "</tr>"
            "</table>")
            .arg(kVerdict.iconPath)
            .arg(kLocalFileInfo.fileName().toHtmlEscaped().isEmpty()
                ? QStringLiteral("<未知文件>")
                : kLocalFileInfo.fileName().toHtmlEscaped())
            .arg(kVerdictColorText)
            .arg(kVerdict.labelText.toHtmlEscaped())
            .arg(kDetectedCount)
            .arg(kEngineTotal)
            .arg(kStatusText.toHtmlEscaped())
            .arg(analysisId_.toHtmlEscaped()));
    }

    if (!fileInfoTable_.isNull())
    {
        fileInfoTable_->setRowCount(0);
        setTableRow(fileInfoTable_, 0, QStringLiteral("文件名"), kLocalFileInfo.fileName());
        setTableRow(fileInfoTable_, 1, QStringLiteral("文件大小"), formatByteCount(kDisplaySizeBytes));
        setTableRow(fileInfoTable_, 2, QStringLiteral("SHA256"), kSha256Text.isEmpty() ? QStringLiteral("-") : kSha256Text);
        setTableRow(fileInfoTable_, 3, QStringLiteral("SHA1"), kSha1Text.isEmpty() ? QStringLiteral("-") : kSha1Text);
        setTableRow(fileInfoTable_, 4, QStringLiteral("MD5"), kMd5Text.isEmpty() ? QStringLiteral("-") : kMd5Text);
        setTableRow(fileInfoTable_, 5, QStringLiteral("AnalysisId"), kDataObject.value(QStringLiteral("id")).toString(analysisId_));
        setTableRow(fileInfoTable_, 6, QStringLiteral("分析时间"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("date")).toDouble(0.0))));
        setTableRow(fileInfoTable_, 7, QStringLiteral("VT 文件链接"), kLinksObject.value(QStringLiteral("item")).toString(QStringLiteral("-")));
        fitTableHeightToRows(fileInfoTable_);
    }

    if (!engineTable_.isNull())
    {
        struct EngineRow
        {
            QString engineText;
            QString categoryRawText;
            QString resultText;
            QString versionText;
            QString updateText;
        };
        std::vector<EngineRow> engineRows;
        engineRows.reserve(static_cast<std::size_t>(kResultsObject.size()));
        for (auto iterator = kResultsObject.constBegin(); iterator != kResultsObject.constEnd(); ++iterator)
        {
            const QJsonObject kEngineObject = iterator.value().toObject();
            EngineRow row;
            row.engineText = kEngineObject.value(QStringLiteral("engine_name")).toString(iterator.key());
            row.categoryRawText = kEngineObject.value(QStringLiteral("category")).toString();
            row.resultText = kEngineObject.value(QStringLiteral("result")).toString();
            row.versionText = kEngineObject.value(QStringLiteral("engine_version")).toString();
            row.updateText = kEngineObject.value(QStringLiteral("engine_update")).toString();
            engineRows.push_back(row);
        }
        std::sort(engineRows.begin(), engineRows.end(), [](const EngineRow& left, const EngineRow& right)
            {
                const int kLeftPriority = categoryPriority(left.categoryRawText);
                const int kRightPriority = categoryPriority(right.categoryRawText);
                if (kLeftPriority != kRightPriority)
                {
                    return kLeftPriority < kRightPriority;
                }
                return QString::localeAwareCompare(left.engineText, right.engineText) < 0;
            });

        const int kTableRowCount = static_cast<int>((engineRows.size() + 1) / 2);
        engineTable_->clearContents();
        engineTable_->setRowCount(kTableRowCount);
        for (int visibleIndex = 0; visibleIndex < static_cast<int>(engineRows.size()); ++visibleIndex)
        {
            const EngineRow& row = engineRows[static_cast<std::size_t>(visibleIndex)];
            const QColor kRowColor = categoryColor(row.categoryRawText);
            const QString kVersionText = row.versionText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : row.versionText.trimmed();
            const QString kUpdateText = row.updateText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : row.updateText.trimmed();
            const QString kTooltipText = QStringLiteral("版本：%1\n更新时间：%2").arg(kVersionText, kUpdateText);
            const int kTableRow = visibleIndex / 2;
            const int kTableColumn = (visibleIndex % 2) * 2;

            QTableWidgetItem* engineItem = createReadOnlyTableItem(row.engineText);
            QTableWidgetItem* resultItem = createReadOnlyTableItem(
                engineDetectionText(row.categoryRawText, row.resultText),
                kRowColor);
            engineItem->setToolTip(kTooltipText);
            resultItem->setToolTip(kTooltipText);
            engineTable_->setItem(kTableRow, kTableColumn, engineItem);
            engineTable_->setItem(kTableRow, kTableColumn + 1, resultItem);
            engineTable_->setRowHeight(kTableRow, 22);
        }
    }

    if (!staticAnalysisTree_.isNull())
    {
        staticAnalysisTree_->clear();
        QTreeWidgetItem* basicItem = new QTreeWidgetItem(staticAnalysisTree_);
        basicItem->setText(0, QStringLiteral("基础信息"));
        basicItem->setText(1, QStringLiteral("文件与 Analysis 上下文"));
        addTreeLeaf(basicItem, QStringLiteral("文件名"), kLocalFileInfo.fileName());
        addTreeLeaf(basicItem, QStringLiteral("大小"), formatByteCount(kDisplaySizeBytes));
        addTreeLeaf(basicItem, QStringLiteral("SHA256"), kSha256Text.isEmpty() ? QStringLiteral("-") : kSha256Text);
        addTreeLeaf(basicItem, QStringLiteral("SHA1"), kSha1Text.isEmpty() ? QStringLiteral("-") : kSha1Text);
        addTreeLeaf(basicItem, QStringLiteral("MD5"), kMd5Text.isEmpty() ? QStringLiteral("-") : kMd5Text);

        QTreeWidgetItem* analysisItem = new QTreeWidgetItem(staticAnalysisTree_);
        analysisItem->setText(0, QStringLiteral("分析任务"));
        analysisItem->setText(1, QStringLiteral("VirusTotal analysis"));
        addTreeLeaf(analysisItem, QStringLiteral("AnalysisId"), kDataObject.value(QStringLiteral("id")).toString(analysisId_));
        addTreeLeaf(analysisItem, QStringLiteral("状态"), kStatusText);
        addTreeLeaf(analysisItem, QStringLiteral("提交/分析时间"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("date")).toDouble(0.0))));
        addTreeLeaf(analysisItem, QStringLiteral("Self 链接"), kLinksObject.value(QStringLiteral("self")).toString(QStringLiteral("-")));
        addTreeLeaf(analysisItem, QStringLiteral("File 链接"), kLinksObject.value(QStringLiteral("item")).toString(QStringLiteral("-")));

        QTreeWidgetItem* statsItem = new QTreeWidgetItem(staticAnalysisTree_);
        statsItem->setText(0, QStringLiteral("统计字段"));
        statsItem->setText(1, QStringLiteral("data.attributes.stats"));
        appendJsonValueToTree(statsItem, QStringLiteral("stats"), kStatsObject);

        QTreeWidgetItem* rawAttributesItem = new QTreeWidgetItem(staticAnalysisTree_);
        rawAttributesItem->setText(0, QStringLiteral("原始 attributes"));
        rawAttributesItem->setText(1, QStringLiteral("可展开查看 VT 固定字段"));
        appendJsonValueToTree(rawAttributesItem, QStringLiteral("attributes"), kAttributesObject);

        basicItem->setExpanded(true);
        analysisItem->setExpanded(true);
        statsItem->setExpanded(true);
        staticAnalysisTree_->resizeColumnToContents(0);
    }

    if (!resultTabWidget_.isNull())
    {
        resultTabWidget_->setCurrentIndex(0);
    }
}

void VirusTotalOnlineScan::refreshFileProfileResult(const QJsonObject& fileObject)
{
    ensureResultDialog();
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(apiIndex(VtApiKind::kFileProfile))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-file-profile-result"),
            {pane.reportTree.data()},
            [safeThis, fileObject]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshFileProfileResult(fileObject);
                }
            }))
    {
        return;
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(false);
    }

    const QJsonObject kDataObject = fileObject.value(QStringLiteral("data")).toObject();
    const QJsonObject kAttributesObject = kDataObject.value(QStringLiteral("attributes")).toObject();
    const QString kMeaningfulName = kAttributesObject.value(QStringLiteral("meaningful_name")).toString(QFileInfo(filePath_).fileName());
    const QString kTypeText = kAttributesObject.value(QStringLiteral("type_description")).toString(
        kAttributesObject.value(QStringLiteral("type_tag")).toString(QStringLiteral("-")));
    const int kReputation = kAttributesObject.value(QStringLiteral("reputation")).toInt(0);

    if (pane.overviewLabel)
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>%1</div>"
            "<div style='margin-top:6px;'>类型：%2&nbsp;&nbsp; Reputation：%3</div>"
            "<div style='margin-top:6px;'>SHA256：%4</div>")
            .arg(kMeaningfulName.toHtmlEscaped())
            .arg(kTypeText.toHtmlEscaped())
            .arg(kReputation)
            .arg(localHashes_.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    QTreeWidgetItem* basicItem = new QTreeWidgetItem(pane.reportTree);
    basicItem->setText(0, QStringLiteral("文件画像"));
    basicItem->setText(1, QStringLiteral("基础属性"));
    addTreeLeaf(basicItem, QStringLiteral("名称"), kMeaningfulName);
    addTreeLeaf(basicItem, QStringLiteral("类型描述"), kTypeText);
    addTreeLeaf(basicItem, QStringLiteral("类型标签"), kAttributesObject.value(QStringLiteral("type_tag")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("提交次数"), QString::number(kAttributesObject.value(QStringLiteral("times_submitted")).toInt(0)));
    addTreeLeaf(basicItem, QStringLiteral("Reputation"), QString::number(kReputation));
    addTreeLeaf(basicItem, QStringLiteral("首次提交"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("first_submission_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("最后提交"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("last_submission_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("最后分析"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("last_analysis_date")).toDouble(0.0))));
    addTreeLeaf(basicItem, QStringLiteral("MD5"), kAttributesObject.value(QStringLiteral("md5")).toString(localHashes_.md5Text));
    addTreeLeaf(basicItem, QStringLiteral("SHA1"), kAttributesObject.value(QStringLiteral("sha1")).toString(localHashes_.sha1Text));
    addTreeLeaf(basicItem, QStringLiteral("SHA256"), kAttributesObject.value(QStringLiteral("sha256")).toString(localHashes_.sha256Text));
    addTreeLeaf(basicItem, QStringLiteral("SSDEEP"), kAttributesObject.value(QStringLiteral("ssdeep")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("TLSH"), kAttributesObject.value(QStringLiteral("tlsh")).toString(QStringLiteral("-")));
    addTreeLeaf(basicItem, QStringLiteral("Authentihash"), kAttributesObject.value(QStringLiteral("authentihash")).toString(QStringLiteral("-")));

    QTreeWidgetItem* namesItem = new QTreeWidgetItem(pane.reportTree);
    namesItem->setText(0, QStringLiteral("名称 / 标签 / 投票"));
    namesItem->setText(1, QStringLiteral("可展开"));
    appendJsonValueToTree(namesItem, QStringLiteral("names"), kAttributesObject.value(QStringLiteral("names")));
    appendJsonValueToTree(namesItem, QStringLiteral("tags"), kAttributesObject.value(QStringLiteral("tags")));
    appendJsonValueToTree(namesItem, QStringLiteral("total_votes"), kAttributesObject.value(QStringLiteral("total_votes")));
    appendJsonValueToTree(namesItem, QStringLiteral("sandbox_verdicts"), kAttributesObject.value(QStringLiteral("sandbox_verdicts")));

    QTreeWidgetItem* peItem = new QTreeWidgetItem(pane.reportTree);
    peItem->setText(0, QStringLiteral("PE 信息"));
    peItem->setText(1, kAttributesObject.contains(QStringLiteral("pe_info")) ? QStringLiteral("pe_info") : QStringLiteral("无 PE 信息"));
    appendJsonValueToTree(peItem, QStringLiteral("pe_info"), kAttributesObject.value(QStringLiteral("pe_info")));

    QTreeWidgetItem* signatureItem = new QTreeWidgetItem(pane.reportTree);
    signatureItem->setText(0, QStringLiteral("签名信息"));
    signatureItem->setText(1, kAttributesObject.contains(QStringLiteral("signature_info")) ? QStringLiteral("signature_info") : QStringLiteral("无签名信息"));
    appendJsonValueToTree(signatureItem, QStringLiteral("signature_info"), kAttributesObject.value(QStringLiteral("signature_info")));

    QTreeWidgetItem* rawItem = new QTreeWidgetItem(pane.reportTree);
    rawItem->setText(0, QStringLiteral("原始 attributes"));
    rawItem->setText(1, QStringLiteral("完整字段"));
    appendJsonValueToTree(rawItem, QStringLiteral("attributes"), kAttributesObject);

    basicItem->setExpanded(true);
    namesItem->setExpanded(true);
    peItem->setExpanded(true);
    signatureItem->setExpanded(true);
    if (!pane.fileProfileFilterEdit.isNull())
    {
        applyTreeFilter(pane.reportTree, pane.fileProfileFilterEdit->text());
    }
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::refreshIocResult()
{
    ensureResultDialog();
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(apiIndex(VtApiKind::kIoc))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-ioc-result"),
            {pane.reportTree.data()},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshIocResult();
                }
            }))
    {
        return;
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(apiStates_[static_cast<std::size_t>(apiIndex(VtApiKind::kIoc))] != VtApiState::kCompleted);
    }
    if (pane.overviewLabel)
    {
        int totalCount = 0;
        for (const QString& relationshipText : iocRelationships())
        {
            totalCount += iocRelationshipObjects_.value(relationshipText).toObject().value(QStringLiteral("data")).toArray().size();
        }
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>IOC 关系</div>"
            "<div style='margin-top:6px;'>已请求 %1 类关系，命中对象 %2 个。</div>"
            "<div style='margin-top:6px;'>SHA256：%3</div>")
            .arg(iocRelationships().size())
            .arg(totalCount)
            .arg(localHashes_.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    bool hasAnyData = false;
    for (const QString& relationshipText : iocRelationships())
    {
        const QJsonObject kRelationshipObject = iocRelationshipObjects_.value(relationshipText).toObject();
        const QJsonArray kDataArray = kRelationshipObject.value(QStringLiteral("data")).toArray();
        QTreeWidgetItem* relationshipItem = new QTreeWidgetItem(pane.reportTree);
        relationshipItem->setText(0, relationshipDisplayText(relationshipText));
        relationshipItem->setText(1, kRelationshipObject.contains(QStringLiteral("error"))
            ? kRelationshipObject.value(QStringLiteral("error")).toString()
            : kRelationshipObject.value(QStringLiteral("empty_reason")).toString(QStringLiteral("%1 项").arg(kDataArray.size())));
        if (!kDataArray.isEmpty())
        {
            hasAnyData = true;
        }
        for (int itemIndex = 0; itemIndex < kDataArray.size(); ++itemIndex)
        {
            const QJsonObject kItemObject = kDataArray.at(itemIndex).toObject();
            QTreeWidgetItem* objectItem = new QTreeWidgetItem(relationshipItem);
            objectItem->setText(0, jsonValueCompactText(kItemObject.value(QStringLiteral("id"))));
            objectItem->setText(1, kItemObject.value(QStringLiteral("type")).toString(QStringLiteral("{Object}")));
            appendJsonValueToTree(objectItem, QStringLiteral("object"), kItemObject);
        }
        relationshipItem->setExpanded(true);
    }

    if (!hasAnyData)
    {
        QTreeWidgetItem* emptyItem = new QTreeWidgetItem(pane.reportTree);
        emptyItem->setText(0, QStringLiteral("结果"));
        emptyItem->setText(1, QStringLiteral("VT 暂无该文件的常用 IOC 关系数据。"));
    }
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::refreshSandboxResult()
{
    ensureResultDialog();
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(apiIndex(VtApiKind::kSandbox))];
    QPointer<VirusTotalOnlineScan> safeThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("virus-total-sandbox-result"),
            {pane.reportTree.data()},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->refreshSandboxResult();
                }
            }))
    {
        return;
    }
    const QJsonArray kBehavioursArray = sandboxBehavioursObject_.value(QStringLiteral("data")).toArray();
    int htmlAvailableCount = 0;
    for (const QJsonValue& behaviourValue : kBehavioursArray)
    {
        const QJsonObject kBehaviourObject = behaviourValue.toObject();
        if (kBehaviourObject.value(QStringLiteral("attributes")).toObject().value(QStringLiteral("has_html_report")).toBool(false))
        {
            ++htmlAvailableCount;
        }
    }
    if (pane.startButton)
    {
        pane.startButton->setVisible(apiStates_[static_cast<std::size_t>(apiIndex(VtApiKind::kSandbox))] != VtApiState::kCompleted);
    }
    if (pane.sandboxHtmlButton)
    {
        pane.sandboxHtmlButton->setVisible(htmlAvailableCount > sandboxHtmlReports_.size());
    }
    if (pane.sandboxHtmlPreviewGroup && sandboxHtmlReports_.isEmpty())
    {
        pane.sandboxHtmlPreviewGroup->setVisible(false);
    }
    if (pane.overviewLabel)
    {
        pane.overviewLabel->setText(QStringLiteral(
            "<div style='font-size:22px;font-weight:700;'>沙箱行为分析</div>"
            "<div style='margin-top:6px;'>沙箱报告：%1 个，HTML 可用：%2 个，已拉取：%3 个。</div>"
            "<div style='margin-top:6px;'>SHA256：%4</div>")
            .arg(kBehavioursArray.size())
            .arg(htmlAvailableCount)
            .arg(sandboxHtmlReports_.size())
            .arg(localHashes_.sha256Text.toHtmlEscaped()));
    }
    if (!pane.reportTree)
    {
        return;
    }

    pane.reportTree->clear();
    const QJsonObject kSummaryDataObject = sandboxSummaryObject_.value(QStringLiteral("data")).toObject();
    QTreeWidgetItem* summaryItem = new QTreeWidgetItem(pane.reportTree);
    summaryItem->setText(0, QStringLiteral("行为汇总"));
    summaryItem->setText(1, kSummaryDataObject.isEmpty() ? QStringLiteral("无汇总数据") : QStringLiteral("{ %1 fields }").arg(kSummaryDataObject.size()));
    const QStringList kCommonSummaryKeys = QStringList()
        << QStringLiteral("processes_tree")
        << QStringLiteral("processes_created")
        << QStringLiteral("processes_terminated")
        << QStringLiteral("command_executions")
        << QStringLiteral("files_opened")
        << QStringLiteral("files_written")
        << QStringLiteral("files_deleted")
        << QStringLiteral("files_dropped")
        << QStringLiteral("registry_keys_opened")
        << QStringLiteral("registry_keys_set")
        << QStringLiteral("registry_keys_deleted")
        << QStringLiteral("mutexes_created")
        << QStringLiteral("dns_lookups")
        << QStringLiteral("ip_traffic")
        << QStringLiteral("http_conversations")
        << QStringLiteral("tcp_connections")
        << QStringLiteral("udp_conversations")
        << QStringLiteral("contacted_ips")
        << QStringLiteral("contacted_domains")
        << QStringLiteral("contacted_urls")
        << QStringLiteral("ids_alerts")
        << QStringLiteral("mitre_attack_techniques")
        << QStringLiteral("sigma_analysis_results")
        << QStringLiteral("signature_matches");
    for (const QString& keyText : kCommonSummaryKeys)
    {
        if (kSummaryDataObject.contains(keyText))
        {
            appendJsonValueToTree(summaryItem, keyText, kSummaryDataObject.value(keyText));
        }
    }

    QTreeWidgetItem* behavioursItem = new QTreeWidgetItem(pane.reportTree);
    behavioursItem->setText(0, QStringLiteral("单沙箱报告"));
    behavioursItem->setText(1, QStringLiteral("%1 个").arg(kBehavioursArray.size()));
    for (const QJsonValue& behaviourValue : kBehavioursArray)
    {
        const QJsonObject kBehaviourObject = behaviourValue.toObject();
        const QJsonObject kAttributesObject = kBehaviourObject.value(QStringLiteral("attributes")).toObject();
        const QString kBehaviourId = kBehaviourObject.value(QStringLiteral("id")).toString();
        QTreeWidgetItem* behaviourItem = new QTreeWidgetItem(behavioursItem);
        behaviourItem->setText(0, kAttributesObject.value(QStringLiteral("sandbox_name")).toString(kBehaviourId));
        behaviourItem->setText(1, QStringLiteral("HTML:%1 PCAP:%2 EVTX:%3 MEM:%4")
            .arg(kAttributesObject.value(QStringLiteral("has_html_report")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(kAttributesObject.value(QStringLiteral("has_pcap")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(kAttributesObject.value(QStringLiteral("has_evtx")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无"))
            .arg(kAttributesObject.value(QStringLiteral("has_memdump")).toBool(false) ? QStringLiteral("有") : QStringLiteral("无")));
        if (kAttributesObject.value(QStringLiteral("has_html_report")).toBool(false) && !kBehaviourId.isEmpty())
        {
            behaviourItem->setData(0, Qt::UserRole, kBehaviourId);
            behaviourItem->setToolTip(0, QStringLiteral("双击查看 HTML 沙箱报告：%1").arg(kBehaviourId));
            behaviourItem->setToolTip(1, QStringLiteral("双击查看 HTML 沙箱报告"));
        }
        addTreeLeaf(behaviourItem, QStringLiteral("ID"), kBehaviourId);
        addTreeLeaf(behaviourItem, QStringLiteral("分析时间"), unixDateText(static_cast<qint64>(kAttributesObject.value(QStringLiteral("analysis_date")).toDouble(0.0))));
        addTreeLeaf(behaviourItem, QStringLiteral("behash"), kAttributesObject.value(QStringLiteral("behash")).toString(QStringLiteral("-")));
        if (kAttributesObject.value(QStringLiteral("has_html_report")).toBool(false) && !kBehaviourId.isEmpty())
        {
            QTreeWidgetItem* htmlActionItem = addTreeLeaf(
                behaviourItem,
                QStringLiteral("查看HTML报告"),
                sandboxHtmlReports_.contains(kBehaviourId) ? QStringLiteral("已拉取，双击在下方预览") : QStringLiteral("双击开始拉取"));
            if (htmlActionItem != nullptr)
            {
                htmlActionItem->setData(0, Qt::UserRole, kBehaviourId);
                htmlActionItem->setToolTip(0, QStringLiteral("双击查看 HTML 沙箱报告：%1").arg(kBehaviourId));
                htmlActionItem->setToolTip(1, QStringLiteral("双击触发 GET /api/v3/file_behaviours/%1/html").arg(kBehaviourId));
            }
        }
        appendJsonValueToTree(behaviourItem, QStringLiteral("attributes"), kAttributesObject);
    }

    QTreeWidgetItem* htmlItem = new QTreeWidgetItem(pane.reportTree);
    htmlItem->setText(0, QStringLiteral("HTML 报告"));
    htmlItem->setText(1, QStringLiteral("已拉取 %1 个").arg(sandboxHtmlReports_.size()));
    for (auto iterator = sandboxHtmlReports_.constBegin(); iterator != sandboxHtmlReports_.constEnd(); ++iterator)
    {
        const QJsonObject kHtmlObject = iterator.value().toObject();
        QTreeWidgetItem* reportItem = new QTreeWidgetItem(htmlItem);
        reportItem->setText(0, iterator.key());
        if (kHtmlObject.contains(QStringLiteral("error")))
        {
            reportItem->setText(1, kHtmlObject.value(QStringLiteral("error")).toString());
        }
        else if (kHtmlObject.contains(QStringLiteral("empty_reason")))
        {
            reportItem->setText(1, kHtmlObject.value(QStringLiteral("empty_reason")).toString());
        }
        else
        {
            const QString kHtmlText = kHtmlObject.value(QStringLiteral("html")).toString();
            reportItem->setText(1, QStringLiteral("HTML 已保存，长度 %1 字符").arg(kHtmlText.size()));
            addTreeLeaf(
                reportItem,
                QStringLiteral("HTML 预览"),
                kHtmlText.left(1200).replace(QChar('\n'), QChar(' ')).replace(QChar('\r'), QChar(' ')));
        }
    }

    summaryItem->setExpanded(true);
    behavioursItem->setExpanded(true);
    htmlItem->setExpanded(true);
    pane.reportTree->resizeColumnToContents(0);
}

void VirusTotalOnlineScan::showSandboxHtmlPreview(const QString& behaviourId)
{
    // Input: A file_behaviour ID that has been fetched or recorded with an error.
    // Note: Display HTML-rendered content below the sandbox report view; display errors/empty states as compact text cards.
    // Returns: nothing; silently returns if the control or ID does not exist to avoid affecting original data saving.
    const QString kTrimmedId = behaviourId.trimmed();
    if (kTrimmedId.isEmpty())
    {
        return;
    }

    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(apiIndex(VtApiKind::kSandbox))];
    if (pane.sandboxHtmlPreviewGroup.isNull() || pane.sandboxHtmlPreview.isNull())
    {
        return;
    }

    const QJsonObject kHtmlObject = sandboxHtmlReports_.value(kTrimmedId).toObject();
    if (kHtmlObject.isEmpty())
    {
        return;
    }

    QString previewHtml;
    if (kHtmlObject.contains(QStringLiteral("html")))
    {
        previewHtml = kHtmlObject.value(QStringLiteral("html")).toString();
        if (previewHtml.trimmed().isEmpty())
        {
            previewHtml = QStringLiteral(
                "<div style='font-family:Segoe UI,Microsoft YaHei,sans-serif;padding:12px;'>"
                "<b>HTML 报告为空</b><br/>该沙箱对象返回了空 HTML。"
                "</div>");
        }
    }
    else
    {
        const QString kMessageText = kHtmlObject.contains(QStringLiteral("empty_reason"))
            ? kHtmlObject.value(QStringLiteral("empty_reason")).toString()
            : kHtmlObject.value(QStringLiteral("error")).toString(QStringLiteral("HTML 报告暂不可用。"));
        previewHtml = QStringLiteral(
            "<div style='font-family:Segoe UI,Microsoft YaHei,sans-serif;padding:12px;'>"
            "<div style='font-size:16px;font-weight:700;margin-bottom:8px;'>HTML 报告暂不可用</div>"
            "<pre style='white-space:pre-wrap;margin:0;'>%1</pre>"
            "</div>")
            .arg(kMessageText.toHtmlEscaped());
    }

    pane.sandboxHtmlPreviewGroup->setTitle(QStringLiteral("HTML 报告预览 - %1").arg(kTrimmedId));
    pane.sandboxHtmlPreview->setHtml(previewHtml);
    pane.sandboxHtmlPreviewGroup->setVisible(true);
    if (!pane.detailTabWidget.isNull())
    {
        pane.detailTabWidget->setCurrentIndex(0);
    }
}

void VirusTotalOnlineScan::appendResponseTreeJsonSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& timestampText,
    const QJsonObject& jsonObject)
{
    // Input: A parsed VT JSON response.
    // Processing: Append as the top-level node of the response detail page, recursively expanding JSON fields in child nodes.
    // Returns: Nothing.
    const int kIndex = apiIndex(apiKind);
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    if (pane.responseTree.isNull())
    {
        return;
    }

    QTreeWidgetItem* sectionItem = new QTreeWidgetItem(pane.responseTree);
    sectionItem->setText(0, titleText);
    sectionItem->setText(1, QStringLiteral("{ %1 fields }").arg(jsonObject.size()));
    sectionItem->setText(2, timestampText);
    sectionItem->setExpanded(false);
    for (auto iterator = jsonObject.constBegin(); iterator != jsonObject.constEnd(); ++iterator)
    {
        appendJsonValueToTree(sectionItem, iterator.key(), iterator.value());
    }
    pane.responseTree->scrollToItem(sectionItem);
}

void VirusTotalOnlineScan::appendResponseTreeTextSection(
    const VtApiKind apiKind,
    const QString& titleText,
    const QString& timestampText,
    const QString& detailText)
{
    // Input: A non-JSON response or local error details.
    // Processing: Append as a top-level node in the response detail page, placing the body in child nodes to avoid expanding the header.
    // Returns: Nothing.
    const int kIndex = apiIndex(apiKind);
    ApiPaneUi& pane = apiPanes_[static_cast<std::size_t>(kIndex)];
    if (pane.responseTree.isNull())
    {
        return;
    }

    QTreeWidgetItem* sectionItem = new QTreeWidgetItem(pane.responseTree);
    sectionItem->setText(0, titleText);
    sectionItem->setText(1, QStringLiteral("text"));
    sectionItem->setText(2, timestampText);
    addTreeLeaf(sectionItem, QStringLiteral("详情"), detailText);
    sectionItem->setExpanded(true);
    pane.responseTree->scrollToItem(sectionItem);
}
