#include "ThreatBookScan.h"

#include "OnlineScanSupport.h"
#include "../Framework.h"
#include "../settings_dock/AppearanceSettings.h"

#include <QFile>
#include <QFileInfo>
#include <QHttpMultiPart>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QWidget>

#include <algorithm>

namespace
{
    // ThreatBook API constants: centrally maintain official v3 endpoints to avoid scattering them across business logic.
    constexpr const char* kThreatBookUploadEndpoint = "https://api.threatbook.cn/v3/file/upload";
    constexpr const char* kThreatBookReportEndpoint = "https://api.threatbook.cn/v3/file/report";
    constexpr int kInitialPollDelayMs = 15000;
    constexpr int kPollIntervalMs = 15000;
    constexpr int kMaxPollAttempts = 40;

    // addFormField:
    // - Appends standard text fields to a multipart request.
    // - The ThreatBook file/upload apikey field invokes this function.
    // Parameter multiPart: Multipart request body.
    // Parameter fieldName: field name.
    // Parameter fieldValue: Field value.
    // Returns: Nothing.
    void addFormField(QHttpMultiPart* multiPart, const QString& fieldName, const QString& fieldValue)
    {
        if (multiPart == nullptr)
        {
            return;
        }
        QHttpPart formPart;
        formPart.setHeader(
            QNetworkRequest::ContentDispositionHeader,
            QVariant(QStringLiteral("form-data; name=\"%1\"").arg(fieldName)));
        formPart.setBody(fieldValue.toUtf8());
        multiPart->append(formPart);
    }

    // threatBookResponseCode:
    // - Reads the response_code from the ThreatBook response.
    // - Returns -999999 when the field is missing to distinguish it from a normal 0.
    // Input rootObject: Response JSON root object.
    // Returns: the response_code value.
    int threatBookResponseCode(const QJsonObject& rootObject)
    {
        return rootObject.value(QStringLiteral("response_code")).toInt(-999999);
    }

    // threatBookVerboseMessage:
    // - Read verbose_msg or message from the ThreatBook response;
    // - Used for error dialog and 'still analyzing' status identification.
    // Input rootObject: Response JSON root object.
    // Returns: Server message text.
    QString threatBookVerboseMessage(const QJsonObject& rootObject)
    {
        const QString kVerboseText = rootObject.value(QStringLiteral("verbose_msg")).toString().trimmed();
        if (!kVerboseText.isEmpty())
        {
            return kVerboseText;
        }
        return rootObject.value(QStringLiteral("message")).toString().trimmed();
    }

    // jsonContainsPendingHint:
    // - Identify ThreatBook's queuing or analysis status from the response JSON text.
    // - Official documentation examples may show 'In Progress'; Chinese environments may also return 'Analyzing'.
    // Input rootObject: Response JSON root object.
    // Return: true = polling still required; false = not in a waiting state.
    bool jsonContainsPendingHint(const QJsonObject& rootObject)
    {
        const QString kCompactText = QString::fromUtf8(
            QJsonDocument(rootObject).toJson(QJsonDocument::Compact)).toLower();
        return kCompactText.contains(QStringLiteral("in progress"))
            || kCompactText.contains(QStringLiteral("processing"))
            || kCompactText.contains(QStringLiteral("running"))
            || kCompactText.contains(QStringLiteral("queue"))
            || kCompactText.contains(QStringLiteral("analy"))
            || kCompactText.contains(QStringLiteral("正在"))
            || kCompactText.contains(QStringLiteral("排队"))
            || kCompactText.contains(QStringLiteral("分析中"));
    }

    // valueToDisplayText:
    // - Convert fields in the ThreatBook summary that may be strings, numbers, or arrays into display text;
    // - Summary popups avoid directly displaying QVariant type noise.
    // Input parameter value: The JSON value.
    // Returns: The user-readable text.
    QString valueToDisplayText(const QJsonValue& value)
    {
        if (value.isString())
        {
            return value.toString();
        }
        if (value.isDouble())
        {
            return QString::number(value.toDouble(), 'f', 2);
        }
        if (value.isBool())
        {
            return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
        }
        if (value.isArray())
        {
            QStringList itemTexts;
            const QJsonArray kArrayValue = value.toArray();
            for (const QJsonValue& itemValue : kArrayValue)
            {
                itemTexts << valueToDisplayText(itemValue);
            }
            return itemTexts.join(QStringLiteral(", "));
        }
        if (value.isObject())
        {
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        }
        return QStringLiteral("-");
    }
}

ThreatBookScan::ThreatBookScan(QObject* parent)
    : QObject(parent)
    , networkManager_(new QNetworkAccessManager(this))
{
}

ThreatBookScan::~ThreatBookScan() = default;

void ThreatBookScan::scanFile(const QString& filePath, QWidget* dialogParent)
{
    if (scanInProgress_)
    {
        ks::online_scan::showErrorDialog(
            dialogParent,
            QStringLiteral("ThreatBook 在线扫描"),
            QStringLiteral("当前 ThreatBook 扫描仍在进行，请等待完成后再上传新文件。"));
        return;
    }

    resetRuntimeState();
    dialogParent_ = dialogParent;
    filePath_ = filePath.trimmed();

    // settings: Read the API key from the unified settings JSON; if not configured, prompt the user to provide it.
    const ks::settings::AppearanceSettings kSettings = ks::settings::loadAppearanceSettings();
    apiKey_ = kSettings.threatBookApiKey.trimmed();
    if (apiKey_.isEmpty())
    {
        ks::online_scan::showMissingApiKeyDialog(dialogParent, QStringLiteral("ThreatBook（微步在线）"));
        return;
    }

    QString fileErrorText;
    if (!ks::online_scan::validateReadableFile(
        filePath_,
        ks::online_scan::kThreatBookUploadMaxBytes,
        &fileErrorText))
    {
        ks::online_scan::showErrorDialog(dialogParent, QStringLiteral("ThreatBook 在线扫描"), fileErrorText);
        return;
    }

    QString hashErrorText;
    sha256Text_ = ks::online_scan::calculateSha256Hex(filePath_, &hashErrorText);
    if (sha256Text_.isEmpty())
    {
        ks::online_scan::showErrorDialog(dialogParent, QStringLiteral("ThreatBook 在线扫描"), hashErrorText);
        return;
    }

    scanInProgress_ = true;
    progressPid_ = kPro.add(this, "在线扫描", "ThreatBook 上传准备");
    kPro.set(progressPid_, "ThreatBook：准备上传样本", 0, 5.0f);
    uploadFile();
}

void ThreatBookScan::scanFileAndAutoDelete(const QString& filePath, QWidget* dialogParent)
{
    ThreatBookScan* scanner = new ThreatBookScan(dialogParent);
    scanner->autoDeleteWhenFinished_ = true;
    scanner->scanFile(filePath, dialogParent);
    if (!scanner->scanInProgress_)
    {
        scanner->deleteLater();
    }
}

void ThreatBookScan::uploadFile()
{
    QFile* uploadFileObject = new QFile(filePath_);
    if (!uploadFileObject->open(QIODevice::ReadOnly))
    {
        const QString kErrorText = QStringLiteral("打开上传文件失败：%1").arg(uploadFileObject->errorString());
        uploadFileObject->deleteLater();
        finishWithError(QStringLiteral("ThreatBook 上传失败"), kErrorText);
        return;
    }

    // multiPart purpose: Construct the multipart/form-data request body required for ThreatBook file upload.
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    addFormField(multiPart, QStringLiteral("apikey"), apiKey_);

    QHttpPart filePart;
    const QString kSafeFileName = ks::online_scan::sanitizeFileNameForContentDisposition(QFileInfo(filePath_).fileName());
    filePart.setHeader(
        QNetworkRequest::ContentDispositionHeader,
        QVariant(QStringLiteral("form-data; name=\"file\"; filename=\"%1\"").arg(kSafeFileName)));
    filePart.setBodyDevice(uploadFileObject);
    uploadFileObject->setParent(multiPart);
    multiPart->append(filePart);

    QNetworkRequest request(QUrl(QString::fromLatin1(kThreatBookUploadEndpoint)));
    request.setRawHeader("User-Agent", "Ksword5.1-OnlineScan/1.0");

    kPro.set(progressPid_, "ThreatBook：上传样本", 0, 12.0f);
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
            kPro.set(progressPid_, "ThreatBook：上传样本", 0, 12.0f + std::min(kUploadPercent, 40.0f));
        });
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleUploadReply(reply);
        });
}

void ThreatBookScan::handleUploadReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;

    if (!kNetworkOk)
    {
        const QString kErrorText = ks::online_scan::networkReplyErrorText(reply, kBodyBytes);
        reply->deleteLater();
        finishWithError(
            QStringLiteral("ThreatBook 上传失败"),
            kErrorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("ThreatBook 上传失败"), parseErrorText);
        return;
    }

    const int kResponseCode = threatBookResponseCode(kRootObject);
    const QString kVerboseText = threatBookVerboseMessage(kRootObject);
    if (kResponseCode != 0 && !jsonContainsPendingHint(kRootObject))
    {
        finishWithError(
            QStringLiteral("ThreatBook 上传失败"),
            QStringLiteral("response_code=%1\n%2\n\n%3")
                .arg(kResponseCode)
                .arg(kVerboseText.isEmpty() ? QStringLiteral("服务端未返回详细消息。") : kVerboseText)
                .arg(ks::online_scan::formatJsonObject(kRootObject)));
        return;
    }

    const QJsonObject kDataObject = kRootObject.value(QStringLiteral("data")).toObject();
    const QString kRemoteSha256Text = kDataObject.value(QStringLiteral("sha256")).toString().trimmed();
    if (!kRemoteSha256Text.isEmpty())
    {
        sha256Text_ = kRemoteSha256Text;
    }

    kPro.set(progressPid_, "ThreatBook：等待报告生成", 0, 55.0f);
    scheduleReportPoll(kInitialPollDelayMs);
}

void ThreatBookScan::scheduleReportPoll(const int delayMs)
{
    QTimer::singleShot(delayMs, this, [this]()
        {
            requestReport();
        });
}

void ThreatBookScan::requestReport()
{
    if (!scanInProgress_ || sha256Text_.isEmpty())
    {
        return;
    }

    ++pollAttempt_;
    const float kProgressValue = std::min(95.0f, 55.0f + static_cast<float>(pollAttempt_) * 1.0f);
    kPro.set(
        progressPid_,
        QStringLiteral("ThreatBook：轮询报告(%1/%2)").arg(pollAttempt_).arg(kMaxPollAttempts).toStdString(),
        0,
        kProgressValue);

    QUrl reportUrl(QString::fromLatin1(kThreatBookReportEndpoint));
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("apikey"), apiKey_);
    query.addQueryItem(QStringLiteral("resource"), sha256Text_);
    query.addQueryItem(QStringLiteral("query_fields"), QStringLiteral("summary"));
    query.addQueryItem(QStringLiteral("query_fields"), QStringLiteral("multiengines"));
    reportUrl.setQuery(query);

    QNetworkRequest request(reportUrl);
    request.setRawHeader("User-Agent", "Ksword5.1-OnlineScan/1.0");
    QNetworkReply* reply = networkManager_->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]()
        {
            handleReportReply(reply);
        });
}

void ThreatBookScan::handleReportReply(QNetworkReply* reply)
{
    const QByteArray kBodyBytes = reply->readAll();
    const bool kNetworkOk = reply->error() == QNetworkReply::NoError;

    if (!kNetworkOk)
    {
        const QString kErrorText = ks::online_scan::networkReplyErrorText(reply, kBodyBytes);
        reply->deleteLater();
        finishWithError(
            QStringLiteral("ThreatBook 查询失败"),
            kErrorText);
        return;
    }
    reply->deleteLater();

    QString parseErrorText;
    const QJsonObject kRootObject = ks::online_scan::parseJsonObjectFromBytes(kBodyBytes, &parseErrorText);
    if (!parseErrorText.isEmpty())
    {
        finishWithError(QStringLiteral("ThreatBook 查询失败"), parseErrorText);
        return;
    }

    const int kResponseCode = threatBookResponseCode(kRootObject);
    const QJsonObject kDataObject = reportDataObject(kRootObject);
    if (kResponseCode == 0 && !kDataObject.isEmpty() && !jsonContainsPendingHint(kRootObject))
    {
        finishWithResult(kRootObject);
        return;
    }

    if (pollAttempt_ >= kMaxPollAttempts)
    {
        finishWithError(
            QStringLiteral("ThreatBook 查询超时"),
            QStringLiteral("报告尚未完成，SHA-256：%1\n最后响应：\n%2")
                .arg(sha256Text_, ks::online_scan::formatJsonObject(kRootObject)));
        return;
    }

    // If response_code is non-0 but indicates 'analysis in progress', or if data is temporarily empty, continue polling to wait for report generation.
    scheduleReportPoll(kPollIntervalMs);
}

void ThreatBookScan::finishWithError(const QString& titleText, const QString& detailText)
{
    completeProgress(QStringLiteral("ThreatBook：扫描失败"));
    scanInProgress_ = false;
    ks::online_scan::showErrorDialog(dialogParent_.data(), titleText, detailText);
    if (autoDeleteWhenFinished_)
    {
        deleteLater();
    }
}

void ThreatBookScan::finishWithResult(const QJsonObject& reportObject)
{
    completeProgress(QStringLiteral("ThreatBook：扫描完成"));
    scanInProgress_ = false;

    const QString kSummaryText = buildResultSummary(reportObject);
    const QString kDetailText = ks::online_scan::formatJsonObject(reportObject);
    ks::online_scan::showResultDialog(
        dialogParent_.data(),
        QStringLiteral("ThreatBook 扫描结果"),
        kSummaryText,
        kDetailText);

    if (autoDeleteWhenFinished_)
    {
        deleteLater();
    }
}

void ThreatBookScan::resetRuntimeState()
{
    dialogParent_.clear();
    filePath_.clear();
    apiKey_.clear();
    sha256Text_.clear();
    pollAttempt_ = 0;
    scanInProgress_ = false;
    progressPid_ = 0;
}

void ThreatBookScan::completeProgress(const QString& messageText)
{
    if (progressPid_ == 0)
    {
        return;
    }
    kPro.set(progressPid_, messageText.toStdString(), 0, 100.0f);
    progressPid_ = 0;
}

QString ThreatBookScan::buildResultSummary(const QJsonObject& reportObject) const
{
    const QJsonObject kDataObject = reportDataObject(reportObject);
    const QJsonObject kSummaryObject = kDataObject.value(QStringLiteral("summary")).toObject();
    const QJsonObject kMultienginesObject = kDataObject.value(QStringLiteral("multiengines")).toObject();

    QStringList summaryLines;
    summaryLines << QStringLiteral("文件：%1").arg(QFileInfo(filePath_).fileName());
    summaryLines << QStringLiteral("SHA-256：%1").arg(sha256Text_);
    summaryLines << QStringLiteral("ThreatScore：%1")
        .arg(valueToDisplayText(kSummaryObject.value(QStringLiteral("threat_score"))));
    summaryLines << QStringLiteral("ThreatLevel：%1")
        .arg(valueToDisplayText(kSummaryObject.value(QStringLiteral("threat_level"))));
    summaryLines << QStringLiteral("MalwareType：%1")
        .arg(valueToDisplayText(kSummaryObject.value(QStringLiteral("malware_type"))));
    summaryLines << QStringLiteral("MalwareFamily：%1")
        .arg(valueToDisplayText(kSummaryObject.value(QStringLiteral("malware_family"))));
    if (!kMultienginesObject.isEmpty())
    {
        summaryLines << QStringLiteral("多引擎结果字段数：%1").arg(kMultienginesObject.size());
    }
    summaryLines << QStringLiteral("响应消息：%1")
        .arg(threatBookVerboseMessage(reportObject).isEmpty()
            ? QStringLiteral("-")
            : threatBookVerboseMessage(reportObject));
    return summaryLines.join(QChar('\n'));
}

QJsonObject ThreatBookScan::reportDataObject(const QJsonObject& reportObject) const
{
    const QJsonObject kDataObject = reportObject.value(QStringLiteral("data")).toObject();
    if (kDataObject.isEmpty())
    {
        return QJsonObject();
    }

    // ThreatBook reports commonly use hash as a key under the 'data' level; if present, prioritize this group.
    const QJsonObject kHashObject = kDataObject.value(sha256Text_).toObject();
    if (!kHashObject.isEmpty())
    {
        return kHashObject;
    }
    return kDataObject;
}
