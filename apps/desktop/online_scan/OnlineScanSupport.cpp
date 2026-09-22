#include "OnlineScanSupport.h"

#include "../ui/CodeEditorWidget.h"
#include "../Theme.h"

#include <QCryptographicHash>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkReply>
#include <QPushButton>
#include <QVBoxLayout>

namespace
{
    // formatByteCount:
    // - Format byte count into human-readable text;
    // - This function is called for file size error messages.
    // Input byteCount: Original byte count.
    // Returns: A size string with units.
    QString formatByteCount(const qint64 byteCount)
    {
        const double kMibValue = static_cast<double>(byteCount) / 1024.0 / 1024.0;
        return QStringLiteral("%1 MB").arg(kMibValue, 0, 'f', 2);
    }

    // compactBodyPreview:
    // - Compress the HTTP response body into a limited-length preview;
    // - Prevent error popups from overflowing the window due to large JSON responses from the server.
    // Input bodyBytes: Original response body.
    // Returns: Preview text of up to ~4096 characters.
    QString compactBodyPreview(const QByteArray& bodyBytes)
    {
        QString previewText = QString::fromUtf8(bodyBytes).trimmed();
        previewText.replace(QChar('\r'), QChar(' '));
        previewText.replace(QChar('\n'), QChar(' '));
        if (previewText.size() > 4096)
        {
            previewText = previewText.left(4096) + QStringLiteral(" ...");
        }
        return previewText;
    }
}

bool ks::online_scan::validateReadableFile(
    const QString& filePath,
    const qint64 maxBytes,
    QString* errorTextOut)
{
    const QString kNormalizedPath = filePath.trimmed();
    if (kNormalizedPath.isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件路径为空。");
        }
        return false;
    }

    // fileInfo purpose: holds file attributes of the input path, subsequently used for existence, type, and size checks.
    const QFileInfo kFileInfo(kNormalizedPath);
    if (!kFileInfo.exists())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件不存在：%1").arg(kNormalizedPath);
        }
        return false;
    }
    if (!kFileInfo.isFile())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("目标不是普通文件：%1").arg(kNormalizedPath);
        }
        return false;
    }
    if (!kFileInfo.isReadable())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件不可读：%1").arg(kNormalizedPath);
        }
        return false;
    }

    // fileSizeBytes purpose: Check the hard limit on uploaded sample size imposed by the online scanning service.
    const qint64 kFileSizeBytes = kFileInfo.size();
    if (maxBytes > 0 && kFileSizeBytes > maxBytes)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("文件大小 %1 超过当前服务允许的 %2。")
                .arg(formatByteCount(kFileSizeBytes), formatByteCount(maxBytes));
        }
        return false;
    }
    return true;
}

QString ks::online_scan::sanitizeFileNameForContentDisposition(const QString& fileName)
{
    QString safeFileName = fileName.trimmed();
    if (safeFileName.isEmpty())
    {
        safeFileName = QStringLiteral("sample.bin");
    }

    // The filename in Content-Disposition cannot directly accept quotes or path separators.
    safeFileName.replace(QChar('"'), QChar('_'));
    safeFileName.replace(QChar('/'), QChar('_'));
    safeFileName.replace(QChar('\\'), QChar('_'));
    return safeFileName;
}

QJsonObject ks::online_scan::parseJsonObjectFromBytes(const QByteArray& bodyBytes, QString* errorTextOut)
{
    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(bodyBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("JSON 解析失败：%1").arg(parseError.errorString());
        }
        return QJsonObject();
    }
    if (!kJsonDocument.isObject())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("响应不是 JSON 对象。");
        }
        return QJsonObject();
    }
    return kJsonDocument.object();
}

QString ks::online_scan::formatJsonObject(const QJsonObject& jsonObject)
{
    const QJsonDocument kJsonDocument(jsonObject);
    return QString::fromUtf8(kJsonDocument.toJson(QJsonDocument::Indented));
}

QString ks::online_scan::networkReplyErrorText(QNetworkReply* reply, const QByteArray& bodyBytes)
{
    if (reply == nullptr)
    {
        return QStringLiteral("网络响应对象为空。");
    }

    // statusCode purpose: Records the HTTP status code, which must be displayed even outside of Qt network errors.
    const QVariant kStatusCodeVariant = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    const int kStatusCode = kStatusCodeVariant.isValid() ? kStatusCodeVariant.toInt() : 0;
    const QString kBodyPreviewText = compactBodyPreview(bodyBytes);

    QStringList messageLines;
    messageLines << QStringLiteral("HTTP 状态码：%1").arg(kStatusCode == 0 ? QStringLiteral("未知") : QString::number(kStatusCode));
    messageLines << QStringLiteral("Qt 网络错误：%1 (%2)")
        .arg(static_cast<int>(reply->error()))
        .arg(reply->errorString());
    if (!kBodyPreviewText.isEmpty())
    {
        messageLines << QStringLiteral("响应摘要：%1").arg(kBodyPreviewText);
    }
    return messageLines.join(QChar('\n'));
}

QString ks::online_scan::calculateSha256Hex(const QString& filePath, QString* errorTextOut)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("打开文件失败：%1").arg(inputFile.errorString());
        }
        return QString();
    }

    // sha256Hasher purpose: Accumulate file content in a streaming manner to avoid excessive memory usage when reading large files.
    QCryptographicHash sha256Hasher(QCryptographicHash::Sha256);
    while (!inputFile.atEnd())
    {
        const QByteArray kChunkBytes = inputFile.read(1024 * 1024);
        if (kChunkBytes.isEmpty() && inputFile.error() != QFile::NoError)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取文件失败：%1").arg(inputFile.errorString());
            }
            return QString();
        }
        sha256Hasher.addData(kChunkBytes);
    }
    return QString::fromLatin1(sha256Hasher.result().toHex());
}

void ks::online_scan::showMissingApiKeyDialog(QWidget* parentWidget, const QString& serviceName)
{
    QMessageBox::information(
        parentWidget,
        QStringLiteral("在线扫描 API Key 未配置"),
        QStringLiteral("%1 API Key 为空。\n\n请在“设置 -> 在线扫描”中填写 API Key，保存后重新上传文件。").arg(serviceName));
}

void ks::online_scan::showErrorDialog(
    QWidget* parentWidget,
    const QString& titleText,
    const QString& detailText)
{
    QMessageBox::warning(parentWidget, titleText, detailText);
}

void ks::online_scan::showResultDialog(
    QWidget* parentWidget,
    const QString& titleText,
    const QString& summaryText,
    const QString& detailJsonText)
{
    QDialog resultDialog(parentWidget);
    resultDialog.setObjectName(QStringLiteral("onlineScanResultDialog"));
    resultDialog.setWindowTitle(titleText);
    resultDialog.resize(880, 640);
    resultDialog.setStyleSheet(ksword_theme::opaqueDialogStyle(resultDialog.objectName()));

    // dialogLayout: Places the summary at the top, CodeEditorWidget in the middle, and copy/close buttons at the bottom.
    QVBoxLayout* dialogLayout = new QVBoxLayout(&resultDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QLabel* summaryLabel = new QLabel(summaryText, &resultDialog);
    summaryLabel->setWordWrap(true);
    dialogLayout->addWidget(summaryLabel, 0);

    CodeEditorWidget* resultEditor = new CodeEditorWidget(&resultDialog);
    resultEditor->setReadOnly(true);
    resultEditor->setRawText(detailJsonText);
    dialogLayout->addWidget(resultEditor, 1);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &resultDialog);
    QPushButton* copyButton = buttonBox->addButton(QStringLiteral("复制结果"), QDialogButtonBox::ActionRole);
    QObject::connect(copyButton, &QPushButton::clicked, &resultDialog, [resultEditor]()
        {
            if (resultEditor != nullptr && QGuiApplication::clipboard() != nullptr)
            {
                QGuiApplication::clipboard()->setText(resultEditor->text());
            }
        });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &resultDialog, &QDialog::reject);
    dialogLayout->addWidget(buttonBox, 0);

    resultDialog.exec();
}
