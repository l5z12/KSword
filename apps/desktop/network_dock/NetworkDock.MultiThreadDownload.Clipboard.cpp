#include "NetworkDock.InternalCommon.h"

#include "../settings_dock/AppearanceSettings.h"
#include "../Theme.h"

#include <QCoreApplication>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

namespace
{
    // JSON key name constants:
    // - Centralize maintenance to avoid scattered read/write paths and hardcoded values;
    // - Allows centralized modification when upgrading fields later.
    constexpr const char* kCaptureSettingsFileName = "network_multidownload_settings.json";
    constexpr const char* kCaptureEnabledKey = "clipboard_auto_capture_enabled";
    constexpr const char* kCaptureSuffixArrayKey = "clipboard_recognize_suffixes";

    // buildCaptureSettingsJsonPath:
    // - Parse the absolute path of the download capture settings JSON.
    // - Invocation: Called before loading or saving settings.
    // - Input: None;
    // - Out: Returns the absolute path of the settings file.
    QString buildCaptureSettingsJsonPath()
    {
        // appearanceSettingsPath purpose: Use the unified settings module's 'stable write path' to locate the style directory.
        const QString kAppearanceSettingsPath = ks::settings::resolveSettingsJsonPathForWrite();
        QFileInfo appearanceFileInfo(kAppearanceSettingsPath);
        QString styleDirectoryPath = appearanceFileInfo.absolutePath();
        if (styleDirectoryPath.trimmed().isEmpty())
        {
            styleDirectoryPath = QDir(QCoreApplication::applicationDirPath())
                .absoluteFilePath(QStringLiteral("style"));
        }
        return QDir(styleDirectoryPath).filePath(QString::fromLatin1(kCaptureSettingsFileName));
    }

    // buildDefaultCaptureSuffixList:
    // - Provides a default set of suffixes for automatically recognized download links.
    // - Usage: Called when the settings file does not exist or user input is empty.
    // - Input: None;
    // - Output: returns the default suffix list (lowercase, with leading dot).
    QStringList buildDefaultCaptureSuffixList()
    {
        return {
            // Image files: Cover web pages, camera captures, design drafts, and common icon resources to prevent automatic recognition failures for image download links.
            QStringLiteral(".jpg"),
            QStringLiteral(".jpeg"),
            QStringLiteral(".png"),
            QStringLiteral(".gif"),
            QStringLiteral(".webp"),
            QStringLiteral(".bmp"),
            QStringLiteral(".svg"),
            QStringLiteral(".ico"),
            QStringLiteral(".tif"),
            QStringLiteral(".tiff"),
            QStringLiteral(".heic"),
            QStringLiteral(".heif"),
            QStringLiteral(".avif"),
            QStringLiteral(".raw"),
            QStringLiteral(".psd"),
            QStringLiteral(".ai"),
            QStringLiteral(".eps"),

            // Video files: covering mainstream container formats, web videos, camera footage, and transport stream files.
            QStringLiteral(".mp4"),
            QStringLiteral(".mkv"),
            QStringLiteral(".avi"),
            QStringLiteral(".mov"),
            QStringLiteral(".wmv"),
            QStringLiteral(".flv"),
            QStringLiteral(".webm"),
            QStringLiteral(".m4v"),
            QStringLiteral(".mpg"),
            QStringLiteral(".mpeg"),
            QStringLiteral(".ts"),
            QStringLiteral(".mts"),
            QStringLiteral(".m2ts"),
            QStringLiteral(".3gp"),

            // Audio files: covering lossy, lossless, mobile, voice, and MIDI download resources.
            QStringLiteral(".mp3"),
            QStringLiteral(".wav"),
            QStringLiteral(".flac"),
            QStringLiteral(".aac"),
            QStringLiteral(".m4a"),
            QStringLiteral(".ogg"),
            QStringLiteral(".opus"),
            QStringLiteral(".wma"),
            QStringLiteral(".ape"),
            QStringLiteral(".alac"),
            QStringLiteral(".mid"),
            QStringLiteral(".midi"),
            QStringLiteral(".amr"),

            // Document files: covering office documents, e-books, plain text, spreadsheets, and common configuration documentation.
            QStringLiteral(".pdf"),
            QStringLiteral(".doc"),
            QStringLiteral(".docx"),
            QStringLiteral(".xls"),
            QStringLiteral(".xlsx"),
            QStringLiteral(".ppt"),
            QStringLiteral(".pptx"),
            QStringLiteral(".txt"),
            QStringLiteral(".md"),
            QStringLiteral(".rtf"),
            QStringLiteral(".csv"),
            QStringLiteral(".json"),
            QStringLiteral(".xml"),
            QStringLiteral(".yaml"),
            QStringLiteral(".yml"),
            QStringLiteral(".log"),
            QStringLiteral(".chm"),
            QStringLiteral(".epub"),
            QStringLiteral(".mobi"),

            // Development files: source code, scripts, web resources, database scripts, and common build/deployment scripts.
            QStringLiteral(".c"),
            QStringLiteral(".cpp"),
            QStringLiteral(".h"),
            QStringLiteral(".hpp"),
            QStringLiteral(".cs"),
            QStringLiteral(".java"),
            QStringLiteral(".py"),
            QStringLiteral(".js"),
            QStringLiteral(".html"),
            QStringLiteral(".css"),
            QStringLiteral(".php"),
            QStringLiteral(".go"),
            QStringLiteral(".rs"),
            QStringLiteral(".swift"),
            QStringLiteral(".kt"),
            QStringLiteral(".sh"),
            QStringLiteral(".bat"),
            QStringLiteral(".cmd"),
            QStringLiteral(".ps1"),
            QStringLiteral(".sql"),

            // Executables and installers: covering Windows, Android, macOS, Linux, and Java application delivery files.
            QStringLiteral(".exe"),
            QStringLiteral(".msi"),
            QStringLiteral(".msix"),
            QStringLiteral(".appx"),
            QStringLiteral(".apk"),
            QStringLiteral(".dmg"),
            QStringLiteral(".pkg"),
            QStringLiteral(".deb"),
            QStringLiteral(".rpm"),
            QStringLiteral(".run"),
            QStringLiteral(".bin"),
            QStringLiteral(".com"),
            QStringLiteral(".scr"),
            QStringLiteral(".dll"),
            QStringLiteral(".sys"),
            QStringLiteral(".jar"),
            QStringLiteral(".war"),

            // Archives and images: covering single-file compression, multi-file archives, distribution images, and common cross-platform compression formats.
            QStringLiteral(".zip"),
            QStringLiteral(".7z"),
            QStringLiteral(".rar"),
            QStringLiteral(".iso"),
            QStringLiteral(".cab"),
            QStringLiteral(".gz"),
            QStringLiteral(".xz"),
            QStringLiteral(".bz2"),
            QStringLiteral(".tar"),
            QStringLiteral(".tgz"),
            QStringLiteral(".tbz2"),
            QStringLiteral(".txz"),
            QStringLiteral(".tar.gz"),
            QStringLiteral(".tar.bz2"),
            QStringLiteral(".tar.xz"),
            QStringLiteral(".zst"),
            QStringLiteral(".lz"),
            QStringLiteral(".lzma"),
            QStringLiteral(".arj")
        };
    }

    // normalizeSuffixText:
    // - normalize a single suffix token (trim whitespace, prepend leading dot, convert to lowercase);
    // - Invocation: called when parsing the user-input suffix list;
    // - Input suffixText: original suffix text.
    // - Output: returns the normalized suffix (empty string if invalid).
    QString normalizeSuffixText(const QString& suffixText)
    {
        QString normalizedText = suffixText.trimmed().toLower();
        if (normalizedText.isEmpty())
        {
            return QString();
        }
        if (normalizedText == QStringLiteral("*") || normalizedText == QStringLiteral(".*"))
        {
            return QStringLiteral("*");
        }
        if (!normalizedText.startsWith('.'))
        {
            normalizedText.prepend('.');
        }
        if (normalizedText.size() <= 1)
        {
            return QString();
        }
        return normalizedText;
    }

    // normalizeSuffixList:
    // - Parse and normalize the suffix list, automatically removing duplicates.
    // - Invocation: Called after reading from JSON or reading input box text;
    // - Input rawSuffixList: original suffix list;
    // - Out: Returns a normalized, deduplicated list.
    QStringList normalizeSuffixList(const QStringList& rawSuffixList)
    {
        QStringList normalizedList;
        for (const QString& rawSuffixText : rawSuffixList)
        {
            const QString kNormalizedSuffix = normalizeSuffixText(rawSuffixText);
            if (kNormalizedSuffix.isEmpty())
            {
                continue;
            }
            if (!normalizedList.contains(kNormalizedSuffix, Qt::CaseInsensitive))
            {
                normalizedList.push_back(kNormalizedSuffix);
            }
        }
        return normalizedList;
    }

    // parseSuffixLineEditText:
    // - Split single-line edit box input into a suffix list.
    // - Invocation: Call before saving settings.
    // - Input: suffixLineEditText (input box text);
    // - Out: Returns a normalized, deduplicated suffix list.
    QStringList parseSuffixLineEditText(const QString& suffixLineEditText)
    {
        // tokenSeparatorPattern usage: Delimiter rules supporting ; , space, and newline.
        static const QRegularExpression kTokenSeparatorPattern(QStringLiteral("[,;\\s]+"));
        const QStringList kRawTokenList = suffixLineEditText.split(kTokenSeparatorPattern, Qt::SkipEmptyParts);
        return normalizeSuffixList(kRawTokenList);
    }

    // joinSuffixListForLineEdit:
    // - Join suffix list back into an editable string;
    // - Invocation: Call when populating the UI after loading the configuration;
    // - Input suffixList: list of suffixes.
    // Output: return semicolon-separated text.
    QString joinSuffixListForLineEdit(const QStringList& suffixList)
    {
        return suffixList.join(QStringLiteral(";"));
    }

    // extractFirstHttpUrlText:
    // - Extract the first HTTP/HTTPS link from the clipboard text;
    // - Invocation: Called when clipboard changes occur.
    // - Input clipboardText: raw clipboard text;
    // - Out: Returns the matched URL string; returns empty if no match is found.
    QString extractFirstHttpUrlText(const QString& clipboardText)
    {
        static const QRegularExpression kUrlPattern(
            QStringLiteral("(https?://[^\\s\"'<>]+)"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch kMatchObject = kUrlPattern.match(clipboardText);
        if (!kMatchObject.hasMatch())
        {
            return QString();
        }

        // extractedUrlText: candidate URL text, with common trailing punctuation to be trimmed later.
        QString extractedUrlText = kMatchObject.captured(1).trimmed();
        while (!extractedUrlText.isEmpty())
        {
            const QChar kTailCharacter = extractedUrlText.back();
            const bool kNeedTrimTail = (
                kTailCharacter == '.' ||
                kTailCharacter == ',' ||
                kTailCharacter == ';' ||
                kTailCharacter == ')' ||
                kTailCharacter == ']' ||
                kTailCharacter == '}' ||
                kTailCharacter == '!' ||
                kTailCharacter == '?');
            if (!kNeedTrimTail)
            {
                break;
            }
            extractedUrlText.chop(1);
        }
        return extractedUrlText;
    }
}

void NetworkDock::loadMultiThreadDownloadCaptureSettings()
{
    // loadEvent usage: A unified log event object spanning the 'read download capture settings' flow.
    KLogEvent loadEvent;
    const QString kSettingsJsonPath = buildCaptureSettingsJsonPath(); // settingsJsonPath: Absolute path to the downloaded capture settings JSON.

    bool autoCaptureEnabled = true; // autoCaptureEnabled: Whether to enable automatic clipboard capture.
    QStringList suffixList = buildDefaultCaptureSuffixList(); // suffixList: Currently active suffix matching list.
    QFile settingsFile(kSettingsJsonPath); // settingsFile: download capture settings file object.
    if (settingsFile.exists() && settingsFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        QJsonParseError parseError;
        const QJsonDocument kJsonDocument = QJsonDocument::fromJson(settingsFile.readAll(), &parseError);
        settingsFile.close();
        if (parseError.error == QJsonParseError::NoError && kJsonDocument.isObject())
        {
            const QJsonObject kRootObject = kJsonDocument.object();
            autoCaptureEnabled = kRootObject.value(QString::fromLatin1(kCaptureEnabledKey)).toBool(autoCaptureEnabled);
            if (kRootObject.contains(QString::fromLatin1(kCaptureSuffixArrayKey))
                && kRootObject.value(QString::fromLatin1(kCaptureSuffixArrayKey)).isArray())
            {
                const QJsonArray kSuffixArray = kRootObject.value(QString::fromLatin1(kCaptureSuffixArrayKey)).toArray(); // suffixArray: The suffix array in the JSON.
                QStringList rawSuffixList; // rawSuffixList: unnormalized suffix list.
                rawSuffixList.reserve(kSuffixArray.size());
                for (const QJsonValue& suffixValue : kSuffixArray)
                {
                    rawSuffixList.push_back(suffixValue.toString());
                }
                const QStringList kNormalizedSuffixList = normalizeSuffixList(rawSuffixList);
                if (!kNormalizedSuffixList.isEmpty())
                {
                    suffixList = kNormalizedSuffixList;
                }
            }
        }
        else
        {
            warn << loadEvent
                << "[NetworkDock] 下载捕获设置 JSON 解析失败，将回退默认设置, path="
                << kSettingsJsonPath.toStdString()
                << eol;
        }
    }

    multiDownloadAutoCaptureClipboardEnabled_ = autoCaptureEnabled;
    multiDownloadCaptureSuffixList_ = suffixList;
    if (multiDownloadAutoCaptureClipboardCheck_ != nullptr)
    {
        const QSignalBlocker kBlocker(multiDownloadAutoCaptureClipboardCheck_);
        multiDownloadAutoCaptureClipboardCheck_->setChecked(multiDownloadAutoCaptureClipboardEnabled_);
    }
    if (multiDownloadCaptureSuffixEdit_ != nullptr)
    {
        const QSignalBlocker kBlocker(multiDownloadCaptureSuffixEdit_);
        multiDownloadCaptureSuffixEdit_->setText(joinSuffixListForLineEdit(multiDownloadCaptureSuffixList_));
    }

    if (QGuiApplication::clipboard() != nullptr)
    {
        multiDownloadLastClipboardText_ = QGuiApplication::clipboard()->text(QClipboard::Clipboard).trimmed();
    }

    info << loadEvent
        << "[NetworkDock] 下载捕获设置加载完成, autoCapture="
        << (multiDownloadAutoCaptureClipboardEnabled_ ? "true" : "false")
        << ", suffixCount=" << multiDownloadCaptureSuffixList_.size()
        << ", path=" << kSettingsJsonPath.toStdString()
        << eol;
}

void NetworkDock::saveMultiThreadDownloadCaptureSettings()
{
    // saveEvent purpose: A unified log event object spanning the 'save download capture settings' flow.
    KLogEvent saveEvent;
    const QString kSettingsJsonPath = buildCaptureSettingsJsonPath(); // settingsJsonPath: Absolute path to the downloaded capture settings JSON.

    const bool kAutoCaptureEnabled = (multiDownloadAutoCaptureClipboardCheck_ != nullptr) // autoCaptureEnabled: The value of the automatic capture switch for data to be saved.
        ? multiDownloadAutoCaptureClipboardCheck_->isChecked()
        : multiDownloadAutoCaptureClipboardEnabled_;
    QStringList suffixList = (multiDownloadCaptureSuffixEdit_ != nullptr) // suffixList: List of suffixes to be saved.
        ? parseSuffixLineEditText(multiDownloadCaptureSuffixEdit_->text())
        : multiDownloadCaptureSuffixList_;
    if (suffixList.isEmpty())
    {
        suffixList = buildDefaultCaptureSuffixList();
    }

    multiDownloadAutoCaptureClipboardEnabled_ = kAutoCaptureEnabled;
    multiDownloadCaptureSuffixList_ = suffixList;
    if (multiDownloadCaptureSuffixEdit_ != nullptr)
    {
        const QSignalBlocker kBlocker(multiDownloadCaptureSuffixEdit_);
        multiDownloadCaptureSuffixEdit_->setText(joinSuffixListForLineEdit(multiDownloadCaptureSuffixList_));
    }

    const QFileInfo kSettingsFileInfo(kSettingsJsonPath); // settingsFileInfo: Settings file path information.
    QDir settingsDirectory(kSettingsFileInfo.absolutePath()); // settingsDirectory: Settings directory object.
    if (!settingsDirectory.exists() && !settingsDirectory.mkpath(QStringLiteral(".")))
    {
        warn << saveEvent
            << "[NetworkDock] 下载捕获设置保存失败：创建目录失败, path="
            << settingsDirectory.absolutePath().toStdString()
            << eol;
        return;
    }

    QJsonObject rootObject; // rootObject: The root JSON object to be serialized.
    rootObject.insert(QString::fromLatin1(kCaptureEnabledKey), multiDownloadAutoCaptureClipboardEnabled_);
    QJsonArray suffixArray; // suffixArray: suffix array to be serialized.
    for (const QString& suffixText : multiDownloadCaptureSuffixList_)
    {
        suffixArray.push_back(suffixText);
    }
    rootObject.insert(QString::fromLatin1(kCaptureSuffixArrayKey), suffixArray);

    QFile settingsFile(kSettingsJsonPath); // settingsFile: File object used to write the settings JSON.
    if (!settingsFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        warn << saveEvent
            << "[NetworkDock] 下载捕获设置保存失败：打开文件失败, path="
            << kSettingsJsonPath.toStdString()
            << eol;
        return;
    }

    settingsFile.write(QJsonDocument(rootObject).toJson(QJsonDocument::Indented));
    settingsFile.close();
    info << saveEvent
        << "[NetworkDock] 下载捕获设置已保存, autoCapture="
        << (multiDownloadAutoCaptureClipboardEnabled_ ? "true" : "false")
        << ", suffixCount=" << multiDownloadCaptureSuffixList_.size()
        << ", path=" << kSettingsJsonPath.toStdString()
        << eol;
}

bool NetworkDock::isMultiThreadDownloadClipboardUrlSupported(const QUrl& urlObject) const
{
    if (!urlObject.isValid())
    {
        return false;
    }

    const QString kUrlSchemeText = urlObject.scheme().toLower(); // urlSchemeText: Lowercase text of the URL scheme.
    if (kUrlSchemeText != QStringLiteral("http") && kUrlSchemeText != QStringLiteral("https"))
    {
        return false;
    }

    if (multiDownloadCaptureSuffixList_.contains(QStringLiteral("*")))
    {
        return true;
    }

    const QString kDecodedPathText = QUrl::fromPercentEncoding(urlObject.path().toUtf8()).toLower(); // decodedPathText: URL-decoded path text.
    const QString kFileNameText = QFileInfo(kDecodedPathText).fileName().toLower(); // fileNameText: Filename at the end of the path (including extension).
    if (kFileNameText.isEmpty())
    {
        return false;
    }
    for (const QString& suffixText : multiDownloadCaptureSuffixList_)
    {
        if (kFileNameText.endsWith(suffixText, Qt::CaseInsensitive))
        {
            return true;
        }
    }
    return false;
}

void NetworkDock::onMultiThreadDownloadClipboardChanged()
{
    if (!multiDownloadAutoCaptureClipboardEnabled_ || QGuiApplication::clipboard() == nullptr)
    {
        return;
    }

    const QString kClipboardText = QGuiApplication::clipboard()->text(QClipboard::Clipboard).trimmed(); // clipboardText: Current primary clipboard text.
    if (kClipboardText.isEmpty() || kClipboardText == multiDownloadLastClipboardText_)
    {
        return;
    }
    multiDownloadLastClipboardText_ = kClipboardText;

    const QString kUrlText = extractFirstHttpUrlText(kClipboardText); // urlText: the first URL extracted from clipboard text.
    if (kUrlText.isEmpty())
    {
        return;
    }

    const QUrl kCandidateUrl = QUrl::fromUserInput(kUrlText); // candidateUrl: Candidate download URL object.
    if (!isMultiThreadDownloadClipboardUrlSupported(kCandidateUrl))
    {
        return;
    }

    showMultiThreadDownloadClipboardPrompt(kCandidateUrl.toString());
}

void NetworkDock::showMultiThreadDownloadClipboardPrompt(const QString& urlText)
{
    if (urlText.trimmed().isEmpty())
    {
        return;
    }

    if (multiDownloadClipboardPromptDialog_ != nullptr)
    {
        multiDownloadClipboardPromptDialog_->raise();
        multiDownloadClipboardPromptDialog_->activateWindow();
        return;
    }

    // defaultSaveDirectoryText usage: Initial save directory in the dialog, prioritizing reuse of the current directory from the download page.
    QString defaultSaveDirectoryText = (multiDownloadSaveDirEdit_ != nullptr)
        ? multiDownloadSaveDirEdit_->text().trimmed()
        : QString();
    if (defaultSaveDirectoryText.isEmpty())
    {
        defaultSaveDirectoryText = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    }
    if (defaultSaveDirectoryText.isEmpty())
    {
        defaultSaveDirectoryText = QDir::homePath();
    }

    QDialog* promptDialog = new QDialog(this); // promptDialog: Non-blocking download prompt dialog object.
    multiDownloadClipboardPromptDialog_ = promptDialog;
    promptDialog->setAttribute(Qt::WA_DeleteOnClose, true);
    promptDialog->setObjectName(QStringLiteral("NetworkMultiDownloadPromptDialog"));
    promptDialog->setWindowFlag(Qt::Window, true);
    promptDialog->setWindowModality(Qt::NonModal);
    promptDialog->setModal(false);
    promptDialog->setWindowTitle(QStringLiteral("检测到可下载链接"));
    promptDialog->resize(760, 200);
    // Explicitly fill the popup background to prevent a black background caused by inheriting transparent styles in light mode.
    promptDialog->setStyleSheet(ksword_theme::opaqueDialogStyle(promptDialog->objectName()));

    QVBoxLayout* rootLayout = new QVBoxLayout(promptDialog); // rootLayout: Root layout for the prompt dialog.
    QLabel* descriptionLabel = new QLabel(
        QStringLiteral("已在剪贴板检测到匹配后缀的下载链接，请确认 URL 与保存目录。"),
        promptDialog); // descriptionLabel: Top description text in the prompt dialog.
    descriptionLabel->setWordWrap(true);

    QLabel* urlLabel = new QLabel(QStringLiteral("下载 URL:"), promptDialog); // urlLabel: Label for the URL input field title.
    QLineEdit* urlEdit = new QLineEdit(urlText, promptDialog); // urlEdit: Editable input box for confirming the download URL.
    urlEdit->setToolTip(QStringLiteral("确认本次要下载的 HTTP/HTTPS 链接。"));

    QLabel* saveDirLabel = new QLabel(QStringLiteral("保存目录:"), promptDialog); // saveDirLabel: Label for the save directory input box title.
    QLineEdit* saveDirEdit = new QLineEdit(defaultSaveDirectoryText, promptDialog); // saveDirEdit: Editable input box for confirming the save directory.
    saveDirEdit->setToolTip(QStringLiteral("确认下载文件保存目录。"));
    QPushButton* browseButton = new QPushButton(promptDialog); // browseButton: Browse button for the save directory.
    browseButton->setIcon(QIcon(":/Icon/file_find.svg"));
    browseButton->setToolTip(QStringLiteral("浏览并选择保存目录"));

    QHBoxLayout* saveDirLayout = new QHBoxLayout(); // saveDirLayout: Save directory row layout (input box + browse button).
    saveDirLayout->addWidget(saveDirEdit, 1);
    saveDirLayout->addWidget(browseButton);

    QPushButton* startButton = new QPushButton(QStringLiteral("开始下载"), promptDialog); // startButton: Button to confirm and start the download.
    startButton->setIcon(QIcon(":/Icon/process_start.svg"));
    startButton->setToolTip(QStringLiteral("按当前 URL 和保存目录创建下载任务"));
    QPushButton* cancelButton = new QPushButton(QStringLiteral("取消下载"), promptDialog); // cancelButton: Button to cancel the current prompt.
    cancelButton->setIcon(QIcon(":/Icon/titlebar_close.svg"));
    cancelButton->setToolTip(QStringLiteral("关闭本次下载询问框，不创建任务"));

    QHBoxLayout* actionLayout = new QHBoxLayout(); // actionLayout: Layout for bottom action buttons.
    actionLayout->addStretch(1);
    actionLayout->addWidget(startButton);
    actionLayout->addWidget(cancelButton);

    rootLayout->addWidget(descriptionLabel);
    rootLayout->addWidget(urlLabel);
    rootLayout->addWidget(urlEdit);
    rootLayout->addWidget(saveDirLabel);
    rootLayout->addLayout(saveDirLayout);
    rootLayout->addLayout(actionLayout);

    connect(promptDialog, &QDialog::destroyed, this, [this]()
        {
            multiDownloadClipboardPromptDialog_ = nullptr;
        });
    connect(browseButton, &QPushButton::clicked, promptDialog, [promptDialog, saveDirEdit]()
        {
            const QString kSelectedDirectory = QFileDialog::getExistingDirectory(
                promptDialog,
                QStringLiteral("选择保存目录"),
                saveDirEdit->text().trimmed().isEmpty() ? QDir::homePath() : saveDirEdit->text().trimmed(),
                QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
            if (!kSelectedDirectory.isEmpty())
            {
                saveDirEdit->setText(kSelectedDirectory);
            }
        });
    connect(startButton, &QPushButton::clicked, promptDialog, [this, promptDialog, urlEdit, saveDirEdit]()
        {
            const bool kStarted = startMultiThreadDownloadTaskFromInput(
                urlEdit->text().trimmed(),
                saveDirEdit->text().trimmed());
            if (kStarted)
            {
                promptDialog->close();
            }
        });
    connect(cancelButton, &QPushButton::clicked, promptDialog, [promptDialog]()
        {
            promptDialog->close();
        });

    KLogEvent promptEvent;
    info << promptEvent
        << "[NetworkDock] 检测到剪贴板下载链接并弹出非阻塞询问框, url="
        << urlText.toStdString()
        << eol;
    promptDialog->show();
    promptDialog->raise();
    promptDialog->activateWindow();
}
