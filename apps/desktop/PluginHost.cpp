#include "PluginHost.h"
#include "ui/VisibleTableWidget.h"

#include "Theme.h"
#include "internationalization/LanguageManager.h"
#include "../../shared/platform/log/Log.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QProgressBar>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextDocument>
#include <QTimer>
#include <QUrl>
#include <QVersionNumber>
#include <QUuid>
#include <QVBoxLayout>
#include <QWidget>

#include <functional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    constexpr qint64 kMaxManifestBytes = 64 * 1024;
    constexpr qint64 kMaxMarketplaceArchiveBytes = 256LL * 1024LL * 1024LL;
    constexpr int kMaxVisualizationColumns = 8;
    constexpr int kMaxVisualizationSummaryItems = 8;
    constexpr int kMaxVisualizationRows = 10000;
    constexpr int kMaxBufferedStdoutBytes = 1024 * 1024;
    constexpr char kMarketplaceCatalogUrl[] = "https://raw.githubusercontent.com/KSwordDEV/Plugins/main/catalog.json";

    struct VisualizationValueStyle
    {
        QString label;
        QString tone;
    };

    struct VisualizationField
    {
        QString field;
        QString label;
        QString format;
        QHash<QString, VisualizationValueStyle> valueStyles;
    };

    struct PluginVisualization
    {
        bool enabled = false;
        QString type;
        QString title;
        QString startEvent;
        QString resultEvent;
        QString completeEvent;
        QString totalField;
        QList<VisualizationField> columns;
        QList<VisualizationField> summary;
    };

    struct PluginTabPresentation
    {
        bool enabled = false;
        QString command;
        QString title;
        QString readyEvent;
        int startupTimeoutMs = 15000;
    };

    struct PluginDescriptor
    {
        QString id;
        QString name;
        QString version;
        QString description;
        QString pluginType = QStringLiteral("command");
        QString runtime;
        QString entrypointPath;
        QString defaultCommand;
        QString pluginDirectory;
        QStringList targets;
        PluginVisualization visualization;
        PluginTabPresentation tabPresentation;
    };

    struct PluginListResult
    {
        QList<PluginDescriptor> plugins;
        QString pluginRoot;
        QStringList ignoredManifests;
    };

    struct MarketplacePlugin
    {
        QString id;
        QString name;
        QString version;
        QString description;
        QStringList targets;
        QString installDirectory;
        QUrl archiveUrl;
        QString sha256;
        QString licenseName;
        QUrl licenseUrl;
    };

    enum class MarketplaceUpdateState
    {
        kNotInstalled,
        kCurrent,
        kAvailable,
        kNotComparable,
    };

    MarketplaceUpdateState marketplaceUpdateState(
        const QString& installedVersion,
        const QString& marketplaceVersion)
    {
        if (installedVersion.isEmpty())
        {
            return MarketplaceUpdateState::kNotInstalled;
        }

        qsizetype installedSuffix = 0;
        qsizetype marketplaceSuffix = 0;
        const QVersionNumber kInstalled = QVersionNumber::fromString(installedVersion.trimmed(), &installedSuffix);
        const QVersionNumber kMarketplace = QVersionNumber::fromString(marketplaceVersion.trimmed(), &marketplaceSuffix);
        if (kInstalled.segments().isEmpty() || kMarketplace.segments().isEmpty() ||
            installedSuffix != installedVersion.trimmed().size() ||
            marketplaceSuffix != marketplaceVersion.trimmed().size())
        {
            return MarketplaceUpdateState::kNotComparable;
        }
        return QVersionNumber::compare(kMarketplace, kInstalled) > 0
            ? MarketplaceUpdateState::kAvailable
            : MarketplaceUpdateState::kCurrent;
    }

    QString marketplaceLicenseAcceptanceKey(const MarketplacePlugin& plugin)
    {
        return QStringLiteral("PluginMarketplace/AcceptedLicenses/%1").arg(plugin.id);
    }

    QString marketplaceLicenseFingerprint(
        const MarketplacePlugin& plugin,
        const QByteArray& licensePayload)
    {
        // The license body hash participates in the acceptance fingerprint; content changes at the same URL also force re-confirmation.
        const QString kContentSha256 = QString::fromLatin1(
            QCryptographicHash::hash(
                licensePayload,
                QCryptographicHash::Sha256).toHex());
        return plugin.licenseName
            + QChar('\n')
            + plugin.licenseUrl.toString(QUrl::FullyEncoded)
            + QChar('\n')
            + kContentSha256;
    }

    bool isValidPluginId(const QString& id)
    {
        if (id.isEmpty() || id.size() > 64 || id.front() == QChar('-') || id.back() == QChar('-'))
        {
            return false;
        }
        for (const QChar kCharacter : id)
        {
            const bool kLower = kCharacter >= QChar('a') && kCharacter <= QChar('z');
            const bool kDigit = kCharacter >= QChar('0') && kCharacter <= QChar('9');
            if (!kLower && !kDigit && kCharacter != QChar('-'))
            {
                return false;
            }
        }
        return true;
    }

    bool isSafeRelativePath(const QString& value)
    {
        if (value.isEmpty() || value.size() > 240 || QDir::isAbsolutePath(value) || value.contains(QChar(':')))
        {
            return false;
        }
        QString normalized = value;
        normalized.replace(QChar('\\'), QChar('/'));
        const QStringList kComponents = normalized.split(QChar('/'), Qt::SkipEmptyParts);
        if (kComponents.isEmpty())
        {
            return false;
        }
        for (const QString& component : kComponents)
        {
            if (component == QStringLiteral(".") || component == QStringLiteral(".."))
            {
                return false;
            }
        }
        return !value.startsWith(QChar('/')) && !value.startsWith(QChar('\\'));
    }

    bool isSafeCommandToken(const QString& value)
    {
        return !value.isEmpty() && value.size() <= 64 &&
            !value.contains(QChar('/')) && !value.contains(QChar('\\')) &&
            !value.contains(QChar(':')) && value != QStringLiteral(".") && value != QStringLiteral("..");
    }

    QString findPluginRoot()
    {
        const QString kConfiguredRoot = qEnvironmentVariable("KSWORD_PLUGIN_ROOT").trimmed();
        if (!kConfiguredRoot.isEmpty() && QDir(kConfiguredRoot).exists())
        {
            return QDir(kConfiguredRoot).absolutePath();
        }

        const QString kCurrentCandidate = QDir::current().filePath(QStringLiteral("plugin"));
        if (QDir(kCurrentCandidate).exists())
        {
            return QDir(kCurrentCandidate).absolutePath();
        }

        QDir searchDirectory(QCoreApplication::applicationDirPath());
        for (int depth = 0; depth < 7; ++depth)
        {
            const QString kCandidate = searchDirectory.filePath(QStringLiteral("plugin"));
            if (QDir(kCandidate).exists())
            {
                return QDir(kCandidate).absolutePath();
            }
            if (!searchDirectory.cdUp())
            {
                break;
            }
        }
        return {};
    }

    QString resolvePluginInstallRoot()
    {
        const QString kConfiguredRoot = qEnvironmentVariable("KSWORD_PLUGIN_ROOT").trimmed();
        if (!kConfiguredRoot.isEmpty())
        {
            return QDir(kConfiguredRoot).absolutePath();
        }

        const QString kExistingRoot = findPluginRoot();
        if (!kExistingRoot.isEmpty())
        {
            return kExistingRoot;
        }

        // When a newly installed distribution lacks the plugin\ directory, the first marketplace plugin is installed next to the main executable.
        return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("plugin"));
    }

    QString quotePowerShellLiteral(const QString& value)
    {
        QString escaped = value;
        escaped.replace(QChar('\''), QStringLiteral("''"));
        return QChar('\'') + escaped + QChar('\'');
    }

    bool readRequiredString(const QJsonObject& object, const char* key, QString* valueOut, QString* errorOut)
    {
        const QString kValue = object.value(QLatin1String(key)).toString().trimmed();
        if (kValue.isEmpty())
        {
            *errorOut = QStringLiteral("缺少或无效的清单字符串字段：%1").arg(QLatin1String(key));
            return false;
        }
        *valueOut = kValue;
        return true;
    }

    bool isValidProtocolName(const QString& value)
    {
        static const QRegularExpression kPattern(QStringLiteral("^[A-Za-z_][A-Za-z0-9_.-]{0,63}$"));
        return kPattern.match(value).hasMatch();
    }

    bool isAllowedVisualizationFormat(const QString& format)
    {
        return format == QStringLiteral("text") ||
            format == QStringLiteral("path") ||
            format == QStringLiteral("percent") ||
            format == QStringLiteral("integer") ||
            format == QStringLiteral("number") ||
            format == QStringLiteral("badge");
    }

    bool isAllowedVisualizationTone(const QString& tone)
    {
        return tone == QStringLiteral("success") ||
            tone == QStringLiteral("danger") ||
            tone == QStringLiteral("warning") ||
            tone == QStringLiteral("info") ||
            tone == QStringLiteral("muted");
    }

    bool parseVisualizationField(
        const QJsonValue& value,
        VisualizationField* fieldOut,
        QString* errorOut)
    {
        if (fieldOut == nullptr || errorOut == nullptr || !value.isObject())
        {
            if (errorOut != nullptr) *errorOut = QStringLiteral("visualization 字段定义必须是对象。");
            return false;
        }

        const QJsonObject kObject = value.toObject();
        VisualizationField field;
        if (!readRequiredString(kObject, "field", &field.field, errorOut) ||
            !readRequiredString(kObject, "label", &field.label, errorOut) ||
            !readRequiredString(kObject, "format", &field.format, errorOut))
        {
            return false;
        }
        field.format = field.format.toLower();
        if (!isValidProtocolName(field.field) || field.label.size() > 64 ||
            !isAllowedVisualizationFormat(field.format))
        {
            *errorOut = QStringLiteral("visualization 字段名、标签或 format 不合法。");
            return false;
        }

        const QJsonValue kValuesValue = kObject.value(QStringLiteral("values"));
        if (!kValuesValue.isUndefined())
        {
            if (field.format != QStringLiteral("badge") || !kValuesValue.isObject())
            {
                *errorOut = QStringLiteral("visualization.values 仅允许用于 badge，且必须是对象。");
                return false;
            }
            const QJsonObject kValues = kValuesValue.toObject();
            if (kValues.size() > 32)
            {
                *errorOut = QStringLiteral("visualization.values 最多允许 32 个映射。");
                return false;
            }
            for (auto iterator = kValues.constBegin(); iterator != kValues.constEnd(); ++iterator)
            {
                if (!isValidProtocolName(iterator.key()) || !iterator.value().isObject())
                {
                    *errorOut = QStringLiteral("visualization.values 的键或值不合法。");
                    return false;
                }
                VisualizationValueStyle style;
                const QJsonObject kStyleObject = iterator.value().toObject();
                if (!readRequiredString(kStyleObject, "label", &style.label, errorOut) ||
                    !readRequiredString(kStyleObject, "tone", &style.tone, errorOut))
                {
                    return false;
                }
                style.tone = style.tone.toLower();
                if (style.label.size() > 64 || !isAllowedVisualizationTone(style.tone))
                {
                    *errorOut = QStringLiteral("visualization.values 的 label 或 tone 不合法。");
                    return false;
                }
                field.valueStyles.insert(iterator.key(), style);
            }
        }
        if (field.format == QStringLiteral("badge") && field.valueStyles.isEmpty())
        {
            *errorOut = QStringLiteral("badge 字段必须提供非空 values 映射。");
            return false;
        }

        *fieldOut = field;
        return true;
    }

    bool parseVisualization(
        const QJsonObject& manifest,
        PluginVisualization* visualizationOut,
        QString* errorOut)
    {
        if (visualizationOut == nullptr || errorOut == nullptr)
        {
            return false;
        }

        *visualizationOut = {};
        const QJsonValue kVisualizationValue = manifest.value(QStringLiteral("visualization"));
        if (kVisualizationValue.isUndefined())
        {
            return true;
        }
        if (!kVisualizationValue.isObject())
        {
            *errorOut = QStringLiteral("visualization 必须是对象。");
            return false;
        }

        const QJsonObject kObject = kVisualizationValue.toObject();
        PluginVisualization visualization;
        if (!readRequiredString(kObject, "type", &visualization.type, errorOut) ||
            !readRequiredString(kObject, "title", &visualization.title, errorOut) ||
            !readRequiredString(kObject, "start_event", &visualization.startEvent, errorOut) ||
            !readRequiredString(kObject, "result_event", &visualization.resultEvent, errorOut) ||
            !readRequiredString(kObject, "complete_event", &visualization.completeEvent, errorOut) ||
            !readRequiredString(kObject, "total_field", &visualization.totalField, errorOut))
        {
            return false;
        }
        visualization.type = visualization.type.toLower();
        if (visualization.type != QStringLiteral("scan-table") ||
            visualization.title.size() > 96 ||
            !isValidProtocolName(visualization.startEvent) ||
            !isValidProtocolName(visualization.resultEvent) ||
            !isValidProtocolName(visualization.completeEvent) ||
            !isValidProtocolName(visualization.totalField))
        {
            *errorOut = QStringLiteral("visualization 的类型、标题、事件名或 total_field 不合法。");
            return false;
        }

        const QJsonArray kColumns = kObject.value(QStringLiteral("columns")).toArray();
        if (kColumns.isEmpty() || kColumns.size() > kMaxVisualizationColumns)
        {
            *errorOut = QStringLiteral("scan-table 必须定义 1 到 %1 个 columns。").arg(kMaxVisualizationColumns);
            return false;
        }
        QStringList columnNames;
        for (const QJsonValue& columnValue : kColumns)
        {
            VisualizationField field;
            if (!parseVisualizationField(columnValue, &field, errorOut))
            {
                return false;
            }
            if (columnNames.contains(field.field))
            {
                *errorOut = QStringLiteral("visualization.columns 不能包含重复 field。");
                return false;
            }
            columnNames.push_back(field.field);
            visualization.columns.push_back(field);
        }

        const QJsonValue kSummaryValue = kObject.value(QStringLiteral("summary"));
        if (!kSummaryValue.isUndefined())
        {
            if (!kSummaryValue.isArray() || kSummaryValue.toArray().size() > kMaxVisualizationSummaryItems)
            {
                *errorOut = QStringLiteral("visualization.summary 必须是数组，且最多 %1 项。")
                    .arg(kMaxVisualizationSummaryItems);
                return false;
            }
            QStringList summaryNames;
            for (const QJsonValue& summaryFieldValue : kSummaryValue.toArray())
            {
                VisualizationField field;
                if (!parseVisualizationField(summaryFieldValue, &field, errorOut))
                {
                    return false;
                }
                if (summaryNames.contains(field.field))
                {
                    *errorOut = QStringLiteral("visualization.summary 不能包含重复 field。");
                    return false;
                }
                summaryNames.push_back(field.field);
                visualization.summary.push_back(field);
            }
        }

        visualization.enabled = true;
        *visualizationOut = visualization;
        return true;
    }

    bool parseTabPresentation(
        const QJsonObject& manifest,
        const QString& pluginType,
        const QString& defaultCommand,
        PluginTabPresentation* presentationOut,
        QString* errorOut)
    {
        if (presentationOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        *presentationOut = {};
        const QJsonValue kTabValue = manifest.value(QStringLiteral("tab"));
        const bool kSupportsTab = pluginType == QStringLiteral("tab") ||
            pluginType == QStringLiteral("hybrid");
        if (!kSupportsTab)
        {
            if (!kTabValue.isUndefined())
            {
                *errorOut = QStringLiteral("tab 配置只允许用于 plugin_type=tab 或 hybrid 的插件。");
                return false;
            }
            return true;
        }
        if (!kTabValue.isObject())
        {
            *errorOut = QStringLiteral("Tab 型插件必须提供 tab 配置对象。");
            return false;
        }

        const QJsonObject kTabObject = kTabValue.toObject();
        PluginTabPresentation presentation;
        presentation.command = kTabObject.value(QStringLiteral("command")).toString().trimmed();
        if (presentation.command.isEmpty())
        {
            presentation.command = defaultCommand;
        }
        if (!readRequiredString(kTabObject, "title", &presentation.title, errorOut) ||
            !readRequiredString(kTabObject, "ready_event", &presentation.readyEvent, errorOut))
        {
            return false;
        }
        if (!isSafeCommandToken(presentation.command))
        {
            *errorOut = QStringLiteral("tab.command 不合法。");
            return false;
        }
        if (presentation.title.size() > 96 || !isValidProtocolName(presentation.readyEvent))
        {
            *errorOut = QStringLiteral("tab.title 或 tab.ready_event 不合法。");
            return false;
        }
        const QJsonValue kTimeoutValue = kTabObject.value(QStringLiteral("startup_timeout_ms"));
        if (!kTimeoutValue.isUndefined())
        {
            const int kTimeoutMs = kTimeoutValue.toInt(-1);
            if (!kTimeoutValue.isDouble() || kTimeoutMs < 1000 || kTimeoutMs > 60000)
            {
                *errorOut = QStringLiteral("tab.startup_timeout_ms 必须介于 1000 与 60000 毫秒之间。");
                return false;
            }
            presentation.startupTimeoutMs = kTimeoutMs;
        }
        presentation.enabled = true;
        *presentationOut = presentation;
        return true;
    }

    bool isApprovedMarketplaceUrl(const QUrl& url)
    {
        return url.isValid() && url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0 &&
            url.host().compare(QStringLiteral("raw.githubusercontent.com"), Qt::CaseInsensitive) == 0;
    }

    QString networkReplyErrorText(QNetworkReply* reply)
    {
        const int kHttpStatus = reply != nullptr
            ? reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()
            : 0;
        const QString kNetworkError = reply != nullptr ? reply->errorString() : QStringLiteral("未知网络错误");
        return kHttpStatus > 0
            ? QStringLiteral("HTTP %1：%2").arg(kHttpStatus).arg(kNetworkError)
            : kNetworkError;
    }

    bool parseMarketplacePlugin(const QJsonObject& object, MarketplacePlugin* pluginOut, QString* errorOut)
    {
        if (pluginOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        MarketplacePlugin plugin;
        QString archiveUrlText;
        QString licenseUrlText;
        if (!readRequiredString(object, "id", &plugin.id, errorOut) ||
            !readRequiredString(object, "name", &plugin.name, errorOut) ||
            !readRequiredString(object, "version", &plugin.version, errorOut) ||
            !readRequiredString(object, "description", &plugin.description, errorOut) ||
            !readRequiredString(object, "install_directory", &plugin.installDirectory, errorOut) ||
            !readRequiredString(object, "archive_url", &archiveUrlText, errorOut) ||
            !readRequiredString(object, "sha256", &plugin.sha256, errorOut) ||
            !readRequiredString(object, "license_name", &plugin.licenseName, errorOut) ||
            !readRequiredString(object, "license_url", &licenseUrlText, errorOut))
        {
            return false;
        }
        if (!isValidPluginId(plugin.id) || !isValidPluginId(plugin.installDirectory))
        {
            *errorOut = QStringLiteral("商城条目的 id 或 install_directory 不合法。");
            return false;
        }
        plugin.archiveUrl = QUrl(archiveUrlText);
        plugin.licenseUrl = QUrl(licenseUrlText);
        if (!isApprovedMarketplaceUrl(plugin.archiveUrl) || !isApprovedMarketplaceUrl(plugin.licenseUrl))
        {
            *errorOut = QStringLiteral("商城仅接受 raw.githubusercontent.com 的 HTTPS 下载地址。");
            return false;
        }
        if (!QRegularExpression(QStringLiteral("^[0-9A-Fa-f]{64}$")).match(plugin.sha256).hasMatch())
        {
            *errorOut = QStringLiteral("商城条目的 sha256 必须是 64 位十六进制值。");
            return false;
        }
        const QJsonArray kTargetValues = object.value(QStringLiteral("targets")).toArray();
        for (const QJsonValue& value : kTargetValues)
        {
            const QString kTarget = value.toString().trimmed().toLower();
            if ((kTarget == QStringLiteral("file") || kTarget == QStringLiteral("process") ||
                kTarget == QStringLiteral("network") || kTarget == QStringLiteral("tab")) &&
                !plugin.targets.contains(kTarget))
            {
                plugin.targets.push_back(kTarget);
            }
        }
        if (plugin.targets.isEmpty())
        {
            *errorOut = QStringLiteral("商城条目的 targets 必须包含 file、process、network 和/或 tab。");
            return false;
        }
        *pluginOut = plugin;
        return true;
    }

    bool loadPluginManifest(
        const QString& pluginRoot,
        const QString& pluginId,
        PluginDescriptor* descriptorOut,
        QString* errorOut)
    {
        if (descriptorOut == nullptr || errorOut == nullptr || !isValidPluginId(pluginId))
        {
            if (errorOut != nullptr)
            {
                *errorOut = QStringLiteral("插件 ID 只能包含小写字母、数字和连字符。");
            }
            return false;
        }

        const QString kPluginDirectory = QDir(pluginRoot).filePath(pluginId);
        const QFileInfo kManifestInfo(QDir(kPluginDirectory).filePath(QStringLiteral("plugin.json")));
        if (!kManifestInfo.isFile() || kManifestInfo.size() > kMaxManifestBytes)
        {
            *errorOut = QStringLiteral("缺少 plugin.json，或其大小超过 64 KiB。");
            return false;
        }

        QFile manifestFile(kManifestInfo.absoluteFilePath());
        if (!manifestFile.open(QIODevice::ReadOnly))
        {
            *errorOut = QStringLiteral("无法读取 plugin.json：%1").arg(manifestFile.errorString());
            return false;
        }
        QJsonParseError parseError;
        const QJsonDocument kDocument = QJsonDocument::fromJson(manifestFile.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            *errorOut = QStringLiteral("plugin.json 不是有效 JSON：%1").arg(parseError.errorString());
            return false;
        }

        const QJsonObject kObject = kDocument.object();
        if (kObject.value(QStringLiteral("ksword_plugin_api")).toString() != QStringLiteral("1"))
        {
            *errorOut = QStringLiteral("不支持的 ksword_plugin_api；当前仅支持 \"1\"。");
            return false;
        }

        PluginDescriptor descriptor;
        QString entrypoint;
        if (!readRequiredString(kObject, "id", &descriptor.id, errorOut) ||
            !readRequiredString(kObject, "name", &descriptor.name, errorOut) ||
            !readRequiredString(kObject, "version", &descriptor.version, errorOut) ||
            !readRequiredString(kObject, "description", &descriptor.description, errorOut) ||
            !readRequiredString(kObject, "runtime", &descriptor.runtime, errorOut) ||
            !readRequiredString(kObject, "entrypoint", &entrypoint, errorOut) ||
            !readRequiredString(kObject, "default_command", &descriptor.defaultCommand, errorOut))
        {
            return false;
        }
        descriptor.pluginType = kObject.value(QStringLiteral("plugin_type")).toString(QStringLiteral("command")).trimmed().toLower();
        if (descriptor.pluginType != QStringLiteral("command") &&
            descriptor.pluginType != QStringLiteral("tab") &&
            descriptor.pluginType != QStringLiteral("hybrid"))
        {
            *errorOut = QStringLiteral("plugin_type 只能是 command、tab 或 hybrid。");
            return false;
        }
        if (descriptor.id != pluginId || !isValidPluginId(descriptor.id))
        {
            *errorOut = QStringLiteral("清单 id 必须与插件目录名完全一致。");
            return false;
        }
        if (descriptor.runtime != QStringLiteral("python") && descriptor.runtime != QStringLiteral("executable"))
        {
            *errorOut = QStringLiteral("runtime 只能是 python 或 executable。");
            return false;
        }
        if (!isSafeRelativePath(entrypoint) || !isSafeCommandToken(descriptor.defaultCommand))
        {
            *errorOut = QStringLiteral("entrypoint 或 default_command 含有不安全路径/令牌。");
            return false;
        }

        const QJsonArray kTargets = kObject.value(QStringLiteral("targets")).toArray();
        for (const QJsonValue& target : kTargets)
        {
            const QString kTargetText = target.toString().trimmed().toLower();
            const bool kCommandTarget =
                kTargetText == QStringLiteral("file") ||
                kTargetText == QStringLiteral("process") ||
                kTargetText == QStringLiteral("network");
            const bool kAllowedTarget = descriptor.pluginType == QStringLiteral("tab")
                ? kTargetText == QStringLiteral("tab")
                : descriptor.pluginType == QStringLiteral("hybrid")
                    ? kCommandTarget || kTargetText == QStringLiteral("tab")
                    : kCommandTarget;
            if (!kAllowedTarget)
            {
                *errorOut = descriptor.pluginType == QStringLiteral("tab")
                    ? QStringLiteral("Tab 型插件的 targets 只能包含 tab。")
                    : descriptor.pluginType == QStringLiteral("hybrid")
                        ? QStringLiteral("Hybrid 型插件的 targets 只能包含 file、process、network 和/或 tab。")
                        : QStringLiteral("命令型插件的 targets 只能包含 file、process 和/或 network。");
                return false;
            }
            if (!descriptor.targets.contains(kTargetText))
            {
                descriptor.targets.push_back(kTargetText);
            }
        }
        if (descriptor.targets.isEmpty())
        {
            *errorOut = descriptor.pluginType == QStringLiteral("tab")
                ? QStringLiteral("Tab 型插件的 targets 必须包含 tab。")
                : QStringLiteral("targets 必须包含 file、process 和/或 network。");
            return false;
        }
        if (descriptor.pluginType == QStringLiteral("hybrid"))
        {
            const bool kHasCommandTarget =
                descriptor.targets.contains(QStringLiteral("file")) ||
                descriptor.targets.contains(QStringLiteral("process")) ||
                descriptor.targets.contains(QStringLiteral("network"));
            if (!descriptor.targets.contains(QStringLiteral("tab")) || !kHasCommandTarget)
            {
                *errorOut = QStringLiteral("Hybrid 型插件的 targets 必须包含 tab 和至少一个命令目标。");
                return false;
            }
        }
        if (!parseVisualization(kObject, &descriptor.visualization, errorOut))
        {
            return false;
        }
        if (!parseTabPresentation(
                kObject,
                descriptor.pluginType,
                descriptor.defaultCommand,
                &descriptor.tabPresentation,
                errorOut))
        {
            return false;
        }
        if (descriptor.pluginType == QStringLiteral("tab") && descriptor.visualization.enabled)
        {
            *errorOut = QStringLiteral("Tab 型插件不能同时声明 scan-table visualization。");
            return false;
        }

        descriptor.pluginDirectory = QDir(kPluginDirectory).absolutePath();
        descriptor.entrypointPath = QDir(descriptor.pluginDirectory).filePath(entrypoint);
        if (!QFileInfo(descriptor.entrypointPath).isFile())
        {
            *errorOut = QStringLiteral("入口文件不存在：%1").arg(entrypoint);
            return false;
        }
        *descriptorOut = descriptor;
        return true;
    }

    bool discoverPlugins(PluginListResult* resultOut, QString* errorOut)
    {
        if (resultOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        *resultOut = {};
        *errorOut = {};
        const QString kPluginRoot = findPluginRoot();
        if (kPluginRoot.isEmpty())
        {
            *errorOut = QStringLiteral("找不到 plugin 目录。请在程序目录部署 plugin\\，或设置 KSWORD_PLUGIN_ROOT。");
            return false;
        }

        const QDir kRootDirectory(kPluginRoot);
        const QStringList kDirectoryNames = kRootDirectory.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
        for (const QString& pluginId : kDirectoryNames)
        {
            if (!isValidPluginId(pluginId))
            {
                continue;
            }
            PluginDescriptor descriptor;
            QString manifestError;
            if (loadPluginManifest(kPluginRoot, pluginId, &descriptor, &manifestError))
            {
                resultOut->plugins.push_back(descriptor);
            }
            else if (QFileInfo(kRootDirectory.filePath(pluginId + QStringLiteral("/plugin.json"))).isFile())
            {
                resultOut->ignoredManifests.push_back(QStringLiteral("%1：%2").arg(pluginId, manifestError));
            }
        }
        resultOut->pluginRoot = kPluginRoot;
        return true;
    }

    QString targetName(const ks::plugin_host::TargetKind targetKind)
    {
        switch (targetKind)
        {
        case ks::plugin_host::TargetKind::kFile: return QStringLiteral("file");
        case ks::plugin_host::TargetKind::kProcess: return QStringLiteral("process");
        case ks::plugin_host::TargetKind::kNetwork: return QStringLiteral("network");
        }
        return QString();
    }

    bool isUsableContext(const ks::plugin_host::InvocationContext& context, QString* errorOut)
    {
        if (context.targetKind == ks::plugin_host::TargetKind::kFile)
        {
            if (QFileInfo(context.filePath).isFile())
            {
                return true;
            }
            *errorOut = QStringLiteral("插件入口仅支持单个常规文件。");
            return false;
        }
        if (context.targetKind == ks::plugin_host::TargetKind::kNetwork)
        {
            return true;
        }
        if (context.processId != 0)
        {
            return true;
        }
        *errorOut = QStringLiteral("当前进程没有有效 PID，不能交给插件。");
        return false;
    }

    bool buildPluginCommand(
        const PluginDescriptor& descriptor,
        const ks::plugin_host::InvocationContext& context,
        QString* programOut,
        QStringList* argumentsOut,
        QString* errorOut)
    {
        if (programOut == nullptr || argumentsOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        QStringList arguments;
        if (descriptor.runtime == QStringLiteral("python"))
        {
            QString python = qEnvironmentVariable("KSWORD_PLUGIN_PYTHON").trimmed();
            bool usePythonLauncher = false;
            if (!python.isEmpty() && !QFileInfo(python).isFile())
            {
                *errorOut = QStringLiteral("KSWORD_PLUGIN_PYTHON 未指向有效文件：%1").arg(python);
                return false;
            }
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
            }
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("py.exe"));
                usePythonLauncher = !python.isEmpty();
            }
            if (python.isEmpty())
            {
                *errorOut = QStringLiteral("找不到 Python 运行时；请安装 python.exe/py.exe 或设置 KSWORD_PLUGIN_PYTHON。");
                return false;
            }
            *programOut = python;
            if (usePythonLauncher)
            {
                arguments << QStringLiteral("-3");
            }
            arguments << descriptor.entrypointPath;
        }
        else
        {
            *programOut = descriptor.entrypointPath;
        }

        arguments << QStringLiteral("--ksword-plugin") << descriptor.defaultCommand << QStringLiteral("--")
                  << QStringLiteral("--target-kind") << targetName(context.targetKind);
        if (context.targetKind == ks::plugin_host::TargetKind::kFile)
        {
            arguments << QStringLiteral("--path") << context.filePath;
        }
        else if (context.targetKind == ks::plugin_host::TargetKind::kProcess)
        {
            arguments << QStringLiteral("--pid") << QString::number(context.processId);
            if (!context.filePath.trimmed().isEmpty())
            {
                arguments << QStringLiteral("--path") << context.filePath;
            }
            if (!context.processName.trimmed().isEmpty())
            {
                arguments << QStringLiteral("--process-name") << context.processName;
            }
        }
        *argumentsOut = arguments;
        return true;
    }

    bool buildTabPluginCommand(
        const PluginDescriptor& descriptor,
        const WId parentWindowId,
        QString* programOut,
        QStringList* argumentsOut,
        QString* errorOut)
    {
        if (programOut == nullptr || argumentsOut == nullptr || errorOut == nullptr ||
            (descriptor.pluginType != QStringLiteral("tab") &&
             descriptor.pluginType != QStringLiteral("hybrid")) ||
            !descriptor.tabPresentation.enabled)
        {
            return false;
        }
        QStringList arguments;
        if (descriptor.runtime == QStringLiteral("python"))
        {
            QString python = qEnvironmentVariable("KSWORD_PLUGIN_PYTHON").trimmed();
            bool usePythonLauncher = false;
            if (!python.isEmpty() && !QFileInfo(python).isFile())
            {
                *errorOut = QStringLiteral("KSWORD_PLUGIN_PYTHON 未指向有效文件：%1").arg(python);
                return false;
            }
            if (python.isEmpty()) python = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("py.exe"));
                usePythonLauncher = !python.isEmpty();
            }
            if (python.isEmpty())
            {
                *errorOut = QStringLiteral("找不到 Python 运行时；请安装 python.exe/py.exe 或设置 KSWORD_PLUGIN_PYTHON。");
                return false;
            }
            *programOut = python;
            if (usePythonLauncher) arguments << QStringLiteral("-3");
            arguments << descriptor.entrypointPath;
        }
        else
        {
            *programOut = descriptor.entrypointPath;
        }

        arguments << QStringLiteral("--ksword-plugin") << descriptor.tabPresentation.command << QStringLiteral("--")
            << QStringLiteral("--parent-hwnd") << QString::number(static_cast<qulonglong>(parentWindowId))
            << QStringLiteral("--host-pid") << QString::number(QCoreApplication::applicationPid());
        *argumentsOut = arguments;
        return true;
    }

    QString visualizationValueText(const QJsonValue& value, const QString& format)
    {
        if (value.isUndefined() || value.isNull())
        {
            return QStringLiteral("—");
        }
        if (format == QStringLiteral("percent") && value.isDouble())
        {
            double percent = value.toDouble();
            if (qAbs(percent) <= 1.0) percent *= 100.0;
            if (percent > 0.0 && percent < 0.01) return QStringLiteral("<0.01%");
            return QStringLiteral("%1%").arg(percent, 0, 'f', 2);
        }
        if (format == QStringLiteral("integer") && value.isDouble())
        {
            return QString::number(qRound64(value.toDouble()));
        }
        if (format == QStringLiteral("number") && value.isDouble())
        {
            return QString::number(value.toDouble(), 'g', 8);
        }
        if (value.isString())
        {
            return value.toString();
        }
        if (value.isDouble())
        {
            return QString::number(value.toDouble(), 'g', 12);
        }
        if (value.isBool())
        {
            return value.toBool() ? QStringLiteral("是") : QStringLiteral("否");
        }
        if (value.isArray())
        {
            return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
        }
        if (value.isObject())
        {
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        }
        return QStringLiteral("—");
    }

    QColor visualizationToneColor(const QString& tone)
    {
        if (tone == QStringLiteral("success")) return ksword_theme::successColor();
        if (tone == QStringLiteral("danger")) return ksword_theme::errorColor();
        if (tone == QStringLiteral("warning")) return ksword_theme::warningColor();
        if (tone == QStringLiteral("info")) return ksword_theme::infoColor();
        if (tone == QStringLiteral("muted")) return ksword_theme::textSecondaryColor();
        return ksword_theme::textPrimaryColor();
    }

    class PluginRunDialog final : public QDialog
    {
    public:
        PluginRunDialog(
            QWidget* parent,
            const PluginDescriptor& descriptor,
            const ks::plugin_host::InvocationContext& context,
            const QString& program,
            const QStringList& arguments)
            : QDialog(parent),
              descriptor_(descriptor)
        {
            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowTitle(descriptor.visualization.enabled
                ? descriptor.visualization.title
                : descriptor.name);
            setWindowIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
            resize(920, 620);
            setModal(false);

            auto* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(16, 16, 16, 16);
            rootLayout->setSpacing(10);

            auto* titleLabel = new QLabel(
                descriptor.visualization.enabled ? descriptor.visualization.title : descriptor.name,
                this);
            titleLabel->setStyleSheet(QStringLiteral("font-size:18px;font-weight:700;color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
            rootLayout->addWidget(titleLabel);

            QString targetText;
            if (context.targetKind == ks::plugin_host::TargetKind::kFile)
            {
                targetText = QStringLiteral("目标文件：%1").arg(QDir::toNativeSeparators(context.filePath));
            }
            else if (context.targetKind == ks::plugin_host::TargetKind::kProcess)
            {
                targetText = QStringLiteral("目标进程：%1  PID %2")
                    .arg(context.processName.trimmed().isEmpty() ? QStringLiteral("未知进程") : context.processName)
                    .arg(context.processId);
                if (!context.filePath.trimmed().isEmpty())
                {
                    targetText += QStringLiteral("\n映像路径：%1").arg(QDir::toNativeSeparators(context.filePath));
                }
            }
            else
            {
                targetText = QStringLiteral("目标：实时网络流量");
            }
            auto* targetLabel = new QLabel(targetText, this);
            targetLabel->setWordWrap(true);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            targetLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
            rootLayout->addWidget(targetLabel);

            progress_ = new QProgressBar(this);
            progress_->setRange(0, 0);
            progress_->setTextVisible(true);
            rootLayout->addWidget(progress_);

            if (!descriptor.visualization.summary.isEmpty())
            {
                auto* summaryLayout = new QHBoxLayout();
                summaryLayout->setSpacing(18);
                for (const VisualizationField& field : descriptor.visualization.summary)
                {
                    auto* label = new QLabel(QStringLiteral("%1：—").arg(field.label), this);
                    label->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                        .arg(ksword_theme::textPrimaryHex()));
                    summaryLayout->addWidget(label);
                    summaryLabels_.insert(field.field, label);
                }
                summaryLayout->addStretch(1);
                rootLayout->addLayout(summaryLayout);
            }

            tabs_ = new QTabWidget(this);
            if (descriptor.visualization.enabled)
            {
                resultTable_ = new ks::ui::VisibleTableWidget(tabs_);
                resultTable_->setColumnCount(descriptor.visualization.columns.size());
                QStringList labels;
                for (const VisualizationField& field : descriptor.visualization.columns) labels.push_back(field.label);
                resultTable_->setHorizontalHeaderLabels(labels);
                resultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
                resultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
                resultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
                resultTable_->setAlternatingRowColors(true);
                resultTable_->setWordWrap(false);
                resultTable_->setSortingEnabled(false);
                resultTable_->verticalHeader()->setVisible(false);
                QHeaderView* header = resultTable_->horizontalHeader();
                header->setStretchLastSection(false);
                for (int column = 0; column < descriptor.visualization.columns.size(); ++column)
                {
                    const QString kFormat = descriptor.visualization.columns.at(column).format;
                    if (kFormat == QStringLiteral("path"))
                    {
                        header->setSectionResizeMode(column, QHeaderView::Stretch);
                    }
                    else if (kFormat == QStringLiteral("text"))
                    {
                        header->setSectionResizeMode(column, QHeaderView::Interactive);
                        resultTable_->setColumnWidth(column, 180);
                    }
                    else
                    {
                        header->setSectionResizeMode(column, QHeaderView::ResizeToContents);
                    }
                }
                tabs_->addTab(resultTable_, QStringLiteral("扫描结果"));
            }
            else
            {
                plainOutput_ = new QPlainTextEdit(tabs_);
                plainOutput_->setReadOnly(true);
                plainOutput_->setMaximumBlockCount(2000);
                tabs_->addTab(plainOutput_, QStringLiteral("插件输出"));
            }

            diagnostics_ = new QPlainTextEdit(tabs_);
            diagnostics_->setReadOnly(true);
            diagnostics_->setMaximumBlockCount(2000);
            diagnostics_->setPlaceholderText(QStringLiteral("插件错误和协议诊断会显示在这里。"));
            tabs_->addTab(diagnostics_, QStringLiteral("诊断"));
            rootLayout->addWidget(tabs_, 1);

            auto* footer = new QHBoxLayout();
            status_ = new QLabel(QStringLiteral("正在启动…"), this);
            status_->setWordWrap(true);
            footer->addWidget(status_, 1);
            closeButton_ = new QPushButton(QStringLiteral("取消"), this);
            footer->addWidget(closeButton_);
            rootLayout->addLayout(footer);

            process_ = new QProcess(this);
            process_->setProgram(program);
            process_->setArguments(arguments);
            process_->setWorkingDirectory(descriptor.pluginDirectory);
            process_->setProcessChannelMode(QProcess::SeparateChannels);
            QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ROOT"), findPluginRoot());
            process_->setProcessEnvironment(environment);

            connect(closeButton_, &QPushButton::clicked, this, [this]() {
                if (process_->state() == QProcess::NotRunning) close();
                else cancelRun();
            });
            connect(process_, &QProcess::started, this, [this]() {
                setStatus(QStringLiteral("正在扫描…"), QStringLiteral("info"));
            });
            connect(process_, &QProcess::readyReadStandardOutput, this, [this]() {
                consumeStandardOutput(false);
            });
            connect(process_, &QProcess::readyReadStandardError, this, [this]() {
                consumeStandardError();
            });
            connect(process_, &QProcess::errorOccurred, this, [this](const QProcess::ProcessError error) {
                if (error != QProcess::FailedToStart || finished_) return;
                finished_ = true;
                progress_->setRange(0, 1);
                progress_->setValue(0);
                appendDiagnostic(QStringLiteral("无法启动插件入口：%1").arg(process_->errorString()));
                setStatus(QStringLiteral("启动失败"), QStringLiteral("danger"));
                closeButton_->setText(QStringLiteral("关闭"));
                closeButton_->setEnabled(true);
                if (tabs_->count() > 1) tabs_->setCurrentIndex(1);
            });
            connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    if (finished_) return;
                    finished_ = true;
                    consumeStandardOutput(true);
                    consumeStandardError();
                    const bool kProtocolComplete = !descriptor_.visualization.enabled || completeSeen_;
                    const bool kSucceeded = exitStatus == QProcess::NormalExit && exitCode == 0 &&
                        !protocolError_ && kProtocolComplete && !cancelRequested_;
                    if (cancelRequested_)
                    {
                        setStatus(QStringLiteral("扫描已取消"), QStringLiteral("warning"));
                    }
                    else if (kSucceeded)
                    {
                        if (totalItems_ > 0)
                        {
                            progress_->setRange(0, totalItems_);
                            progress_->setValue(qMin(completedItems_, totalItems_));
                        }
                        else
                        {
                            progress_->setRange(0, 1);
                            progress_->setValue(1);
                        }
                        setStatus(QStringLiteral("扫描完成，共处理 %1 项").arg(completedItems_),
                            QStringLiteral("success"));
                    }
                    else
                    {
                        if (!kProtocolComplete)
                        {
                            appendDiagnostic(QStringLiteral("插件未发送声明的完成事件：%1")
                                .arg(descriptor_.visualization.completeEvent));
                        }
                        setStatus(QStringLiteral("扫描失败（退出码 %1）").arg(exitCode),
                            QStringLiteral("danger"));
                        if (tabs_->count() > 1) tabs_->setCurrentIndex(1);
                    }
                    closeButton_->setText(QStringLiteral("关闭"));
                    closeButton_->setEnabled(true);
                    if (resultTable_ != nullptr) resultTable_->setSortingEnabled(true);
                });
        }

        void start()
        {
            process_->start();
        }

    protected:
        void closeEvent(QCloseEvent* event) override
        {
            if (process_ != nullptr && process_->state() != QProcess::NotRunning)
            {
                cancelRun();
                event->ignore();
                return;
            }
            QDialog::closeEvent(event);
        }

    private:
        void cancelRun()
        {
            if (process_ == nullptr || process_->state() == QProcess::NotRunning) return;
            cancelRequested_ = true;
            setStatus(QStringLiteral("正在取消扫描…"), QStringLiteral("warning"));
            closeButton_->setEnabled(false);
            process_->terminate();
            QTimer::singleShot(2000, process_, [process = process_]() {
                if (process->state() != QProcess::NotRunning) process->kill();
            });
        }

        void setStatus(const QString& text, const QString& tone)
        {
            status_->setText(text);
            status_->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                .arg(visualizationToneColor(tone).name()));
        }

        void appendDiagnostic(const QString& text)
        {
            if (!text.trimmed().isEmpty()) diagnostics_->appendPlainText(text.trimmed());
        }

        void consumeStandardError()
        {
            const QString kText = QString::fromLocal8Bit(process_->readAllStandardError());
            appendDiagnostic(kText);
        }

        void consumeStandardOutput(const bool flushRemainder)
        {
            stdoutBuffer_ += process_->readAllStandardOutput();
            int newlineIndex = -1;
            while ((newlineIndex = stdoutBuffer_.indexOf('\n')) >= 0)
            {
                QByteArray line = stdoutBuffer_.left(newlineIndex);
                stdoutBuffer_.remove(0, newlineIndex + 1);
                if (line.endsWith('\r')) line.chop(1);
                processOutputLine(line);
            }
            if (stdoutBuffer_.size() > kMaxBufferedStdoutBytes)
            {
                appendDiagnostic(QStringLiteral("插件输出存在超过 1 MiB 的无换行记录，已拒绝解析。"));
                stdoutBuffer_.clear();
                protocolError_ = true;
            }
            if (flushRemainder && !stdoutBuffer_.isEmpty())
            {
                processOutputLine(stdoutBuffer_);
                stdoutBuffer_.clear();
            }
        }

        void processOutputLine(const QByteArray& lineBytes)
        {
            const QString kLine = QString::fromUtf8(lineBytes).trimmed();
            if (kLine.isEmpty()) return;
            if (!descriptor_.visualization.enabled)
            {
                plainOutput_->appendPlainText(kLine);
                return;
            }

            QJsonParseError parseError;
            const QJsonDocument kDocument = QJsonDocument::fromJson(lineBytes, &parseError);
            if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
            {
                appendDiagnostic(QStringLiteral("无法解析插件 JSON Lines：%1\n%2")
                    .arg(parseError.errorString(), kLine));
                protocolError_ = true;
                return;
            }
            const QJsonObject kObject = kDocument.object();
            if (kObject.value(QStringLiteral("protocol")).toString() != QStringLiteral("ksword-plugin/1") ||
                kObject.value(QStringLiteral("plugin_id")).toString() != descriptor_.id)
            {
                appendDiagnostic(QStringLiteral("插件输出的 protocol 或 plugin_id 与清单不一致。"));
                protocolError_ = true;
                return;
            }

            const QString kEvent = kObject.value(QStringLiteral("event")).toString();
            if (kEvent == QStringLiteral("error"))
            {
                protocolError_ = true;
                appendDiagnostic(QStringLiteral("%1：%2")
                    .arg(kObject.value(QStringLiteral("code")).toString(QStringLiteral("plugin_error")),
                         kObject.value(QStringLiteral("message")).toString(QStringLiteral("插件报告错误"))));
                setStatus(QStringLiteral("插件报告错误"), QStringLiteral("danger"));
                return;
            }
            if (kEvent == descriptor_.visualization.startEvent)
            {
                totalItems_ = qMax(0, kObject.value(descriptor_.visualization.totalField).toInt());
                if (totalItems_ > 0)
                {
                    progress_->setRange(0, totalItems_);
                    progress_->setValue(0);
                    progress_->setFormat(QStringLiteral("%v / %m"));
                }
                setStatus(totalItems_ > 0
                    ? QStringLiteral("正在扫描 0 / %1").arg(totalItems_)
                    : QStringLiteral("正在扫描…"), QStringLiteral("info"));
                return;
            }
            if (kEvent == descriptor_.visualization.resultEvent)
            {
                appendResult(kObject);
                ++completedItems_;
                if (totalItems_ > 0)
                {
                    progress_->setValue(qMin(completedItems_, totalItems_));
                    setStatus(QStringLiteral("正在扫描 %1 / %2").arg(completedItems_).arg(totalItems_),
                        QStringLiteral("info"));
                }
                else
                {
                    setStatus(QStringLiteral("已处理 %1 项").arg(completedItems_), QStringLiteral("info"));
                }
                return;
            }
            if (kEvent == descriptor_.visualization.completeEvent)
            {
                completeSeen_ = true;
                updateSummary(kObject);
                if (totalItems_ > 0) progress_->setValue(qMin(completedItems_, totalItems_));
                setStatus(QStringLiteral("正在完成扫描…"), QStringLiteral("info"));
            }
        }

        void appendResult(const QJsonObject& object)
        {
            if (resultTable_ == nullptr) return;
            if (resultTable_->rowCount() >= kMaxVisualizationRows)
            {
                if (!rowLimitReported_)
                {
                    appendDiagnostic(QStringLiteral("扫描结果超过 %1 行，后续结果不再显示。")
                        .arg(kMaxVisualizationRows));
                    rowLimitReported_ = true;
                }
                return;
            }

            const int kRow = resultTable_->rowCount();
            resultTable_->insertRow(kRow);
            for (int column = 0; column < descriptor_.visualization.columns.size(); ++column)
            {
                const VisualizationField& field = descriptor_.visualization.columns.at(column);
                const QJsonValue kValue = object.value(field.field);
                QString text = visualizationValueText(kValue, field.format);
                QString tone;
                if (field.format == QStringLiteral("badge"))
                {
                    const VisualizationValueStyle kStyle = field.valueStyles.value(kValue.toString());
                    if (!kStyle.label.isEmpty()) text = kStyle.label;
                    tone = kStyle.tone;
                }
                auto* item = new QTableWidgetItem(text);
                if (!tone.isEmpty()) item->setForeground(QBrush(visualizationToneColor(tone)));
                if (field.format == QStringLiteral("path") || text.size() > 80) item->setToolTip(text);
                if (field.format == QStringLiteral("integer") ||
                    field.format == QStringLiteral("number") ||
                    field.format == QStringLiteral("percent"))
                {
                    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                }
                resultTable_->setItem(kRow, column, item);
            }
        }

        void updateSummary(const QJsonObject& object)
        {
            for (const VisualizationField& field : descriptor_.visualization.summary)
            {
                QLabel* label = summaryLabels_.value(field.field, nullptr);
                if (label == nullptr) continue;
                const QJsonValue kValue = object.value(field.field);
                QString text = visualizationValueText(kValue, field.format);
                QString tone;
                if (field.format == QStringLiteral("badge"))
                {
                    const VisualizationValueStyle kStyle = field.valueStyles.value(kValue.toString());
                    if (!kStyle.label.isEmpty()) text = kStyle.label;
                    tone = kStyle.tone;
                }
                label->setText(QStringLiteral("%1：%2").arg(field.label, text));
                label->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                    .arg(tone.isEmpty()
                        ? ksword_theme::textPrimaryColorHex()
                        : visualizationToneColor(tone).name()));
            }
        }

        PluginDescriptor descriptor_;
        QProcess* process_ = nullptr;
        QProgressBar* progress_ = nullptr;
        QTabWidget* tabs_ = nullptr;
        QTableWidget* resultTable_ = nullptr;
        QPlainTextEdit* plainOutput_ = nullptr;
        QPlainTextEdit* diagnostics_ = nullptr;
        QLabel* status_ = nullptr;
        QPushButton* closeButton_ = nullptr;
        QHash<QString, QLabel*> summaryLabels_;
        QByteArray stdoutBuffer_;
        int totalItems_ = 0;
        int completedItems_ = 0;
        bool completeSeen_ = false;
        bool protocolError_ = false;
        bool cancelRequested_ = false;
        bool finished_ = false;
        bool rowLimitReported_ = false;
    };

    void launchPlugin(QWidget* owner, const PluginDescriptor& descriptor, const ks::plugin_host::InvocationContext& context)
    {
        QString contextError;
        if (!isUsableContext(context, &contextError))
        {
            QMessageBox::warning(owner, QStringLiteral("插件"), contextError);
            return;
        }

        QString program;
        QStringList arguments;
        QString commandError;
        if (!buildPluginCommand(descriptor, context, &program, &arguments, &commandError))
        {
            QMessageBox::warning(owner, QStringLiteral("插件：%1").arg(descriptor.name), commandError);
            return;
        }

        auto* dialog = new PluginRunDialog(owner, descriptor, context, program, arguments);
        dialog->show();
        dialog->raise();
        dialog->activateWindow();
        dialog->start();
    }

    class PluginTabPage final : public QWidget
    {
    public:
        PluginTabPage(QWidget* parent, const PluginDescriptor& descriptor)
            : QWidget(parent), descriptor_(descriptor)
        {
            setObjectName(QStringLiteral("ksExternalPluginTab_%1").arg(descriptor.id));
            auto* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(4, 4, 4, 4);
            rootLayout->setSpacing(4);

            auto* statusRow = new QHBoxLayout();
            statusLabel_ = new QLabel(QStringLiteral("正在启动外部 Tab 插件…"), this);
            statusLabel_->setWordWrap(true);
            statusRow->addWidget(statusLabel_, 1);
            diagnosticsButton_ = new QPushButton(QStringLiteral("诊断"), this);
            retryButton_ = new QPushButton(QStringLiteral("重试"), this);
            retryButton_->setVisible(false);
            statusRow->addWidget(diagnosticsButton_);
            statusRow->addWidget(retryButton_);
            rootLayout->addLayout(statusRow);

            surface_ = new QWidget(this);
            surface_->setObjectName(QStringLiteral("ksExternalPluginNativeSurface"));
            surface_->setAttribute(Qt::WA_NativeWindow, true);
            surface_->setFocusPolicy(Qt::StrongFocus);
            surface_->setStyleSheet(QStringLiteral("background:%1;border:1px solid %2;")
                .arg(ksword_theme::surfaceHex(), ksword_theme::borderHex()));
            surface_->installEventFilter(this);
            rootLayout->addWidget(surface_, 1);

            diagnostics_ = new QPlainTextEdit(this);
            diagnostics_->setReadOnly(true);
            diagnostics_->setMaximumHeight(180);
            diagnostics_->document()->setMaximumBlockCount(2000);
            diagnostics_->setVisible(false);
            rootLayout->addWidget(diagnostics_);

            connect(diagnosticsButton_, &QPushButton::clicked, this, [this]() {
                diagnostics_->setVisible(!diagnostics_->isVisible());
            });
            connect(retryButton_, &QPushButton::clicked, this, [this]() { start(); });
        }

        ~PluginTabPage() override
        {
            stopping_ = true;
            if (::IsWindow(pluginWindow_))
            {
                ::PostMessageW(pluginWindow_, WM_CLOSE, 0, 0);
            }
            if (process_ != nullptr && process_->state() != QProcess::NotRunning)
            {
                process_->terminate();
                if (!process_->waitForFinished(1200))
                {
                    process_->kill();
                    process_->waitForFinished(800);
                }
            }
        }

    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!startScheduled_)
            {
                startScheduled_ = true;
                QTimer::singleShot(0, this, [this]() { start(); });
            }
        }

        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (watched == surface_ &&
                (event->type() == QEvent::Resize || event->type() == QEvent::Show))
            {
                resizePluginWindow();
            }
            if (watched == surface_ && event->type() == QEvent::MouseButtonPress && ::IsWindow(pluginWindow_))
            {
                ::SetFocus(pluginWindow_);
            }
            return QWidget::eventFilter(watched, event);
        }

    private:
        void start()
        {
            if (process_ != nullptr && process_->state() != QProcess::NotRunning)
            {
                return;
            }
            failed_ = false;
            ready_ = false;
            pluginWindow_ = nullptr;
            stdoutBuffer_.clear();
            retryButton_->setVisible(false);
            statusLabel_->setText(QStringLiteral("正在启动外部 Tab 插件…"));
            statusLabel_->setStyleSheet({});

            QString program;
            QStringList arguments;
            QString errorText;
            const WId kSurfaceId = surface_->winId();
            if (!buildTabPluginCommand(descriptor_, kSurfaceId, &program, &arguments, &errorText))
            {
                fail(QStringLiteral("Tab 插件启动失败：%1").arg(errorText), false);
                return;
            }

            if (process_ != nullptr)
            {
                process_->deleteLater();
            }
            process_ = new QProcess(this);
            process_->setProgram(program);
            process_->setArguments(arguments);
            process_->setWorkingDirectory(descriptor_.pluginDirectory);
            process_->setProcessChannelMode(QProcess::SeparateChannels);
            QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ROOT"), findPluginRoot());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ID"), descriptor_.id);
            // Base style injection protocol:
            // - External processes do not inherit the Qt palette/QSS, so provide stable theme roles via environment variables;
            // - Plugins can gradually consume these values without failing to start due to unimplemented style protocols.
            // - This is a snapshot taken at startup; reopening or retrying the plugin after a theme switch will retrieve the new value.
            // - Always use the *ColorHex() static role: the palette(...) dynamic role is only recognized by the QSS
            //   parser of the current process; passing it to external processes results in unrecognizable literals.
            environment.insert(QStringLiteral("KSWORD_PLUGIN_STYLE_API"), QStringLiteral("1"));
            environment.insert(
                QStringLiteral("KSWORD_PLUGIN_THEME"),
                ksword_theme::isDarkModeEnabled() ? QStringLiteral("dark") : QStringLiteral("light"));
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_WINDOW"), ksword_theme::windowColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_SURFACE"), ksword_theme::surfaceColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_SURFACE_ALT"), ksword_theme::surfaceAltColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_TEXT_PRIMARY"), ksword_theme::textPrimaryColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_TEXT_SECONDARY"), ksword_theme::textSecondaryColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_BORDER"), ksword_theme::borderColorHex());
            environment.insert(
                QStringLiteral("KSWORD_PLUGIN_COLOR_ACCENT"),
                ksword_theme::accentHex(ksword_theme::AccentRole::kBlue));
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_ON_ACCENT"), ksword_theme::onAccentHex());
            process_->setProcessEnvironment(environment);

            connect(process_, &QProcess::started, this, [this]() {
                statusLabel_->setText(QStringLiteral("插件进程已启动，等待窗口握手…"));
            });
            connect(process_, &QProcess::readyReadStandardOutput, this, [this]() { consumeStdout(); });
            connect(process_, &QProcess::readyReadStandardError, this, [this]() {
                const QString kText = QString::fromUtf8(process_->readAllStandardError());
                if (!kText.isEmpty()) diagnostics_->appendPlainText(kText.trimmed());
            });
            connect(process_, &QProcess::errorOccurred, this, [this](const QProcess::ProcessError error) {
                if (error == QProcess::FailedToStart)
                {
                    fail(QStringLiteral("Tab 插件启动失败：%1").arg(process_->errorString()), false);
                }
            });
            connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    if (stopping_) return;
                    pluginWindow_ = nullptr;
                    const QString kExitText = QStringLiteral("插件进程已退出：exit=%1, status=%2")
                        .arg(exitCode)
                        .arg(exitStatus == QProcess::NormalExit ? QStringLiteral("normal") : QStringLiteral("crashed"));
                    diagnostics_->appendPlainText(kExitText);
                    if (!failed_) fail(kExitText, false);
                });
            process_->start();

            QPointer<PluginTabPage> guard(this);
            QTimer::singleShot(descriptor_.tabPresentation.startupTimeoutMs, this, [guard]() {
                if (guard != nullptr && !guard->ready_ && !guard->failed_)
                {
                    guard->fail(QStringLiteral("Tab 插件启动超时，未收到有效的窗口握手。"), true);
                }
            });
        }

        void consumeStdout();
        void processProtocolLine(const QByteArray& line);
        void resizePluginWindow();
        void fail(const QString& message, bool stopProcess);

        PluginDescriptor descriptor_;
        QProcess* process_ = nullptr;
        QWidget* surface_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QPushButton* diagnosticsButton_ = nullptr;
        QPushButton* retryButton_ = nullptr;
        QPlainTextEdit* diagnostics_ = nullptr;
        QByteArray stdoutBuffer_;
        HWND pluginWindow_ = nullptr;
        bool ready_ = false;
        bool failed_ = false;
        bool stopping_ = false;
        bool startScheduled_ = false;
    };

    void PluginTabPage::consumeStdout()
    {
        if (process_ == nullptr)
        {
            return;
        }
        stdoutBuffer_ += process_->readAllStandardOutput();
        if (stdoutBuffer_.size() > kMaxBufferedStdoutBytes && !stdoutBuffer_.contains('\n'))
        {
            fail(QStringLiteral("Tab 插件 stdout 单行缓冲超过 1 MiB，已终止插件。"), true);
            return;
        }
        while (true)
        {
            const qsizetype kNewlineIndex = stdoutBuffer_.indexOf('\n');
            if (kNewlineIndex < 0)
            {
                break;
            }
            if (kNewlineIndex > kMaxBufferedStdoutBytes)
            {
                fail(QStringLiteral("Tab 插件 stdout 单行缓冲超过 1 MiB，已终止插件。"), true);
                return;
            }
            QByteArray line = stdoutBuffer_.left(kNewlineIndex);
            stdoutBuffer_.remove(0, kNewlineIndex + 1);
            if (line.endsWith('\r')) line.chop(1);
            if (!line.trimmed().isEmpty()) processProtocolLine(line);
            if (failed_) return;
        }
    }

    void PluginTabPage::processProtocolLine(const QByteArray& line)
    {
        QJsonParseError parseError;
        const QJsonDocument kDocument = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            diagnostics_->appendPlainText(QString::fromUtf8(line));
            fail(QStringLiteral("Tab 插件输出不是有效的 JSON Lines 协议事件。"), true);
            return;
        }
        const QJsonObject kObject = kDocument.object();
        if (kObject.value(QStringLiteral("protocol")).toString() != QStringLiteral("ksword-plugin/1") ||
            kObject.value(QStringLiteral("plugin_id")).toString() != descriptor_.id)
        {
            fail(QStringLiteral("Tab 插件协议版本或 plugin_id 与清单不匹配。"), true);
            return;
        }
        const QString kEvent = kObject.value(QStringLiteral("event")).toString();
        if (kEvent == QStringLiteral("error"))
        {
            fail(QStringLiteral("Tab 插件报告错误：%1")
                .arg(kObject.value(QStringLiteral("message")).toString(QStringLiteral("未知错误"))), true);
            return;
        }
        if (kEvent != descriptor_.tabPresentation.readyEvent)
        {
            diagnostics_->appendPlainText(QString::fromUtf8(line));
            return;
        }

        const QJsonValue kHandleValue = kObject.value(QStringLiteral("hwnd"));
        bool handleOk = false;
        qulonglong numericHandle = 0;
        if (kHandleValue.isString())
        {
            numericHandle = kHandleValue.toString().toULongLong(&handleOk, 0);
        }
        else if (kHandleValue.isDouble() && kHandleValue.toDouble() > 0.0)
        {
            numericHandle = static_cast<qulonglong>(kHandleValue.toDouble());
            handleOk = true;
        }
        HWND candidateWindow = handleOk
            ? reinterpret_cast<HWND>(static_cast<quintptr>(numericHandle))
            : nullptr;
        if (!handleOk || !::IsWindow(candidateWindow))
        {
            fail(QStringLiteral("Tab 插件返回的窗口句柄无效。"), true);
            return;
        }

        DWORD owningProcessId = 0;
        ::GetWindowThreadProcessId(candidateWindow, &owningProcessId);
        if (process_ == nullptr || owningProcessId != static_cast<DWORD>(process_->processId()))
        {
            fail(QStringLiteral("Tab 插件窗口不属于刚启动的插件进程，已拒绝嵌入。"), true);
            return;
        }
        const HWND kExpectedParent = reinterpret_cast<HWND>(surface_->winId());
        if (::GetParent(candidateWindow) != kExpectedParent ||
            (::GetWindowLongPtrW(candidateWindow, GWL_STYLE) & WS_CHILD) == 0)
        {
            fail(QStringLiteral("Tab 插件窗口未作为宿主容器的直接 WS_CHILD 子窗口创建。"), true);
            return;
        }

        pluginWindow_ = candidateWindow;
        ready_ = true;
        failed_ = false;
        retryButton_->setVisible(false);
        statusLabel_->setStyleSheet({});
        statusLabel_->setText(QStringLiteral("Tab 插件已连接（外部进程 PID %1）。")
            .arg(owningProcessId));
        ::ShowWindow(pluginWindow_, SW_SHOW);
        resizePluginWindow();
    }

    void PluginTabPage::resizePluginWindow()
    {
        if (!::IsWindow(pluginWindow_) || surface_ == nullptr)
        {
            return;
        }
        const QSize kSize = surface_->size();
        ::MoveWindow(pluginWindow_, 0, 0, qMax(1, kSize.width()), qMax(1, kSize.height()), TRUE);
    }

    void PluginTabPage::fail(const QString& message, const bool stopProcess)
    {
        if (stopping_)
        {
            return;
        }
        failed_ = true;
        ready_ = false;
        pluginWindow_ = nullptr;
        statusLabel_->setText(message);
        statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        retryButton_->setVisible(true);
        diagnostics_->appendPlainText(message);
        if (stopProcess && process_ != nullptr && process_->state() != QProcess::NotRunning)
        {
            process_->terminate();
            QPointer<QProcess> processGuard(process_);
            QTimer::singleShot(1500, this, [processGuard]() {
                if (processGuard != nullptr && processGuard->state() != QProcess::NotRunning)
                {
                    processGuard->kill();
                }
            });
        }
    }

    bool promoteExtractedPlugin(
        const MarketplacePlugin& plugin,
        const QString& pluginRoot,
        const QString& stagingDirectory,
        QString* errorOut)
    {
        if (errorOut == nullptr)
        {
            return false;
        }

        PluginDescriptor extractedDescriptor;
        if (!loadPluginManifest(stagingDirectory, plugin.installDirectory, &extractedDescriptor, errorOut))
        {
            return false;
        }
        if (extractedDescriptor.id != plugin.id)
        {
            *errorOut = QStringLiteral("已解压插件的 id 与商城目录不一致。");
            return false;
        }

        QDir rootDirectory(pluginRoot);
        const QString kStagingName = QFileInfo(stagingDirectory).fileName();
        const QString kStagedPluginPath = kStagingName + QChar('/') + plugin.installDirectory;
        const QString kBackupName = QStringLiteral(".ksword-plugin-backup-%1-%2")
            .arg(plugin.installDirectory, QUuid::createUuid().toString(QUuid::WithoutBraces));
        const QString kTargetPath = rootDirectory.filePath(plugin.installDirectory);
        const bool kTargetExists = QFileInfo::exists(kTargetPath);

        if (kTargetExists && !rootDirectory.rename(plugin.installDirectory, kBackupName))
        {
            *errorOut = QStringLiteral("无法备份现有插件目录：%1").arg(QDir::toNativeSeparators(kTargetPath));
            return false;
        }

        if (!rootDirectory.rename(kStagedPluginPath, plugin.installDirectory))
        {
            if (kTargetExists)
            {
                rootDirectory.rename(kBackupName, plugin.installDirectory);
            }
            *errorOut = QStringLiteral("无法将已验证插件安装到：%1").arg(QDir::toNativeSeparators(kTargetPath));
            return false;
        }

        if (kTargetExists)
        {
            // After the new version is in place, a cleanup failure should not report a successful installation as failed.
            // Legacy backups will not be detected as valid plugins (names do not match the plugin ID rules).
            QDir(rootDirectory.filePath(kBackupName)).removeRecursively();
        }
        return true;
    }

    class PluginManagerDialog final : public QDialog
    {
    public:
        explicit PluginManagerDialog(QWidget* parent)
            : QDialog(parent)
        {
            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowTitle(QStringLiteral("插件管理"));
            resize(840, 460);
            setModal(false);
            auto* layout = new QVBoxLayout(this);
            layout->setContentsMargins(8, 8, 8, 8);
            layout->setSpacing(6);

            // The plugin list and process list share the same compact table geometry baseline. Only set row
            // height and scrolling geometry properties locally within the page to avoid polluting the title
            // bar or other tables requiring variable row heights by placing sizing rules in app-level QSS.
            const auto kConfigurePluginTable = [](QTableWidget* table) {
                if (table == nullptr)
                {
                    return;
                }
                table->setAlternatingRowColors(true);
                table->setShowGrid(false);
                table->setWordWrap(false);
                table->setCornerButtonEnabled(false);
                table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                if (QHeaderView* verticalHeader = table->verticalHeader())
                {
                    verticalHeader->setVisible(false);
                    verticalHeader->setSectionResizeMode(QHeaderView::Fixed);
                    verticalHeader->setMinimumSectionSize(20);
                    verticalHeader->setDefaultSectionSize(24);
                }
            };

            networkManager_ = new QNetworkAccessManager(this);
            auto* tabWidget = new QTabWidget(this);
            auto* localPage = new QWidget(tabWidget);
            auto* localLayout = new QVBoxLayout(localPage);
            localLayout->setContentsMargins(6, 6, 6, 6);
            localLayout->setSpacing(4);
            table_ = new ks::ui::VisibleTableWidget(localPage);
            table_->setColumnCount(4);
            table_->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("版本"), QStringLiteral("目标"), QStringLiteral("说明") });
            table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table_->setSelectionBehavior(QAbstractItemView::SelectRows);
            table_->setSelectionMode(QAbstractItemView::SingleSelection);
            table_->horizontalHeader()->setStretchLastSection(true);
            kConfigurePluginTable(table_);
            auto* localActions = new QHBoxLayout();
            localActions->setSpacing(4);
            auto* refreshButton = new QPushButton(QStringLiteral("重新扫描本地"), localPage);
            auto* detailButton = new QPushButton(QStringLiteral("查看清单详情"), localPage);
            openFolderButton_ = new QPushButton(QStringLiteral("打开插件目录"), localPage);
            localActions->addWidget(refreshButton);
            localActions->addWidget(detailButton);
            localActions->addWidget(openFolderButton_);
            localActions->addStretch(1);
            localLayout->addLayout(localActions);
            localLayout->addWidget(table_);
            tabWidget->addTab(localPage, QStringLiteral("已安装"));

            auto* marketplacePage = new QWidget(tabWidget);
            auto* marketplaceLayout = new QVBoxLayout(marketplacePage);
            marketplaceLayout->setContentsMargins(6, 6, 6, 6);
            marketplaceLayout->setSpacing(4);
            marketplaceTable_ = new ks::ui::VisibleTableWidget(marketplacePage);
            marketplaceTable_->setColumnCount(6);
            marketplaceTable_->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("名称"), QStringLiteral("版本"), QStringLiteral("安装状态"), QStringLiteral("目标"), QStringLiteral("许可证"), QStringLiteral("说明") });
            marketplaceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
            marketplaceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
            marketplaceTable_->setSelectionMode(QAbstractItemView::SingleSelection);
            marketplaceTable_->horizontalHeader()->setStretchLastSection(true);
            kConfigurePluginTable(marketplaceTable_);
            auto* marketplaceActions = new QHBoxLayout();
            marketplaceActions->setSpacing(4);
            auto* refreshMarketplaceButton = new QPushButton(QStringLiteral("刷新商城"), marketplacePage);
            auto* checkUpdatesButton = new QPushButton(QStringLiteral("检查插件更新"), marketplacePage);
            auto* installButton = new QPushButton(QStringLiteral("同意许可证并一键安装"), marketplacePage);
            autoUpdateCheck_ = new QCheckBox(QStringLiteral("自动更新已授权插件"), marketplacePage);
            autoUpdateCheck_->setToolTip(QStringLiteral("检查更新时，自动安装已确认当前许可证且有新版本的插件。许可证变化时会要求重新确认。"));
            QSettings settings;
            autoUpdateCheck_->setChecked(settings.value(QStringLiteral("PluginMarketplace/AutoUpdate"), false).toBool());
            marketplaceActions->addWidget(refreshMarketplaceButton);
            marketplaceActions->addWidget(checkUpdatesButton);
            marketplaceActions->addWidget(installButton);
            marketplaceActions->addWidget(autoUpdateCheck_);
            marketplaceActions->addStretch(1);
            marketplaceLayout->addLayout(marketplaceActions);
            marketplaceLayout->addWidget(marketplaceTable_);
            tabWidget->addTab(marketplacePage, QStringLiteral("插件商城"));
            layout->addWidget(tabWidget, 1);

            status_ = new QLabel(this);
            status_->setWordWrap(true);
            status_->setMinimumWidth(0);
            status_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            layout->addWidget(status_);
            installProgress_ = new QProgressBar(this);
            installProgress_->setTextVisible(true);
            installProgress_->setVisible(false);
            layout->addWidget(installProgress_);
            auto* footer = new QHBoxLayout();
            auto* closeButton = new QPushButton(QStringLiteral("关闭"), this);
            footer->addStretch(1);
            footer->addWidget(closeButton);
            layout->addLayout(footer);
            connect(refreshButton, &QPushButton::clicked, this, [this]() { refreshPlugins(); });
            connect(refreshMarketplaceButton, &QPushButton::clicked, this, [this]() { refreshMarketplace(); });
            connect(checkUpdatesButton, &QPushButton::clicked, this, [this]() { checkForUpdates(); });
            connect(detailButton, &QPushButton::clicked, this, [this]() { showSelectedDetails(); });
            connect(installButton, &QPushButton::clicked, this, [this]() { requestSelectedMarketplaceLicense(); });
            connect(autoUpdateCheck_, &QCheckBox::toggled, this, [this](const bool enabled) {
                QSettings settings;
                settings.setValue(QStringLiteral("PluginMarketplace/AutoUpdate"), enabled);
                if (enabled)
                {
                    checkForUpdates();
                }
            });
            connect(openFolderButton_, &QPushButton::clicked, this, [this]() {
                if (!pluginRoot_.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(pluginRoot_));
            });
            connect(closeButton, &QPushButton::clicked, this, &QDialog::close);
            refreshPlugins();
            refreshMarketplace(true);
        }

    private:
        using InstallCompletion = std::function<void(bool, const QString&)>;

        void refreshPlugins()
        {
            PluginListResult result;
            QString errorText;
            table_->setRowCount(0);
            plugins_.clear();
            installedPluginsById_.clear();
            pluginRoot_.clear();
            if (!discoverPlugins(&result, &errorText))
            {
                status_->setText(
                    QStringLiteral("插件目录不可用；详情已写入日志。"));
                KLogEvent discoveryEvent;
                warn << discoveryEvent
                    << "[PluginHost] plugin discovery failed, detail="
                    << errorText.toStdString()
                    << eol;
                openFolderButton_->setEnabled(false);
                return;
            }
            plugins_ = result.plugins;
            for (const PluginDescriptor& descriptor : plugins_)
            {
                installedPluginsById_.insert(descriptor.id, descriptor);
            }
            pluginRoot_ = result.pluginRoot;
            for (const PluginDescriptor& descriptor : plugins_)
            {
                const int kRow = table_->rowCount();
                table_->insertRow(kRow);
                table_->setItem(kRow, 0, new QTableWidgetItem(descriptor.name));
                table_->setItem(kRow, 1, new QTableWidgetItem(descriptor.version));
                table_->setItem(kRow, 2, new QTableWidgetItem(descriptor.targets.join(QStringLiteral(", "))));
                table_->setItem(kRow, 3, new QTableWidgetItem(descriptor.description));
            }
            if (!plugins_.isEmpty()) table_->selectRow(0);
            openFolderButton_->setEnabled(QDir(pluginRoot_).exists());
            QString status = QStringLiteral("已发现 %1 个有效插件。插件目录：%2")
                .arg(plugins_.size())
                .arg(QDir::toNativeSeparators(pluginRoot_));
            if (!result.ignoredManifests.isEmpty())
            {
                status += QStringLiteral(
                    "\n已忽略 %1 个清单；详情已写入日志。")
                    .arg(result.ignoredManifests.size());
                KLogEvent ignoredManifestEvent;
                warn << ignoredManifestEvent
                    << "[PluginHost] ignored plugin manifests, count="
                    << result.ignoredManifests.size()
                    << ", details="
                    << result.ignoredManifests
                        .join(QStringLiteral(" | "))
                        .toStdString()
                    << eol;
            }
            status_->setText(status);
        }

        void showSelectedDetails()
        {
            const int kRow = table_->currentRow();
            if (kRow < 0 || kRow >= plugins_.size())
            {
                QMessageBox::information(this, QStringLiteral("插件管理"), QStringLiteral("请先选择一个插件。"));
                return;
            }
            const PluginDescriptor& descriptor = plugins_.at(kRow);
            const QString kDetailText = QStringLiteral("id=%1\nversion=%2\nplugin_type=%3\nruntime=%4\nentrypoint=%5\ndefault_command=%6\ntargets=%7\nvisualization=%8\ndirectory=%9\n\n%10")
                .arg(descriptor.id)
                .arg(descriptor.version)
                .arg(descriptor.pluginType)
                .arg(descriptor.runtime)
                .arg(descriptor.entrypointPath)
                .arg(descriptor.defaultCommand)
                .arg(descriptor.targets.join(QStringLiteral(", ")))
                .arg(descriptor.visualization.enabled ? descriptor.visualization.type : QStringLiteral("none"))
                .arg(descriptor.pluginDirectory)
                .arg(descriptor.description);
            QMessageBox::information(this, QStringLiteral("插件清单：%1").arg(descriptor.name), kDetailText);
        }

        void refreshMarketplace(const bool checkForUpdates = false)
        {
            marketplaceTable_->setRowCount(0);
            marketplacePlugins_.clear();
            status_->setText(QStringLiteral("正在从 KSwordDEV/Plugins 读取插件商城目录…"));
            QNetworkRequest request(QUrl(QString::fromLatin1(kMarketplaceCatalogUrl)));
            request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KSword-PluginMarketplace/1"));
            request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork);
            QNetworkReply* reply = networkManager_->get(request);
            connect(reply, &QNetworkReply::finished, this, [this, reply, checkForUpdates]() {
                const QByteArray kPayload = reply->readAll();
                const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
                const QString kNetworkError = kNetworkOk ? QString() : networkReplyErrorText(reply);
                reply->deleteLater();
                if (!kNetworkOk)
                {
                    status_->setText(QStringLiteral(
                        "商城目录读取失败；详情已写入日志。"));
                    KLogEvent requestEvent;
                    warn << requestEvent
                        << "[PluginHost] marketplace catalog request failed, detail="
                        << kNetworkError.toStdString()
                        << eol;
                    return;
                }
                QJsonParseError parseError;
                const QJsonDocument kDocument = QJsonDocument::fromJson(kPayload, &parseError);
                if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
                {
                    status_->setText(QStringLiteral(
                        "商城目录不是有效 JSON；详情已写入日志。"));
                    KLogEvent parseEvent;
                    warn << parseEvent
                        << "[PluginHost] marketplace catalog parse failed, detail="
                        << parseError.errorString().toStdString()
                        << eol;
                    return;
                }
                const QJsonObject kRoot = kDocument.object();
                if (kRoot.value(QStringLiteral("ksword_plugin_marketplace_api")).toString() != QStringLiteral("1"))
                {
                    status_->setText(QStringLiteral("商城目录版本不受支持。"));
                    return;
                }
                QStringList ignoredEntries;
                for (const QJsonValue& value : kRoot.value(QStringLiteral("plugins")).toArray())
                {
                    MarketplacePlugin plugin;
                    QString errorText;
                    if (value.isObject() && parseMarketplacePlugin(value.toObject(), &plugin, &errorText))
                    {
                        marketplacePlugins_.push_back(plugin);
                    }
                    else
                    {
                        ignoredEntries.push_back(errorText.isEmpty() ? QStringLiteral("无效条目") : errorText);
                    }
                }
                populateMarketplaceTable();
                if (!marketplacePlugins_.isEmpty()) marketplaceTable_->selectRow(0);
                const QList<MarketplacePlugin> kUpdates = availableMarketplaceUpdates();
                QString status = QStringLiteral("插件商城已从 KSwordDEV/Plugins 刷新：%1 个可下载插件，%2 个插件可更新。")
                    .arg(marketplacePlugins_.size())
                    .arg(kUpdates.size());
                if (!ignoredEntries.isEmpty())
                {
                    status += QStringLiteral(
                        " 已忽略 %1 个无效条目；详情已写入日志。")
                        .arg(ignoredEntries.size());
                    KLogEvent ignoredEntryEvent;
                    warn << ignoredEntryEvent
                        << "[PluginHost] ignored marketplace entries, count="
                        << ignoredEntries.size()
                        << ", details="
                        << ignoredEntries
                            .join(QStringLiteral(" | "))
                            .toStdString()
                        << eol;
                }
                status_->setText(status);
                if (checkForUpdates && !autoUpdateInProgress_ &&
                    autoUpdateCheck_ != nullptr && autoUpdateCheck_->isChecked())
                {
                    beginAutomaticUpdates(kUpdates);
                }
            });
        }

        void checkForUpdates()
        {
            if (autoUpdateInProgress_)
            {
                status_->setText(QStringLiteral("插件自动更新正在进行，请等待当前队列完成。"));
                return;
            }
            refreshPlugins();
            refreshMarketplace(true);
        }

        QString installedVersionFor(const MarketplacePlugin& plugin) const
        {
            const auto kInstalled = installedPluginsById_.constFind(plugin.id);
            return kInstalled == installedPluginsById_.cend() ? QString() : kInstalled->version;
        }

        MarketplaceUpdateState updateStateFor(const MarketplacePlugin& plugin) const
        {
            return marketplaceUpdateState(installedVersionFor(plugin), plugin.version);
        }

        QString updateStateText(const MarketplacePlugin& plugin) const
        {
            const QString kInstalledVersion = installedVersionFor(plugin);
            switch (updateStateFor(plugin))
            {
            case MarketplaceUpdateState::kNotInstalled:
                return QStringLiteral("未安装");
            case MarketplaceUpdateState::kCurrent:
                return QStringLiteral("已是最新（%1）").arg(kInstalledVersion);
            case MarketplaceUpdateState::kAvailable:
                return QStringLiteral("可更新：%1 → %2").arg(kInstalledVersion, plugin.version);
            case MarketplaceUpdateState::kNotComparable:
                return QStringLiteral("版本无法比较（本地 %1）").arg(kInstalledVersion);
            }
            return QStringLiteral("未知");
        }

        QList<MarketplacePlugin> availableMarketplaceUpdates() const
        {
            QList<MarketplacePlugin> updates;
            for (const MarketplacePlugin& plugin : marketplacePlugins_)
            {
                if (updateStateFor(plugin) == MarketplaceUpdateState::kAvailable)
                {
                    updates.push_back(plugin);
                }
            }
            return updates;
        }

        void populateMarketplaceTable()
        {
            marketplaceTable_->setRowCount(0);
            for (const MarketplacePlugin& plugin : marketplacePlugins_)
            {
                const int kRow = marketplaceTable_->rowCount();
                marketplaceTable_->insertRow(kRow);
                marketplaceTable_->setItem(kRow, 0, new QTableWidgetItem(plugin.name));
                marketplaceTable_->setItem(kRow, 1, new QTableWidgetItem(plugin.version));
                marketplaceTable_->setItem(kRow, 2, new QTableWidgetItem(updateStateText(plugin)));
                marketplaceTable_->setItem(kRow, 3, new QTableWidgetItem(plugin.targets.join(QStringLiteral(", "))));
                marketplaceTable_->setItem(kRow, 4, new QTableWidgetItem(plugin.licenseName));
                marketplaceTable_->setItem(kRow, 5, new QTableWidgetItem(plugin.description));
            }
        }

        bool hasMarketplaceLicenseAcceptanceRecord(const MarketplacePlugin& plugin) const
        {
            QSettings settings;
            return !settings.value(
                marketplaceLicenseAcceptanceKey(plugin)).toString().isEmpty();
        }

        bool hasAcceptedMarketplaceLicense(
            const MarketplacePlugin& plugin,
            const QByteArray& licensePayload) const
        {
            // The old acceptance record remains valid only if the name, URL, and the actual downloaded body of this instance all match.
            QSettings settings;
            return settings.value(
                marketplaceLicenseAcceptanceKey(plugin)).toString()
                == marketplaceLicenseFingerprint(plugin, licensePayload);
        }

        void updateInstallProgress(const QString& stage, const int percent)
        {
            installProgress_->setVisible(true);
            installProgress_->setRange(0, 100);
            installProgress_->setValue(qBound(0, percent, 100));
            installProgress_->setFormat(stage + QStringLiteral("：%p%"));
        }

        void updateDownloadProgress(const MarketplacePlugin& plugin, const qint64 received, const qint64 total)
        {
            if (total <= 0)
            {
                installProgress_->setVisible(true);
                installProgress_->setRange(0, 0);
                installProgress_->setFormat(QStringLiteral("正在下载 %1…").arg(plugin.name));
                return;
            }
            const int kOverallPercent = qBound(0, static_cast<int>((received * 70) / total), 70);
            updateInstallProgress(
                QStringLiteral("正在下载 %1（%2 / %3 MiB）")
                    .arg(plugin.name)
                    .arg(QString::number(received / (1024.0 * 1024.0), 'f', 1))
                    .arg(QString::number(total / (1024.0 * 1024.0), 'f', 1)),
                kOverallPercent);
        }

        void finishInstallProgress(const bool keepVisible = false)
        {
            if (keepVisible)
            {
                return;
            }
            QTimer::singleShot(1400, this, [this]() {
                if (!autoUpdateInProgress_)
                {
                    installProgress_->setVisible(false);
                }
            });
        }

        // requestMarketplaceLicensePayload：
        // - Input plugin/completion: marketplace plugin and async completion callback;
        // - Handling: Download the actual license body and normalize network errors or empty bodies uniformly;
        // - Output: callback receives success flag, raw body, and displayable error without triggering ZIP download.
        void requestMarketplaceLicensePayload(
            const MarketplacePlugin& plugin,
            const std::function<void(bool, QByteArray, QString)>& completion)
        {
            QNetworkRequest request(plugin.licenseUrl);
            request.setHeader(
                QNetworkRequest::UserAgentHeader,
                QStringLiteral("KSword-PluginMarketplace/1"));
            QNetworkReply* reply = networkManager_->get(request);
            connect(
                reply,
                &QNetworkReply::finished,
                this,
                [reply, completion]() {
                    const QByteArray kPayload = reply->readAll();
                    const bool kNetworkOk =
                        reply->error() == QNetworkReply::NoError;
                    const QString kFailureMessage = kNetworkOk
                        ? QStringLiteral("许可证正文为空。")
                        : networkReplyErrorText(reply);
                    reply->deleteLater();
                    completion(
                        kNetworkOk && !kPayload.isEmpty(),
                        kPayload,
                        kFailureMessage);
                });
        }

        void beginAutomaticUpdates(const QList<MarketplacePlugin>& updates)
        {
            autoUpdateQueue_.clear();
            int pendingLicenseConfirmation = 0;
            for (const MarketplacePlugin& plugin : updates)
            {
                if (hasMarketplaceLicenseAcceptanceRecord(plugin))
                {
                    autoUpdateQueue_.push_back(plugin);
                }
                else
                {
                    ++pendingLicenseConfirmation;
                }
            }
            if (autoUpdateQueue_.isEmpty())
            {
                status_->setText(pendingLicenseConfirmation > 0
                    ? QStringLiteral("发现 %1 个更新；其中 %2 个需要确认当前许可证，未自动安装。")
                        .arg(updates.size())
                        .arg(pendingLicenseConfirmation)
                    : QStringLiteral("插件已是最新。"));
                return;
            }

            autoUpdateInProgress_ = true;
            autoUpdateTotal_ = autoUpdateQueue_.size();
            autoUpdateCompleted_ = 0;
            autoUpdateFailures_.clear();
            status_->setText(QStringLiteral("开始自动更新 %1 个已授权插件。").arg(autoUpdateTotal_));
            startNextAutomaticUpdate();
        }

        void startNextAutomaticUpdate()
        {
            if (autoUpdateQueue_.isEmpty())
            {
                autoUpdateInProgress_ = false;
                refreshPlugins();
                populateMarketplaceTable();
                if (autoUpdateFailures_.isEmpty())
                {
                    status_->setText(QStringLiteral("已自动更新 %1 个插件。").arg(autoUpdateCompleted_));
                    updateInstallProgress(QStringLiteral("自动更新完成"), 100);
                }
                else
                {
                    status_->setText(QStringLiteral(
                        "自动更新完成：%1 个成功，%2 个失败；详情已写入日志。")
                        .arg(autoUpdateCompleted_ - autoUpdateFailures_.size())
                        .arg(autoUpdateFailures_.size()));
                    KLogEvent autoUpdateEvent;
                    warn << autoUpdateEvent
                        << "[PluginHost] automatic update completed with failures, completed="
                        << autoUpdateCompleted_
                        << ", failureCount="
                        << autoUpdateFailures_.size()
                        << ", failureDetails="
                        << autoUpdateFailures_
                            .join(QStringLiteral(" | "))
                            .toStdString()
                        << eol;
                }
                finishInstallProgress();
                return;
            }

            const MarketplacePlugin kPlugin = autoUpdateQueue_.takeFirst();
            const int kCurrent = autoUpdateTotal_ - autoUpdateQueue_.size();
            updateInstallProgress(QStringLiteral("自动更新 %1（%2 / %3）").arg(kPlugin.name).arg(kCurrent).arg(autoUpdateTotal_), 0);
            requestMarketplaceLicensePayload(
                kPlugin,
                [this, kPlugin](
                    const bool licenseReadOk,
                    const QByteArray licensePayload,
                    const QString& licenseError) {
                    if (!licenseReadOk
                        || !hasAcceptedMarketplaceLicense(
                            kPlugin,
                            licensePayload))
                    {
                        ++autoUpdateCompleted_;
                        const QString kFailureMessage = licenseReadOk
                            ? QStringLiteral("许可证正文已变化，需要手动重新确认。")
                            : QStringLiteral("无法核验许可证：%1")
                                .arg(licenseError);
                        autoUpdateFailures_.push_back(
                            QStringLiteral("%1：%2")
                                .arg(kPlugin.name, kFailureMessage));
                        startNextAutomaticUpdate();
                        return;
                    }

                    // Automatic updates only download the ZIP if the current body hash still matches the accepted record.
                    downloadMarketplaceArchive(
                        kPlugin,
                        [this, kPlugin](
                            const bool success,
                            const QString& message) {
                            ++autoUpdateCompleted_;
                            if (!success)
                            {
                                autoUpdateFailures_.push_back(
                                    QStringLiteral("%1：%2")
                                        .arg(kPlugin.name, message));
                            }
                            startNextAutomaticUpdate();
                        });
                });
        }

        void requestSelectedMarketplaceLicense()
        {
            if (autoUpdateInProgress_)
            {
                status_->setText(QStringLiteral("插件自动更新正在进行，请等待当前队列完成。"));
                return;
            }
            const int kRow = marketplaceTable_->currentRow();
            if (kRow < 0 || kRow >= marketplacePlugins_.size())
            {
                QMessageBox::information(this, QStringLiteral("插件商城"), QStringLiteral("请先在“插件商城”中选择一个插件。"));
                return;
            }
            const MarketplacePlugin kPlugin = marketplacePlugins_.at(kRow);
            status_->setText(QStringLiteral("正在读取 %1 的许可证；同意前不会下载或安装插件。").arg(kPlugin.name));
            requestMarketplaceLicensePayload(
                kPlugin,
                [this, kPlugin](
                    const bool success,
                    const QByteArray licensePayload,
                    const QString& errorMessage) {
                    if (!success)
                    {
                        QMessageBox::warning(
                            this,
                            QStringLiteral("插件商城"),
                            QStringLiteral("无法读取许可证：%1")
                                .arg(errorMessage));
                        return;
                    }
                    if (hasAcceptedMarketplaceLicense(
                            kPlugin,
                            licensePayload))
                    {
                        status_->setText(
                            QStringLiteral("%1 的许可证正文未变化，继续下载安装。")
                                .arg(kPlugin.name));
                        downloadMarketplaceArchive(kPlugin);
                        return;
                    }
                    showLicenseAgreement(kPlugin, licensePayload);
                });
        }

        void showLicenseAgreement(
            const MarketplacePlugin& plugin,
            const QByteArray& licensePayload)
        {
            QDialog licenseDialog(this);
            licenseDialog.setWindowTitle(QStringLiteral("许可证：%1").arg(plugin.name));
            licenseDialog.resize(780, 620);
            auto* layout = new QVBoxLayout(&licenseDialog);
            auto* label = new QLabel(QStringLiteral("安装 %1 前，请阅读并同意：%2。未同意不会发起插件 ZIP 下载。")
                .arg(plugin.name, plugin.licenseName), &licenseDialog);
            label->setWordWrap(true);
            layout->addWidget(label);
            auto* text = new QPlainTextEdit(&licenseDialog);
            text->setReadOnly(true);
            text->setPlainText(QString::fromUtf8(licensePayload));
            layout->addWidget(text, 1);
            auto* agree = new QCheckBox(QStringLiteral("我已阅读并同意上述插件许可证"), &licenseDialog);
            layout->addWidget(agree);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, &licenseDialog);
            QPushButton* acceptButton = buttons->addButton(QStringLiteral("同意并一键安装"), QDialogButtonBox::AcceptRole);
            acceptButton->setEnabled(false);
            layout->addWidget(buttons);
            connect(agree, &QCheckBox::toggled, acceptButton, &QPushButton::setEnabled);
            connect(buttons, &QDialogButtonBox::accepted, &licenseDialog, &QDialog::accept);
            connect(buttons, &QDialogButtonBox::rejected, &licenseDialog, &QDialog::reject);
            if (licenseDialog.exec() != QDialog::Accepted)
            {
                status_->setText(QStringLiteral("未同意许可证，未下载或安装 %1。").arg(plugin.name));
                return;
            }
            QSettings settings;
            settings.setValue(
                marketplaceLicenseAcceptanceKey(plugin),
                marketplaceLicenseFingerprint(plugin, licensePayload));
            downloadMarketplaceArchive(plugin);
        }

        void completeMarketplaceInstall(
            const InstallCompletion& completion,
            const bool success,
            const QString& message)
        {
            if (!success)
            {
                status_->setText(QStringLiteral("插件安装失败：%1").arg(message));
                updateInstallProgress(QStringLiteral("安装失败"), 0);
                if (!completion)
                {
                    QMessageBox::warning(this, QStringLiteral("插件商城"), message);
                }
            }
            if (completion)
            {
                completion(success, message);
            }
            else
            {
                finishInstallProgress();
            }
        }

        void downloadMarketplaceArchive(
            const MarketplacePlugin& plugin,
            InstallCompletion completion = {})
        {
            status_->setText(QStringLiteral("正在下载 %1；将校验 SHA-256 后一键安装。").arg(plugin.name));
            updateInstallProgress(QStringLiteral("正在下载 %1").arg(plugin.name), 0);
            QNetworkRequest request(plugin.archiveUrl);
            request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KSword-PluginMarketplace/1"));
            QNetworkReply* reply = networkManager_->get(request);
            connect(reply, &QNetworkReply::downloadProgress, this,
                [this, plugin](const qint64 received, const qint64 total) {
                    updateDownloadProgress(plugin, received, total);
                });
            connect(reply, &QNetworkReply::finished, this, [this, reply, plugin, completion]() {
                const QByteArray kArchiveBytes = reply->readAll();
                const bool kNetworkOk = reply->error() == QNetworkReply::NoError;
                const QString kNetworkError = kNetworkOk ? QString() : networkReplyErrorText(reply);
                reply->deleteLater();
                if (!kNetworkOk)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("插件下载失败：%1").arg(kNetworkError));
                    return;
                }
                if (kArchiveBytes.isEmpty() || kArchiveBytes.size() > kMaxMarketplaceArchiveBytes)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("插件包为空或超过 256 MiB 限制。"));
                    return;
                }
                updateInstallProgress(QStringLiteral("正在校验 %1 的 SHA-256").arg(plugin.name), 75);
                const QString kActualSha256 = QString::fromLatin1(QCryptographicHash::hash(kArchiveBytes, QCryptographicHash::Sha256).toHex());
                if (kActualSha256.compare(plugin.sha256, Qt::CaseInsensitive) != 0)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("SHA-256 校验失败，已拒绝安装插件。"));
                    return;
                }
                updateInstallProgress(QStringLiteral("SHA-256 校验通过"), 80);
                installMarketplaceArchive(plugin, kArchiveBytes, completion);
            });
        }

        void installMarketplaceArchive(
            const MarketplacePlugin& plugin,
            const QByteArray& archiveBytes,
            const InstallCompletion& completion)
        {
            const QString kPluginRoot = resolvePluginInstallRoot();
            if (!QDir().mkpath(kPluginRoot))
            {
                completeMarketplaceInstall(completion, false, QStringLiteral("无法创建插件目录：%1")
                    .arg(QDir::toNativeSeparators(kPluginRoot)));
                return;
            }

            {
                updateInstallProgress(QStringLiteral("正在准备 %1 的已验证安装包").arg(plugin.name), 84);
                const QString kArchivePath = QDir(kPluginRoot).filePath(
                    QStringLiteral(".ksword-plugin-download-%1.zip")
                        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
                QSaveFile archiveFile(kArchivePath);
                if (!archiveFile.open(QIODevice::WriteOnly) ||
                    archiveFile.write(archiveBytes) != archiveBytes.size() ||
                    !archiveFile.commit())
                {
                    QFile::remove(kArchivePath);
                    completeMarketplaceInstall(completion, false,
                        QStringLiteral("无法准备已验证的插件包：%1").arg(archiveFile.errorString()));
                    return;
                }
                installVerifiedMarketplaceArchive(plugin, kPluginRoot, kArchivePath, completion);
            }
        }

        void installVerifiedMarketplaceArchive(
            const MarketplacePlugin& plugin,
            const QString& pluginRoot,
            const QString& archivePath,
            const InstallCompletion& completion)
        {
            const QString kStagingName = QStringLiteral(".ksword-plugin-stage-%1-%2")
                .arg(plugin.installDirectory, QUuid::createUuid().toString(QUuid::WithoutBraces));
            const QString kStagingPath = QDir(pluginRoot).filePath(kStagingName);
            if (!QDir().mkpath(kStagingPath))
            {
                QFile::remove(archivePath);
                completeMarketplaceInstall(completion, false, QStringLiteral("无法创建插件安装暂存目录。"));
                return;
            }

            const QString kPowerShell = QStandardPaths::findExecutable(QStringLiteral("powershell.exe"));
            if (kPowerShell.isEmpty())
            {
                QDir(kStagingPath).removeRecursively();
                QFile::remove(archivePath);
                completeMarketplaceInstall(completion, false, QStringLiteral("未找到 Windows PowerShell，无法解压插件包。"));
                return;
            }

            auto* extractor = new QProcess(this);
            extractor->setProcessChannelMode(QProcess::SeparateChannels);
            const QString kCommand = QStringLiteral("$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath %1 -DestinationPath %2 -Force")
                .arg(quotePowerShellLiteral(archivePath), quotePowerShellLiteral(kStagingPath));
            extractor->setProgram(kPowerShell);
            extractor->setArguments(QStringList{
                QStringLiteral("-NoLogo"), QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"),
                QStringLiteral("-Command"), kCommand });
            status_->setText(QStringLiteral("已验证 %1，正在安全解压并安装…").arg(plugin.name));
            updateInstallProgress(QStringLiteral("正在安全解压 %1").arg(plugin.name), 90);
            connect(extractor, &QProcess::errorOccurred, this,
                [this, extractor, archivePath, kStagingPath, completion](const QProcess::ProcessError error) {
                    if (error != QProcess::FailedToStart) return;
                    QDir(kStagingPath).removeRecursively();
                    QFile::remove(archivePath);
                    completeMarketplaceInstall(completion, false, QStringLiteral("无法启动插件解压器：%1")
                        .arg(extractor->errorString()));
                    extractor->deleteLater();
                });
            connect(extractor, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, extractor, archivePath, plugin, pluginRoot, kStagingPath, completion](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    const QString kDetails = QString::fromLocal8Bit(extractor->readAllStandardError()).trimmed();
                    extractor->deleteLater();
                    QFile::remove(archivePath);
                    if (exitStatus != QProcess::NormalExit || exitCode != 0)
                    {
                        QDir(kStagingPath).removeRecursively();
                        QString message = QStringLiteral("插件包解压失败（退出码 %1）。").arg(exitCode);
                        if (!kDetails.isEmpty()) message += QStringLiteral("\n%1").arg(kDetails);
                        completeMarketplaceInstall(completion, false, message);
                        return;
                    }

                    updateInstallProgress(QStringLiteral("正在验证并替换 %1").arg(plugin.name), 95);
                    QString installError;
                    const bool kInstalled = promoteExtractedPlugin(plugin, pluginRoot, kStagingPath, &installError);
                    QDir(kStagingPath).removeRecursively();
                    if (!kInstalled)
                    {
                        completeMarketplaceInstall(completion, false,
                            QStringLiteral("插件包已验证，但安装被拒绝：%1").arg(installError));
                        return;
                    }
                    refreshPlugins();
                    const QString kMessage = QStringLiteral("已一键安装并验证 %1 到 %2。")
                        .arg(plugin.name, QDir::toNativeSeparators(QDir(pluginRoot).filePath(plugin.installDirectory)));
                    status_->setText(kMessage);
                    updateInstallProgress(QStringLiteral("%1 安装完成").arg(plugin.name), 100);
                    if (!completion)
                    {
                        QMessageBox::information(this, QStringLiteral("插件商城"), QStringLiteral("%1 已安装，可立即从“插件”菜单调用。")
                            .arg(plugin.name));
                    }
                    completeMarketplaceInstall(completion, true, kMessage);
                });
            extractor->start();
        }

        QTableWidget* table_ = nullptr;
        QTableWidget* marketplaceTable_ = nullptr;
        QLabel* status_ = nullptr;
        QProgressBar* installProgress_ = nullptr;
        QCheckBox* autoUpdateCheck_ = nullptr;
        QPushButton* openFolderButton_ = nullptr;
        QNetworkAccessManager* networkManager_ = nullptr;
        QList<PluginDescriptor> plugins_;
        QHash<QString, PluginDescriptor> installedPluginsById_;
        QList<MarketplacePlugin> marketplacePlugins_;
        QList<MarketplacePlugin> autoUpdateQueue_;
        QStringList autoUpdateFailures_;
        int autoUpdateTotal_ = 0;
        int autoUpdateCompleted_ = 0;
        bool autoUpdateInProgress_ = false;
        QString pluginRoot_;
    };
}

void ks::plugin_host::populateTargetMenu(QMenu* menu, QWidget* owner, const InvocationContext& context)
{
    if (menu == nullptr || owner == nullptr) return;
    menu->clear();
    menu->setToolTipsVisible(true);
    QString contextError;
    if (!isUsableContext(context, &contextError))
    {
        QAction* action = menu->addAction(contextError);
        action->setEnabled(false);
        return;
    }
    PluginListResult result;
    QString errorText;
    if (!discoverPlugins(&result, &errorText))
    {
        QAction* action = menu->addAction(QStringLiteral("插件不可用：%1").arg(errorText));
        action->setEnabled(false);
        return;
    }
    const QString kTarget = targetName(context.targetKind);
    int addedActions = 0;
    for (const PluginDescriptor& descriptor : result.plugins)
    {
        if (!descriptor.targets.contains(kTarget)) continue;
        QAction* action = menu->addAction(descriptor.name);
        action->setToolTip(QStringLiteral("%1\nID：%2\n目标：%3")
            .arg(descriptor.description, descriptor.id, descriptor.targets.join(QStringLiteral(", "))));
        QObject::connect(action, &QAction::triggered, owner, [owner, descriptor, context]() {
            launchPlugin(owner, descriptor, context);
        });
        ++addedActions;
    }
    if (addedActions == 0)
    {
        QString emptyText;
        switch (context.targetKind)
        {
        case TargetKind::kFile: emptyText = QStringLiteral("没有声明支持文件目标的插件"); break;
        case TargetKind::kProcess: emptyText = QStringLiteral("没有声明支持进程目标的插件"); break;
        case TargetKind::kNetwork: emptyText = QStringLiteral("没有声明支持网络目标的插件"); break;
        }
        QAction* action = menu->addAction(emptyText);
        action->setEnabled(false);
    }
}

int ks::plugin_host::populateTabPlugins(QTabWidget* tabWidget, QWidget* owner)
{
    if (tabWidget == nullptr || owner == nullptr)
    {
        return 0;
    }
    PluginListResult result;
    QString errorText;
    if (!discoverPlugins(&result, &errorText))
    {
        return 0;
    }
    int addedTabs = 0;
    for (const PluginDescriptor& descriptor : result.plugins)
    {
        if ((descriptor.pluginType != QStringLiteral("tab") &&
             descriptor.pluginType != QStringLiteral("hybrid")) ||
            !descriptor.tabPresentation.enabled ||
            !descriptor.targets.contains(QStringLiteral("tab")))
        {
            continue;
        }
        auto* page = new PluginTabPage(tabWidget, descriptor);
        page->setProperty("kswordPluginId", descriptor.id);
        tabWidget->addTab(
            page,
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            descriptor.tabPresentation.title);
        tabWidget->setTabToolTip(tabWidget->indexOf(page), descriptor.description);
        ++addedTabs;
    }
    return addedTabs;
}

namespace
{
    // hostWindowIsLayered:
    // - Check if the control's top-level window is currently a layered window (WS_EX_LAYERED).
    // Why use this as the criterion instead of reading the backgroundTransparencyEnabled configuration:
    // - Background transparency must be declared before native window creation; if the configuration is changed but
    //   the application has not restarted, the configuration value and the actual window state will be inconsistent.
    // - Whether the Tab plugin can be displayed is actually determined by whether the window is layered at this moment.
    // Input widgetValue: any control attached to the window tree.
    // Return: true if the top-level window has WS_EX_LAYERED; false if undeterminable (treated as available).
    bool hostWindowIsLayered(const QWidget* widgetValue)
    {
        if (widgetValue == nullptr)
        {
            return false;
        }
        const QWidget* topLevelWidget = widgetValue->window();
        if (topLevelWidget == nullptr || !topLevelWidget->isVisible())
        {
            return false;
        }
        const HWND kTopLevelHandle =
            reinterpret_cast<HWND>(const_cast<QWidget*>(topLevelWidget)->winId());
        if (kTopLevelHandle == nullptr || ::IsWindow(kTopLevelHandle) == FALSE)
        {
            return false;
        }
        const LONG_PTR kExtendedStyle = ::GetWindowLongPtrW(kTopLevelHandle, GWL_EXSTYLE);
        return (kExtendedStyle & WS_EX_LAYERED) != 0;
    }

    // PluginContainerShowWatcher:
    // - Callback each time the plugin container is displayed to verify whether the background-transparent alert bar should appear.
    // - The container is often not yet attached to the window tree upon creation; the top-level window handle is only retrievable after it becomes visible.
    // Note: Only override virtual functions without declaring signals/slots, so Q_OBJECT and moc are not required for the build.
    class PluginContainerShowWatcher final : public QObject
    {
    public:
        PluginContainerShowWatcher(QObject* parentObject, std::function<void()> callbackValue)
            : QObject(parentObject)
            , callback_(std::move(callbackValue))
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            if (eventValue->type() == QEvent::Show && callback_)
            {
                callback_();
            }
            return QObject::eventFilter(watchedObject, eventValue);
        }

    private:
        std::function<void()> callback_; // Review callback executed upon display.
    };
}

QWidget* ks::plugin_host::createTabPluginContainer(QWidget* parent)
{
    auto* container = new QWidget(parent);
    container->setObjectName(QStringLiteral("ksTabPluginContainer"));

    auto* rootLayout = new QVBoxLayout(container);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // Background transparency warning banner:
    // The tab plugin's UI is hosted as a native WS_CHILD window from an external process. Windows layered windows (the result of
    // WA_TranslucentBackground combined with FramelessWindowHint) are composited entirely by UpdateLayeredWindow in a single
    // operation, which does not render native child windows. Consequently, the plugin window exists and receives messages but can
    // never be drawn. This is a platform behavior that the style layer cannot circumvent; it can only be reported truthfully.
    auto* transparencyWarningBanner = new QWidget(container);
    transparencyWarningBanner->setObjectName(QStringLiteral("ksTabPluginTransparencyWarning"));
    auto* warningLayout = new QHBoxLayout(transparencyWarningBanner);
    warningLayout->setContentsMargins(10, 6, 10, 6);
    warningLayout->setSpacing(8);
    auto* warningLabel = new QLabel(
        ks::i18n::text(
            QStringLiteral("plugin.tab.transparency.warning"),
            // Write the entire sentence as a single literal: i18n auditing extracts literals word-by-word; splitting lines would
            // break the sentence into two entries, making it impossible to guarantee correct word order during translation.
            QStringLiteral("已开启背景透明：Windows 分层窗口不会绘制插件的原生子窗口，Tab 插件可能无法显示或显示异常。如需使用，请在「设置 → 外观」关闭背景透明后重启程序。")),
        transparencyWarningBanner);
    warningLabel->setObjectName(QStringLiteral("ksTabPluginTransparencyWarningText"));
    warningLabel->setWordWrap(true);
    warningLayout->addWidget(warningLabel, 1);
    transparencyWarningBanner->setVisible(false);
    rootLayout->addWidget(transparencyWarningBanner, 0);

    auto* tabWidget = new QTabWidget(container);
    tabWidget->setObjectName(QStringLiteral("ksTabPluginHost"));
    tabWidget->setDocumentMode(true);
    tabWidget->setMovable(false);
    tabWidget->setTabsClosable(false);
    rootLayout->addWidget(tabWidget, 1);

    // Host-side base styles anchor only to the plugin container, avoiding pollution of other docks or native plugin sub-windows.
    const QString kPluginContainerStyle = QStringLiteral(
        "QWidget#ksTabPluginContainer{background-color:%1;color:%2;}"
        "QTabWidget#ksTabPluginHost::pane{background-color:%1;border:none;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab{background-color:%4;color:%2;border:none;"
        "border-radius:0;padding:3px 12px;min-height:22px;margin:0;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab:selected{background-color:%5;color:%6;font-weight:700;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab:hover:!selected{background-color:%7;}"
        "QWidget#ksTabPluginEmptyState{background-color:%1;color:%2;}"
        "QLabel#ksTabPluginEmptyTitle{color:%2;font-size:16px;font-weight:600;}"
        "QLabel#ksTabPluginEmptyHint{color:%8;}"
        "QPushButton#ksTabPluginManageButton{background-color:%5;color:%6;border:1px solid %5;"
        "border-radius:3px;padding:4px 10px;font-weight:600;}"
        "QPushButton#ksTabPluginManageButton:hover{background-color:%9;border-color:%9;}"
        "QPushButton#ksTabPluginManageButton:pressed{background-color:%10;border-color:%10;}"
        "QWidget#ksTabPluginTransparencyWarning{background-color:%11;border:1px solid %12;"
        "border-radius:3px;margin:6px 6px 0 6px;}"
        "QLabel#ksTabPluginTransparencyWarningText{color:%12;}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::surfaceAltHex())
        .arg(ksword_theme::activeTabBackgroundHex())
        .arg(ksword_theme::activeTabTextHex())
        .arg(ksword_theme::surfaceMutedColorHex())
        .arg(ksword_theme::textSecondaryHex())
        .arg(ksword_theme::primaryBlueSolidHoverHex())
        .arg(ksword_theme::kPrimaryBluePressedHex)
        .arg(ksword_theme::themeColorName(ksword_theme::warningBackgroundColor()))
        .arg(ksword_theme::warningHex());
    container->setStyleSheet(kPluginContainerStyle);

    // The container may not yet be attached to the window tree upon creation; the top-level window handle is unavailable.
    // Defer the check to the next iteration of the event loop and re-verify on each display (remains accurate after switching docks).
    const auto kRefreshTransparencyWarning =
        [container, transparencyWarningBanner]()
        {
            transparencyWarningBanner->setVisible(hostWindowIsLayered(container));
        };
    QTimer::singleShot(0, container, kRefreshTransparencyWarning);
    container->installEventFilter(new PluginContainerShowWatcher(container, kRefreshTransparencyWarning));

    if (populateTabPlugins(tabWidget, container) == 0)
    {
        auto* emptyPage = new QWidget(tabWidget);
        emptyPage->setObjectName(QStringLiteral("ksTabPluginEmptyState"));
        auto* emptyLayout = new QVBoxLayout(emptyPage);
        emptyLayout->setContentsMargins(24, 24, 24, 24);
        emptyLayout->setSpacing(10);
        emptyLayout->addStretch(1);

        auto* titleLabel = new QLabel(
            ks::i18n::text(QStringLiteral("plugin.tab.empty.title"), QStringLiteral("尚未安装 Tab 型插件")),
            emptyPage);
        titleLabel->setObjectName(QStringLiteral("ksTabPluginEmptyTitle"));
        titleLabel->setAlignment(Qt::AlignCenter);
        emptyLayout->addWidget(titleLabel);

        auto* hintLabel = new QLabel(
            ks::i18n::text(
                QStringLiteral("plugin.tab.empty.hint"),
                QStringLiteral("请从插件管理器安装 Tab 型插件，安装完成后重启 KSword。")),
            emptyPage);
        hintLabel->setObjectName(QStringLiteral("ksTabPluginEmptyHint"));
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        emptyLayout->addWidget(hintLabel);

        auto* buttonRow = new QHBoxLayout();
        buttonRow->addStretch(1);
        auto* manageButton = new QPushButton(
            ks::i18n::text(QStringLiteral("plugin.tab.empty.manage"), QStringLiteral("打开插件管理器")),
            emptyPage);
        manageButton->setObjectName(QStringLiteral("ksTabPluginManageButton"));
        buttonRow->addWidget(manageButton);
        buttonRow->addStretch(1);
        emptyLayout->addLayout(buttonRow);
        emptyLayout->addStretch(1);

        QObject::connect(manageButton, &QPushButton::clicked, emptyPage, [emptyPage]() {
            ks::plugin_host::showPluginManager(emptyPage);
        });
        tabWidget->addTab(
            emptyPage,
            ks::i18n::text(QStringLiteral("plugin.tab.empty.overview"), QStringLiteral("概览")));
    }

    return container;
}
void ks::plugin_host::showPluginManager(QWidget* owner)
{
    auto* dialog = new PluginManagerDialog(owner);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}
