#include "StartupDock.Internal.h"

#include "../Theme.h"

#include <QPainter>
#include <QPixmap>
#include <QSvgRenderer>


namespace startup_dock_detail
{
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize)
    {
        const QString kIconPath = QString::fromUtf8(resourcePath);
        QSvgRenderer renderer(kIconPath);
        if (!renderer.isValid())
        {
            return QIcon(kIconPath);
        }

        QPixmap pixmap(iconSize);
        pixmap.fill(Qt::transparent);

        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(pixmap.rect(), ksword_theme::primaryBlueColor);
        painter.end();

        return QIcon(pixmap);
    }

    QTableWidgetItem* createReadOnlyItem(const QString& textValue)
    {
        QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
        itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
        itemPointer->setToolTip(textValue);
        return itemPointer;
    }

    QString winErrorText(const DWORD errorCode)
    {
        LPWSTR bufferPointer = nullptr;
        const DWORD kCharCount = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&bufferPointer),
            0,
            nullptr);
        if (kCharCount == 0 || bufferPointer == nullptr)
        {
            return QStringLiteral("Win32Error=%1").arg(errorCode);
        }

        const QString kMessageText = QString::fromWCharArray(bufferPointer).trimmed();
        ::LocalFree(bufferPointer);
        return QStringLiteral("%1 (code=%2)").arg(kMessageText).arg(errorCode);
    }

    QString buildStatusText(const bool enabled)
    {
        return enabled
            ? startupText("startup.value.enabled", QStringLiteral("启用"))
            : startupText("startup.value.disabled", QStringLiteral("禁用"));
    }

    QString buildStatusText(const ks::startup::StartupEntry& entry)
    {
        if (entry.actionKind != ks::startup::StartupActionKind::kScmStartType)
        {
            return buildStatusText(entry.enabled);
        }
        switch (entry.actionLocator.serviceStartMode)
        {
        case ks::startup::StartupScmStartMode::kBoot:
            return startupText("startup.value.scm.boot", QStringLiteral("引导启动"));
        case ks::startup::StartupScmStartMode::kSystem:
            return startupText("startup.value.scm.system", QStringLiteral("系统启动"));
        case ks::startup::StartupScmStartMode::kAutomatic:
            return startupText("startup.value.scm.automatic", QStringLiteral("自动启动"));
        case ks::startup::StartupScmStartMode::kManual:
            return startupText("startup.value.scm.manual", QStringLiteral("手动启动"));
        case ks::startup::StartupScmStartMode::kDisabled:
            return startupText("startup.value.scm.disabled", QStringLiteral("已禁用"));
        case ks::startup::StartupScmStartMode::kNone:
        default:
            return buildStatusText(entry.enabled);
        }
    }

    QString startupRiskReasonText(const ks::startup::StartupEntry& backendEntry)
    {
        QString fallbackText = QString::fromUtf8(
            backendEntry.riskReasonText.c_str(),
            static_cast<qsizetype>(backendEntry.riskReasonText.size())).trimmed();
        if (fallbackText.isEmpty())
        {
            fallbackText = startupText(
                "startup.risk_reason.unspecified",
                QStringLiteral("后端未提供风险说明"));
        }

        if (backendEntry.riskReasonCode.empty())
        {
            return fallbackText;
        }

        const std::string kTranslationKey = "startup.risk_reason." + backendEntry.riskReasonCode;
        return startupText(kTranslationKey.c_str(), fallbackText);
    }

    QString startupLocalizedDetailText(const QString& detailText)
    {
        const QString kTaskStatePrefix = QStringLiteral("状态=");
        const QString kTaskTriggerSeparator = QStringLiteral("；触发器=");
        const QString kTaskDescriptionSeparator = QStringLiteral("；描述=");
        const qsizetype kTriggerIndex = detailText.indexOf(kTaskTriggerSeparator);
        const qsizetype kDescriptionIndex = detailText.indexOf(
            kTaskDescriptionSeparator,
            kTriggerIndex < 0 ? 0 : kTriggerIndex + kTaskTriggerSeparator.size());
        if (detailText.startsWith(kTaskStatePrefix)
            && kTriggerIndex >= kTaskStatePrefix.size()
            && kDescriptionIndex > kTriggerIndex)
        {
            const QString kStateText = detailText.sliced(
                kTaskStatePrefix.size(),
                kTriggerIndex - kTaskStatePrefix.size());
            const qsizetype kTriggerValueStart = kTriggerIndex + kTaskTriggerSeparator.size();
            const QString kTriggerText = detailText.sliced(
                kTriggerValueStart,
                kDescriptionIndex - kTriggerValueStart);
            const QString kDescriptionText = detailText.sliced(
                kDescriptionIndex + kTaskDescriptionSeparator.size());
            return startupText(
                "startup.detail.scheduled_task",
                QStringLiteral("状态：%1；触发器：%2；描述：%3"))
                .arg(kStateText)
                .arg(kTriggerText)
                .arg(kDescriptionText);
        }

        const QString kBackupPrefix = QStringLiteral("KSword 备份=");
        if (detailText.startsWith(kBackupPrefix))
        {
            return startupText(
                "startup.detail.backup_record",
                QStringLiteral("KSword 备份记录：%1"))
                .arg(detailText.sliced(kBackupPrefix.size()));
        }

        const QString kParkingPrefix = QStringLiteral("KSword 暂存=");
        if (detailText.startsWith(kParkingPrefix))
        {
            return startupText(
                "startup.detail.parking_path",
                QStringLiteral("KSword 暂存路径：%1"))
                .arg(detailText.sliced(kParkingPrefix.size()));
        }
        return ks::i18n::sourceText(detailText);
    }

    QStringList parseCsvLine(const QString& csvLineText)
    {
        QStringList fieldList;
        QString currentFieldText;
        bool inQuotes = false;

        for (int index = 0; index < csvLineText.size(); ++index)
        {
            const QChar kCurrentChar = csvLineText.at(index);
            if (kCurrentChar == QChar('"'))
            {
                if (inQuotes && index + 1 < csvLineText.size() && csvLineText.at(index + 1) == QChar('"'))
                {
                    currentFieldText.push_back(QChar('"'));
                    ++index;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
                continue;
            }

            if (!inQuotes && kCurrentChar == QChar(','))
            {
                fieldList.push_back(currentFieldText);
                currentFieldText.clear();
                continue;
            }

            currentFieldText.push_back(kCurrentChar);
        }

        fieldList.push_back(currentFieldText);
        return fieldList;
    }

    namespace
    {
        // fromBackendText:
        // - Convert UTF-8 std::string used by ks::startup back to Qt UI string;
        // - Input textValue: backend text field;
        // - Output QString: for display in tables, trees, or menus.
        QString fromBackendText(const std::string& textValue)
        {
            return QString::fromUtf8(textValue.c_str(), static_cast<int>(textValue.size()));
        }

        // fromBackendCategory:
        // - Map ks::startup::StartupCategory to StartupDock::StartupCategory.
        // - Input category: backend enumeration category.
        // - Output UI layer category enum; unknown values fall back to All.
        StartupDock::StartupCategory fromBackendCategory(const ks::startup::StartupCategory category)
        {
            switch (category)
            {
            case ks::startup::StartupCategory::kAll:
                return StartupDock::StartupCategory::kAll;
            case ks::startup::StartupCategory::kLogon:
                return StartupDock::StartupCategory::kLogon;
            case ks::startup::StartupCategory::kServices:
                return StartupDock::StartupCategory::kServices;
            case ks::startup::StartupCategory::kDrivers:
                return StartupDock::StartupCategory::kDrivers;
            case ks::startup::StartupCategory::kTasks:
                return StartupDock::StartupCategory::kTasks;
            case ks::startup::StartupCategory::kImageHijack:
                return StartupDock::StartupCategory::kImageHijack;
            case ks::startup::StartupCategory::kRegistry:
                return StartupDock::StartupCategory::kRegistry;
            case ks::startup::StartupCategory::kWmi:
                return StartupDock::StartupCategory::kWmi;
            case ks::startup::StartupCategory::kHidden:
                return StartupDock::StartupCategory::kHidden;
            default:
                return StartupDock::StartupCategory::kAll;
            }
        }
    }

    void appendBackendStartupEntries(
        std::vector<StartupDock::StartupEntry>* entryListOut,
        const std::vector<ks::startup::StartupEntry>& backendEntryList)
    {
        if (entryListOut == nullptr)
        {
            return;
        }

        entryListOut->reserve(entryListOut->size() + backendEntryList.size());
        for (const ks::startup::StartupEntry& backendEntry : backendEntryList)
        {
            // Conversion principle:
            // - The backend is responsible only for enumeration and text/boolean fields.
            // - QIcon is left empty; StartupDock::resolveEntryIcon will resolve it on the UI thread later.
            StartupDock::StartupEntry entry;
            entry.backendEntry = backendEntry;
            entry.uniqueIdText = fromBackendText(backendEntry.uniqueIdText);
            entry.category = fromBackendCategory(backendEntry.category);
            entry.categoryText = fromBackendText(backendEntry.categoryText);
            entry.itemNameText = fromBackendText(backendEntry.itemNameText);
            entry.publisherText = fromBackendText(backendEntry.publisherText);
            entry.imagePathText = QDir::toNativeSeparators(fromBackendText(backendEntry.imagePathText));
            entry.commandText = fromBackendText(backendEntry.commandText);
            entry.locationText = QDir::toNativeSeparators(fromBackendText(backendEntry.locationText));
            entry.locationGroupText = QDir::toNativeSeparators(fromBackendText(backendEntry.locationGroupText));
            entry.registryValueNameText = fromBackendText(backendEntry.registryValueNameText);
            entry.userText = fromBackendText(backendEntry.userText);
            entry.detailText = fromBackendText(backendEntry.detailText);
            entry.sourceTypeText = fromBackendText(backendEntry.sourceTypeText);
            entry.enabled = backendEntry.enabled;
            entry.canOpenFileLocation = backendEntry.canOpenFileLocation;
            entry.canOpenRegistryLocation = backendEntry.canOpenRegistryLocation;
            entry.canDelete = backendEntry.canDelete;
            entry.deleteRegistryTree = backendEntry.deleteRegistryTree;
            entryListOut->push_back(std::move(entry));
        }
    }
}
