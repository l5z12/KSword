#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QDateTime>
#include <QMessageBox>
#include <QUuid>

#include <algorithm>

#pragma comment(lib, "Advapi32.lib")

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    constexpr wchar_t kBackupRootPath[] =
        L"Software\\KSword\\ContextMenuCleaner\\UrlBindingBackups";
    constexpr wchar_t kLastBackupIdValue[] = L"LastBackupId";
    constexpr wchar_t kTargetPathValue[] = L"TargetPath";
    constexpr wchar_t kRootKindValue[] = L"RootKind";
    constexpr wchar_t kViewFlagValue[] = L"ViewFlag";
    constexpr wchar_t kBackupDataKey[] = L"Data";
    constexpr DWORD kRootKindCurrentUser = 1UL;
    constexpr DWORD kRootKindLocalMachine = 2UL;

    // isAllowedUrlBindingPath：
    // - Input rootKey/path: Root key and subkey path prepared for deletion or restoration;
    // - Handling: HKLM accepts only a single-layer Software\Classes protocol; HKCU additionally accepts UserChoice;
    // - Return: true if the path satisfies the minimum scope for the URL binding page.
    bool isAllowedUrlBindingPath(const HKEY rootKey, const QString& path)
    {
        const QString kTrimmedPath = path.trimmed();
        const QString kClassesPrefix = QStringLiteral("Software\\Classes\\");
        if (kTrimmedPath.startsWith(kClassesPrefix, Qt::CaseInsensitive))
        {
            const QString kScheme = kTrimmedPath.mid(kClassesPrefix.size());
            return (rootKey == HKEY_CURRENT_USER || rootKey == HKEY_LOCAL_MACHINE)
                && !kScheme.isEmpty()
                && !kScheme.contains('\\');
        }
        if (rootKey != HKEY_CURRENT_USER)
        {
            return false;
        }

        const QString kUserChoicePrefix =
            QStringLiteral("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\");
        const QString kUserChoiceSuffix = QStringLiteral("\\UserChoice");
        if (!kTrimmedPath.startsWith(kUserChoicePrefix, Qt::CaseInsensitive)
            || !kTrimmedPath.endsWith(kUserChoiceSuffix, Qt::CaseInsensitive))
        {
            return false;
        }

        const QString kScheme = kTrimmedPath.mid(
            kUserChoicePrefix.size(),
            kTrimmedPath.size() - kUserChoicePrefix.size() - kUserChoiceSuffix.size());
        return !kScheme.isEmpty() && !kScheme.contains('\\');
    }

    DWORD backupRootKind(const HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return kRootKindCurrentUser;
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return kRootKindLocalMachine;
        }
        return 0UL;
    }

    HKEY rootKeyFromBackupKind(const DWORD rootKind)
    {
        if (rootKind == kRootKindCurrentUser)
        {
            return HKEY_CURRENT_USER;
        }
        if (rootKind == kRootKindLocalMachine)
        {
            return HKEY_LOCAL_MACHINE;
        }
        return nullptr;
    }

    // isSupportedViewFlag：
    // - Input viewFlag: WOW64 view saved by the entry;
    // - Processing: Reject mixed access permission bits or unknown flags.
    // - Returns: true only for default, 32-bit, or 64-bit views.
    bool isSupportedViewFlag(const REGSAM viewFlag)
    {
        return viewFlag == 0
            || viewFlag == KEY_WOW64_32KEY
            || viewFlag == KEY_WOW64_64KEY;
    }

    // writeStringValue：
    // - Input key/name/value: target registry key, value name, and UTF-16 text.
    // - Processing: Write REG_SZ including the trailing null character;
    // - Returns: Win32 status code.
    LSTATUS writeStringValue(HKEY key, const wchar_t* name, const QString& value)
    {
        const DWORD kByteCount = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        return ::RegSetValueExW(
            key,
            name,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.utf16()),
            kByteCount);
    }

    // readStringValue：
    // - Input: key/name: target key and value name
    // - Processing: Two-stage reading of REG_SZ/REG_EXPAND_SZ;
    // - Return: On success, writes the text and returns ERROR_SUCCESS.
    LSTATUS readStringValue(HKEY key, const wchar_t* name, QString* valueOut)
    {
        if (valueOut == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }
        valueOut->clear();

        DWORD valueType = REG_NONE;
        DWORD byteCount = 0;
        LSTATUS status = ::RegQueryValueExW(
            key,
            name,
            nullptr,
            &valueType,
            nullptr,
            &byteCount);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
        if ((valueType != REG_SZ && valueType != REG_EXPAND_SZ)
            || byteCount < sizeof(wchar_t))
        {
            return ERROR_INVALID_DATA;
        }

        QVector<wchar_t> buffer(
            static_cast<qsizetype>(byteCount / sizeof(wchar_t)) + 1,
            L'\0');
        status = ::RegQueryValueExW(
            key,
            name,
            nullptr,
            &valueType,
            reinterpret_cast<BYTE*>(buffer.data()),
            &byteCount);
        if (status == ERROR_SUCCESS)
        {
            *valueOut = QString::fromWCharArray(buffer.constData()).trimmed();
        }
        return status;
    }

    // cleanupFailedBatch：
    // - Input backupRoot/batchId: unpublished backup batch;
    // Processing: Remove incomplete batches to ensure LastBackupId never points to a partial backup.
    // - Returns: Nothing.
    void cleanupFailedBatch(HKEY backupRoot, const QString& batchId)
    {
        if (backupRoot != nullptr && !batchId.isEmpty())
        {
            (void)::RegDeleteTreeW(
                backupRoot,
                reinterpret_cast<const wchar_t*>(batchId.utf16()));
        }
    }

    // setBackupError：
    // - Input errorTextOut/context/status: Error output, operation description, and Win32 status.
    // - Processing: Generate text identifying the failed stage.
    // - Returns: Nothing.
    void setBackupError(
        QString* errorTextOut,
        const QString& context,
        const LSTATUS status)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("%1：%2")
                .arg(context, winErrorText(static_cast<DWORD>(status)));
        }
    }
}

bool ContextMenuCleanerTab::isUrlBindingDeletionAllowed(const ContextMenuEntry& entry)
{
    return entry.area == MenuArea::kUrlBinding
        && (entry.rootKey == HKEY_CURRENT_USER || entry.rootKey == HKEY_LOCAL_MACHINE)
        && entry.deleteKind == DeleteKind::kRegistryTree
        && isSupportedViewFlag(entry.viewFlag)
        && isAllowedUrlBindingPath(entry.rootKey, entry.subKeyPath)
        && !isProtectedUrlBindingEntry(entry);
}

bool ContextMenuCleanerTab::createUrlBindingBackup(
    const QVector<int>& entryIndexes,
    QString* errorTextOut) const
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (entryIndexes.isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("没有可备份的 URL 绑定项目。");
        }
        return false;
    }

    const AreaWidgets* areaWidgets = widgetsForArea(MenuArea::kUrlBinding);
    if (areaWidgets == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("URL 绑定页面状态不可用。");
        }
        return false;
    }

    HKEY backupRoot = nullptr;
    LSTATUS status = ::RegCreateKeyExW(
        HKEY_CURRENT_USER,
        kBackupRootPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &backupRoot,
        nullptr);
    if (status != ERROR_SUCCESS || backupRoot == nullptr)
    {
        setBackupError(errorTextOut, QStringLiteral("无法创建备份根键"), status);
        return false;
    }

    const QString kBatchId = QStringLiteral("%1-%2")
        .arg(
            QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmsszzz")),
            QUuid::createUuid().toString(QUuid::WithoutBraces));
    HKEY batchKey = nullptr;
    status = ::RegCreateKeyExW(
        backupRoot,
        reinterpret_cast<const wchar_t*>(kBatchId.utf16()),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &batchKey,
        nullptr);
    if (status != ERROR_SUCCESS || batchKey == nullptr)
    {
        setBackupError(errorTextOut, QStringLiteral("无法创建备份批次"), status);
        ::RegCloseKey(backupRoot);
        return false;
    }

    for (int itemIndex = 0; itemIndex < entryIndexes.size(); ++itemIndex)
    {
        const int kEntryIndex = entryIndexes.at(itemIndex);
        if (kEntryIndex < 0 || kEntryIndex >= areaWidgets->entries.size())
        {
            status = ERROR_INVALID_INDEX;
            setBackupError(errorTextOut, QStringLiteral("备份条目下标无效"), status);
            break;
        }

        const ContextMenuEntry& entry = areaWidgets->entries.at(kEntryIndex);
        if (!isUrlBindingDeletionAllowed(entry))
        {
            status = ERROR_ACCESS_DENIED;
            setBackupError(errorTextOut, QStringLiteral("备份安全校验拒绝目标"), status);
            break;
        }

        HKEY sourceKey = nullptr;
        status = ::RegOpenKeyExW(
            entry.rootKey,
            reinterpret_cast<const wchar_t*>(entry.subKeyPath.utf16()),
            0,
            KEY_READ | entry.viewFlag,
            &sourceKey);
        if (status != ERROR_SUCCESS || sourceKey == nullptr)
        {
            setBackupError(
                errorTextOut,
                QStringLiteral("无法打开待备份注册表树 %1").arg(entry.subKeyPath),
                status);
            break;
        }

        const QString kItemName = QStringLiteral("%1").arg(itemIndex, 4, 10, QLatin1Char('0'));
        HKEY itemKey = nullptr;
        status = ::RegCreateKeyExW(
            batchKey,
            reinterpret_cast<const wchar_t*>(kItemName.utf16()),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            nullptr,
            &itemKey,
            nullptr);
        if (status == ERROR_SUCCESS && itemKey != nullptr)
        {
            status = writeStringValue(itemKey, kTargetPathValue, entry.subKeyPath);
        }
        if (status == ERROR_SUCCESS)
        {
            const DWORD kStoredRootKind = backupRootKind(entry.rootKey);
            if (kStoredRootKind == 0UL)
            {
                status = ERROR_INVALID_PARAMETER;
            }
            else
            {
                status = ::RegSetValueExW(
                    itemKey,
                    kRootKindValue,
                    0,
                    REG_DWORD,
                    reinterpret_cast<const BYTE*>(&kStoredRootKind),
                    sizeof(kStoredRootKind));
            }
        }
        if (status == ERROR_SUCCESS)
        {
            const DWORD kStoredViewFlag = static_cast<DWORD>(entry.viewFlag);
            status = ::RegSetValueExW(
                itemKey,
                kViewFlagValue,
                0,
                REG_DWORD,
                reinterpret_cast<const BYTE*>(&kStoredViewFlag),
                sizeof(kStoredViewFlag));
        }

        HKEY dataKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegCreateKeyExW(
                itemKey,
                kBackupDataKey,
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                nullptr,
                &dataKey,
                nullptr);
        }
        if (status == ERROR_SUCCESS && dataKey != nullptr)
        {
            status = ::RegCopyTreeW(sourceKey, nullptr, dataKey);
        }

        if (dataKey != nullptr)
        {
            ::RegCloseKey(dataKey);
        }
        if (itemKey != nullptr)
        {
            ::RegCloseKey(itemKey);
        }
        ::RegCloseKey(sourceKey);

        if (status != ERROR_SUCCESS)
        {
            setBackupError(
                errorTextOut,
                QStringLiteral("复制注册表树 %1 失败").arg(entry.subKeyPath),
                status);
            break;
        }
    }

    if (status == ERROR_SUCCESS)
    {
        status = writeStringValue(backupRoot, kLastBackupIdValue, kBatchId);
        if (status != ERROR_SUCCESS)
        {
            setBackupError(errorTextOut, QStringLiteral("无法发布最近备份索引"), status);
        }
    }

    ::RegCloseKey(batchKey);
    if (status != ERROR_SUCCESS)
    {
        cleanupFailedBatch(backupRoot, kBatchId);
    }
    ::RegCloseKey(backupRoot);
    return status == ERROR_SUCCESS;
}

void ContextMenuCleanerTab::restoreLastUrlBindingBackup()
{
    HKEY backupRoot = nullptr;
    LSTATUS status = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kBackupRootPath,
        0,
        KEY_READ,
        &backupRoot);
    if (status == ERROR_FILE_NOT_FOUND)
    {
        QMessageBox::information(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("当前没有可恢复的 URL 绑定备份。"));
        return;
    }
    if (status != ERROR_SUCCESS || backupRoot == nullptr)
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("无法打开 URL 绑定备份：%1")
                .arg(winErrorText(static_cast<DWORD>(status))));
        return;
    }

    QString batchId;
    status = readStringValue(backupRoot, kLastBackupIdValue, &batchId);
    ::RegCloseKey(backupRoot);
    if (status != ERROR_SUCCESS || batchId.isEmpty())
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("最近备份索引无效：%1")
                .arg(winErrorText(static_cast<DWORD>(status))));
        return;
    }

    const QString kBatchPath = QStringLiteral("%1\\%2")
        .arg(QString::fromWCharArray(kBackupRootPath), batchId);
    const QStringList kItemNames = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        kBatchPath,
        0);
    if (kItemNames.isEmpty())
    {
        QMessageBox::critical(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("最近备份不包含任何注册表树。"));
        return;
    }

    QStringList failedItems;
    int restoredCount = 0;
    for (const QString& itemName : kItemNames)
    {
        const QString kItemPath = QStringLiteral("%1\\%2").arg(kBatchPath, itemName);
        HKEY itemKey = nullptr;
        status = ::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            reinterpret_cast<const wchar_t*>(kItemPath.utf16()),
            0,
            KEY_READ,
            &itemKey);
        QString targetPath;
        DWORD rootKind = kRootKindCurrentUser;
        DWORD viewFlag = 0;
        if (status == ERROR_SUCCESS && itemKey != nullptr)
        {
            status = readStringValue(itemKey, kTargetPathValue, &targetPath);
        }
        if (status == ERROR_SUCCESS)
        {
            DWORD valueType = REG_NONE;
            DWORD byteCount = sizeof(rootKind);
            const LSTATUS kRootKindStatus = ::RegQueryValueExW(
                itemKey,
                kRootKindValue,
                nullptr,
                &valueType,
                reinterpret_cast<BYTE*>(&rootKind),
                &byteCount);
            if (kRootKindStatus != ERROR_SUCCESS
                && kRootKindStatus != ERROR_FILE_NOT_FOUND)
            {
                status = kRootKindStatus;
            }
            else if (kRootKindStatus == ERROR_SUCCESS
                && (valueType != REG_DWORD || byteCount != sizeof(rootKind)))
            {
                status = ERROR_INVALID_DATA;
            }
        }
        if (status == ERROR_SUCCESS)
        {
            DWORD valueType = REG_NONE;
            DWORD byteCount = sizeof(viewFlag);
            status = ::RegQueryValueExW(
                itemKey,
                kViewFlagValue,
                nullptr,
                &valueType,
                reinterpret_cast<BYTE*>(&viewFlag),
                &byteCount);
            if (status == ERROR_SUCCESS
                && (valueType != REG_DWORD || byteCount != sizeof(viewFlag)))
            {
                status = ERROR_INVALID_DATA;
            }
        }
        const HKEY kTargetRootKey = rootKeyFromBackupKind(rootKind);
        if (status == ERROR_SUCCESS
            && (kTargetRootKey == nullptr
                || !isAllowedUrlBindingPath(kTargetRootKey, targetPath)
                || !isSupportedViewFlag(static_cast<REGSAM>(viewFlag))))
        {
            status = ERROR_ACCESS_DENIED;
        }

        HKEY dataKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegOpenKeyExW(
                itemKey,
                kBackupDataKey,
                0,
                KEY_READ,
                &dataKey);
        }

        HKEY targetKey = nullptr;
        if (status == ERROR_SUCCESS)
        {
            status = ::RegCreateKeyExW(
                kTargetRootKey,
                reinterpret_cast<const wchar_t*>(targetPath.utf16()),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | static_cast<REGSAM>(viewFlag),
                nullptr,
                &targetKey,
                nullptr);
        }
        if (status == ERROR_SUCCESS && dataKey != nullptr && targetKey != nullptr)
        {
            status = ::RegCopyTreeW(dataKey, nullptr, targetKey);
        }

        if (targetKey != nullptr)
        {
            ::RegCloseKey(targetKey);
        }
        if (dataKey != nullptr)
        {
            ::RegCloseKey(dataKey);
        }
        if (itemKey != nullptr)
        {
            ::RegCloseKey(itemKey);
        }

        if (status == ERROR_SUCCESS)
        {
            ++restoredCount;
        }
        else
        {
            failedItems.push_back(QStringLiteral("%1：%2")
                .arg(
                    targetPath.isEmpty() ? itemName : targetPath,
                    winErrorText(static_cast<DWORD>(status))));
        }
    }

    refreshArea(MenuArea::kUrlBinding);
    if (failedItems.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("已从最近备份恢复 %1 个 URL 绑定注册表树。").arg(restoredCount));
    }
    else
    {
        QMessageBox::warning(
            this,
            QStringLiteral("恢复 URL 绑定"),
            QStringLiteral("成功恢复 %1 项，失败 %2 项：\n\n%3")
                .arg(restoredCount)
                .arg(failedItems.size())
                .arg(failedItems.join('\n')));
    }
}

} // namespace ks::misc
