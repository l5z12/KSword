#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QDir>
#include <QSet>
#include <QStringList>

#include <array>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // NamespaceLocation：
    // - Purpose: Describe a NameSpace container under Explorer Desktop, MyComputer, or HomeFolder;
    // - Invocation: enumerateExplorerHomeEntries enumerates direct CLSID subkeys by location.
    // - Output: Preserves the actual root key/view to ensure deletion and enumeration target the same registry location.
    struct NamespaceLocation
    {
        HKEY rootKey = nullptr;     // rootKey: Win32 root key.
        QString rootLabel;          // rootLabel: Root key text for table display.
        QString parentPath;         // parentPath: Container path where the CLSID subkey resides.
        REGSAM viewFlag = 0;        // viewFlag: 32/64-bit machine view.
        QString sourceGroup;        // sourceGroup: Source description for Home/Desktop/This PC.
        bool userScope = false;     // userScope: third-party registration is more likely at the current user location.
    };

    // knownSystemNamespaceIds：
    // - Inputs: None;
    // - Processing: Centrally maintain common Windows Home, Gallery, Libraries, system folders, and device namespaces.
    // - Return: A set of lowercase CLSIDs used to protect built-in entries, ensuring system components are not handed to the delete button.
    const QSet<QString>& knownSystemNamespaceIds()
    {
        static const QSet<QString> kIds{
            QStringLiteral("{031e4825-7b94-4dc3-b131-e946b44c8dd5}"),
            QStringLiteral("{04731b67-d933-450a-90e6-4acd2e9408fe}"),
            QStringLiteral("{1cf1260c-4dd0-4ebb-811f-33c572699fde}"),
            QStringLiteral("{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"),
            QStringLiteral("{26ee0668-a00a-44d7-9371-beb064c98683}"),
            QStringLiteral("{374de290-123f-4565-9164-39c4925e467b}"),
            QStringLiteral("{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}"),
            QStringLiteral("{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"),
            QStringLiteral("{4336a54d-038b-4685-ab02-99bb52d3fb8b}"),
            QStringLiteral("{450d8fba-ad25-11d0-98a8-0800361b1103}"),
            QStringLiteral("{5399e694-6ce5-4d6c-8fce-1d8870fdcba0}"),
            QStringLiteral("{59031a47-3f72-44a7-89c5-5595fe6b30ee}"),
            QStringLiteral("{645ff040-5081-101b-9f08-00aa002f954e}"),
            QStringLiteral("{a0953c92-50dc-43bf-be83-3742fed03c9c}"),
            QStringLiteral("{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}"),
            QStringLiteral("{b2b4a4d1-2754-4140-a2eb-9a76d9d7cdc6}"),
            QStringLiteral("{b4bfcc3a-db2c-424c-b029-7fe99a87c641}"),
            QStringLiteral("{d3162b92-9365-467a-956b-92703aca08af}"),
            QStringLiteral("{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"),
            QStringLiteral("{f02c1a0d-be21-4350-88b0-7367fc96ef3c}"),
            QStringLiteral("{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"),
            QStringLiteral("{f874310e-b6b7-47dc-bc84-b9e6b38f5903}")
        };
        return kIds;
    }

    // looksLikeWindowsComponent：
    // - Note: Input clsid/default/friendly/server/target: multi-class identity clues for the namespace.
    // - Processing: Identify system/first-party components by combining built-in CLSIDs, the Windows directory, and Microsoft product markers.
    // - Return: true indicates this page is hidden and protected; false allows proceeding to third-party candidate checks.
    bool looksLikeWindowsComponent(
        const QString& clsidText,
        const QString& defaultName,
        const QString& friendlyName,
        const QString& serverPath,
        const QString& targetPath)
    {
        if (knownSystemNamespaceIds().contains(clsidText.trimmed().toLower()))
        {
            return true;
        }

        // Text evidence:
        // - Built-in items heavily use CLSID_* resource identifiers;
        // - OneDrive/Windows/Microsoft are categorized as system or first-party and are not displayed as "third-party programs".
        const QString kCombinedText = QStringList{
            defaultName,
            friendlyName,
            serverPath,
            targetPath }.join('\n').toLower();
        if (kCombinedText.contains(QStringLiteral("clsid_"))
            || kCombinedText.contains(QStringLiteral("microsoft"))
            || kCombinedText.contains(QStringLiteral("windows"))
            || kCombinedText.contains(QStringLiteral("onedrive")))
        {
            return true;
        }
        const QString kNormalizedServer = QDir::fromNativeSeparators(serverPath).toLower();
        return kNormalizedServer.contains(QStringLiteral("/windows/"))
            || kNormalizedServer.contains(QStringLiteral("%systemroot%"))
            || kNormalizedServer.contains(QStringLiteral("%windir%"));
    }

    // shouldExposeThirdPartyNamespace：
    // - Input location and namespace clues;
    // - Processing: User-level non-system items are included directly; machine-level items are included only when there is evidence of non-Windows Server/Target.
    // - Return: Whether to display in the 'Explorer Home Third-Party Programs' page and allow deletion.
    bool shouldExposeThirdPartyNamespace(
        const NamespaceLocation& location,
        const QString& clsidText,
        const QString& defaultName,
        const QString& friendlyName,
        const QString& serverPath,
        const QString& targetPath)
    {
        if (looksLikeWindowsComponent(
                clsidText,
                defaultName,
                friendlyName,
                serverPath,
                targetPath))
        {
            return false;
        }
        if (location.userScope)
        {
            return true;
        }
        return !serverPath.trimmed().isEmpty()
            || !targetPath.trimmed().isEmpty();
    }

    // appendBaseLocations：
    // - Input output/root/rootLabel/view/userScope: array to append and a registry scope;
    // - Processing: Add common containers: Desktop, This PC, HomeFolder, and DelegateFolders.
    // - Output: enumerate based on actual existence later; missing paths naturally return an empty list.
    void appendBaseLocations(
        std::vector<NamespaceLocation>* output,
        HKEY rootKey,
        const QString& rootLabel,
        const REGSAM viewFlag,
        const bool userScope)
    {
        if (output == nullptr)
        {
            return;
        }
        const QString kExplorerBase =
            QStringLiteral("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer");
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            kExplorerBase + QStringLiteral("\\Desktop\\NameSpace"),
            viewFlag,
            QStringLiteral("Explorer 桌面/主页"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            kExplorerBase + QStringLiteral("\\Desktop\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("Explorer 主页委托文件夹"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            kExplorerBase + QStringLiteral("\\MyComputer\\NameSpace"),
            viewFlag,
            QStringLiteral("此电脑命名空间"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            kExplorerBase + QStringLiteral("\\MyComputer\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("此电脑委托文件夹"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            kExplorerBase + QStringLiteral("\\HomeFolder\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("Explorer HomeFolder"),
            userScope });

        // Windows 11 branch:
        // Some versions register Home/Gallery, etc., under Desktop\NameSpace_<build tag>;
        // - Dynamically discover common prefixes to avoid hard-coding specific system build numbers.
        const QString kDesktopPath = kExplorerBase + QStringLiteral("\\Desktop");
        const QStringList kDesktopSubKeys = enumerateRegistrySubKeys(
            rootKey,
            kDesktopPath,
            viewFlag);
        for (const QString& childName : kDesktopSubKeys)
        {
            if (!childName.startsWith(
                    QStringLiteral("NameSpace_"),
                    Qt::CaseInsensitive))
            {
                continue;
            }
            output->push_back(NamespaceLocation{
                rootKey,
                rootLabel,
                QStringLiteral("%1\\%2").arg(kDesktopPath, childName),
                viewFlag,
                QStringLiteral("Windows 11 主页命名空间"),
                userScope });
        }
    }
}

// enumerateExplorerHomeEntries：
// - Displays only third-party or current user-registered Explorer namespaces.
// - Windows built-in CLSIDs, Windows directory Server, and Microsoft/OneDrive components are protected and hidden.
// - The deletion target is a single CLSID subtree within the NameSpace container; the application's own CLSID class registration is not deleted.
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateExplorerHomeEntries() const
{
    std::vector<NamespaceLocation> locations;
    appendBaseLocations(
        &locations,
        HKEY_CURRENT_USER,
        QStringLiteral("HKCU"),
        0,
        true);
    appendBaseLocations(
        &locations,
        HKEY_LOCAL_MACHINE,
        QStringLiteral("HKLM(64位)"),
        KEY_WOW64_64KEY,
        false);
    appendBaseLocations(
        &locations,
        HKEY_LOCAL_MACHINE,
        QStringLiteral("HKLM(32位)"),
        KEY_WOW64_32KEY,
        false);

    QVector<ContextMenuEntry> entries;
    QSet<QString> seenTargets;
    for (const NamespaceLocation& location : locations)
    {
        const QStringList kChildKeys = enumerateRegistrySubKeys(
            location.rootKey,
            location.parentPath,
            location.viewFlag);
        for (const QString& clsidText : kChildKeys)
        {
            if (!looksLikeClsid(clsidText))
            {
                continue;
            }
            const QString kFullSubKey = QStringLiteral("%1\\%2")
                .arg(location.parentPath, clsidText);
            const QString kTargetIdentity = QStringLiteral("%1|%2|%3")
                .arg(location.rootLabel, kFullSubKey)
                .arg(location.viewFlag)
                .toLower();
            if (seenTargets.contains(kTargetIdentity))
            {
                continue;
            }

            // Name and target resolution:
            // - The default value of the NameSpace subkey often stores the product token.
            // - CLSID class registration provides a friendly name, COM Server, or target folder path.
            const QString kDefaultName = queryRegistryValueText(
                location.rootKey,
                kFullSubKey,
                QString(),
                location.viewFlag).value_or(QString());
            const QString kFriendlyName = queryClsidFriendlyName(clsidText);
            const QString kServerPath = queryClsidServerPath(clsidText);
            const QString kClassPath = QStringLiteral("Software\\Classes\\CLSID\\%1")
                .arg(clsidText);
            QString targetPath = queryRegistryValueText(
                HKEY_CURRENT_USER,
                kClassPath + QStringLiteral("\\Instance\\InitPropertyBag"),
                QStringLiteral("TargetFolderPath"),
                0).value_or(QString());
            if (targetPath.trimmed().isEmpty())
            {
                targetPath = queryRegistryValueText(
                    HKEY_LOCAL_MACHINE,
                    kClassPath + QStringLiteral("\\Instance\\InitPropertyBag"),
                    QStringLiteral("TargetFolderPath"),
                    location.viewFlag).value_or(QString());
            }
            if (!shouldExposeThirdPartyNamespace(
                    location,
                    clsidText,
                    kDefaultName,
                    kFriendlyName,
                    kServerPath,
                    targetPath))
            {
                continue;
            }
            seenTargets.insert(kTargetIdentity);

            ContextMenuEntry entry;
            entry.area = MenuArea::kExplorerHome;
            entry.rootKey = location.rootKey;
            entry.rootLabel = location.rootLabel;
            entry.subKeyPath = kFullSubKey;
            entry.viewFlag = location.viewFlag;
            entry.sourceGroup = location.sourceGroup;
            entry.entryKind = QStringLiteral("Explorer NameSpace");
            entry.itemName = clsidText;
            entry.displayName = firstNonEmpty({
                kFriendlyName,
                kDefaultName,
                clsidText });
            entry.commandOrHandler = firstNonEmpty({
                targetPath,
                kServerPath,
                kDefaultName });
            entry.clsidText = clsidText;
            entry.statusText = location.userScope
                ? QStringLiteral("当前用户第三方项")
                : QStringLiteral("全局第三方项");
            QStringList details;
            appendOptionalDetail(&details, QStringLiteral("注册名"), kDefaultName);
            appendOptionalDetail(&details, QStringLiteral("CLSID"), clsidText);
            appendOptionalDetail(&details, QStringLiteral("Server"), kServerPath);
            appendOptionalDetail(&details, QStringLiteral("Target"), targetPath);
            entry.detailText = details.join(QStringLiteral("；"));
            entry.canDelete = true;
            entries.push_back(entry);
        }
    }
    return entries;
}

} // namespace ks::misc
