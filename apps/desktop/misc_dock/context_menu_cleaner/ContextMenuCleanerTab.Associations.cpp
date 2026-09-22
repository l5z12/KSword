#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QHash>
#include <QSet>
#include <QStringList>

#include <array>
#include <cstddef>
#include <tuple>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // ClassRootDefinition：
    // - Purpose: Unify HKCU/HKLM Software\Classes entries of different bitness into a single traversable array.
    // - Usage: Shared by URL, Open With, and file format context menu enumerators.
    // - Output: does not hold a handle; only stores root key constants, display names, paths, and view flags.
    struct ClassRootDefinition
    {
        HKEY rootKey = nullptr;    // rootKey: Win32 registry root key.
        QString rootLabel;         // rootLabel: Root key name for table display.
        QString classesPath;       // classesPath: Actual location of Software\Classes.
        REGSAM viewFlag = 0;       // viewFlag: HKLM 32/64-bit view flag.
        bool userScope = false;    // userScope: Whether it belongs to the current user overlay.
    };

    // classRoots：
    // - Inputs: None;
    // - Processing: Fixed to return current user, 64-bit global, and 32-bit global Classes entries.
    // - Returns: An array of three items ordered by user priority.
    std::array<ClassRootDefinition, 3> classRoots()
    {
        return {
            ClassRootDefinition{
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                QStringLiteral("Software\\Classes"),
                0,
                true },
            ClassRootDefinition{
                HKEY_LOCAL_MACHINE,
                QStringLiteral("HKLM(64位)"),
                QStringLiteral("Software\\Classes"),
                KEY_WOW64_64KEY,
                false },
            ClassRootDefinition{
                HKEY_LOCAL_MACHINE,
                QStringLiteral("HKLM(32位)"),
                QStringLiteral("Software\\Classes"),
                KEY_WOW64_32KEY,
                false }
        };
    }

    // joinedClassPath：
    // - Input root/classRelativePath: Classes root definition and relative ProgID/extension path;
    // - Processing: Uniformly concatenate to avoid scattered Software\Classes strings across enumerators.
    // - Returns: A full subkey path directly usable by the Win32 registry helper.
    QString joinedClassPath(
        const ClassRootDefinition& root,
        const QString& classRelativePath)
    {
        return QStringLiteral("%1\\%2").arg(root.classesPath, classRelativePath);
    }

    // ClassKeyBranchPresence：
    // - Purpose: Records whether the shell, shellex, or OpenWithProgids branches exist under a Classes association key.
    // - Call: Format right-click menu enumeration uses this to converge multiple RegOpenKeyEx probes for each association key into a single subkey enumeration.
    // - Output: Pure boolean snapshot; holds no registry handles; all three fields are false if the associated key does not exist.
    struct ClassKeyBranchPresence
    {
        bool hasShellBranch = false;           // hasShellBranch: Whether a shell subkey exists.
        bool hasShellExtensionBranch = false;  // hasShellExtensionBranch: Whether the shellex subkey exists.
        bool hasOpenWithProgidsBranch = false; // hasOpenWithProgidsBranch: whether the OpenWithProgids subkey exists.
    };

    // queryMergedClassValue：
    // - Input relativePath/valueName/preferredView: Classes relative path and value name.
    // - Processing: Parse and merge associations sequentially via HKCU, preferred HKLM view, and another HKLM view.
    // - Returns: The first non-null value, suitable for parsing ProgID friendly names and open commands.
    QString queryMergedClassValue(
        const QString& relativePath,
        const QString& valueName,
        const REGSAM preferredView)
    {
        const QString kUserPath = QStringLiteral("Software\\Classes\\%1").arg(relativePath);
        const QString kUserValue = queryRegistryValueText(
            HKEY_CURRENT_USER,
            kUserPath,
            valueName,
            0).value_or(QString());
        if (!kUserValue.trimmed().isEmpty())
        {
            return kUserValue.trimmed();
        }

        // Global fallback:
        // - Use the entry's own view first so a 32-bit association preferentially resolves a 32-bit ProgID;
        // - Check the other view to handle installers where extensions and application registrations are distributed across different views.
        const std::array<REGSAM, 2> kMachineViews = preferredView == KEY_WOW64_32KEY
            ? std::array<REGSAM, 2>{ KEY_WOW64_32KEY, KEY_WOW64_64KEY }
            : std::array<REGSAM, 2>{ KEY_WOW64_64KEY, KEY_WOW64_32KEY };
        for (const REGSAM kViewFlag : kMachineViews)
        {
            const QString kMachineValue = queryRegistryValueText(
                HKEY_LOCAL_MACHINE,
                kUserPath,
                valueName,
                kViewFlag).value_or(QString());
            if (!kMachineValue.trimmed().isEmpty())
            {
                return kMachineValue.trimmed();
            }
        }
        return QString();
    }

    // handlerRelativePath：
    // - Input: handlerName/executableHandler; ProgID or executable name and its type.
    // - Handling: Maps exe to Applications\<exe>, keeps ProgID as-is.
    // - Return: Classes relative path suitable for further concatenation with shell\open\command.
    QString handlerRelativePath(
        const QString& handlerName,
        const bool executableHandler)
    {
        if (executableHandler)
        {
            return QStringLiteral("Applications\\%1").arg(handlerName);
        }
        return handlerName;
    }

    // handlerDisplayName：
    // - Input handlerName/executableHandler/viewFlag: candidate handler identity;
    // - Processing: Read FriendlyAppName or ProgID default description; fall back to original name if missing.
    // - Returns: Contextual display name used in the 'Open with' table.
    QString handlerDisplayName(
        const QString& handlerName,
        const bool executableHandler,
        const REGSAM viewFlag)
    {
        const QString kRelativePath = handlerRelativePath(handlerName, executableHandler);
        const QString kFriendlyName = queryMergedClassValue(
            kRelativePath,
            QStringLiteral("FriendlyAppName"),
            viewFlag);
        const QString kDefaultName = queryMergedClassValue(
            kRelativePath,
            QString(),
            viewFlag);
        return firstNonEmpty({ kFriendlyName, kDefaultName, handlerName });
    }

    // handlerCommand：
    // - Input handlerName/executableHandler/viewFlag: candidate handler identity;
    // - Processing: Read the default value of shell\open\command from handler Classes registration.
    // - Return: The command line used to identify the program target; empty if missing.
    QString handlerCommand(
        const QString& handlerName,
        const bool executableHandler,
        const REGSAM viewFlag)
    {
        const QString kRelativePath = handlerRelativePath(handlerName, executableHandler)
            + QStringLiteral("\\shell\\open\\command");
        return queryMergedClassValue(kRelativePath, QString(), viewFlag);
    }

}

bool ContextMenuCleanerTab::isProtectedUrlBindingEntry(const ContextMenuEntry& entry)
{
    if (entry.area != MenuArea::kUrlBinding
        || entry.rootKey != HKEY_LOCAL_MACHINE
        || entry.deleteKind != DeleteKind::kRegistryTree)
    {
        return false;
    }

    const QString kClassesPrefix = QStringLiteral("Software\\Classes\\");
    if (!entry.subKeyPath.startsWith(kClassesPrefix, Qt::CaseInsensitive))
    {
        return true;
    }
    const QString kSchemeName = entry.subKeyPath.mid(kClassesPrefix.size()).trimmed();
    if (kSchemeName.isEmpty() || kSchemeName.contains('\\'))
    {
        return true;
    }

    // Explicitly override audit reproduction items; ms-* denotes the reserved Windows URI namespace.
    static const QSet<QString> kProtectedSchemes = {
        QStringLiteral("windowsdefender"),
        QStringLiteral("ms-device-enrollment"),
        QStringLiteral("ms-search"),
        QStringLiteral("ms-windows-search"),
        QStringLiteral("ms-actioncenter"),
        QStringLiteral("ms-print-addprinter"),
        QStringLiteral("explorer.zipselection")
    };
    if (kProtectedSchemes.contains(kSchemeName.toLower())
        || kSchemeName.startsWith(QStringLiteral("ms-"), Qt::CaseInsensitive))
    {
        return true;
    }

    const QString kOpenPath = entry.subKeyPath + QStringLiteral("\\shell\\open");
    const QString kCommandPath = kOpenPath + QStringLiteral("\\command");
    if (registryValueExists(
            entry.rootKey,
            entry.subKeyPath,
            QStringLiteral("EditFlags"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            kCommandPath,
            QStringLiteral("DelegateExecute"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            kOpenPath,
            QStringLiteral("PackageId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            kOpenPath,
            QStringLiteral("ActivatableClassId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            kOpenPath,
            QStringLiteral("ContractId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            entry.subKeyPath + QStringLiteral("\\Application"),
            QStringLiteral("AppUserModelId"),
            entry.viewFlag))
    {
        return true;
    }

    return false;
}

// enumerateUrlBindingEntries：
// - Enumerates protocol registrations with URL Protocol values in Classes;
// - Additionally enumerate the current user's UrlAssociations\UserChoice to allow clearing default bindings separately.
// - System/Packaged COM/DelegateExecute protocols are read-only; third-party machine-level protocols retain high-risk deletion capabilities.
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateUrlBindingEntries() const
{
    QVector<ContextMenuEntry> entries;
    for (const ClassRootDefinition& root : classRoots())
    {
        const QStringList kClassNames = enumerateRegistrySubKeys(
            root.rootKey,
            root.classesPath,
            root.viewFlag);
        for (const QString& schemeName : kClassNames)
        {
            if (schemeName.startsWith('.'))
            {
                continue;
            }

            const QString kProtocolPath = joinedClassPath(root, schemeName);
            if (!registryValueExists(
                    root.rootKey,
                    kProtocolPath,
                    QStringLiteral("URL Protocol"),
                    root.viewFlag))
            {
                continue;
            }

            // Single protocol registration:
            // - Default value is typically URL:<Product> Protocol;
            // - The open command is the core evidence for determining system/third-party origins and troubleshooting failed bindings.
            const QString kDisplayName = queryRegistryValueText(
                root.rootKey,
                kProtocolPath,
                QString(),
                root.viewFlag).value_or(QString());
            const QString kCommand = queryRegistryValueText(
                root.rootKey,
                kProtocolPath + QStringLiteral("\\shell\\open\\command"),
                QString(),
                root.viewFlag).value_or(QString());
            const QString kIcon = queryRegistryValueText(
                root.rootKey,
                kProtocolPath + QStringLiteral("\\DefaultIcon"),
                QString(),
                root.viewFlag).value_or(QString());
            ContextMenuEntry entry;
            entry.area = MenuArea::kUrlBinding;
            entry.rootKey = root.rootKey;
            entry.rootLabel = root.rootLabel;
            entry.subKeyPath = kProtocolPath;
            entry.viewFlag = root.viewFlag;
            entry.sourceGroup = root.userScope
                ? QStringLiteral("当前用户协议注册")
                : QStringLiteral("全局协议注册");
            entry.entryKind = QStringLiteral("URL Protocol");
            entry.itemName = schemeName;
            entry.displayName = firstNonEmpty({ kDisplayName, schemeName });
            entry.commandOrHandler = kCommand;
            const bool kProtectedProtocol = isProtectedUrlBindingEntry(entry);
            entry.statusText = kProtectedProtocol
                ? QStringLiteral("系统/封装协议（保护）")
                : (!root.userScope
                    ? QStringLiteral("全局第三方协议（高风险，可删除）")
                    : kCommand.trimmed().isEmpty()
                    ? QStringLiteral("打开命令为空")
                    : QStringLiteral("协议已注册"));
            QStringList details;
            appendOptionalDetail(&details, QStringLiteral("Icon"), kIcon);
            appendOptionalDetail(
                &details,
                QStringLiteral("范围"),
                root.userScope ? QStringLiteral("当前用户") : QStringLiteral("所有用户"));
            entry.detailText = details.join(QStringLiteral("；"));
            entry.canDelete = !kProtectedProtocol;
            entries.push_back(entry);
        }
    }

    // Current default binding:
    // - UserChoice contains a system-generated hash; this page does not attempt to edit ProgId or forge the hash.
    // - Deleting the entire UserChoice only resets that user's choice; Windows will subsequently prompt again or fall back.
    const QString kUserChoiceBase =
        QStringLiteral("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations");
    const QStringList kAssociatedSchemes = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        kUserChoiceBase,
        0);
    for (const QString& schemeName : kAssociatedSchemes)
    {
        const QString kChoicePath = QStringLiteral("%1\\%2\\UserChoice")
            .arg(kUserChoiceBase, schemeName);
        const QString kProgId = queryRegistryValueText(
            HKEY_CURRENT_USER,
            kChoicePath,
            QStringLiteral("ProgId"),
            0).value_or(QString());
        if (kProgId.trimmed().isEmpty())
        {
            continue;
        }

        ContextMenuEntry entry;
        entry.area = MenuArea::kUrlBinding;
        entry.rootKey = HKEY_CURRENT_USER;
        entry.rootLabel = QStringLiteral("HKCU");
        entry.subKeyPath = kChoicePath;
        entry.sourceGroup = QStringLiteral("当前默认 URL 绑定");
        entry.entryKind = QStringLiteral("UserChoice");
        entry.itemName = schemeName;
        entry.displayName = handlerDisplayName(kProgId, false, KEY_WOW64_64KEY);
        entry.commandOrHandler = handlerCommand(kProgId, false, KEY_WOW64_64KEY);
        entry.statusText = QStringLiteral("当前用户默认");
        entry.detailText = QStringLiteral("ProgId=%1；Hash 由 Windows 维护").arg(kProgId);
        entry.canDelete = true;
        entries.push_back(entry);
    }
    return entries;
}

// enumerateOpenWithEntries：
// - Enumerates user history candidates from Explorer\FileExts records;
// - enumerate registered candidates under Classes extensions' OpenWithProgids/OpenWithList.
// - Each row binds to a precise value or application subkey; deletion does not touch the extension's default ProgID or UserChoice.
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateOpenWithEntries() const
{
    QVector<ContextMenuEntry> entries;
    QSet<QString> seenTargets;

    // appendValueEntry：
    // - Input: registry value location, extension, handler identity, and source.
    // - Processing: Parse display names and commands to generate a 'single-value deletion' snapshot.
    // - Output: Appends deduplicated entries to 'entries' to prevent duplicate display of the same target across different scan paths.
    const auto kAppendValueEntry = [&entries, &seenTargets](
        HKEY rootKey,
        const QString& rootLabel,
        const QString& parentPath,
        const REGSAM viewFlag,
        const QString& extensionName,
        const QString& handlerName,
        const QString& valueName,
        const QString& sourceGroup,
        const QString& entryKind,
        const bool executableHandler,
        const bool cleanupMru) {
        if (handlerName.trimmed().isEmpty() || valueName.isEmpty())
        {
            return;
        }
        const QString kTargetIdentity = QStringLiteral("%1|%2|%3")
            .arg(rootLabel, parentPath, valueName)
            .toLower();
        if (seenTargets.contains(kTargetIdentity))
        {
            return;
        }
        seenTargets.insert(kTargetIdentity);

        ContextMenuEntry entry;
        entry.area = MenuArea::kOpenWith;
        entry.rootKey = rootKey;
        entry.rootLabel = rootLabel;
        entry.subKeyPath = parentPath;
        entry.viewFlag = viewFlag;
        entry.sourceGroup = sourceGroup;
        entry.entryKind = entryKind;
        entry.itemName = extensionName;
        entry.displayName = handlerDisplayName(handlerName, executableHandler, viewFlag);
        entry.commandOrHandler = handlerCommand(handlerName, executableHandler, viewFlag);
        entry.statusText = entry.commandOrHandler.trimmed().isEmpty()
            ? QStringLiteral("处理器命令未解析")
            : QStringLiteral("候选处理器");
        entry.detailText = executableHandler
            ? QStringLiteral("应用=%1；值名=%2").arg(handlerName, valueName)
            : QStringLiteral("ProgID=%1；值名=%2").arg(handlerName, valueName);
        entry.deleteKind = DeleteKind::kRegistryValue;
        entry.valueName = valueName;
        entry.cleanupOpenWithMru = cleanupMru;
        entry.canDelete = true;
        entries.push_back(entry);
    };

    // Explorer user history:
    // - The a/b/c values in OpenWithList store exe paths, while MRUList only stores the order and is not displayed separately;
    // - The value name of OpenWithProgids is itself the ProgID; the data is typically empty.
    const QString kExplorerFileExts =
        QStringLiteral("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts");
    const QStringList kUserExtensions = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        kExplorerFileExts,
        0);
    for (const QString& extensionName : kUserExtensions)
    {
        if (!extensionName.startsWith('.'))
        {
            continue;
        }
        const QString kExtensionPath = QStringLiteral("%1\\%2")
            .arg(kExplorerFileExts, extensionName);
        const QString kOpenWithListPath = kExtensionPath + QStringLiteral("\\OpenWithList");
        for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                 HKEY_CURRENT_USER,
                 kOpenWithListPath,
                 0))
        {
            if (value.valueName.compare(
                    QStringLiteral("MRUList"),
                    Qt::CaseInsensitive) == 0)
            {
                continue;
            }
            kAppendValueEntry(
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                kOpenWithListPath,
                0,
                extensionName,
                value.valueText,
                value.valueName,
                QStringLiteral("用户打开历史"),
                QStringLiteral("OpenWithList"),
                true,
                true);
        }

        const QString kOpenWithProgidsPath =
            kExtensionPath + QStringLiteral("\\OpenWithProgids");
        for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                 HKEY_CURRENT_USER,
                 kOpenWithProgidsPath,
                 0))
        {
            kAppendValueEntry(
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                kOpenWithProgidsPath,
                0,
                extensionName,
                value.valueName,
                value.valueName,
                QStringLiteral("用户候选 ProgID"),
                QStringLiteral("OpenWithProgids"),
                false,
                false);
        }
    }

    // Classes candidates:
    // - OpenWithProgids uses named values;
    // - Legacy OpenWithList uses exe name subkeys, so the deletion granularity is a single application subtree.
    for (const ClassRootDefinition& root : classRoots())
    {
        const QStringList kClassNames = enumerateRegistrySubKeys(
            root.rootKey,
            root.classesPath,
            root.viewFlag);
        for (const QString& extensionName : kClassNames)
        {
            if (!extensionName.startsWith('.'))
            {
                continue;
            }
            const QString kExtensionPath = joinedClassPath(root, extensionName);
            const QString kProgidsPath = kExtensionPath + QStringLiteral("\\OpenWithProgids");
            for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                     root.rootKey,
                     kProgidsPath,
                     root.viewFlag))
            {
                kAppendValueEntry(
                    root.rootKey,
                    root.rootLabel,
                    kProgidsPath,
                    root.viewFlag,
                    extensionName,
                    value.valueName,
                    value.valueName,
                    root.userScope
                        ? QStringLiteral("当前用户 Classes")
                        : QStringLiteral("全局 Classes"),
                    QStringLiteral("OpenWithProgids"),
                    false,
                    false);
            }

            const QString kLegacyListPath = kExtensionPath + QStringLiteral("\\OpenWithList");
            const QStringList kApplicationNames = enumerateRegistrySubKeys(
                root.rootKey,
                kLegacyListPath,
                root.viewFlag);
            for (const QString& applicationName : kApplicationNames)
            {
                const QString kApplicationPath = QStringLiteral("%1\\%2")
                    .arg(kLegacyListPath, applicationName);
                const QString kTargetIdentity = QStringLiteral("%1|%2")
                    .arg(root.rootLabel, kApplicationPath)
                    .toLower();
                if (seenTargets.contains(kTargetIdentity))
                {
                    continue;
                }
                seenTargets.insert(kTargetIdentity);

                ContextMenuEntry entry;
                entry.area = MenuArea::kOpenWith;
                entry.rootKey = root.rootKey;
                entry.rootLabel = root.rootLabel;
                entry.subKeyPath = kApplicationPath;
                entry.viewFlag = root.viewFlag;
                entry.sourceGroup = root.userScope
                    ? QStringLiteral("当前用户 Classes")
                    : QStringLiteral("全局 Classes");
                entry.entryKind = QStringLiteral("OpenWithList 子键");
                entry.itemName = extensionName;
                entry.displayName = handlerDisplayName(
                    applicationName,
                    true,
                    root.viewFlag);
                entry.commandOrHandler = handlerCommand(
                    applicationName,
                    true,
                    root.viewFlag);
                entry.statusText = QStringLiteral("旧式候选应用");
                entry.detailText = QStringLiteral("应用=%1").arg(applicationName);
                entry.canDelete = true;
                entries.push_back(entry);
            }
        }
    }
    return entries;
}

} // namespace ks::misc

namespace ks::misc::context_menu_cleaner_detail
{
    // addFormatContextMenuLocations：
    // - Input outputList: The caller's array of scan locations. This function only appends without clearing; returns immediately if null.
    // - Processing: Collect shell/shellex entries for extensions directly, default/candidate
    //   ProgID values, and parent keys of SystemFileAssociations\.ext and PerceivedType.
    // - Return: None. All results are written to outputList.
    //
    // Registry round-trip convergence (this is the heaviest scan on this page; must reduce O(extension × root) RegOpenKeyEx calls):
    // 1) enumerate each of the three Class root-level subkeys and each of the SystemFileAssociations root-level subkeys exactly once; change 'whether
    //    extension/ProgID/perceived type exists at this root' to an in-memory hash lookup, eliminating zero registry round-trips when not found.
    // 2) Note: For each association key, the three branches (shell, shellex, OpenWithProgids) are simultaneously evaluated and cached via a single
    //    subkey enumeration; association keys lacking both shell and shellex (the vast majority of extensions) skip the subsequent 2 enumerations.
    // 3) Regardless of whether a match is found, record the probed menu parent key in probedLocations to
    //    avoid probing the same non-existent location three times across the three sourceRoot iterations.
    void addFormatContextMenuLocations(
        std::vector<RegistryLocationDefinition>* outputList)
    {
        if (outputList == nullptr)
        {
            return;
        }

        const std::array<ClassRootDefinition, 3> kRoots = classRoots();

        // Root-level one-time index:
        // - classesChildNameLists: Original names of first-level subkeys under each root Classes; reused directly in the main loop without re-enumeration.
        // - classesChildNameSets/systemFileAssociationChildNameSets: Lowercase sets of the same names, used for existence lookups.
        // - An empty set indicates the root index is unavailable (enumeration failed or no subkeys exist); subsequent fallback to per-key probing preserves original coverage.
        std::array<QStringList, 3> classesChildNameLists;
        std::array<QSet<QString>, 3> classesChildNameSets;
        std::array<QSet<QString>, 3> systemFileAssociationChildNameSets;
        for (std::size_t rootIndex = 0; rootIndex < kRoots.size(); ++rootIndex)
        {
            const ClassRootDefinition& indexedRoot = kRoots[rootIndex];
            classesChildNameLists[rootIndex] = enumerateRegistrySubKeys(
                indexedRoot.rootKey,
                indexedRoot.classesPath,
                indexedRoot.viewFlag);
            for (const QString& childName : classesChildNameLists[rootIndex])
            {
                classesChildNameSets[rootIndex].insert(childName.toLower());
            }
            if (!classesChildNameSets[rootIndex].contains(
                    QStringLiteral("systemfileassociations")))
            {
                continue;
            }
            const QStringList kAssociationChildNames = enumerateRegistrySubKeys(
                indexedRoot.rootKey,
                joinedClassPath(
                    indexedRoot,
                    QStringLiteral("SystemFileAssociations")),
                indexedRoot.viewFlag);
            for (const QString& childName : kAssociationChildNames)
            {
                systemFileAssociationChildNameSets[rootIndex].insert(childName.toLower());
            }
        }

        // associationKeyMayExist：
        // - Input rootIndex/associationPath: Classes root index and association relative path (extension, ProgID, or SystemFileAssociations\X).
        // - Handling: Determine if the association key might exist using the root-level index; if the index is unavailable, conservatively allow it.
        // - Return: false indicates the key definitely does not exist, allowing the caller to skip all registry round-trips.
        const auto kAssociationKeyMayExist =
            [&classesChildNameSets, &systemFileAssociationChildNameSets](
                const std::size_t rootIndex,
                const QString& associationPath) -> bool
        {
            if (classesChildNameSets[rootIndex].isEmpty())
            {
                return true;
            }
            const qsizetype kSeparatorIndex = associationPath.indexOf('\\');
            const QString kTopLevelName = kSeparatorIndex < 0
                ? associationPath
                : associationPath.left(kSeparatorIndex);
            if (!classesChildNameSets[rootIndex].contains(kTopLevelName.toLower()))
            {
                return false;
            }
            if (kSeparatorIndex < 0)
            {
                return true;
            }
            if (kTopLevelName.compare(
                    QStringLiteral("SystemFileAssociations"),
                    Qt::CaseInsensitive) != 0
                || systemFileAssociationChildNameSets[rootIndex].isEmpty())
            {
                return true;
            }
            const QString kRemainingPath = associationPath.mid(kSeparatorIndex + 1);
            if (kRemainingPath.contains('\\'))
            {
                return true;
            }
            return systemFileAssociationChildNameSets[rootIndex].contains(
                kRemainingPath.toLower());
        };

        // branchPresenceCache：
        // - Key is the lowercase text of 'Root Display Name | Association Relative Path'; value is a snapshot of the branch existence for that association key;
        // - When the same ProgID is referenced by multiple extensions, or the same extension is rescanned by three rounds of sourceRoot, it directly hits the cache.
        QHash<QString, ClassKeyBranchPresence> branchPresenceCache;

        // branchPresenceOf：
        // - Input rootIndex/associationPath: index under Classes root and relative association path;
        // - Processing: First perform a presence table lookup; if necessary, enumerate subkeys once to simultaneously check shell/shellex/OpenWithProgids and write to cache.
        // - Returns: A snapshot of the branch presence for the association key; all three fields are false if the key does not exist or is not enumerable.
        const auto kBranchPresenceOf =
            [&kRoots, &branchPresenceCache, &kAssociationKeyMayExist](
                const std::size_t rootIndex,
                const QString& associationPath) -> ClassKeyBranchPresence
        {
            const ClassRootDefinition& root = kRoots[rootIndex];
            const QString kCacheKey = QStringLiteral("%1|%2")
                .arg(root.rootLabel, associationPath)
                .toLower();
            const auto kCachedIterator = branchPresenceCache.constFind(kCacheKey);
            if (kCachedIterator != branchPresenceCache.constEnd())
            {
                return kCachedIterator.value();
            }

            ClassKeyBranchPresence presence;
            if (kAssociationKeyMayExist(rootIndex, associationPath))
            {
                const QStringList kChildNames = enumerateRegistrySubKeys(
                    root.rootKey,
                    joinedClassPath(root, associationPath),
                    root.viewFlag);
                for (const QString& childName : kChildNames)
                {
                    if (childName.compare(
                            QStringLiteral("shell"),
                            Qt::CaseInsensitive) == 0)
                    {
                        presence.hasShellBranch = true;
                    }
                    else if (childName.compare(
                                 QStringLiteral("shellex"),
                                 Qt::CaseInsensitive) == 0)
                    {
                        presence.hasShellExtensionBranch = true;
                    }
                    else if (childName.compare(
                                 QStringLiteral("OpenWithProgids"),
                                 Qt::CaseInsensitive) == 0)
                    {
                        presence.hasOpenWithProgidsBranch = true;
                    }
                }
            }
            branchPresenceCache.insert(kCacheKey, presence);
            return presence;
        };

        // probedLocations：
        // - Record the identity of menu parent keys that have been probed, rather than those that have been matched.
        // - Non-existent locations are also cached; three rounds of sourceRoot will not repeatedly call RegOpenKeyEx on the same empty location.
        QSet<QString> probedLocations;

        // appendMenuLocations：
        // - Input rootIndex/associationPath/sourceGroup: Classes root index, relative association key, and source description;
        // - Processing: First skip association keys without shell/shellex based on branch snapshots, then only append scan locations for menu parent keys that actually have child items;
        // - Output: No return value; appends each root key/view/path at most once to control large-scale extension scanning results.
        const auto kAppendMenuLocations =
            [outputList, &kRoots, &probedLocations, &kBranchPresenceOf](
                const std::size_t rootIndex,
                const QString& associationPath,
                const QString& sourceGroup)
        {
            const ClassRootDefinition& root = kRoots[rootIndex];
            const ClassKeyBranchPresence kPresence = kBranchPresenceOf(
                rootIndex,
                associationPath);
            if (!kPresence.hasShellBranch && !kPresence.hasShellExtensionBranch)
            {
                return;
            }

            const std::array<std::tuple<QString, QString, bool, bool, bool>, 2> kMenuKinds{
                std::make_tuple(
                    QStringLiteral("shell"),
                    QStringLiteral("shell"),
                    true,
                    false,
                    kPresence.hasShellBranch),
                std::make_tuple(
                    QStringLiteral("shellex\\ContextMenuHandlers"),
                    QStringLiteral("shellex"),
                    false,
                    true,
                    kPresence.hasShellExtensionBranch)
            };
            for (const auto& [pathSuffix, entryKind, shellVerb, shellExtension, branchPresent]
                 : kMenuKinds)
            {
                if (!branchPresent)
                {
                    continue;
                }
                const QString kMenuPath = QStringLiteral("%1\\%2\\%3")
                    .arg(root.classesPath, associationPath, pathSuffix);
                const QString kIdentity = QStringLiteral("%1|%2|%3")
                    .arg(root.rootLabel, kMenuPath)
                    .arg(root.viewFlag)
                    .toLower();
                if (probedLocations.contains(kIdentity))
                {
                    continue;
                }
                probedLocations.insert(kIdentity);
                if (enumerateRegistrySubKeys(
                        root.rootKey,
                        kMenuPath,
                        root.viewFlag).isEmpty())
                {
                    continue;
                }
                outputList->push_back(RegistryLocationDefinition{
                    root.rootKey,
                    root.rootLabel,
                    kMenuPath,
                    root.viewFlag,
                    sourceGroup,
                    entryKind,
                    shellVerb,
                    shellExtension,
                    false });
            }
        };

        // Extension association scan:
        // - Each source root reuses the already enumerated extension list above and reads its default ProgID/OpenWithProgids.
        // - ProgID may be registered in another view or HKLM, so probe the three Classes roots separately (existence check first via table).
        for (std::size_t sourceRootIndex = 0; sourceRootIndex < kRoots.size(); ++sourceRootIndex)
        {
            const ClassRootDefinition& sourceRoot = kRoots[sourceRootIndex];
            for (const QString& extensionName : classesChildNameLists[sourceRootIndex])
            {
                if (!extensionName.startsWith('.'))
                {
                    continue;
                }
                kAppendMenuLocations(
                    sourceRootIndex,
                    extensionName,
                    QStringLiteral("扩展名 %1").arg(extensionName));

                // The .ext branch of SystemFileAssociations does not rely on the default ProgID;
                // Probe at each Classes root to support user overrides and both machine views.
                for (std::size_t targetRootIndex = 0; targetRootIndex < kRoots.size(); ++targetRootIndex)
                {
                    kAppendMenuLocations(
                        targetRootIndex,
                        QStringLiteral("SystemFileAssociations\\%1").arg(extensionName),
                        QStringLiteral("格式关联 %1").arg(extensionName));
                }

                // extensionPresence comes from the cache already populated by the earlier appendMenuLocations call; this is a pure memory hit.
                // Skip one value enumeration when the OpenWithProgids subkey is absent.
                const ClassKeyBranchPresence kExtensionPresence = kBranchPresenceOf(
                    sourceRootIndex,
                    extensionName);
                const QString kExtensionPath = joinedClassPath(
                    sourceRoot,
                    extensionName);
                QStringList progIds;
                const QString kDefaultProgId = queryRegistryValueText(
                    sourceRoot.rootKey,
                    kExtensionPath,
                    QString(),
                    sourceRoot.viewFlag).value_or(QString());
                if (!kDefaultProgId.trimmed().isEmpty())
                {
                    progIds.push_back(kDefaultProgId.trimmed());
                }
                if (kExtensionPresence.hasOpenWithProgidsBranch)
                {
                    const QString kProgidsPath =
                        kExtensionPath + QStringLiteral("\\OpenWithProgids");
                    for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                             sourceRoot.rootKey,
                             kProgidsPath,
                             sourceRoot.viewFlag))
                    {
                        if (!value.valueName.trimmed().isEmpty())
                        {
                            progIds.push_back(value.valueName.trimmed());
                        }
                    }
                }
                progIds.removeDuplicates();

                // ProgID menu:
                // - Probes the real registration location for all Classes roots;
                // - sourceGroup preserves the extension chain to help users understand "which format this menu affects".
                for (const QString& progId : progIds)
                {
                    if (progId.contains('\\') || progId.contains('/'))
                    {
                        continue;
                    }
                    for (std::size_t targetRootIndex = 0; targetRootIndex < kRoots.size(); ++targetRootIndex)
                    {
                        kAppendMenuLocations(
                            targetRootIndex,
                            progId,
                            QStringLiteral("%1 → %2").arg(extensionName, progId));
                    }
                }

                const QString kPerceivedType = queryRegistryValueText(
                    sourceRoot.rootKey,
                    kExtensionPath,
                    QStringLiteral("PerceivedType"),
                    sourceRoot.viewFlag).value_or(QString());
                if (!kPerceivedType.trimmed().isEmpty()
                    && !kPerceivedType.contains('\\')
                    && !kPerceivedType.contains('/'))
                {
                    for (std::size_t targetRootIndex = 0; targetRootIndex < kRoots.size(); ++targetRootIndex)
                    {
                        kAppendMenuLocations(
                            targetRootIndex,
                            QStringLiteral("SystemFileAssociations\\%1")
                                .arg(kPerceivedType.trimmed()),
                            QStringLiteral("%1 感知类型 %2")
                                .arg(extensionName, kPerceivedType.trimmed()));
                    }
                }
            }
        }
    }
}
