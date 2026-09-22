#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateEntriesForArea(const MenuArea area) const
{
    // Association/namespace partition:
    // - These three categories require enumerating registry values or performing third-party judgments, so they use separate implementation files.
    // - The right-click menu formatting still reuses the unified shell/shellex parsing chain below.
    if (area == MenuArea::kUrlBinding)
    {
        return enumerateUrlBindingEntries();
    }
    if (area == MenuArea::kOpenWith)
    {
        return enumerateOpenWithEntries();
    }
    if (area == MenuArea::kExplorerHome)
    {
        return enumerateExplorerHomeEntries();
    }

    std::vector<RegistryLocationDefinition> locations;
    if (area == MenuArea::kInternetExplorer)
    {
        addIeMenuExtLocations(&locations);
    }
    else if (area == MenuArea::kDesktop)
    {
        addUserAndMachineClassLocations(&locations, QStringLiteral("DesktopBackground\\Shell"), QStringLiteral("桌面背景"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("DesktopBackground\\shellex\\ContextMenuHandlers"), QStringLiteral("桌面背景处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\Background\\shell"), QStringLiteral("目录背景"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\Background\\shellex\\ContextMenuHandlers"), QStringLiteral("目录背景处理器"), QStringLiteral("shellex"), false, true);
    }
    else if (area == MenuArea::kFile)
    {
        addUserAndMachineClassLocations(&locations, QStringLiteral("*\\shell"), QStringLiteral("所有文件"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("*\\shellex\\ContextMenuHandlers"), QStringLiteral("所有文件处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("AllFilesystemObjects\\shell"), QStringLiteral("文件系统对象"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("AllFilesystemObjects\\shellex\\ContextMenuHandlers"), QStringLiteral("文件系统对象处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\shell"), QStringLiteral("目录"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\shellex\\ContextMenuHandlers"), QStringLiteral("目录处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Folder\\shell"), QStringLiteral("文件夹"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Folder\\shellex\\ContextMenuHandlers"), QStringLiteral("文件夹处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Drive\\shell"), QStringLiteral("磁盘驱动器"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Drive\\shellex\\ContextMenuHandlers"), QStringLiteral("磁盘驱动器处理器"), QStringLiteral("shellex"), false, true);
    }
    else if (area == MenuArea::kFormatMenu)
    {
        addFormatContextMenuLocations(&locations);
    }

    QVector<ContextMenuEntry> entries;
    for (const RegistryLocationDefinition& location : locations)
    {
        const QStringList kSubKeys = enumerateRegistrySubKeys(location.rootKey, location.subKeyPath, location.viewFlag);
        for (const QString& subKeyName : kSubKeys)
        {
            const QString kFullSubKey = QStringLiteral("%1\\%2").arg(location.subKeyPath, subKeyName);
            ContextMenuEntry entry;
            entry.area = area;
            entry.rootKey = location.rootKey;
            entry.rootLabel = location.rootLabel;
            entry.subKeyPath = kFullSubKey;
            entry.viewFlag = location.viewFlag;
            entry.sourceGroup = location.sourceGroup;
            entry.entryKind = location.entryKind;
            entry.itemName = subKeyName;
            entry.canDelete = true;

            QStringList detailList;
            if (location.ieMenuExt)
            {
                const QString kDefaultCommand = queryRegistryValueText(location.rootKey, kFullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString kContexts = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("Contexts"), location.viewFlag).value_or(QString());
                const QString kFlags = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("Flags"), location.viewFlag).value_or(QString());
                entry.displayName = subKeyName;
                entry.commandOrHandler = kDefaultCommand;
                entry.statusText = kDefaultCommand.trimmed().isEmpty() ? QStringLiteral("命令为空") : QStringLiteral("正常");
                appendOptionalDetail(&detailList, QStringLiteral("Contexts"), kContexts);
                appendOptionalDetail(&detailList, QStringLiteral("Flags"), kFlags);
            }
            else if (location.shellVerb)
            {
                const QString kDefaultName = queryRegistryValueText(location.rootKey, kFullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString kMuiVerb = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("MUIVerb"), location.viewFlag).value_or(QString());
                const QString kIcon = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("Icon"), location.viewFlag).value_or(QString());
                const QString kAppliesTo = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("AppliesTo"), location.viewFlag).value_or(QString());
                const QString kCommand = queryRegistryValueText(location.rootKey, kFullSubKey + QStringLiteral("\\command"), QString(), location.viewFlag).value_or(QString());
                const QString kDelegateExecute = queryRegistryValueText(location.rootKey, kFullSubKey + QStringLiteral("\\command"), QStringLiteral("DelegateExecute"), location.viewFlag).value_or(QString());
                const QString kExplorerCommandHandler = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("ExplorerCommandHandler"), location.viewFlag).value_or(QString());
                const QString kSubCommands = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("SubCommands"), location.viewFlag).value_or(QString());
                const QString kExtendedSubCommandsKey = queryRegistryValueText(location.rootKey, kFullSubKey, QStringLiteral("ExtendedSubCommandsKey"), location.viewFlag).value_or(QString());
                const bool kLegacyDisabled = registryValueExists(location.rootKey, kFullSubKey, QStringLiteral("LegacyDisable"), location.viewFlag);
                const bool kProgrammaticOnly = registryValueExists(location.rootKey, kFullSubKey, QStringLiteral("ProgrammaticAccessOnly"), location.viewFlag);
                const bool kExtendedOnly = registryValueExists(location.rootKey, kFullSubKey, QStringLiteral("Extended"), location.viewFlag);

                entry.displayName = firstNonEmpty({ kMuiVerb, kDefaultName, subKeyName });
                entry.commandOrHandler = firstNonEmpty({ kCommand, kDelegateExecute, kExplorerCommandHandler, kSubCommands, kExtendedSubCommandsKey });
                if (kLegacyDisabled)
                {
                    entry.statusText = QStringLiteral("已禁用(LegacyDisable)");
                }
                else if (kProgrammaticOnly)
                {
                    entry.statusText = QStringLiteral("仅程序访问");
                }
                else if (kExtendedOnly)
                {
                    entry.statusText = QStringLiteral("Shift 扩展菜单");
                }
                else if (entry.commandOrHandler.trimmed().isEmpty())
                {
                    entry.statusText = QStringLiteral("命令为空");
                }
                else
                {
                    entry.statusText = QStringLiteral("正常");
                }
                appendOptionalDetail(&detailList, QStringLiteral("Icon"), kIcon);
                appendOptionalDetail(&detailList, QStringLiteral("AppliesTo"), kAppliesTo);
                appendOptionalDetail(&detailList, QStringLiteral("DelegateExecute"), kDelegateExecute);
                appendOptionalDetail(&detailList, QStringLiteral("ExplorerCommandHandler"), kExplorerCommandHandler);
                appendOptionalDetail(&detailList, QStringLiteral("SubCommands"), kSubCommands);
                appendOptionalDetail(&detailList, QStringLiteral("ExtendedSubCommandsKey"), kExtendedSubCommandsKey);
            }
            else if (location.shellExtension)
            {
                const QString kClsid = queryRegistryValueText(location.rootKey, kFullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString kFriendlyName = queryClsidFriendlyName(kClsid);
                const QString kServerPath = queryClsidServerPath(kClsid);
                entry.clsidText = kClsid;
                entry.displayName = firstNonEmpty({ kFriendlyName, subKeyName });
                entry.commandOrHandler = firstNonEmpty({ kClsid, kServerPath });
                entry.statusText = looksLikeClsid(kClsid) ? QStringLiteral("正常") : QStringLiteral("CLSID 为空/异常");
                appendOptionalDetail(&detailList, QStringLiteral("CLSID"), kClsid);
                appendOptionalDetail(&detailList, QStringLiteral("Server"), kServerPath);
            }

            entry.detailText = detailList.join(QStringLiteral("；"));
            entries.push_back(entry);
        }
    }

    return entries;
}

} // namespace ks::misc
