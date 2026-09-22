#pragma once

// ============================================================
// ContextMenuCleanerTab.Internal.h
// Purpose:
// 1) Provide shared column definitions and registry helper declarations for multiple .cpp files in the right-click menu cleanup page;
// 2) Keep the main header file of the QWidget page exposing only control types, without leaking implementation details.
// 3) Avoids exceeding the project's agreed-upon length limit for a single source file.
// ============================================================

#include <QString>
#include <QStringList>
#include <QVector>

#include <initializer_list>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::misc::context_menu_cleaner_detail
{
    // Table column definitions:
    // - Input: All right-click menu category tables share a fixed column order;
    // - Processing: UI rendering, filtering, copying, and deletion all use these constants to locate columns.
    // - Returns: Compile-time integer constant; no runtime return value.
    inline constexpr int kColumnName = 0;
    inline constexpr int kColumnDisplayName = 1;
    inline constexpr int kColumnKind = 2;
    inline constexpr int kColumnSource = 3;
    inline constexpr int kColumnCommandOrHandler = 4;
    inline constexpr int kColumnRegistryPath = 5;
    inline constexpr int kColumnStatus = 6;
    inline constexpr int kColumnDetail = 7;
    inline constexpr int kColumnCount = 8;

    // RegistryLocationDefinition：
    // - Input: Constructed by enumeration logic by category;
    // - Processing: Describe a registry parent key and its resolution type;
    // - Returns: Plain data structure; does not execute logic proactively.
    struct RegistryLocationDefinition
    {
        HKEY rootKey = nullptr;       // rootKey: Actual root key.
        QString rootLabel;            // rootLabel: Root key text for display.
        QString subKeyPath;           // subKeyPath: Parent key path.
        REGSAM viewFlag = 0;          // viewFlag: WOW64 view flag.
        QString sourceGroup;          // sourceGroup: Source category.
        QString entryKind;            // entryKind：shell/shellex/IE MenuExt。
        bool shellVerb = false;       // shellVerb: true indicates the subkey is a shell verb.
        bool shellExtension = false;  // shellExtension: true indicates the subkey is ContextMenuHandlers.
        bool ieMenuExt = false;       // ieMenuExt: true indicates the subkey is an IE MenuExt.
    };

    // RegistryValueSnapshot：
    // - Input: Read from the registry by enumerateRegistryValues.
    // - Processing: Preserve value name, display text, and original type for precise deletion on 'Open With' pages.
    // - Return: Plain data snapshot; does not hold a registry handle.
    struct RegistryValueSnapshot
    {
        QString valueName;       // valueName: Name of the value; defaults to an empty string.
        QString valueText;       // valueText: Converted human-readable data.
        DWORD valueType = REG_NONE; // valueType: Original Win32 registry type.
    };

    // buildInputStyle: Takes no input, generates the themed filter-field style, and returns text ready for setStyleSheet.
    QString buildInputStyle();

    // buildHeaderStyle: Takes no input, generates the themed header style, and returns text ready for setStyleSheet.
    QString buildHeaderStyle();

    // queryRegistryValueText: Input registry location; handles reading and formatting the value; returns text or std::nullopt.
    std::optional<QString> queryRegistryValueText(HKEY rootKey, const QString& subKeyPath, const QString& valueName, REGSAM viewFlag);

    // registryValueExists: Input registry location; handle only probing for value existence; return a boolean indicating existence.
    bool registryValueExists(HKEY rootKey, const QString& subKeyPath, const QString& valueName, REGSAM viewFlag);

    // enumerateRegistrySubKeys: Input parent key location; process enumeration of first-level subkeys; return sorted list of subkey names.
    QStringList enumerateRegistrySubKeys(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag);

    // enumerateRegistryValues: Input parent key location; enumerate all values of the current key; return a snapshot sorted by value name.
    QVector<RegistryValueSnapshot> enumerateRegistryValues(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag);

    // rootPathText: Accepts the display root key and sub-key; processes concatenation of the full path; returns UI/clipboard text.
    QString rootPathText(const QString& rootLabel, const QString& subKeyPath);

    // registryTargetPathText: Input key and value targets; handle concatenation of the precise deletion location; return UI/clipboard text.
    QString registryTargetPathText(
        const QString& rootLabel,
        const QString& subKeyPath,
        bool valueTarget,
        const QString& valueName);

    // firstNonEmpty: Input a list of candidate texts; process to select the first non-empty value; return the non-empty candidate or an empty string.
    QString firstNonEmpty(const std::initializer_list<QString>& values);

    // looksLikeClsid: Input text; performs rough identification of {GUID} format; returns whether it resembles a CLSID.
    bool looksLikeClsid(const QString& text);

    // queryClsidFriendlyName: Input CLSID; queries the friendly name under HKCR\CLSID; returns text or an empty string.
    QString queryClsidFriendlyName(const QString& clsidText);

    // queryClsidServerPath: input CLSID; process queries for InprocServer32/LocalServer32; return text or empty string.
    QString queryClsidServerPath(const QString& clsidText);

    // appendOptionalDetail: Accept detail list and key-value pair; append non-null values; no return value.
    void appendOptionalDetail(QStringList* detailList, const QString& name, const QString& value);

    // winErrorText: accepts a Win32 error code; parses and resolves the system error text; returns a human-readable error message.
    QString winErrorText(DWORD errorCode);

    // deleteRegistryTreeWithView: Input the registry subtree to delete; process deletion according to the specified view; return success boolean and write error text.
    bool deleteRegistryTreeWithView(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag, QString* errorTextOut);

    // deleteRegistryValueWithView: Input the registry value to delete; handles precise deletion and cleans up OpenWith MRU; returns a boolean indicating success.
    bool deleteRegistryValueWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        REGSAM viewFlag,
        bool cleanupOpenWithMru,
        QString* errorTextOut);

    // addUserAndMachineClassLocations: Input is the classes relative path; processes appending HKCU/HKLM 32/64 scan items; no return value.
    void addUserAndMachineClassLocations(
        std::vector<RegistryLocationDefinition>* outputList,
        const QString& classesRelativePath,
        const QString& sourceGroup,
        const QString& entryKind,
        bool shellVerb,
        bool shellExtension);

    // addIeMenuExtLocations: Input is a scan item array; appends common IE MenuExt locations; no return value.
    void addIeMenuExtLocations(std::vector<RegistryLocationDefinition>* outputList);

    // addFormatContextMenuLocations: Input is a scan item array; processes and appends extension/ProgID/SystemFileAssociations menu locations; no return value.
    void addFormatContextMenuLocations(std::vector<RegistryLocationDefinition>* outputList);
}
