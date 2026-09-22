#include "ContextMenuCleanerTab.Internal.h"

#include "../../Theme.h"

#include <QVector>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

#pragma comment(lib, "Advapi32.lib")

namespace ks::misc::context_menu_cleaner_detail
{
    // buildInputStyle：
    // - Inputs: None;
    // - Processing: Reuse project theme color to generate input box style;
    // - Returns: Style text ready for setStyleSheet.
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // buildHeaderStyle：
    // - Inputs: None;
    // - Processing: Generate header styles compatible with light/dark themes.
    // - Returns: Style text applicable to QHeaderView.
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:1px solid %3;"
            "  font-weight:600;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // winErrorText：
    // - Input errorCode: Win32 error code;
    // - Processing: Call FormatMessageW to parse system error text.
    // - Returns: Chinese/system language error text; returns the hexadecimal error code if parsing fails.
    QString winErrorText(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD kCopiedChars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (kCopiedChars > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(kCopiedChars)).trimmed();
            ::LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("Win32 error 0x%1")
                .arg(static_cast<qulonglong>(errorCode), 0, 16)
                .toUpper();
        }
        return messageText;
    }

    // valueNamePointer：
    // - Input valueName: Qt string, null indicates the default value;
    // - Processing: Map default values to nullptr and named values to UTF-16 pointers.
    // - Return: A value name pointer suitable for passing to RegQueryValueExW.
    const wchar_t* valueNamePointer(const QString& valueName)
    {
        return valueName.isNull() ? nullptr : reinterpret_cast<const wchar_t*>(valueName.utf16());
    }

    // trimTrailingNullWide：
    // - Input text: Wide string potentially with trailing NUL;
    // - Processing: Remove one or more trailing NULs common in registry strings;
    // - Returns: A clean string suitable for UI display.
    QString trimTrailingNullWide(std::wstring text)
    {
        while (!text.empty() && text.back() == L'\0')
        {
            text.pop_back();
        }
        return QString::fromStdWString(text).trimmed();
    }

    // registryDataToText：
    // - Input valueType/rawData: Type and raw bytes returned by RegQueryValueExW;
    // - Processing: Convert to short text based on common registry types;
    // - Returns: String used for command/detail column display.
    QString registryDataToText(const DWORD valueType, const std::vector<std::uint8_t>& rawData)
    {
        if (rawData.empty())
        {
            return QString();
        }

        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
        {
            const std::size_t kWcharCount = rawData.size() / sizeof(wchar_t);
            if (kWcharCount == 0)
            {
                return QString();
            }
            const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawData.data());
            QString text = trimTrailingNullWide(std::wstring(textBegin, textBegin + kWcharCount));
            if (valueType == REG_EXPAND_SZ && !text.isEmpty())
            {
                std::vector<wchar_t> expandedBuffer(32768, L'\0');
                const DWORD kCopiedChars = ::ExpandEnvironmentStringsW(
                    reinterpret_cast<const wchar_t*>(text.utf16()),
                    expandedBuffer.data(),
                    static_cast<DWORD>(expandedBuffer.size()));
                if (kCopiedChars > 0 && kCopiedChars < expandedBuffer.size())
                {
                    text = QString::fromWCharArray(expandedBuffer.data()).trimmed();
                }
            }
            return text;
        }

        if (valueType == REG_MULTI_SZ)
        {
            QStringList items;
            const std::size_t kWcharCount = rawData.size() / sizeof(wchar_t);
            const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawData.data());
            std::size_t offset = 0;
            while (offset < kWcharCount)
            {
                const std::size_t kStartOffset = offset;
                while (offset < kWcharCount && textBegin[offset] != L'\0')
                {
                    ++offset;
                }
                if (offset == kStartOffset)
                {
                    break;
                }
                const QString kItem = QString::fromWCharArray(
                    textBegin + kStartOffset,
                    static_cast<int>(offset - kStartOffset)).trimmed();
                if (!kItem.isEmpty())
                {
                    items.push_back(kItem);
                }
                if (offset < kWcharCount)
                {
                    ++offset;
                }
            }
            return items.join(QStringLiteral(" | "));
        }

        if (valueType == REG_DWORD && rawData.size() >= sizeof(DWORD))
        {
            const DWORD kValue = *reinterpret_cast<const DWORD*>(rawData.data());
            return QStringLiteral("%1 (0x%2)")
                .arg(static_cast<qulonglong>(kValue))
                .arg(static_cast<qulonglong>(kValue), 8, 16, QChar('0'))
                .toUpper();
        }

        if (valueType == REG_QWORD && rawData.size() >= sizeof(qulonglong))
        {
            const qulonglong kValue = *reinterpret_cast<const qulonglong*>(rawData.data());
            return QStringLiteral("%1 (0x%2)")
                .arg(kValue)
                .arg(kValue, 16, 16, QChar('0'))
                .toUpper();
        }

        QStringList bytes;
        const int kDisplayCount = std::min<int>(static_cast<int>(rawData.size()), 16);
        for (int i = 0; i < kDisplayCount; ++i)
        {
            bytes.push_back(QStringLiteral("%1").arg(rawData[static_cast<std::size_t>(i)], 2, 16, QChar('0')).toUpper());
        }
        if (rawData.size() > static_cast<std::size_t>(kDisplayCount))
        {
            bytes.push_back(QStringLiteral("...(%1 bytes)").arg(static_cast<qulonglong>(rawData.size())));
        }
        return bytes.join(' ');
    }

    // queryRegistryValueText：
    // - Input: root/subKey/valueName/viewFlag: target registry value location.
    // - Processing: Read the original value and convert it to display text.
    // - Returns: The text value on success; std::nullopt on failure or if the value does not exist.
    std::optional<QString> queryRegistryValueText(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return std::nullopt;
        }

        DWORD valueType = REG_NONE;
        DWORD bufferBytes = 0;
        const LONG kSizeResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            nullptr,
            &bufferBytes);
        if (kSizeResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return std::nullopt;
        }

        std::vector<std::uint8_t> rawData(static_cast<std::size_t>(std::max<DWORD>(bufferBytes, sizeof(wchar_t))));
        const LONG kDataResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            rawData.data(),
            &bufferBytes);
        ::RegCloseKey(openedKey);
        if (kDataResult != ERROR_SUCCESS)
        {
            return std::nullopt;
        }
        rawData.resize(static_cast<std::size_t>(bufferBytes));
        return registryDataToText(valueType, rawData);
    }

    // registryValueExists：
    // - Input: root/subKey/valueName/viewFlag: target registry value location.
    // - Processing: Query only value headers, do not read data content;
    // - Returns: true if the value exists; false otherwise.
    bool registryValueExists(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return false;
        }
        DWORD valueType = REG_NONE;
        const LONG kQueryResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            nullptr,
            nullptr);
        ::RegCloseKey(openedKey);
        return kQueryResult == ERROR_SUCCESS || kQueryResult == ERROR_MORE_DATA;
    }

    // enumerateRegistrySubKeys：
    // - Input: root/subKey/viewFlag - Parent key location;
    // - Processing: enumerate first-level subkey names, ignoring individual items with permission errors.
    // - Returns: list of subkey names; returns an empty list if opening fails.
    QStringList enumerateRegistrySubKeys(HKEY rootKey, const QString& subKeyPath, const REGSAM viewFlag)
    {
        QStringList resultList;
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return resultList;
        }

        DWORD index = 0;
        while (true)
        {
            std::vector<wchar_t> nameBuffer(256, L'\0');
            DWORD nameChars = static_cast<DWORD>(nameBuffer.size());
            FILETIME writeTime{};
            LONG enumResult = ::RegEnumKeyExW(
                openedKey,
                index,
                nameBuffer.data(),
                &nameChars,
                nullptr,
                nullptr,
                nullptr,
                &writeTime);
            if (enumResult == ERROR_MORE_DATA)
            {
                nameBuffer.resize(nameBuffer.size() * 2, L'\0');
                nameChars = static_cast<DWORD>(nameBuffer.size());
                enumResult = ::RegEnumKeyExW(
                    openedKey,
                    index,
                    nameBuffer.data(),
                    &nameChars,
                    nullptr,
                    nullptr,
                    nullptr,
                    &writeTime);
            }
            if (enumResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (enumResult == ERROR_SUCCESS)
            {
                resultList.push_back(QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameChars)));
            }
            ++index;
        }

        ::RegCloseKey(openedKey);
        resultList.sort(Qt::CaseInsensitive);
        return resultList;
    }

    // enumerateRegistryValues：
    // - Input root/subKey/viewFlag: Target registry key and WOW64 view;
    // - Processing: Query maximum name/data size first, then read each value sequentially and convert to displayable text.
    // - Returns: A snapshot sorted case-insensitively by value name; returns an empty array if opening fails.
    QVector<RegistryValueSnapshot> enumerateRegistryValues(
        HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag)
    {
        QVector<RegistryValueSnapshot> resultList;
        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return resultList;
        }

        // Size query:
        // - maxValueNameChars excludes the trailing NUL, so allocate one extra byte.
        // - maxValueDataBytes can be zero; still reserve one byte to prevent data() from being null.
        DWORD valueCount = 0;
        DWORD maxValueNameChars = 0;
        DWORD maxValueDataBytes = 0;
        const LONG kInfoResult = ::RegQueryInfoKeyW(
            openedKey,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &valueCount,
            &maxValueNameChars,
            &maxValueDataBytes,
            nullptr,
            nullptr);
        if (kInfoResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return resultList;
        }

        // Value enumeration:
        // - Reset buffer length each iteration because RegEnumValueW writes back the actual length.
        // - REG_NONE empty data still retains the value name; the 'Open With' ProgID is exactly this common form.
        std::vector<wchar_t> nameBuffer(
            static_cast<std::size_t>(maxValueNameChars) + 2,
            L'\0');
        std::vector<std::uint8_t> dataBuffer(
            static_cast<std::size_t>(std::max<DWORD>(maxValueDataBytes, 1)),
            0);
        for (DWORD valueIndex = 0; valueIndex < valueCount; ++valueIndex)
        {
            DWORD nameChars = static_cast<DWORD>(nameBuffer.size());
            DWORD dataBytes = static_cast<DWORD>(dataBuffer.size());
            DWORD valueType = REG_NONE;
            const LONG kEnumResult = ::RegEnumValueW(
                openedKey,
                valueIndex,
                nameBuffer.data(),
                &nameChars,
                nullptr,
                &valueType,
                dataBuffer.data(),
                &dataBytes);
            if (kEnumResult != ERROR_SUCCESS)
            {
                continue;
            }

            RegistryValueSnapshot snapshot;
            snapshot.valueName = QString::fromWCharArray(
                nameBuffer.data(),
                static_cast<int>(nameChars));
            snapshot.valueType = valueType;
            const std::vector<std::uint8_t> kRawData(
                dataBuffer.begin(),
                dataBuffer.begin() + static_cast<std::ptrdiff_t>(dataBytes));
            snapshot.valueText = registryDataToText(valueType, kRawData);
            resultList.push_back(snapshot);
        }

        ::RegCloseKey(openedKey);
        std::sort(
            resultList.begin(),
            resultList.end(),
            [](const RegistryValueSnapshot& left, const RegistryValueSnapshot& right) {
                return QString::compare(left.valueName, right.valueName, Qt::CaseInsensitive) < 0;
            });
        return resultList;
    }

    // rootPathText：
    // - Input rootLabel/subKeyPath: Display root key and subkey;
    // - Action: Concatenate into a full registry path;
    // - Returns: The path text for the table and clipboard.
    QString rootPathText(const QString& rootLabel, const QString& subKeyPath)
    {
        return QStringLiteral("%1\\%2").arg(rootLabel, subKeyPath);
    }

    // registryTargetPathText：
    // - Inputs: rootLabel, subKeyPath, valueTarget, valueName (components of the deletion target);
    // - Processing: Subtrees follow standard paths; registry values append a clear 'Value' marker.
    // - Returns: A UI/clipboard path that will not be misinterpreted as the exact path of the entire subtree.
    QString registryTargetPathText(
        const QString& rootLabel,
        const QString& subKeyPath,
        const bool valueTarget,
        const QString& valueName)
    {
        const QString kKeyPath = rootPathText(rootLabel, subKeyPath);
        if (!valueTarget)
        {
            return kKeyPath;
        }
        const QString kShownValueName = valueName.isEmpty()
            ? QStringLiteral("(默认)")
            : valueName;
        return QStringLiteral("%1 [值: %2]").arg(kKeyPath, kShownValueName);
    }

    // firstNonEmpty：
    // - Input values: candidate text list;
    // - Processing: Return the first non-empty text in order.
    // - Returns: The first non-empty candidate or an empty string.
    QString firstNonEmpty(const std::initializer_list<QString>& values)
    {
        for (const QString& value : values)
        {
            if (!value.trimmed().isEmpty())
            {
                return value.trimmed();
            }
        }
        return QString();
    }

    // looksLikeClsid：
    // - Input: text string read from the registry.
    // - Handling: Roughly identify CLSIDs in {GUID} format.
    // - Returns: true if the text resembles a CLSID.
    bool looksLikeClsid(const QString& text)
    {
        const QString kTrimmedText = text.trimmed();
        return kTrimmedText.size() >= 38 && kTrimmedText.startsWith('{') && kTrimmedText.endsWith('}');
    }

    // queryClsidValue：
    // - Input clsid/subPath/valueName/viewFlag: CLSID relative path and value name.
    // - Processing: Read the friendly name or Server path under HKCR\CLSID.
    // - Returns: The text if it exists; otherwise, an empty string.
    QString queryClsidValue(
        const QString& clsidText,
        const QString& subPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        if (!looksLikeClsid(clsidText))
        {
            return QString();
        }
        QString path = QStringLiteral("CLSID\\%1").arg(clsidText.trimmed());
        if (!subPath.isEmpty())
        {
            path += QStringLiteral("\\%1").arg(subPath);
        }
        const std::optional<QString> kValue = queryRegistryValueText(
            HKEY_CLASSES_ROOT,
            path,
            valueName,
            viewFlag);
        return kValue.has_value() ? kValue->trimmed() : QString();
    }

    // queryClsidFriendlyName：
    // - Input clsid: COM class identifier;
    // - Processing: Prioritize querying the 64-bit HKCR; if that fails, query the 32-bit HKCR.
    // - Returns: COM friendly name; empty if missing.
    QString queryClsidFriendlyName(const QString& clsidText)
    {
        QString friendlyName = queryClsidValue(clsidText, QString(), QString(), KEY_WOW64_64KEY);
        if (friendlyName.isEmpty())
        {
            friendlyName = queryClsidValue(clsidText, QString(), QString(), KEY_WOW64_32KEY);
        }
        return friendlyName;
    }

    // queryClsidServerPath：
    // - Input clsid: COM class identifier;
    // - Processing: Attempt to read InprocServer32 and LocalServer32.
    // - Returns: Server path or an empty string.
    QString queryClsidServerPath(const QString& clsidText)
    {
        for (const REGSAM kViewFlag : { KEY_WOW64_64KEY, KEY_WOW64_32KEY })
        {
            QString serverPath = queryClsidValue(clsidText, QStringLiteral("InprocServer32"), QString(), kViewFlag);
            if (!serverPath.isEmpty())
            {
                return serverPath;
            }
            serverPath = queryClsidValue(clsidText, QStringLiteral("LocalServer32"), QString(), kViewFlag);
            if (!serverPath.isEmpty())
            {
                return serverPath;
            }
        }
        return QString();
    }

    // appendOptionalDetail：
    // - Input detailList/name/value: Detail list, field name, field value.
    // - Processing: Append name=value only if value is non-empty;
    // - Returns: Nothing.
    void appendOptionalDetail(QStringList* detailList, const QString& name, const QString& value)
    {
        if (detailList == nullptr || value.trimmed().isEmpty())
        {
            return;
        }
        detailList->push_back(QStringLiteral("%1=%2").arg(name, value.trimmed()));
    }

    // deleteRegistryTreeWithView：
    // - Input root/subKeyPath/viewFlag: Registry subtree to be deleted;
    // - Processing: Open the parent key with the specified WOW64 view first, then call RegDeleteTreeW to delete the subkey.
    // - Returns true on success or if the target does not exist; returns false on failure and writes to errorTextOut.
    bool deleteRegistryTreeWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        const QString kTrimmedPath = subKeyPath.trimmed();
        if (kTrimmedPath.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("注册表子键路径为空。");
            }
            return false;
        }

        const int kSlashIndex = kTrimmedPath.lastIndexOf('\\');
        const QString kParentPath = kSlashIndex > 0 ? kTrimmedPath.left(kSlashIndex) : QString();
        const QString kChildName = kSlashIndex > 0 ? kTrimmedPath.mid(kSlashIndex + 1) : kTrimmedPath;
        if (kChildName.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法删除根键或空子键。");
            }
            return false;
        }

        HKEY parentKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            kParentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kParentPath.utf16()),
            0,
            DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
            &parentKey);
        if (kOpenResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (kOpenResult != ERROR_SUCCESS || parentKey == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(kOpenResult));
            }
            return false;
        }

        const LONG kDeleteResult = ::RegDeleteTreeW(
            parentKey,
            reinterpret_cast<const wchar_t*>(kChildName.utf16()));
        ::RegCloseKey(parentKey);
        if (kDeleteResult == ERROR_SUCCESS || kDeleteResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = winErrorText(static_cast<DWORD>(kDeleteResult));
        }
        return false;
    }

    // deleteRegistryValueWithView：
    // - Input root/subKey/valueName/viewFlag/cleanupOpenWithMru: Precise value location and cleanup strategy;
    // - Processing: Delete a single value; if it originates from Explorer's OpenWithList, also remove the corresponding slot letter from the MRUList.
    // - Return: Returns true if the target did not exist or was deleted successfully; returns false on failure and writes the Win32 error.
    bool deleteRegistryValueWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag,
        const bool cleanupOpenWithMru,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (subKeyPath.trimmed().isEmpty() || valueName.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("注册表键路径或值名称为空。");
            }
            return false;
        }

        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
            &openedKey);
        if (kOpenResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (kOpenResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(kOpenResult));
            }
            return false;
        }

        // Delete value:
        // - valueName is always a named value to avoid accidentally deleting the entire OpenWithList/OpenWithProgids key;
        // - Handles non-existent entries idempotently as success, facilitating repeated refreshes or batch operations.
        const LONG kDeleteResult = ::RegDeleteValueW(
            openedKey,
            reinterpret_cast<const wchar_t*>(valueName.utf16()));
        if (kDeleteResult != ERROR_SUCCESS && kDeleteResult != ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(openedKey);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(kDeleteResult));
            }
            return false;
        }

        // MRU fix:
        // - Explorer history lists use slots a/b/c and the MRUList value to store order;
        // - After removing slots, attempt to synchronize strings; do not roll back exact deletions if synchronization fails.
        if (cleanupOpenWithMru)
        {
            DWORD mruType = REG_NONE;
            DWORD mruBytes = 0;
            const LONG kSizeResult = ::RegQueryValueExW(
                openedKey,
                L"MRUList",
                nullptr,
                &mruType,
                nullptr,
                &mruBytes);
            if (kSizeResult == ERROR_SUCCESS && mruType == REG_SZ && mruBytes >= sizeof(wchar_t))
            {
                std::vector<wchar_t> mruBuffer(
                    static_cast<std::size_t>(mruBytes / sizeof(wchar_t)) + 1,
                    L'\0');
                DWORD copiedBytes = mruBytes;
                const LONG kQueryResult = ::RegQueryValueExW(
                    openedKey,
                    L"MRUList",
                    nullptr,
                    &mruType,
                    reinterpret_cast<LPBYTE>(mruBuffer.data()),
                    &copiedBytes);
                if (kQueryResult == ERROR_SUCCESS)
                {
                    QString mruText = QString::fromWCharArray(mruBuffer.data());
                    mruText.remove(valueName, Qt::CaseInsensitive);
                    const DWORD kUpdatedBytes = static_cast<DWORD>(
                        (mruText.size() + 1) * sizeof(wchar_t));
                    (void)::RegSetValueExW(
                        openedKey,
                        L"MRUList",
                        0,
                        REG_SZ,
                        reinterpret_cast<const BYTE*>(mruText.utf16()),
                        kUpdatedBytes);
                }
            }
        }

        ::RegCloseKey(openedKey);
        return true;
    }

    // addUserAndMachineClassLocations：
    // - Inputs: outputList, classesRelativePath, sourceGroup, entryKind, type flags;
    // - Processing: Add scan entries for HKCU\Software\Classes and HKLM 64/32\Software\Classes;
    // - Returns: Nothing.
    void addUserAndMachineClassLocations(
        std::vector<RegistryLocationDefinition>* outputList,
        const QString& classesRelativePath,
        const QString& sourceGroup,
        const QString& entryKind,
        const bool shellVerb,
        const bool shellExtension)
    {
        if (outputList == nullptr)
        {
            return;
        }

        outputList->push_back(RegistryLocationDefinition{
            HKEY_CURRENT_USER,
            QStringLiteral("HKCU"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            0,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(64位)"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            KEY_WOW64_64KEY,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(32位)"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            KEY_WOW64_32KEY,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
    }

    // addIeMenuExtLocations：
    // - Input outputList: Output array for scanned directory entries;
    // - Processing: Add Internet Explorer MenuExt locations under HKCU/HKLM.
    // - Returns: Nothing.
    void addIeMenuExtLocations(std::vector<RegistryLocationDefinition>* outputList)
    {
        if (outputList == nullptr)
        {
            return;
        }
        outputList->push_back(RegistryLocationDefinition{
            HKEY_CURRENT_USER,
            QStringLiteral("HKCU"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            0,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(64位)"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            KEY_WOW64_64KEY,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(32位)"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            KEY_WOW64_32KEY,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
    }
}
