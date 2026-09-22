#include "RegistryOptimizationPage.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include "../Theme.h"
#include "../ui/TableColumnAutoFit.h"
#include "../../../shared/platform/profile/ProfileJsonLoader.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QOperatingSystemVersion>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSize>
#include <QSizePolicy>
#include <QSplitter>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Shellapi.h>
#include <ShlObj.h>
#include <objbase.h>

namespace
{
    constexpr const char* kOptimizationProfileFileName = "registry_optimization_items.json";
    constexpr int kRoleGroupName = Qt::UserRole + 1;
    constexpr int kItemNameColumn = 0;
    constexpr int kScopeColumn = 1;
    constexpr int kTypeColumn = 2;
    constexpr int kCurrentStateColumn = 3;
    constexpr int kTargetControlColumn = 4;
    constexpr int kActionButtonColumn = 5;
    constexpr int kConditionWarningColumn = 6;
    constexpr int kTargetColumnWidth = 132;
    constexpr int kActionColumnWidth = 82;
    constexpr int kDefaultRowHeight = 30;
    constexpr int kFilterDebounceMs = 200;

    struct VisibleStateRefreshResult
    {
        int tableRow = -1;
        QString stateText;
        QString targetLabel;
        bool targetEnabled = false;
    };

    // jsonString:
    // - Input object/name: JSON object and property name;
    // - Processing: converts scalar JSON values to trimmed QString text;
    // - Return: fallback when the property is missing or unsupported.
    QString jsonString(const QJsonObject& object, const QString& name, const QString& fallback = QString())
    {
        const QJsonValue kValue = object.value(name);
        if (kValue.isString()) return kValue.toString().trimmed();
        if (kValue.isDouble()) return QString::number(kValue.toDouble(), 'f', 0).trimmed();
        if (kValue.isBool()) return kValue.toBool() ? QStringLiteral("True") : QStringLiteral("False");
        return fallback;
    }

    // buildCenteredCellWidget:
    // - Input child/parent: the real editor button/checkbox/combobox and its table parent;
    // - Processing: wraps the child in a transparent QWidget with a centered HBox layout;
    // - Return: container widget for QTableWidget::setCellWidget, while child remains discoverable by findChild.
    QWidget* buildCenteredCellWidget(QWidget* child, QWidget* parent)
    {
        QWidget* container = new QWidget(parent);
        container->setAutoFillBackground(false);
        QHBoxLayout* layout = new QHBoxLayout(container);
        layout->setContentsMargins(4, 1, 4, 1);
        layout->setSpacing(0);
        layout->addStretch(1);
        layout->addWidget(child, 0, Qt::AlignCenter);
        layout->addStretch(1);
        child->setParent(container);
        return container;
    }

    // findTargetComboBox:
    // - Input: Target option cell widget, which may be a direct control or a centered container.
    // - Handling: Attempt direct conversion first; if failed, search for the object by name in child widgets;
    // - Returns the target combo box pointer; nullptr if not found.
    QComboBox* findTargetComboBox(QWidget* cellWidget)
    {
        if (cellWidget == nullptr)
        {
            return nullptr;
        }
        if (QComboBox* comboBox = qobject_cast<QComboBox*>(cellWidget))
        {
            return comboBox;
        }
        return cellWidget->findChild<QComboBox*>(QStringLiteral("optimizationTargetCombo"));
    }

    // findTargetCheckBox:
    // - Input: Target option cell widget, which may be a direct control or a centered container.
    // - Handling: Attempt direct conversion first; if failed, search for the object by name in child widgets;
    // - Returns the target check box pointer; nullptr if not found.
    QCheckBox* findTargetCheckBox(QWidget* cellWidget)
    {
        if (cellWidget == nullptr)
        {
            return nullptr;
        }
        if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(cellWidget))
        {
            return checkBox;
        }
        return cellWidget->findChild<QCheckBox*>(QStringLiteral("optimizationTargetCheck"));
    }

    // jsonInt:
    // - Input object/name: JSON object and property name;
    // - Processing: reads numeric or string integer fields;
    // - Return: fallback on missing/invalid data.
    int jsonInt(const QJsonObject& object, const QString& name, const int fallback = 0)
    {
        const QJsonValue kValue = object.value(name);
        if (kValue.isDouble()) return kValue.toInt(fallback);
        if (kValue.isString())
        {
            bool ok = false;
            const int kParsed = kValue.toString().trimmed().toInt(&ok);
            return ok ? kParsed : fallback;
        }
        return fallback;
    }

    // scopeDisplayText:
    // - Input scopeText: Dism++ scope identifier;
    // - Processing: maps known scope identifiers to Chinese display text;
    // - Return: readable scope name while preserving unknown values.
    QString scopeDisplayText(const QString& scopeText)
    {
        if (scopeText.compare(QStringLiteral("Current"), Qt::CaseInsensitive) == 0) return QStringLiteral("当前用户");
        if (scopeText.compare(QStringLiteral("Default"), Qt::CaseInsensitive) == 0) return QStringLiteral("默认用户");
        if (scopeText.compare(QStringLiteral("System"), Qt::CaseInsensitive) == 0) return QStringLiteral("系统");
        return scopeText.isEmpty() ? QStringLiteral("未指定") : scopeText;
    }

    // trimDefaultValueName:
    // - Input valueName: UI/JSON value name;
    // - Processing: maps empty and "(Default)" to WinAPI default-value nullptr;
    // - Return: normalized registry value name.
    QString trimDefaultValueName(const QString& valueName)
    {
        const QString kTrimmed = valueName.trimmed();
        if (kTrimmed.isEmpty() || kTrimmed == QStringLiteral("(默认)")) return QString();
        return kTrimmed;
    }

    // winErrorText:
    // - Input errorCode: Win32 LSTATUS/GetLastError value;
    // - Processing: formats system error text through FormatMessageW;
    // - Return: localized diagnostic string.
    QString winErrorText(const LONG errorCode)
    {
        wchar_t* buffer = nullptr;
        const DWORD kSize = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            static_cast<DWORD>(errorCode),
            0,
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr);

        QString text = QStringLiteral("错误码 %1").arg(errorCode);
        if (kSize > 0 && buffer != nullptr)
        {
            text += QStringLiteral(": ") + QString::fromWCharArray(buffer, static_cast<int>(kSize)).trimmed();
        }
        if (buffer != nullptr) ::LocalFree(buffer);
        return text;
    }

    // parseRegistryPath:
    // - Input pathText: HKEY_* or HK* registry path;
    // - Processing: normalizes separators and resolves the root HKEY;
    // - Return: true with root/subpath on valid input, false otherwise.
    bool parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut)
    {
        if (rootKeyOut == nullptr || subPathOut == nullptr) return false;

        QString text = pathText.trimmed();
        text.replace('/', '\\');
        while (text.contains(QStringLiteral("\\\\"))) text.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        if (text.endsWith('\\')) text.chop(1);
        if (text.isEmpty()) return false;

        const int kSplitIndex = text.indexOf('\\');
        const QString kRootText = kSplitIndex < 0 ? text : text.left(kSplitIndex);
        const QString kSubPath = kSplitIndex < 0 ? QString() : text.mid(kSplitIndex + 1);

        struct RootName
        {
            const wchar_t* fullName;
            const wchar_t* shortName;
            HKEY root;
        };
        static const std::array<RootName, 5> kRootNames{ {
            { L"HKEY_CLASSES_ROOT", L"HKCR", HKEY_CLASSES_ROOT },
            { L"HKEY_CURRENT_USER", L"HKCU", HKEY_CURRENT_USER },
            { L"HKEY_LOCAL_MACHINE", L"HKLM", HKEY_LOCAL_MACHINE },
            { L"HKEY_USERS", L"HKU", HKEY_USERS },
            { L"HKEY_CURRENT_CONFIG", L"HKCC", HKEY_CURRENT_CONFIG },
        } };

        for (const RootName& entry : kRootNames)
        {
            if (kRootText.compare(QString::fromWCharArray(entry.fullName), Qt::CaseInsensitive) == 0 ||
                kRootText.compare(QString::fromWCharArray(entry.shortName), Qt::CaseInsensitive) == 0)
            {
                *rootKeyOut = entry.root;
                *subPathOut = kSubPath;
                return true;
            }
        }
        return false;
    }

    // actionRegistryViewFlags:
    // - Input actionObject: one action JSON object;
    // - Processing: maps Wow64=True to KEY_WOW64_32KEY for 32-bit registry view operations;
    // - Return: extra REGSAM flags to OR into RegOpen/Create access masks.
    REGSAM actionRegistryViewFlags(const QJsonObject& actionObject)
    {
        const QString kWow64Text = jsonString(actionObject, QStringLiteral("Wow64"));
        return kWow64Text.compare(QStringLiteral("True"), Qt::CaseInsensitive) == 0 ? KEY_WOW64_32KEY : 0;
    }

    // parseRegistryType:
    // - Input typeText: REG_* string from JSON;
    // - Processing: maps supported registry types to WinAPI constants;
    // - Return: true when type is supported and stored in typeOut.
    bool parseRegistryType(const QString& typeText, DWORD* typeOut)
    {
        if (typeOut == nullptr) return false;
        const QString kNormalized = typeText.trimmed().toUpper();
        if (kNormalized == QStringLiteral("REG_SZ")) { *typeOut = REG_SZ; return true; }
        if (kNormalized == QStringLiteral("REG_EXPAND_SZ")) { *typeOut = REG_EXPAND_SZ; return true; }
        if (kNormalized == QStringLiteral("REG_BINARY")) { *typeOut = REG_BINARY; return true; }
        if (kNormalized == QStringLiteral("REG_DWORD")) { *typeOut = REG_DWORD; return true; }
        if (kNormalized == QStringLiteral("REG_QWORD")) { *typeOut = REG_QWORD; return true; }
        if (kNormalized == QStringLiteral("REG_MULTI_SZ")) { *typeOut = REG_MULTI_SZ; return true; }
        if (kNormalized == QStringLiteral("REG_NONE")) { *typeOut = REG_NONE; return true; }
        return false;
    }

    // parseHexInteger:
    // - Input text: Dism++ numeric text, usually hex without 0x for DWORD/QWORD;
    // - Processing: strips whitespace and parses base 16 unless 0x is present;
    // - Return: true and parsed value when valid.
    bool parseHexInteger(const QString& text, quint64* valueOut)
    {
        if (valueOut == nullptr) return false;
        QString normalized = text.trimmed();
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
        }
        bool ok = false;
        const quint64 kValue = normalized.toULongLong(&ok, 16);
        if (!ok) return false;
        *valueOut = kValue;
        return true;
    }

    // kExplorerBroadcastTimeoutMs：
    // - Purpose: Maximum response timeout (in milliseconds) for each top-level window during HWND_BROADCAST.
    // - Note: Broadcasts are now executed on a background thread; timeouts only affect that thread and no longer freeze the UI.
    constexpr UINT kExplorerBroadcastTimeoutMs = 1500;

    // kStateApplyGenerationProperty：
    // - Purpose: Generation of the optimization action sequence, attached as a dynamic property on the page object;
    // - Note: When broadcasting back to the UI thread in the background, compare generation numbers to prevent pushing expired results into the new application sequence.
    constexpr const char* kStateApplyGenerationProperty = "kswordStateApplyGeneration";

    // ExplorerNotifyOutcome：
    // - Purpose: Pure value-type object carrying the execution result of an ExplorerNotify broadcast, safe for cross-thread return;
    // - Parameters: None;
    // - Returns: None. succeeded indicates whether the action executed successfully; errorTextValue contains the failure reason.
    struct ExplorerNotifyOutcome
    {
        bool succeeded = false;     // Whether the broadcast action executed successfully.
        QString errorTextValue;     // Error text; empty on success.
    };

    // actionUsesBlockingBroadcast：
    // - Purpose: Determine if the action belongs to an ExplorerNotify broadcast (AssocChanged / Custom) that blocks the calling thread.
    // - Input actionObject: JSON object for a single optimization action;
    // - Return: true indicates the action must be executed on a background thread; otherwise, the UI will be blocked by the top-level window's response timeout.
    bool actionUsesBlockingBroadcast(const QJsonObject& actionObject)
    {
        const QString kFamilyText = jsonString(actionObject, QStringLiteral("action_family"),
            jsonString(actionObject, QStringLiteral("action_tag"))).trimmed();
        if (kFamilyText.compare(QStringLiteral("ExplorerNotify"), Qt::CaseInsensitive) != 0)
        {
            return false;
        }

        const QString kTypeText = jsonString(actionObject, QStringLiteral("Type"));
        return kTypeText.compare(QStringLiteral("AssocChanged"), Qt::CaseInsensitive) == 0 ||
            kTypeText.compare(QStringLiteral("Custom"), Qt::CaseInsensitive) == 0;
    }

    // runExplorerNotifyBroadcast：
    // - Purpose: Actually execute the ExplorerNotify shell notification and top-level window broadcast; the calling thread will be blocked.
    // - Input actionObject: A single ExplorerNotify action;
    //         initializeComApartment: Whether this thread needs to initialize the COM apartment independently (background threads must pass true);
    // - Return: Execution result value object. Throughout, only Win32/Shell APIs are used; no QWidget is touched.
    ExplorerNotifyOutcome runExplorerNotifyBroadcast(const QJsonObject& actionObject, const bool initializeComApartment)
    {
        ExplorerNotifyOutcome outcome;
        const QString kTypeText = jsonString(actionObject, QStringLiteral("Type"));

        if (kTypeText.compare(QStringLiteral("AssocChanged"), Qt::CaseInsensitive) == 0)
        {
            bool comApartmentInitialized = false;
            if (initializeComApartment)
            {
                comApartmentInitialized = SUCCEEDED(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED));
            }
            ::SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
            if (comApartmentInitialized)
            {
                ::CoUninitialize();
            }
            outcome.succeeded = true;
            return outcome;
        }

        if (kTypeText.compare(QStringLiteral("Custom"), Qt::CaseInsensitive) == 0)
        {
            quint64 messageValue = 0;
            quint64 wParamValue = 0;
            const bool kMessageOk = parseHexInteger(jsonString(actionObject, QStringLiteral("msg")), &messageValue);
            parseHexInteger(jsonString(actionObject, QStringLiteral("wParam"), QStringLiteral("0")), &wParamValue);
            if (!kMessageOk)
            {
                outcome.errorTextValue = QStringLiteral("ExplorerNotify Custom 缺少有效 msg。");
                return outcome;
            }

            const QString kLParamText = jsonString(actionObject, QStringLiteral("lParam"));
            const QByteArray kLParamUtf16 = QByteArray(
                reinterpret_cast<const char*>(kLParamText.utf16()),
                (kLParamText.size() + 1) * static_cast<int>(sizeof(wchar_t)));
            DWORD_PTR sendResult = 0;
            ::SendMessageTimeoutW(
                HWND_BROADCAST,
                static_cast<UINT>(messageValue),
                static_cast<WPARAM>(wParamValue),
                kLParamText.isEmpty() ? 0 : reinterpret_cast<LPARAM>(kLParamUtf16.constData()),
                SMTO_ABORTIFHUNG,
                kExplorerBroadcastTimeoutMs,
                &sendResult);
            outcome.succeeded = true;
            return outcome;
        }

        outcome.errorTextValue = QStringLiteral("暂不支持 ExplorerNotify 类型：%1").arg(kTypeText);
        return outcome;
    }

    // hexStringToBytes:
    // - Input text: contiguous or separated hex byte string;
    // - Processing: removes non-hex separators and converts pairs to bytes;
    // - Return: true with raw bytes when input has even hex length.
    bool hexStringToBytes(const QString& text, QByteArray* bytesOut)
    {
        if (bytesOut == nullptr) return false;
        QString hexText = text.trimmed();
        hexText.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
        if (hexText.isEmpty())
        {
            bytesOut->clear();
            return true;
        }
        if ((hexText.size() % 2) != 0)
        {
            hexText.prepend(QLatin1Char('0'));
        }
        QByteArray output;
        output.reserve(hexText.size() / 2);
        for (int index = 0; index < hexText.size(); index += 2)
        {
            bool ok = false;
            const unsigned int kByteValue = hexText.mid(index, 2).toUInt(&ok, 16);
            if (!ok) return false;
            output.append(static_cast<char>(kByteValue & 0xFFU));
        }
        *bytesOut = output;
        return true;
    }

    // writeUnsignedLittleEndian:
    // - Input value/byteCount: integer value and output width;
    // - Processing: serializes to Windows little-endian registry byte order;
    // - Return: QByteArray containing byteCount bytes.
    QByteArray writeUnsignedLittleEndian(const quint64 value, const int byteCount)
    {
        QByteArray output(byteCount, 0);
        for (int index = 0; index < byteCount; ++index)
        {
            output[index] = static_cast<char>((value >> (index * 8)) & 0xFFU);
        }
        return output;
    }

    // readUnsignedLittleEndian:
    // - Input bytes/byteCount: raw registry data and number of bytes to consume;
    // - Processing: decodes little-endian unsigned integer;
    // - Return: decoded value, or 0 when data is shorter than requested.
    quint64 readUnsignedLittleEndian(const QByteArray& bytes, const int byteCount)
    {
        if (bytes.size() < byteCount) return 0;
        quint64 value = 0;
        for (int index = 0; index < byteCount; ++index)
        {
            value |= (static_cast<quint64>(static_cast<unsigned char>(bytes.at(index))) << (index * 8));
        }
        return value;
    }

    // stringToUtf16RegistryData:
    // - Input text: REG_SZ/REG_EXPAND_SZ text;
    // - Processing: stores UTF-16LE including trailing NUL;
    // - Return: raw registry data.
    QByteArray stringToUtf16RegistryData(const QString& text)
    {
        QByteArray output;
        output.resize((text.size() + 1) * static_cast<int>(sizeof(wchar_t)));
        if (!text.isEmpty())
        {
            std::memcpy(output.data(), text.utf16(), text.size() * static_cast<int>(sizeof(wchar_t)));
        }
        output[output.size() - 2] = '\0';
        output[output.size() - 1] = '\0';
        return output;
    }

    // registryDataFromJsonText:
    // - Input type/dataText: registry type and Dism++ Data text;
    // - Processing: converts JSON text into raw WinAPI data bytes;
    // - Return: true on supported conversion, false with errorTextOut otherwise.
    bool registryDataFromJsonText(
        const DWORD type,
        const QString& dataText,
        QByteArray* rawDataOut,
        QString* errorTextOut)
    {
        if (rawDataOut == nullptr) return false;
        rawDataOut->clear();
        if (errorTextOut != nullptr) errorTextOut->clear();

        if (type == REG_DWORD)
        {
            quint64 value = 0;
            if (!parseHexInteger(dataText, &value) || value > 0xFFFFFFFFULL)
            {
                if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("REG_DWORD 数据不是有效十六进制数：%1").arg(dataText);
                return false;
            }
            *rawDataOut = writeUnsignedLittleEndian(value, 4);
            return true;
        }
        if (type == REG_QWORD)
        {
            quint64 value = 0;
            if (!parseHexInteger(dataText, &value))
            {
                if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("REG_QWORD 数据不是有效十六进制数：%1").arg(dataText);
                return false;
            }
            *rawDataOut = writeUnsignedLittleEndian(value, 8);
            return true;
        }
        if (type == REG_BINARY || type == REG_NONE)
        {
            if (!hexStringToBytes(dataText, rawDataOut))
            {
                if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("REG_BINARY 数据不是有效十六进制字节串：%1").arg(dataText);
                return false;
            }
            return true;
        }
        if (type == REG_SZ || type == REG_EXPAND_SZ)
        {
            *rawDataOut = stringToUtf16RegistryData(dataText);
            return true;
        }
        if (type == REG_MULTI_SZ)
        {
            const QStringList kLines = dataText.split(QLatin1Char('|'), Qt::SkipEmptyParts);
            QByteArray output;
            for (const QString& line : kLines)
            {
                const QByteArray kOne = stringToUtf16RegistryData(line.trimmed());
                output.append(kOne.constData(), kOne.size() - static_cast<int>(sizeof(wchar_t)));
            }
            output.append('\0');
            output.append('\0');
            *rawDataOut = output;
            return true;
        }

        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("暂不支持写入注册表类型：%1").arg(type);
        return false;
    }

    // readRegistryValue:
    // - Input keyPath/valueName/accessFlags: registry key, value, and view flags;
    // - Processing: opens the key and queries the raw value;
    // - Return: true with type/data when the value exists and can be read.
    bool readRegistryValue(
        const QString& keyPath,
        const QString& valueName,
        const REGSAM accessFlags,
        DWORD* typeOut,
        QByteArray* dataOut,
        QString* errorTextOut)
    {
        if (typeOut == nullptr || dataOut == nullptr) return false;
        if (errorTextOut != nullptr) errorTextOut->clear();

        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(keyPath, &root, &subPath))
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
            return false;
        }

        HKEY key = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            root,
            subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()),
            0,
            KEY_QUERY_VALUE | accessFlags,
            &key);
        if (kOpenResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kOpenResult);
            return false;
        }

        const QString kRealValueName = trimDefaultValueName(valueName);
        const wchar_t* valueNamePtr = kRealValueName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealValueName.utf16());
        DWORD type = REG_NONE;
        DWORD dataBytes = 0;
        LONG queryResult = ::RegQueryValueExW(key, valueNamePtr, nullptr, &type, nullptr, &dataBytes);
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(key);
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(queryResult);
            return false;
        }

        QByteArray rawData(static_cast<int>(dataBytes), 0);
        queryResult = ::RegQueryValueExW(
            key,
            valueNamePtr,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(rawData.data()),
            &dataBytes);
        ::RegCloseKey(key);
        if (queryResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(queryResult);
            return false;
        }

        rawData.resize(static_cast<int>(dataBytes));
        *typeOut = type;
        *dataOut = rawData;
        return true;
    }

    // writeRegistryValue:
    // - Input key/value/type/data/accessFlags: target registry value and raw bytes;
    // - Processing: creates the key if needed, then writes value data;
    // - Return: true when RegSetValueExW succeeds.
    bool writeRegistryValue(
        const QString& keyPath,
        const QString& valueName,
        const DWORD type,
        const QByteArray& rawData,
        const REGSAM accessFlags,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr) errorTextOut->clear();
        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(keyPath, &root, &subPath))
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
            return false;
        }

        HKEY key = nullptr;
        const LONG kCreateResult = ::RegCreateKeyExW(
            root,
            subPath.isEmpty() ? L"" : reinterpret_cast<const wchar_t*>(subPath.utf16()),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | accessFlags,
            nullptr,
            &key,
            nullptr);
        if (kCreateResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kCreateResult);
            return false;
        }

        const QString kRealValueName = trimDefaultValueName(valueName);
        const wchar_t* valueNamePtr = kRealValueName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealValueName.utf16());
        const LONG kSetResult = ::RegSetValueExW(
            key,
            valueNamePtr,
            0,
            type,
            reinterpret_cast<const BYTE*>(rawData.constData()),
            static_cast<DWORD>(rawData.size()));
        ::RegCloseKey(key);
        if (kSetResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kSetResult);
            return false;
        }
        return true;
    }

    // deleteRegistryValueOrKey:
    // - Input keyPath/valueName/accessFlags: target key or value;
    // - Processing: deletes a value when valueName is present, otherwise deletes the key tree;
    // - Return: true when the delete operation succeeds.
    bool deleteRegistryValueOrKey(
        const QString& keyPath,
        const QString& valueName,
        const bool hasValueName,
        const REGSAM accessFlags,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr) errorTextOut->clear();
        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(keyPath, &root, &subPath))
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
            return false;
        }

        if (hasValueName)
        {
            HKEY key = nullptr;
            const LONG kOpenResult = ::RegOpenKeyExW(
                root,
                subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()),
                0,
                KEY_SET_VALUE | accessFlags,
                &key);
            if (kOpenResult != ERROR_SUCCESS)
            {
                if (errorTextOut != nullptr) *errorTextOut = winErrorText(kOpenResult);
                return false;
            }
            const QString kRealValueName = trimDefaultValueName(valueName);
            const wchar_t* valueNamePtr = kRealValueName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealValueName.utf16());
            const LONG kDeleteResult = ::RegDeleteValueW(key, valueNamePtr);
            ::RegCloseKey(key);
            if (kDeleteResult != ERROR_SUCCESS)
            {
                if (errorTextOut != nullptr) *errorTextOut = winErrorText(kDeleteResult);
                return false;
            }
            return true;
        }

        if (subPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("拒绝删除注册表根键。");
            return false;
        }

        const LONG kDeleteResult = ::RegDeleteTreeW(root, reinterpret_cast<const wchar_t*>(subPath.utf16()));
        if (kDeleteResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kDeleteResult);
            return false;
        }
        return true;
    }

    // shouldSkipActionError:
    // - Input actionObject: action JSON carrying optional SkipError field;
    // - Processing: Dism++ uses SkipError=2 for missing/expected failures;
    // - Return: true when this action error should be reported as skipped.
    bool shouldSkipActionError(const QJsonObject& actionObject)
    {
        return jsonString(actionObject, QStringLiteral("SkipError")).trimmed() == QStringLiteral("2");
    }

    // expandEnvironmentPath:
    // - Input pathText: path containing Windows environment variables;
    // - Processing: calls ExpandEnvironmentStringsW and normalizes separators;
    // - Return: expanded path, or original text if expansion fails.
    QString expandEnvironmentPath(const QString& pathText)
    {
        const QString kTrimmedPath = pathText.trimmed();
        if (kTrimmedPath.isEmpty()) return QString();
        DWORD requiredChars = ::ExpandEnvironmentStringsW(
            reinterpret_cast<const wchar_t*>(kTrimmedPath.utf16()),
            nullptr,
            0);
        if (requiredChars == 0) return QDir::toNativeSeparators(kTrimmedPath);

        QString expanded;
        expanded.resize(static_cast<int>(requiredChars));
        const DWORD kWrittenChars = ::ExpandEnvironmentStringsW(
            reinterpret_cast<const wchar_t*>(kTrimmedPath.utf16()),
            reinterpret_cast<wchar_t*>(expanded.data()),
            requiredChars);
        if (kWrittenChars == 0) return QDir::toNativeSeparators(kTrimmedPath);
        while (expanded.endsWith(QChar::Null)) expanded.chop(1);
        return QDir::toNativeSeparators(expanded);
    }

    // splitZipFileReference:
    // - Input zipReference: JSON ZIPFile text such as Config\Data.zip/SwapMouse.exe;
    // - Processing: separates relative zip path from inner entry path;
    // - Return: true when both pieces are available.
    bool splitZipFileReference(const QString& zipReference, QString* zipRelativePathOut, QString* entryPathOut)
    {
        if (zipRelativePathOut == nullptr || entryPathOut == nullptr) return false;
        QString normalized = zipReference.trimmed();
        normalized.replace('\\', '/');
        const int kZipSuffixIndex = normalized.indexOf(QStringLiteral(".zip"), 0, Qt::CaseInsensitive);
        if (kZipSuffixIndex < 0) return false;
        const int kZipEndIndex = kZipSuffixIndex + 4;
        QString zipRelativePath = normalized.left(kZipEndIndex);
        QString entryPath = normalized.mid(kZipEndIndex);
        while (entryPath.startsWith('/')) entryPath.remove(0, 1);
        if (zipRelativePath.isEmpty() || entryPath.isEmpty()) return false;
        *zipRelativePathOut = QDir::fromNativeSeparators(zipRelativePath);
        *entryPathOut = QDir::fromNativeSeparators(entryPath);
        return true;
    }

    // registryOptimizationAssetCandidates:
    // - Input zipRelativePath: relative path inside registry_optimization_assets;
    // - Processing: searches runtime profiles first, then source-tree profiles for development;
    // - Return: candidate zip paths in priority order.
    QStringList registryOptimizationAssetCandidates(const QString& zipRelativePath)
    {
        QStringList candidates;
        const QString kNormalizedZipPath = QDir::fromNativeSeparators(zipRelativePath);
        const QString kAppDir = QCoreApplication::applicationDirPath();
        const QString kCurrentDir = QDir::currentPath();
        candidates << QDir(kAppDir).filePath(QStringLiteral("profiles/registry_optimization_assets/%1").arg(kNormalizedZipPath));
        candidates << QDir(kAppDir).filePath(QStringLiteral("../profiles/registry_optimization_assets/%1").arg(kNormalizedZipPath));
        candidates << QDir(kCurrentDir).filePath(QStringLiteral("profiles/registry_optimization_assets/%1").arg(kNormalizedZipPath));
        candidates << QDir(kCurrentDir).filePath(QStringLiteral("apps/desktop/profiles/registry_optimization_assets/%1").arg(kNormalizedZipPath));
        candidates.removeDuplicates();
        return candidates;
    }

    // splitRegistryParent:
    // - Input keyPath: normalized HKEY path;
    // - Processing: separates parent key and leaf key name;
    // - Return: true when keyPath has a parent segment.
    bool splitRegistryParent(const QString& keyPath, QString* parentPathOut, QString* leafNameOut)
    {
        if (parentPathOut == nullptr || leafNameOut == nullptr) return false;
        QString normalized = keyPath.trimmed();
        normalized.replace('/', '\\');
        if (normalized.endsWith('\\')) normalized.chop(1);
        const int kSplitIndex = normalized.lastIndexOf('\\');
        if (kSplitIndex <= 0) return false;
        *parentPathOut = normalized.left(kSplitIndex);
        *leafNameOut = normalized.mid(kSplitIndex + 1);
        return !parentPathOut->isEmpty() && !leafNameOut->isEmpty();
    }

    // renameRegistryKeySameParent:
    // - Input oldKeyPath/newKeyPath/accessFlags: source and target key path;
    // - Processing: calls RegRenameKey when both keys share the same parent;
    // - Return: true on successful key rename.
    bool renameRegistryKeySameParent(
        const QString& oldKeyPath,
        const QString& newKeyPath,
        const REGSAM accessFlags,
        QString* errorTextOut)
    {
        QString oldParent;
        QString oldLeaf;
        QString newParent;
        QString newLeaf;
        if (!splitRegistryParent(oldKeyPath, &oldParent, &oldLeaf) ||
            !splitRegistryParent(newKeyPath, &newParent, &newLeaf) ||
            oldParent.compare(newParent, Qt::CaseInsensitive) != 0)
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("仅支持同父注册表键重命名：%1 -> %2").arg(oldKeyPath, newKeyPath);
            return false;
        }

        HKEY parentRoot = nullptr;
        QString parentSubPath;
        if (!parseRegistryPath(oldParent, &parentRoot, &parentSubPath))
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("父注册表路径无效：%1").arg(oldParent);
            return false;
        }

        HKEY parentKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            parentRoot,
            parentSubPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(parentSubPath.utf16()),
            0,
            KEY_WRITE | accessFlags,
            &parentKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kOpenResult);
            return false;
        }

        using RegRenameKeyFunc = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
        const HMODULE kAdvapiModule = ::GetModuleHandleW(L"Advapi32.dll");
        const auto kRenameKey = kAdvapiModule != nullptr
            ? reinterpret_cast<RegRenameKeyFunc>(::GetProcAddress(kAdvapiModule, "RegRenameKey"))
            : nullptr;
        if (kRenameKey == nullptr)
        {
            ::RegCloseKey(parentKey);
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前系统不支持 RegRenameKey。");
            return false;
        }

        const LONG kRenameResult = kRenameKey(
            parentKey,
            reinterpret_cast<const wchar_t*>(oldLeaf.utf16()),
            reinterpret_cast<const wchar_t*>(newLeaf.utf16()));
        ::RegCloseKey(parentKey);
        if (kRenameResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr) *errorTextOut = winErrorText(kRenameResult);
            return false;
        }
        return true;
    }

    // parseFunctionParameters:
    // - Input text: semicolon-delimited Dism++ function argument body;
    // - Processing: splits Key=Value pairs and keeps case-insensitive keys in lower case;
    // - Return: parameter map for RegExist/QueryServiceStart/OSVersion evaluation.
    QHash<QString, QString> parseFunctionParameters(const QString& text)
    {
        QHash<QString, QString> parameters;
        const QStringList kParts = text.split(QLatin1Char(';'), Qt::SkipEmptyParts);
        for (const QString& part : kParts)
        {
            const int kEqualIndex = part.indexOf('=');
            if (kEqualIndex < 0) continue;
            const QString kKey = part.left(kEqualIndex).trimmed().toLower();
            const QString kValue = part.mid(kEqualIndex + 1).trimmed();
            parameters.insert(kKey, kValue);
        }
        return parameters;
    }

    // compareRawRegistryData:
    // - Input actual/expected data and type;
    // - Processing: trims REG_SZ trailing NULs and compares binary data exactly otherwise;
    // - Return: true when current registry value equals expected JSON state.
    bool compareRawRegistryData(const DWORD type, const QByteArray& actualData, const QByteArray& expectedData)
    {
        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
        {
            QString actual = QString::fromWCharArray(
                reinterpret_cast<const wchar_t*>(actualData.constData()),
                actualData.size() / static_cast<int>(sizeof(wchar_t)));
            QString expected = QString::fromWCharArray(
                reinterpret_cast<const wchar_t*>(expectedData.constData()),
                expectedData.size() / static_cast<int>(sizeof(wchar_t)));
            while (actual.endsWith(QChar::Null)) actual.chop(1);
            while (expected.endsWith(QChar::Null)) expected.chop(1);
            return actual == expected;
        }
        return actualData == expectedData;
    }

    // evaluateRegExistFunction:
    // - Input body: RegExist(...) argument text;
    // - Processing: checks key/value existence plus optional type/data comparison;
    // - Return: true when the registry condition is satisfied.
    bool evaluateRegExistFunction(const QString& body)
    {
        const QHash<QString, QString> kParameters = parseFunctionParameters(body);
        const QString kKeyPath = kParameters.value(QStringLiteral("key")).trimmed();
        const QString kValueName = kParameters.value(QStringLiteral("value"));
        if (kKeyPath.isEmpty()) return false;

        HKEY root = nullptr;
        QString subPath;
        if (!parseRegistryPath(kKeyPath, &root, &subPath)) return false;

        const REGSAM kViewFlags =
            kParameters.value(QStringLiteral("wow64")).compare(QStringLiteral("True"), Qt::CaseInsensitive) == 0
            ? KEY_WOW64_32KEY
            : 0;

        if (!kParameters.contains(QStringLiteral("value")))
        {
            HKEY key = nullptr;
            const LONG kOpenResult = ::RegOpenKeyExW(
                root,
                subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()),
                0,
                KEY_QUERY_VALUE | kViewFlags,
                &key);
            if (kOpenResult == ERROR_SUCCESS) ::RegCloseKey(key);
            return kOpenResult == ERROR_SUCCESS;
        }

        DWORD actualType = REG_NONE;
        QByteArray actualData;
        if (!readRegistryValue(kKeyPath, kValueName, kViewFlags, &actualType, &actualData, nullptr))
        {
            return false;
        }

        if (kParameters.contains(QStringLiteral("type")))
        {
            DWORD expectedType = REG_NONE;
            if (!parseRegistryType(kParameters.value(QStringLiteral("type")), &expectedType) || actualType != expectedType)
            {
                return false;
            }
        }
        if (!kParameters.contains(QStringLiteral("data")))
        {
            return true;
        }

        DWORD expectedType = actualType;
        if (kParameters.contains(QStringLiteral("type")))
        {
            parseRegistryType(kParameters.value(QStringLiteral("type")), &expectedType);
        }
        QByteArray expectedData;
        QString errorText;
        if (!registryDataFromJsonText(expectedType, kParameters.value(QStringLiteral("data")), &expectedData, &errorText))
        {
            return false;
        }
        return compareRawRegistryData(actualType, actualData, expectedData);
    }

    // evaluateQueryServiceStartFunction:
    // - Input body: QueryServiceStart(...) argument text;
    // - Processing: queries service configuration and compares dwStartType;
    // - Return: true when service start type matches the JSON Type value.
    bool evaluateQueryServiceStartFunction(const QString& body)
    {
        const QHash<QString, QString> kParameters = parseFunctionParameters(body);
        const QString kServiceName = kParameters.value(QStringLiteral("name")).trimmed();
        const QString kTypeText = kParameters.value(QStringLiteral("type")).trimmed();
        if (kServiceName.isEmpty() || kTypeText.isEmpty()) return false;

        bool ok = false;
        const DWORD kExpectedStartType = kTypeText.toULong(&ok, 10);
        if (!ok) return false;

        SC_HANDLE managerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (managerHandle == nullptr) return false;
        SC_HANDLE serviceHandle = ::OpenServiceW(
            managerHandle,
            reinterpret_cast<const wchar_t*>(kServiceName.utf16()),
            SERVICE_QUERY_CONFIG);
        if (serviceHandle == nullptr)
        {
            ::CloseServiceHandle(managerHandle);
            return false;
        }

        DWORD bytesNeeded = 0;
        ::QueryServiceConfigW(serviceHandle, nullptr, 0, &bytesNeeded);
        QByteArray buffer(static_cast<int>(bytesNeeded), 0);
        const BOOL kQueryOk = ::QueryServiceConfigW(
            serviceHandle,
            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data()),
            bytesNeeded,
            &bytesNeeded);
        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(managerHandle);
        if (!kQueryOk) return false;

        const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.constData());
        return config != nullptr && config->dwStartType == kExpectedStartType;
    }

    // evaluateOsVersionFunction:
    // - Input body: OSVersion(...) argument text;
    // - Processing: compares current Windows major.minor version to the Text value;
    // - Return: true when the comparison is satisfied.
    bool evaluateOsVersionFunction(const QString& body)
    {
        const QHash<QString, QString> kParameters = parseFunctionParameters(body);
        const QString kTargetText = kParameters.value(QStringLiteral("text")).trimmed();
        if (kTargetText.isEmpty()) return false;

        const QStringList kParts = kTargetText.split(QLatin1Char('.'));
        if (kParts.size() < 2) return false;
        bool majorOk = false;
        bool minorOk = false;
        const int kTargetMajor = kParts.at(0).toInt(&majorOk);
        const int kTargetMinor = kParts.at(1).toInt(&minorOk);
        if (!majorOk || !minorOk) return false;

        const QOperatingSystemVersion kCurrent = QOperatingSystemVersion::current();
        const int kCurrentScore = kCurrent.majorVersion() * 1000 + kCurrent.minorVersion();
        const int kTargetScore = kTargetMajor * 1000 + kTargetMinor;
        const QString kCompareText = kParameters.value(QStringLiteral("compare"), QStringLiteral("=")).trimmed();
        if (kCompareText == QStringLiteral(">=")) return kCurrentScore >= kTargetScore;
        if (kCompareText == QStringLiteral("<=")) return kCurrentScore <= kTargetScore;
        if (kCompareText == QStringLiteral(">")) return kCurrentScore > kTargetScore;
        if (kCompareText == QStringLiteral("<")) return kCurrentScore < kTargetScore;
        if (kCompareText == QStringLiteral("!=")) return kCurrentScore != kTargetScore;
        return kCurrentScore == kTargetScore;
    }

    // ConditionParser:
    // - Input expression: Dism++ boolean condition text;
    // - Processing: recursive-descent parses NOT/AND/OR, parentheses, and supported functions;
    // - Return: boolean result; unsupported functions evaluate false to avoid false positives.
    class ConditionParser
    {
    public:
        explicit ConditionParser(const QString& expression)
            : expression_(expression)
        {
        }

        bool evaluate()
        {
            position_ = 0;
            const bool kResult = parseOrExpression();
            skipWhitespace();
            return kResult && position_ <= expression_.size();
        }

    private:
        void skipWhitespace()
        {
            while (position_ < expression_.size() && expression_.at(position_).isSpace())
            {
                ++position_;
            }
        }

        bool matchKeyword(const QString& keyword)
        {
            skipWhitespace();
            if (expression_.mid(position_, keyword.size()).compare(keyword, Qt::CaseInsensitive) != 0)
            {
                return false;
            }
            const int kEnd = position_ + keyword.size();
            if (kEnd < expression_.size() && (expression_.at(kEnd).isLetterOrNumber() || expression_.at(kEnd) == QLatin1Char('_')))
            {
                return false;
            }
            position_ = kEnd;
            return true;
        }

        bool parseOrExpression()
        {
            bool value = parseAndExpression();
            while (matchKeyword(QStringLiteral("OR")))
            {
                const bool kRhs = parseAndExpression();
                value = value || kRhs;
            }
            return value;
        }

        bool parseAndExpression()
        {
            bool value = parseUnaryExpression();
            while (matchKeyword(QStringLiteral("AND")))
            {
                const bool kRhs = parseUnaryExpression();
                value = value && kRhs;
            }
            return value;
        }

        bool parseUnaryExpression()
        {
            if (matchKeyword(QStringLiteral("NOT")))
            {
                return !parseUnaryExpression();
            }
            return parsePrimaryExpression();
        }

        bool parsePrimaryExpression()
        {
            skipWhitespace();
            if (position_ >= expression_.size()) return false;
            if (expression_.at(position_) == QLatin1Char('('))
            {
                ++position_;
                const bool kValue = parseOrExpression();
                skipWhitespace();
                if (position_ < expression_.size() && expression_.at(position_) == QLatin1Char(')'))
                {
                    ++position_;
                }
                return kValue;
            }
            return parseFunctionCall();
        }

        bool parseFunctionCall()
        {
            skipWhitespace();
            const int kNameStart = position_;
            while (position_ < expression_.size() &&
                (expression_.at(position_).isLetterOrNumber() || expression_.at(position_) == QLatin1Char('_')))
            {
                ++position_;
            }
            const QString kFunctionName = expression_.mid(kNameStart, position_ - kNameStart).trimmed();
            skipWhitespace();
            if (kFunctionName.isEmpty() || position_ >= expression_.size() || expression_.at(position_) != QLatin1Char('('))
            {
                return false;
            }

            ++position_;
            const int kBodyStart = position_;
            int depth = 1;
            while (position_ < expression_.size() && depth > 0)
            {
                const QChar kCh = expression_.at(position_);
                if (kCh == QLatin1Char('(')) ++depth;
                else if (kCh == QLatin1Char(')')) --depth;
                if (depth > 0) ++position_;
            }
            const QString kBody = expression_.mid(kBodyStart, position_ - kBodyStart);
            if (position_ < expression_.size() && expression_.at(position_) == QLatin1Char(')'))
            {
                ++position_;
            }

            if (kFunctionName.compare(QStringLiteral("RegExist"), Qt::CaseInsensitive) == 0)
            {
                return evaluateRegExistFunction(kBody);
            }
            if (kFunctionName.compare(QStringLiteral("QueryServiceStart"), Qt::CaseInsensitive) == 0)
            {
                return evaluateQueryServiceStartFunction(kBody);
            }
            if (kFunctionName.compare(QStringLiteral("OSVersion"), Qt::CaseInsensitive) == 0)
            {
                return evaluateOsVersionFunction(kBody);
            }
            return false;
        }

        QString expression_;
        int position_ = 0;
    };
}

RegistryOptimizationPage::RegistryOptimizationPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    loadOptimizationProfile();
}

RegistryOptimizationPage::~RegistryOptimizationPage()
{
    cancelStateApply();
}

void RegistryOptimizationPage::initializeUi()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    QWidget* presetButtonWidget = new QWidget(this);
    QHBoxLayout* presetButtonLayout = new QHBoxLayout(presetButtonWidget);
    presetButtonLayout->setContentsMargins(0, 0, 0, 0);
    presetButtonLayout->setSpacing(0);
    columnPresetAButton_ = new QPushButton(QStringLiteral("A"), presetButtonWidget);
    columnPresetBButton_ = new QPushButton(QStringLiteral("B"), presetButtonWidget);
    columnPresetAButton_->setFixedWidth(30);
    columnPresetBButton_->setFixedWidth(30);
    columnPresetAButton_->setToolTip(QStringLiteral("A 组：操作视图，只显示项目、作用域、状态、目标和应用按钮。"));
    columnPresetBButton_->setToolTip(QStringLiteral("B 组：诊断视图，只显示项目、作用域、类型和条件/警告。"));
    presetButtonLayout->addWidget(columnPresetAButton_);
    presetButtonLayout->addWidget(columnPresetBButton_);

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(QStringLiteral("过滤组名、项目名、作用域或条件"));
    filterEdit_->setStyleSheet(QStringLiteral(
        "QLineEdit{border:1px solid %1;border-radius:3px;background:transparent;/* %2 */color:%3;padding:3px 6px;}"
        "QLineEdit:focus{border:1px solid %4;}").arg(
            ksword_theme::borderHex(),
            ksword_theme::surfaceHex(),
            ksword_theme::textPrimaryHex(),
            ksword_theme::kPrimaryBlueHex));
    filterDebounceTimer_ = new QTimer(this);
    filterDebounceTimer_->setSingleShot(true);
    filterDebounceTimer_->setInterval(kFilterDebounceMs);

    reloadButton_ = new QPushButton(QStringLiteral("重新加载 JSON"), this);
    refreshStateButton_ = new QPushButton(QStringLiteral("刷新可见状态"), this);
    cancelApplyButton_ = new QPushButton(QStringLiteral("取消应用"), this);
    reloadButton_->setToolTip(QStringLiteral("从配置文件重新读取优化项清单"));
    refreshStateButton_->setToolTip(QStringLiteral("重新读取注册表，刷新列表中各优化项的当前状态"));
    cancelApplyButton_->setToolTip(QStringLiteral("中止正在进行的批量应用操作"));
    reloadButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    refreshStateButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    cancelApplyButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    cancelApplyButton_->setEnabled(false);

    toolLayout->addWidget(presetButtonWidget, 0);
    toolLayout->addWidget(filterEdit_, 1);
    toolLayout->addWidget(cancelApplyButton_, 0);
    toolLayout->addWidget(refreshStateButton_, 0);
    toolLayout->addWidget(reloadButton_, 0);
    rootLayout->addLayout(toolLayout, 0);

    splitter_ = new QSplitter(Qt::Horizontal, this);
    rootLayout->addWidget(splitter_, 1);

    groupTree_ = new QTreeWidget(splitter_);
    groupTree_->setColumnCount(1);
    groupTree_->setHeaderLabel(QStringLiteral("优化分组"));
    groupTree_->setMinimumWidth(260);
    groupTree_->header()->setStyleSheet(QStringLiteral("QHeaderView::section{color:%1;font-weight:600;}").arg(ksword_theme::kPrimaryBlueHex));

    QWidget* rightWidget = new QWidget(splitter_);
    QVBoxLayout* rightLayout = new QVBoxLayout(rightWidget);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(6);

    itemTable_ = new ks::ui::VisibleTableWidget(rightWidget);
    itemTable_->setColumnCount(7);
    itemTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("项目"),
        QStringLiteral("作用域"),
        QStringLiteral("类型"),
        QStringLiteral("当前状态"),
        QStringLiteral("目标选项"),
        QStringLiteral("操作"),
        QStringLiteral("条件/警告")
    });
    itemTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    itemTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    itemTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    itemTable_->setAlternatingRowColors(true);
    itemTable_->setCornerButtonEnabled(false);
    itemTable_->setWordWrap(false);
    itemTable_->setTextElideMode(Qt::ElideRight);
    itemTable_->verticalHeader()->setDefaultSectionSize(kDefaultRowHeight);
    itemTable_->verticalHeader()->setMinimumSectionSize(kDefaultRowHeight);
    itemTable_->horizontalHeader()->setStyleSheet(QStringLiteral("QHeaderView::section{color:%1;font-weight:600;}").arg(ksword_theme::kPrimaryBlueHex));
    itemTable_->horizontalHeader()->setSectionResizeMode(kItemNameColumn, QHeaderView::Stretch);
    itemTable_->horizontalHeader()->setSectionResizeMode(kScopeColumn, QHeaderView::ResizeToContents);
    itemTable_->horizontalHeader()->setSectionResizeMode(kTypeColumn, QHeaderView::ResizeToContents);
    itemTable_->horizontalHeader()->setSectionResizeMode(kCurrentStateColumn, QHeaderView::ResizeToContents);
    itemTable_->horizontalHeader()->setSectionResizeMode(kTargetControlColumn, QHeaderView::Fixed);
    itemTable_->horizontalHeader()->setSectionResizeMode(kActionButtonColumn, QHeaderView::Fixed);
    itemTable_->horizontalHeader()->setSectionResizeMode(kConditionWarningColumn, QHeaderView::Stretch);
    itemTable_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
    itemTable_->setColumnWidth(kTargetControlColumn, kTargetColumnWidth);
    itemTable_->setColumnWidth(kActionButtonColumn, kActionColumnWidth);
    rightLayout->addWidget(itemTable_, 2);

    // Optimization details are generated by the program based on the current line; the unified editor preserves the canonical source text and redraws when switching languages.
    detailText_ = new CodeEditorWidget(rightWidget);
    detailText_->setReadOnly(true);
    detailText_->setMinimumHeight(190);
    rightLayout->addWidget(detailText_, 1);

    statusLabel_ = new QLabel(QStringLiteral("系统优化：等待加载 profiles JSON。"), this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(statusLabel_, 0);

    splitter_->setStretchFactor(0, 0);
    splitter_->setStretchFactor(1, 1);
    refreshColumnPresetButtonStyles();
}

void RegistryOptimizationPage::initializeConnections()
{
    connect(columnPresetAButton_, &QPushButton::clicked, this, [this]() { applyColumnPreset(ColumnPreset::kA); });
    connect(columnPresetBButton_, &QPushButton::clicked, this, [this]() { applyColumnPreset(ColumnPreset::kB); });
    connect(reloadButton_, &QPushButton::clicked, this, [this]() { loadOptimizationProfile(); });
    connect(refreshStateButton_, &QPushButton::clicked, this, [this]() { refreshVisibleStates(); });
    connect(cancelApplyButton_, &QPushButton::clicked, this, [this]() { cancelStateApply(QStringLiteral("用户已取消应用。")); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { filterDebounceTimer_->start(); });
    connect(filterDebounceTimer_, &QTimer::timeout, this, [this]() { rebuildItemTable(); });
    connect(groupTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*) {
        filterDebounceTimer_->stop();
        rebuildItemTable();
    });
    connect(itemTable_, &QTableWidget::currentCellChanged, this, [this](int currentRow, int, int, int) {
        updateDetailPanel(currentRow);
    });
    connect(itemTable_->horizontalHeader(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPos) {
        showHeaderColumnMenu(localPos);
    });
}

QStringList RegistryOptimizationPage::profileCandidatePaths() const
{
    QStringList paths;
    const QString kFileName = QString::fromLatin1(kOptimizationProfileFileName);
    const QString kApplicationDirectory = QCoreApplication::applicationDirPath();
    const QString kCurrentDirectory = QDir::currentPath();
    paths << QDir(kApplicationDirectory).filePath(QStringLiteral("profiles/%1").arg(kFileName));
    paths << QDir(kApplicationDirectory).filePath(QStringLiteral("../profiles/%1").arg(kFileName));
    paths << QDir(kCurrentDirectory).filePath(QStringLiteral("profiles/%1").arg(kFileName));
    paths << QDir(kCurrentDirectory).filePath(QStringLiteral("apps/desktop/profiles/%1").arg(kFileName));
    paths << QDir(kCurrentDirectory).filePath(QStringLiteral("../profiles/%1").arg(kFileName));
    paths.removeDuplicates();
    return paths;
}

void RegistryOptimizationPage::loadOptimizationProfile()
{
    cancelStateRefresh();
    cancelStateApply(QStringLiteral("已取消正在进行的应用，因为优化配置已重新加载。"));
    if (filterDebounceTimer_ != nullptr) filterDebounceTimer_->stop();
    itemList_.clear();
    visibleRows_.clear();
    loadedProfilePath_.clear();
    itemTable_->setRowCount(0);
    groupTree_->clear();
    detailText_->setLocalizedText(QString());

    QString selectedPath;
    for (const QString& candidatePath : profileCandidatePaths())
    {
        const QString kResolvedPath = ks::profile::resolveProfileJsonPath(candidatePath);
        if (!kResolvedPath.isEmpty())
        {
            selectedPath = QDir::cleanPath(kResolvedPath);
            break;
        }
    }

    if (selectedPath.isEmpty())
    {
        updateStatusText(QStringLiteral("未找到 profiles/%1；系统优化页已加载，但没有可显示项目。").arg(QString::fromLatin1(kOptimizationProfileFileName)));
        return;
    }

    QJsonParseError parseError{};
    QString readErrorText;
    const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(selectedPath, &parseError, &readErrorText);
    if (parseError.error != QJsonParseError::NoError || !kDocument.isArray())
    {
        const QString kReasonText = readErrorText.isEmpty() ? parseError.errorString() : readErrorText;
        updateStatusText(QStringLiteral("系统优化 JSON 解析失败：%1 (%2)").arg(kReasonText, selectedPath));
        return;
    }

    const QJsonArray kItemArray = kDocument.array();
    for (const QJsonValue& itemValue : kItemArray)
    {
        if (!itemValue.isObject()) continue;
        const QJsonObject kItemObject = itemValue.toObject();

        OptimizationItem item;
        item.groupIndex = jsonInt(kItemObject, QStringLiteral("group_index"));
        item.itemIndex = jsonInt(kItemObject, QStringLiteral("item_index"));
        item.groupNameText = jsonString(kItemObject, QStringLiteral("group_name"));
        item.itemNameText = jsonString(kItemObject, QStringLiteral("item_name"));
        item.itemTypeText = jsonString(kItemObject, QStringLiteral("item_type"));
        item.groupConditionText = jsonString(kItemObject, QStringLiteral("group_condition"));
        item.itemConditionText = jsonString(kItemObject, QStringLiteral("item_condition"));
        item.warningText = jsonString(kItemObject, QStringLiteral("item_warning"));

        const QJsonArray kScopeArray = kItemObject.value(QStringLiteral("scopes")).toArray();
        for (const QJsonValue& scopeValue : kScopeArray)
        {
            if (!scopeValue.isObject()) continue;
            const QJsonObject kScopeObject = scopeValue.toObject();
            OptimizationScope scope;
            scope.scopeText = jsonString(kScopeObject, QStringLiteral("scope"));
            scope.conditionText = jsonString(kScopeObject, QStringLiteral("scope_condition"));

            const QJsonArray kStateArray = kScopeObject.value(QStringLiteral("states")).toArray();
            for (const QJsonValue& stateValue : kStateArray)
            {
                if (!stateValue.isObject()) continue;
                const QJsonObject kStateObject = stateValue.toObject();
                OptimizationState state;
                state.tagText = jsonString(kStateObject, QStringLiteral("state_tag"));
                state.labelText = jsonString(kStateObject, QStringLiteral("state_label"));
                state.conditionText = jsonString(kStateObject, QStringLiteral("state_condition"));
                state.warningText = jsonString(kStateObject, QStringLiteral("state_warning"));

                const QJsonArray kActionArray = kStateObject.value(QStringLiteral("actions")).toArray();
                for (const QJsonValue& actionValue : kActionArray)
                {
                    if (actionValue.isObject()) state.actionList.push_back(actionValue.toObject());
                }
                scope.stateList.push_back(state);
            }
            item.scopeList.push_back(scope);
        }
        itemList_.push_back(item);
    }

    loadedProfilePath_ = selectedPath;
    rebuildGroupTree();
    rebuildItemTable();
    applyColumnPreset(columnPreset_);
    updateStatusText(QStringLiteral("已加载系统优化 JSON：%1；项目 %2 个。").arg(selectedPath).arg(itemList_.size()));
}

void RegistryOptimizationPage::rebuildGroupTree()
{
    QSignalBlocker blocker(groupTree_);
    groupTree_->clear();

    QHash<QString, int> groupCounts;
    QVector<QString> groupOrder;
    int rowCount = 0;
    for (const OptimizationItem& item : itemList_)
    {
        const int kItemScopeCount = std::max(1, static_cast<int>(item.scopeList.size()));
        if (!groupCounts.contains(item.groupNameText))
        {
            groupOrder.push_back(item.groupNameText);
        }
        groupCounts[item.groupNameText] += kItemScopeCount;
        rowCount += kItemScopeCount;
    }

    QTreeWidgetItem* allItem = new QTreeWidgetItem(groupTree_);
    allItem->setText(0, QStringLiteral("全部 (%1)").arg(rowCount));
    allItem->setData(0, kRoleGroupName, QString());
    allItem->setSelected(true);
    groupTree_->setCurrentItem(allItem);

    for (const QString& groupName : groupOrder)
    {
        QTreeWidgetItem* groupItem = new QTreeWidgetItem(groupTree_);
        groupItem->setText(0, QStringLiteral("%1 (%2)").arg(groupName).arg(groupCounts.value(groupName)));
        groupItem->setData(0, kRoleGroupName, groupName);
    }
    groupTree_->expandAll();
}

void RegistryOptimizationPage::rebuildItemTable()
{
    // The debounce timer for filtering may expire within a nested menu event loop.
    // Wait for the menu to close before clearing visible rows and cell controls.
    const QPointer<RegistryOptimizationPage> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("registry-optimization-table-rebuild"),
        {itemTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->rebuildItemTable();
            }
        }))
    {
        return;
    }

    cancelStateRefresh();
    cancelStateApply(QStringLiteral("已取消正在进行的应用，因为筛选结果已改变。"));
    rebuildingTable_ = true;
    QSignalBlocker blocker(itemTable_);
    const bool kUpdatesEnabled = itemTable_->updatesEnabled();
    itemTable_->setUpdatesEnabled(false);
    visibleRows_.clear();
    itemTable_->setRowCount(0);

    const QTreeWidgetItem* selectedGroupItem = groupTree_->currentItem();
    const QString kSelectedGroup = selectedGroupItem == nullptr ? QString() : selectedGroupItem->data(0, kRoleGroupName).toString();
    const QString kFilterText = filterEdit_->text().trimmed();

    for (int itemIndex = 0; itemIndex < itemList_.size(); ++itemIndex)
    {
        const OptimizationItem& item = itemList_.at(itemIndex);
        if (!kSelectedGroup.isEmpty() && item.groupNameText.compare(kSelectedGroup, Qt::CaseInsensitive) != 0)
        {
            continue;
        }

        for (int scopeIndex = 0; scopeIndex < item.scopeList.size(); ++scopeIndex)
        {
            const OptimizationScope& scope = item.scopeList.at(scopeIndex);
            const QString kHaystack = QStringLiteral("%1\n%2\n%3\n%4\n%5\n%6")
                .arg(item.groupNameText, item.itemNameText, item.itemTypeText, scope.scopeText, item.itemConditionText, item.warningText);
            if (!kFilterText.isEmpty() && !kHaystack.contains(kFilterText, Qt::CaseInsensitive))
            {
                continue;
            }

            const int kTableRow = itemTable_->rowCount();
            itemTable_->insertRow(kTableRow);
            itemTable_->setRowHeight(kTableRow, kDefaultRowHeight);
            visibleRows_.push_back(VisibleRow{ itemIndex, scopeIndex });

            itemTable_->setItem(kTableRow, 0, new QTableWidgetItem(item.itemNameText));
            itemTable_->setItem(kTableRow, 1, new QTableWidgetItem(scopeDisplayText(scope.scopeText)));
            itemTable_->setItem(kTableRow, 2, new QTableWidgetItem(item.itemTypeText));
            itemTable_->setItem(
                kTableRow,
                3,
                new QTableWidgetItem(ks::i18n::sourceText(QStringLiteral("未检测"))));
            QTableWidgetItem* targetPlaceholderItem = new QTableWidgetItem();
            targetPlaceholderItem->setSizeHint(QSize(kTargetColumnWidth, kDefaultRowHeight));
            targetPlaceholderItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            itemTable_->setItem(kTableRow, kTargetControlColumn, targetPlaceholderItem);
            QTableWidgetItem* actionPlaceholderItem = new QTableWidgetItem();
            actionPlaceholderItem->setSizeHint(QSize(kActionColumnWidth, kDefaultRowHeight));
            actionPlaceholderItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            itemTable_->setItem(kTableRow, kActionButtonColumn, actionPlaceholderItem);

            if (item.itemTypeText.compare(QStringLiteral("Combo"), Qt::CaseInsensitive) == 0)
            {
                QComboBox* comboBox = new QComboBox(itemTable_);
                comboBox->setObjectName(QStringLiteral("optimizationTargetCombo"));
                comboBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                comboBox->setMinimumWidth(kTargetColumnWidth - 16);
                for (const OptimizationState& state : scope.stateList)
                {
                    if (state.tagText.compare(QStringLiteral("Dropdown"), Qt::CaseInsensitive) == 0)
                    {
                        comboBox->addItem(state.labelText, state.labelText);
                    }
                }
                comboBox->setProperty("row", kTableRow);
                itemTable_->setCellWidget(kTableRow, kTargetControlColumn, buildCenteredCellWidget(comboBox, itemTable_));
            }
            else
            {
                QCheckBox* checkBox = new QCheckBox(QStringLiteral("启用"), itemTable_);
                checkBox->setObjectName(QStringLiteral("optimizationTargetCheck"));
                checkBox->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
                checkBox->setProperty("row", kTableRow);
                itemTable_->setCellWidget(kTableRow, kTargetControlColumn, buildCenteredCellWidget(checkBox, itemTable_));
            }

            QPushButton* applyButton = new QPushButton(QStringLiteral("应用"), itemTable_);
            applyButton->setObjectName(QStringLiteral("registryOptimizationApplyButton"));
            applyButton->setToolTip(QStringLiteral("对这一项执行注册表优化设置"));
            applyButton->setStyleSheet(ksword_theme::themedButtonStyle());
            applyButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
            applyButton->setFixedWidth(kActionColumnWidth - 14);
            applyButton->setProperty("row", kTableRow);
            connect(applyButton, &QPushButton::clicked, this, [this, applyButton]() {
                const int kRow = applyButton->property("row").toInt();
                applyVisibleRow(kRow);
            });
            itemTable_->setCellWidget(kTableRow, kActionButtonColumn, buildCenteredCellWidget(applyButton, itemTable_));

            QStringList conditionLines;
            if (!item.groupConditionText.isEmpty()) conditionLines << QStringLiteral("组条件: %1").arg(item.groupConditionText);
            if (!item.itemConditionText.isEmpty()) conditionLines << QStringLiteral("项目条件: %1").arg(item.itemConditionText);
            if (!scope.conditionText.isEmpty()) conditionLines << QStringLiteral("作用域条件: %1").arg(scope.conditionText);
            if (!item.warningText.isEmpty()) conditionLines << QStringLiteral("警告: %1").arg(item.warningText);
            itemTable_->setItem(kTableRow, 6, new QTableWidgetItem(conditionLines.join(QStringLiteral(" | "))));
        }
    }

    rebuildingTable_ = false;
    if (itemTable_->rowCount() > 0)
    {
        itemTable_->setCurrentCell(0, 0);
        updateDetailPanel(0);
    }
    else
    {
        detailText_->setLocalizedText(QString());
    }
    updateStatusText(QStringLiteral("系统优化：当前显示 %1 行；来源 %2。").arg(itemTable_->rowCount()).arg(loadedProfilePath_));
    applyColumnPreset(columnPreset_);
    itemTable_->setUpdatesEnabled(kUpdatesEnabled);
    if (kUpdatesEnabled) itemTable_->viewport()->update();
}

void RegistryOptimizationPage::refreshVisibleStates()
{
    if (stateRefreshInProgress_) return;

    const QVector<OptimizationItem> kItemSnapshot = itemList_;
    const QVector<VisibleRow> kVisibleRowsSnapshot = visibleRows_;
    const std::uint64_t kGeneration = ++stateRefreshGeneration_;
    stateRefreshInProgress_ = true;
    refreshStateButton_->setEnabled(false);

    QPointer<RegistryOptimizationPage> guardThis(this);
    std::thread([guardThis, kGeneration, kItemSnapshot, kVisibleRowsSnapshot]() {
        QVector<VisibleStateRefreshResult> results;
        results.reserve(kVisibleRowsSnapshot.size());
        for (int tableRow = 0; tableRow < kVisibleRowsSnapshot.size(); ++tableRow)
        {
            const VisibleRow& rowRef = kVisibleRowsSnapshot.at(tableRow);
            VisibleStateRefreshResult result;
            result.tableRow = tableRow;
            result.stateText = QStringLiteral("未匹配/未知");
            if (rowRef.itemIndex >= 0 && rowRef.itemIndex < kItemSnapshot.size())
            {
                const OptimizationItem& item = kItemSnapshot.at(rowRef.itemIndex);
                if (rowRef.scopeIndex >= 0 && rowRef.scopeIndex < item.scopeList.size())
                {
                    const OptimizationScope& scope = item.scopeList.at(rowRef.scopeIndex);
                    for (const OptimizationState& state : scope.stateList)
                    {
                        if (!state.conditionText.trimmed().isEmpty() &&
                            RegistryOptimizationPage::evaluateConditionText(state.conditionText))
                        {
                            result.stateText = state.labelText;
                            result.targetLabel = state.labelText;
                            result.targetEnabled = state.tagText.compare(QStringLiteral("State"), Qt::CaseInsensitive) == 0;
                            break;
                        }
                    }
                }
            }
            results.push_back(std::move(result));
        }

        QMetaObject::invokeMethod(qApp, [guardThis, kGeneration, results = std::move(results)]() {
            if (guardThis == nullptr || guardThis->stateRefreshGeneration_ != kGeneration) return;

            guardThis->stateRefreshInProgress_ = false;
            guardThis->refreshStateButton_->setEnabled(true);
            const bool kUpdatesEnabled = guardThis->itemTable_->updatesEnabled();
            guardThis->itemTable_->setUpdatesEnabled(false);
            for (const VisibleStateRefreshResult& result : results)
            {
                if (result.tableRow < 0 || result.tableRow >= guardThis->itemTable_->rowCount()) continue;
                if (QTableWidgetItem* statusItem = guardThis->itemTable_->item(result.tableRow, kCurrentStateColumn))
                {
                    statusItem->setText(result.stateText);
                }

                QWidget* targetWidget = guardThis->itemTable_->cellWidget(result.tableRow, kTargetControlColumn);
                if (QComboBox* comboBox = findTargetComboBox(targetWidget))
                {
                    const int kComboIndex = comboBox->findData(result.targetLabel);
                    if (kComboIndex >= 0) comboBox->setCurrentIndex(kComboIndex);
                }
                else if (QCheckBox* checkBox = findTargetCheckBox(targetWidget))
                {
                    checkBox->setChecked(result.targetEnabled);
                }
            }
            guardThis->itemTable_->setUpdatesEnabled(kUpdatesEnabled);
            if (kUpdatesEnabled) guardThis->itemTable_->viewport()->update();
            guardThis->updateStatusText(QStringLiteral("系统优化：已刷新 %1 个可见项状态。").arg(results.size()));
        }, Qt::QueuedConnection);
    }).detach();
}

void RegistryOptimizationPage::cancelStateRefresh()
{
    if (!stateRefreshInProgress_) return;

    ++stateRefreshGeneration_;
    stateRefreshInProgress_ = false;
    if (refreshStateButton_ != nullptr) refreshStateButton_->setEnabled(true);
}

void RegistryOptimizationPage::refreshVisibleRowState(const int tableRow)
{
    if (tableRow < 0 || tableRow >= visibleRows_.size()) return;
    const VisibleRow kRowRef = visibleRows_.at(tableRow);
    if (kRowRef.itemIndex < 0 || kRowRef.itemIndex >= itemList_.size()) return;
    const OptimizationItem& item = itemList_.at(kRowRef.itemIndex);
    if (kRowRef.scopeIndex < 0 || kRowRef.scopeIndex >= item.scopeList.size()) return;
    const OptimizationScope& scope = item.scopeList.at(kRowRef.scopeIndex);

    const OptimizationState* detectedState = detectedStateForScope(scope);
    const QString kStateText = detectedState == nullptr
        ? QStringLiteral("未匹配/未知")
        : detectedState->labelText;
    if (QTableWidgetItem* statusItem = itemTable_->item(tableRow, 3))
    {
        statusItem->setText(kStateText);
    }

    QWidget* targetWidget = itemTable_->cellWidget(tableRow, kTargetControlColumn);
    if (QComboBox* comboBox = findTargetComboBox(targetWidget))
    {
        if (detectedState != nullptr)
        {
            const int kComboIndex = comboBox->findData(detectedState->labelText);
            if (kComboIndex >= 0) comboBox->setCurrentIndex(kComboIndex);
        }
    }
    else if (QCheckBox* checkBox = findTargetCheckBox(targetWidget))
    {
        checkBox->setChecked(detectedState != nullptr &&
            detectedState->tagText.compare(QStringLiteral("State"), Qt::CaseInsensitive) == 0);
    }
}

void RegistryOptimizationPage::updateDetailPanel(const int tableRow)
{
    if (rebuildingTable_ || tableRow < 0 || tableRow >= visibleRows_.size())
    {
        detailText_->setLocalizedText(QString());
        return;
    }

    const VisibleRow kRowRef = visibleRows_.at(tableRow);
    const OptimizationItem& item = itemList_.at(kRowRef.itemIndex);
    const OptimizationScope& scope = item.scopeList.at(kRowRef.scopeIndex);

    QStringList lines;
    lines << QStringLiteral("项目: %1").arg(item.itemNameText);
    lines << QStringLiteral("分组: %1").arg(item.groupNameText);
    lines << QStringLiteral("作用域: %1 (%2)").arg(scopeDisplayText(scope.scopeText), scope.scopeText);
    lines << QStringLiteral("类型: %1").arg(item.itemTypeText);
    if (!item.warningText.isEmpty()) lines << QStringLiteral("项目警告: %1").arg(item.warningText);
    if (!item.groupConditionText.isEmpty()) lines << QStringLiteral("组条件: %1").arg(item.groupConditionText);
    if (!item.itemConditionText.isEmpty()) lines << QStringLiteral("项目条件: %1").arg(item.itemConditionText);
    if (!scope.conditionText.isEmpty()) lines << QStringLiteral("作用域条件: %1").arg(scope.conditionText);
    lines << QStringLiteral("");
    lines << QStringLiteral("状态/动作:");
    for (const OptimizationState& state : scope.stateList)
    {
        lines << QStringLiteral("- %1 [%2] 条件=%3").arg(state.labelText, state.tagText, state.conditionText);
        if (!state.warningText.isEmpty()) lines << QStringLiteral("  警告: %1").arg(state.warningText);
        for (const QJsonObject& action : state.actionList)
        {
            lines << QStringLiteral("  * %1").arg(jsonString(action, QStringLiteral("summary"), QString::fromUtf8(QJsonDocument(action).toJson(QJsonDocument::Compact))));
        }
    }
    detailText_->setLocalizedText(lines.join(QLatin1Char('\n')));
}

void RegistryOptimizationPage::updateStatusText(const QString& text)
{
    if (statusLabel_ != nullptr) statusLabel_->setText(text);
}

void RegistryOptimizationPage::applyColumnPreset(const ColumnPreset preset)
{
    columnPreset_ = preset;
    for (int columnIndex = 0; columnIndex < itemTable_->columnCount(); ++columnIndex)
    {
        itemTable_->setColumnHidden(columnIndex, !isColumnVisibleInPreset(columnIndex, preset));
    }
    itemTable_->setColumnWidth(kTargetControlColumn, kTargetColumnWidth);
    itemTable_->setColumnWidth(kActionButtonColumn, kActionColumnWidth);
    refreshColumnPresetButtonStyles();
    ks::ui::requestTableColumnAutoFit(itemTable_);
}

void RegistryOptimizationPage::refreshColumnPresetButtonStyles()
{
    const QString kInactiveStyle = ksword_theme::themedButtonStyle();
    const QString kActiveStyle = QStringLiteral(
        "QPushButton{background:%1;color:palette(highlighted-text);border:1px solid %2;border-radius:3px;padding:3px 8px;font-weight:700;}"
        "QPushButton:hover{background:%3;}"
        "QPushButton:pressed{background:%4;}").arg(
            ksword_theme::kPrimaryBlueHex,
            ksword_theme::kPrimaryBlueBorderHex,
            ksword_theme::kPrimaryBlueActiveHex,
            ksword_theme::kPrimaryBluePressedHex);

    if (columnPresetAButton_ != nullptr)
    {
        columnPresetAButton_->setStyleSheet(columnPreset_ == ColumnPreset::kA ? kActiveStyle : kInactiveStyle);
    }
    if (columnPresetBButton_ != nullptr)
    {
        columnPresetBButton_->setStyleSheet(columnPreset_ == ColumnPreset::kB ? kActiveStyle : kInactiveStyle);
    }
}

void RegistryOptimizationPage::showHeaderColumnMenu(const QPoint& localPos)
{
    QMenu columnMenu(this);
    columnMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    for (int columnIndex = 0; columnIndex < itemTable_->columnCount(); ++columnIndex)
    {
        const QString kHeaderText = itemTable_->horizontalHeaderItem(columnIndex) == nullptr
            ? QStringLiteral("列 %1").arg(columnIndex)
            : itemTable_->horizontalHeaderItem(columnIndex)->text();
        QAction* columnAction = columnMenu.addAction(kHeaderText);
        columnAction->setCheckable(true);
        columnAction->setChecked(!itemTable_->isColumnHidden(columnIndex));
        columnAction->setData(columnIndex);
    }

    QAction* selectedAction = columnMenu.exec(itemTable_->horizontalHeader()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        return;
    }

    const int kColumnIndex = selectedAction->data().toInt();
    if (kColumnIndex < 0 || kColumnIndex >= itemTable_->columnCount())
    {
        return;
    }
    if (!selectedAction->isChecked())
    {
        int visibleColumnCount = 0;
        for (int currentColumn = 0; currentColumn < itemTable_->columnCount(); ++currentColumn)
        {
            if (!itemTable_->isColumnHidden(currentColumn))
            {
                ++visibleColumnCount;
            }
        }
        if (visibleColumnCount <= 1)
        {
            return;
        }
    }

    itemTable_->setColumnHidden(kColumnIndex, !selectedAction->isChecked());
    columnPreset_ = ColumnPreset::kCustom;
    refreshColumnPresetButtonStyles();
    ks::ui::requestTableColumnAutoFit(itemTable_);
}

bool RegistryOptimizationPage::isColumnVisibleInPreset(const int columnIndex, const ColumnPreset preset) const
{
    if (preset == ColumnPreset::kA)
    {
        return columnIndex == kItemNameColumn ||
            columnIndex == kScopeColumn ||
            columnIndex == kCurrentStateColumn ||
            columnIndex == kTargetControlColumn ||
            columnIndex == kActionButtonColumn;
    }
    if (preset == ColumnPreset::kB)
    {
        return columnIndex == kItemNameColumn ||
            columnIndex == kScopeColumn ||
            columnIndex == kTypeColumn ||
            columnIndex == kConditionWarningColumn;
    }
    return !itemTable_->isColumnHidden(columnIndex);
}

const RegistryOptimizationPage::OptimizationState* RegistryOptimizationPage::selectedTargetStateForRow(const int tableRow) const
{
    if (tableRow < 0 || tableRow >= visibleRows_.size()) return nullptr;
    const VisibleRow kRowRef = visibleRows_.at(tableRow);
    if (kRowRef.itemIndex < 0 || kRowRef.itemIndex >= itemList_.size()) return nullptr;
    const OptimizationItem& item = itemList_.at(kRowRef.itemIndex);
    if (kRowRef.scopeIndex < 0 || kRowRef.scopeIndex >= item.scopeList.size()) return nullptr;
    const OptimizationScope& scope = item.scopeList.at(kRowRef.scopeIndex);

    QWidget* targetWidget = itemTable_->cellWidget(tableRow, kTargetControlColumn);
    if (const QComboBox* comboBox = findTargetComboBox(targetWidget))
    {
        const QString kTargetLabel = comboBox->currentData().toString();
        for (const OptimizationState& state : scope.stateList)
        {
            if (state.tagText.compare(QStringLiteral("Dropdown"), Qt::CaseInsensitive) == 0 &&
                state.labelText == kTargetLabel)
            {
                return &state;
            }
        }
        return nullptr;
    }

    const QCheckBox* targetCheckBox = findTargetCheckBox(targetWidget);
    const bool kTargetEnabled = targetCheckBox == nullptr
        ? false
        : targetCheckBox->isChecked();
    const QString kDesiredTag = kTargetEnabled ? QStringLiteral("True") : QStringLiteral("False");
    for (const OptimizationState& state : scope.stateList)
    {
        if (state.tagText.compare(kDesiredTag, Qt::CaseInsensitive) == 0)
        {
            return &state;
        }
    }
    return nullptr;
}

const RegistryOptimizationPage::OptimizationState* RegistryOptimizationPage::detectedStateForScope(const OptimizationScope& scope) const
{
    for (const OptimizationState& state : scope.stateList)
    {
        if (!state.conditionText.trimmed().isEmpty() && evaluateConditionText(state.conditionText))
        {
            return &state;
        }
    }
    return nullptr;
}

bool RegistryOptimizationPage::applyVisibleRow(const int tableRow)
{
    if (stateApplyInProgress_)
    {
        updateStatusText(QStringLiteral("系统优化：已有动作正在应用，请等待完成或点击“取消应用”。"));
        return false;
    }

    cancelStateRefresh();
    if (tableRow < 0 || tableRow >= visibleRows_.size()) return false;
    const VisibleRow kRowRef = visibleRows_.at(tableRow);
    const OptimizationItem& item = itemList_.at(kRowRef.itemIndex);
    const OptimizationScope& scope = item.scopeList.at(kRowRef.scopeIndex);
    const OptimizationState* state = selectedTargetStateForRow(tableRow);
    if (state == nullptr)
    {
        QMessageBox::warning(this, QStringLiteral("系统优化"), QStringLiteral("未找到当前行对应的目标状态。"));
        return false;
    }

    QString warningText;
    if (!item.warningText.isEmpty()) warningText += item.warningText + QLatin1Char('\n');
    if (!state->warningText.isEmpty()) warningText += state->warningText + QLatin1Char('\n');
    const QString kMessageText = QStringLiteral("即将应用：\n%1\n作用域：%2\n目标：%3\n\n%4是否继续？")
        .arg(item.itemNameText, scopeDisplayText(scope.scopeText), state->labelText, warningText);
    if (QMessageBox::question(
            this,
            QStringLiteral("确认系统优化"),
            kMessageText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return false;
    }

    beginStateApply(tableRow, item, scope, *state);
    return true;
}

void RegistryOptimizationPage::beginStateApply(
    const int tableRow,
    const OptimizationItem& item,
    const OptimizationScope& scope,
    const OptimizationState& state)
{
    stateApplyInProgress_ = true;
    stateApplyTableRow_ = tableRow;
    stateApplyItemName_ = item.itemNameText;
    stateApplyTargetLabel_ = state.labelText;
    stateApplyActions_ = state.actionList;
    stateApplyNextActionIndex_ = 0;
    stateApplyActiveAction_ = QJsonObject();
    stateApplyDetailLines_ = {
        QStringLiteral("应用项目: %1").arg(item.itemNameText),
        QStringLiteral("作用域: %1").arg(scopeDisplayText(scope.scopeText)),
        QStringLiteral("目标状态: %1").arg(state.labelText)
    };
    stateApplyAllOk_ = true;
    stateApplyRestartExplorer_ = false;
    // Sequence generation increment: Broadcast actions from the previous round still executing in the background will be identified as expired and discarded upon re-injection.
    setProperty(kStateApplyGenerationProperty, property(kStateApplyGenerationProperty).toULongLong() + 1);
    setApplyControlsEnabled(false);
    detailText_->setLocalizedText(stateApplyDetailLines_.join(QLatin1Char('\n')));

    if (stateApplyActions_.isEmpty())
    {
        stateApplyDetailLines_ << QStringLiteral("该状态没有动作。");
        finishStateApply();
        return;
    }

    updateStatusText(QStringLiteral("系统优化：正在应用 %1 -> %2（共 %3 个动作）。")
        .arg(stateApplyItemName_, stateApplyTargetLabel_)
        .arg(stateApplyActions_.size()));
    QTimer::singleShot(0, this, [this]() { continueStateApply(); });
}

void RegistryOptimizationPage::continueStateApply()
{
    if (!stateApplyInProgress_ || stateApplyProcess_ != nullptr) return;

    if (stateApplyNextActionIndex_ >= stateApplyActions_.size())
    {
        finishStateApply();
        return;
    }

    stateApplyActiveAction_ = stateApplyActions_.at(stateApplyNextActionIndex_);
    const int kActionNumber = stateApplyNextActionIndex_ + 1;
    updateStatusText(QStringLiteral("系统优化：正在应用 %1 -> %2（动作 %3/%4）。")
        .arg(stateApplyItemName_, stateApplyTargetLabel_)
        .arg(kActionNumber)
        .arg(stateApplyActions_.size()));

    if (actionRequiresExternalProcess(stateApplyActiveAction_))
    {
        QString startErrorText;
        if (!startExternalAction(stateApplyActiveAction_, &startErrorText))
        {
            completePendingAction(false, startErrorText);
        }
        return;
    }

    // ExplorerNotify broadcasts wait for responses from each top-level window for HWND_BROADCAST. Busy windows wait for their full timeouts, causing
    // several seconds of UI thread freezing. Execute this on a background thread here, then post back to continue the action sequence upon completion.
    if (actionUsesBlockingBroadcast(stateApplyActiveAction_))
    {
        const QJsonObject kBroadcastAction = stateApplyActiveAction_;
        const QPointer<RegistryOptimizationPage> kGuardedSelf(this);
        const quint64 kRequestGeneration = property(kStateApplyGenerationProperty).toULongLong();
        QThreadPool::globalInstance()->start(
            [kGuardedSelf, kBroadcastAction, kRequestGeneration]()
            {
                const ExplorerNotifyOutcome kOutcome = runExplorerNotifyBroadcast(kBroadcastAction, true);

                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr) { return; }

                QMetaObject::invokeMethod(kAppInstance,
                    [kGuardedSelf, kRequestGeneration, kOutcome]()
                    {
                        if (kGuardedSelf.isNull()) { return; }
                        if (kGuardedSelf->property(kStateApplyGenerationProperty).toULongLong() != kRequestGeneration) { return; }
                        kGuardedSelf->completePendingAction(kOutcome.succeeded, kOutcome.errorTextValue);
                    });
            });
        return;
    }

    QStringList actionDetailLines;
    bool actionRestartExplorer = false;
    const bool kActionOk = executeAction(stateApplyActiveAction_, &actionDetailLines, &actionRestartExplorer);
    stateApplyRestartExplorer_ = stateApplyRestartExplorer_ || actionRestartExplorer;
    stateApplyAllOk_ = stateApplyAllOk_ && kActionOk;
    stateApplyDetailLines_.append(actionDetailLines);
    ++stateApplyNextActionIndex_;
    detailText_->setLocalizedText(stateApplyDetailLines_.join(QLatin1Char('\n')));
    QTimer::singleShot(0, this, [this]() { continueStateApply(); });
}

void RegistryOptimizationPage::completePendingAction(const bool actionOk, const QString& errorText)
{
    if (!stateApplyInProgress_ || stateApplyActiveAction_.isEmpty()) return;

    if (!actionOk)
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("执行系统优化"),
            errorText);
    }

    bool actionRestartExplorer = false;
    QStringList actionDetailLines;
    const QString kSummaryText = jsonString(stateApplyActiveAction_, QStringLiteral("summary"),
        QString::fromUtf8(QJsonDocument(stateApplyActiveAction_).toJson(QJsonDocument::Compact)));
    const QString kRestartText = jsonString(stateApplyActiveAction_, QStringLiteral("activate_restart"));
    actionRestartExplorer = kRestartText.contains(QStringLiteral("Explorer"), Qt::CaseInsensitive);
    const bool kSkippedError = !actionOk && shouldSkipActionError(stateApplyActiveAction_);
    if (kSkippedError)
    {
        actionDetailLines << QStringLiteral("[跳过] %1；原因：%2").arg(kSummaryText, errorText);
    }
    else
    {
        actionDetailLines << (actionOk
            ? QStringLiteral("[成功] %1").arg(kSummaryText)
            : QStringLiteral("[失败] %1；原因：%2").arg(kSummaryText, errorText));
    }

    stateApplyRestartExplorer_ = stateApplyRestartExplorer_ || actionRestartExplorer;
    stateApplyAllOk_ = stateApplyAllOk_ && (actionOk || kSkippedError);
    stateApplyDetailLines_.append(actionDetailLines);
    stateApplyActiveAction_ = QJsonObject();
    ++stateApplyNextActionIndex_;
    detailText_->setLocalizedText(stateApplyDetailLines_.join(QLatin1Char('\n')));
    QTimer::singleShot(0, this, [this]() { continueStateApply(); });
}

void RegistryOptimizationPage::finishStateApply()
{
    if (!stateApplyInProgress_) return;

    if (stateApplyRestartExplorer_)
    {
        stateApplyDetailLines_ << QStringLiteral("提示: 部分动作标记需要重启 Explorer 或重新登录后完全生效。");
    }
    detailText_->setLocalizedText(stateApplyDetailLines_.join(QLatin1Char('\n')));
    refreshVisibleRowState(stateApplyTableRow_);
    const bool kAllOk = stateApplyAllOk_;
    const QString kItemName = stateApplyItemName_;
    const QString kTargetLabel = stateApplyTargetLabel_;
    stateApplyInProgress_ = false;
    stateApplyTableRow_ = -1;
    stateApplyActions_.clear();
    stateApplyActiveAction_ = QJsonObject();
    stateApplyNextActionIndex_ = 0;
    setApplyControlsEnabled(true);
    updateStatusText(kAllOk
        ? QStringLiteral("系统优化：已应用 %1 -> %2。").arg(kItemName, kTargetLabel)
        : QStringLiteral("系统优化：应用失败 %1 -> %2；请查看详情。").arg(kItemName, kTargetLabel));
}

void RegistryOptimizationPage::cancelStateApply(const QString& reasonText)
{
    if (!stateApplyInProgress_) return;

    // Sequence generation increment: do not advance this round (or the next) sequence after broadcast actions still blocking in the background have completed.
    setProperty(kStateApplyGenerationProperty, property(kStateApplyGenerationProperty).toULongLong() + 1);

    if (stateApplyProcess_ != nullptr)
    {
        stateApplyProcess_->disconnect(this);
        stateApplyProcess_->kill();
        stateApplyProcess_->deleteLater();
        stateApplyProcess_ = nullptr;
    }
    delete stateApplyTemporaryDir_;
    stateApplyTemporaryDir_ = nullptr;
    stateApplyZipDestinationPath_.clear();
    if (!reasonText.isEmpty())
    {
        stateApplyDetailLines_ << QStringLiteral("[已取消] %1").arg(reasonText);
        detailText_->setLocalizedText(stateApplyDetailLines_.join(QLatin1Char('\n')));
        updateStatusText(QStringLiteral("系统优化：%1").arg(reasonText));
    }
    stateApplyInProgress_ = false;
    stateApplyTableRow_ = -1;
    stateApplyActions_.clear();
    stateApplyActiveAction_ = QJsonObject();
    stateApplyNextActionIndex_ = 0;
    setApplyControlsEnabled(true);
}

void RegistryOptimizationPage::setApplyControlsEnabled(const bool enabled)
{
    if (itemTable_ != nullptr)
    {
        const QList<QPushButton*> kApplyButtons = itemTable_->findChildren<QPushButton*>(QStringLiteral("registryOptimizationApplyButton"));
        for (QPushButton* button : kApplyButtons)
        {
            button->setEnabled(enabled);
        }
    }
    if (cancelApplyButton_ != nullptr) cancelApplyButton_->setEnabled(!enabled);
    if (refreshStateButton_ != nullptr) refreshStateButton_->setEnabled(enabled && !stateRefreshInProgress_);
}

bool RegistryOptimizationPage::actionRequiresExternalProcess(const QJsonObject& actionObject)
{
    const QString kFamilyText = jsonString(actionObject, QStringLiteral("action_family"),
        jsonString(actionObject, QStringLiteral("action_tag"))).trimmed();
    if (kFamilyText.compare(QStringLiteral("FileCreateByZIP"), Qt::CaseInsensitive) == 0)
    {
        return true;
    }
    if (kFamilyText.compare(QStringLiteral("ExplorerNotify"), Qt::CaseInsensitive) != 0)
    {
        return false;
    }
    return jsonString(actionObject, QStringLiteral("Type")).compare(QStringLiteral("Cmd"), Qt::CaseInsensitive) == 0;
}

bool RegistryOptimizationPage::startExternalAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    if (errorTextOut != nullptr) errorTextOut->clear();
    const QString kFamilyText = jsonString(actionObject, QStringLiteral("action_family"),
        jsonString(actionObject, QStringLiteral("action_tag"))).trimmed();

    QString programPath;
    QStringList arguments;
    if (kFamilyText.compare(QStringLiteral("ExplorerNotify"), Qt::CaseInsensitive) == 0)
    {
        const QString kCommandText = jsonString(actionObject, QStringLiteral("Cmd"));
        if (kCommandText.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("ExplorerNotify Cmd 缺少命令。");
            return false;
        }
        programPath = QStringLiteral("cmd.exe");
        arguments = { QStringLiteral("/c"), kCommandText };
    }
    else if (kFamilyText.compare(QStringLiteral("FileCreateByZIP"), Qt::CaseInsensitive) == 0)
    {
        const QString kDestinationPath = expandEnvironmentPath(jsonString(actionObject, QStringLiteral("Path")));
        const QString kZipReference = jsonString(actionObject, QStringLiteral("ZIPFile"));
        if (kDestinationPath.isEmpty() || kZipReference.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("FileCreateByZIP 缺少 Path 或 ZIPFile。");
            return false;
        }

        QString zipRelativePath;
        QString entryPath;
        if (!splitZipFileReference(kZipReference, &zipRelativePath, &entryPath))
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("ZIPFile 格式无效：%1").arg(kZipReference);
            return false;
        }

        QString zipPath;
        for (const QString& candidate : registryOptimizationAssetCandidates(zipRelativePath))
        {
            if (QFileInfo::exists(candidate))
            {
                zipPath = QDir::cleanPath(candidate);
                break;
            }
        }
        if (zipPath.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("未找到 ZIP 资产：profiles/registry_optimization_assets/%1").arg(zipRelativePath);
            }
            return false;
        }

        stateApplyTemporaryDir_ = new QTemporaryDir();
        if (!stateApplyTemporaryDir_->isValid())
        {
            delete stateApplyTemporaryDir_;
            stateApplyTemporaryDir_ = nullptr;
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("无法创建临时目录用于解压 ZIP。");
            return false;
        }

        programPath = QStringLiteral("tar.exe");
        arguments = {
            QStringLiteral("-xf"),
            QDir::toNativeSeparators(zipPath),
            QStringLiteral("-C"),
            QDir::toNativeSeparators(stateApplyTemporaryDir_->path()),
            QDir::fromNativeSeparators(entryPath)
        };
        stateApplyZipDestinationPath_ = kDestinationPath;
    }
    else
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("不支持的外部动作族：%1").arg(kFamilyText);
        return false;
    }

    QProcess* process = new QProcess(this);
    stateApplyProcess_ = process;
    connect(process, &QProcess::errorOccurred, this, [this, process](const QProcess::ProcessError) {
        if (stateApplyProcess_ != process) return;
        const QString kErrorText = process->errorString();
        stateApplyProcess_ = nullptr;
        process->deleteLater();
        delete stateApplyTemporaryDir_;
        stateApplyTemporaryDir_ = nullptr;
        stateApplyZipDestinationPath_.clear();
        completePendingAction(false, kErrorText);
    });
    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this, process, kFamilyText](const int exitCode, const QProcess::ExitStatus exitStatus) {
            if (stateApplyProcess_ != process) return;
            const QString kStandardError = QString::fromLocal8Bit(process->readAllStandardError()).trimmed();
            stateApplyProcess_ = nullptr;
            process->deleteLater();

            bool actionOk = exitStatus == QProcess::NormalExit && exitCode == 0;
            QString errorText;
            if (!actionOk)
            {
                errorText = kStandardError.isEmpty()
                    ? QStringLiteral("命令退出码：%1").arg(exitCode)
                    : kStandardError;
            }
            else if (kFamilyText.compare(QStringLiteral("FileCreateByZIP"), Qt::CaseInsensitive) == 0)
            {
                QString zipRelativePath;
                QString entryPath;
                splitZipFileReference(jsonString(stateApplyActiveAction_, QStringLiteral("ZIPFile")), &zipRelativePath, &entryPath);
                const QString kExtractedPath = QDir(stateApplyTemporaryDir_->path()).filePath(QDir::fromNativeSeparators(entryPath));
                if (!QFileInfo::exists(kExtractedPath))
                {
                    actionOk = false;
                    errorText = QStringLiteral("ZIP 中未找到条目：%1").arg(QDir::fromNativeSeparators(entryPath));
                }
                else
                {
                    const QFileInfo kDestinationInfo(stateApplyZipDestinationPath_);
                    QDir destinationDirectory = kDestinationInfo.dir();
                    if (!destinationDirectory.exists() && !destinationDirectory.mkpath(QStringLiteral(".")))
                    {
                        actionOk = false;
                        errorText = QStringLiteral("无法创建目标目录：%1").arg(destinationDirectory.absolutePath());
                    }
                    else if (QFileInfo::exists(stateApplyZipDestinationPath_) && !QFile::remove(stateApplyZipDestinationPath_))
                    {
                        actionOk = false;
                        errorText = QStringLiteral("无法覆盖目标文件：%1").arg(stateApplyZipDestinationPath_);
                    }
                    else if (!QFile::copy(kExtractedPath, stateApplyZipDestinationPath_))
                    {
                        actionOk = false;
                        errorText = QStringLiteral("无法复制 ZIP 条目到目标：%1").arg(stateApplyZipDestinationPath_);
                    }
                }
            }

            delete stateApplyTemporaryDir_;
            stateApplyTemporaryDir_ = nullptr;
            stateApplyZipDestinationPath_.clear();
            completePendingAction(actionOk, errorText);
        });
    process->setProgram(programPath);
    process->setArguments(arguments);
    process->start();
    return true;
}

bool RegistryOptimizationPage::executeAction(
    const QJsonObject& actionObject,
    QStringList* detailLinesOut,
    bool* restartExplorerOut)
{
    if (restartExplorerOut != nullptr) *restartExplorerOut = false;
    const QString kFamilyText = jsonString(actionObject, QStringLiteral("action_family"),
        jsonString(actionObject, QStringLiteral("action_tag"))).trimmed();
    const QString kSummaryText = jsonString(actionObject, QStringLiteral("summary"),
        QString::fromUtf8(QJsonDocument(actionObject).toJson(QJsonDocument::Compact)));
    QString errorText;
    bool ok = false;

    if (kFamilyText.compare(QStringLiteral("RegWrite"), Qt::CaseInsensitive) == 0 ||
        kFamilyText.compare(QStringLiteral("RegExist"), Qt::CaseInsensitive) == 0)
    {
        ok = executeRegistryWriteAction(actionObject, &errorText);
    }
    else if (kFamilyText.compare(QStringLiteral("RegDelete"), Qt::CaseInsensitive) == 0 ||
        kFamilyText.compare(QStringLiteral("RegDetete"), Qt::CaseInsensitive) == 0)
    {
        ok = executeRegistryDeleteAction(actionObject, &errorText);
    }
    else if (kFamilyText.compare(QStringLiteral("RegMove"), Qt::CaseInsensitive) == 0)
    {
        ok = executeRegistryMoveAction(actionObject, &errorText);
    }
    else if (kFamilyText.compare(QStringLiteral("SetServiceStart"), Qt::CaseInsensitive) == 0)
    {
        ok = executeServiceStartAction(actionObject, &errorText);
    }
    else if (kFamilyText.compare(QStringLiteral("ExplorerNotify"), Qt::CaseInsensitive) == 0)
    {
        ok = executeExplorerNotifyAction(actionObject, &errorText);
    }
    else if (kFamilyText.compare(QStringLiteral("FileCreateByZIP"), Qt::CaseInsensitive) == 0)
    {
        errorText = QStringLiteral("FileCreateByZIP 必须通过异步外部动作执行。");
        ok = false;
    }
    else
    {
        errorText = QStringLiteral("暂不支持动作族：%1").arg(kFamilyText);
        ok = false;
    }

    const QString kRestartText = jsonString(actionObject, QStringLiteral("activate_restart"));
    if (restartExplorerOut != nullptr && kRestartText.contains(QStringLiteral("Explorer"), Qt::CaseInsensitive))
    {
        *restartExplorerOut = true;
    }

    if (!ok && shouldSkipActionError(actionObject))
    {
        if (detailLinesOut != nullptr) *detailLinesOut << QStringLiteral("[跳过] %1；原因：%2").arg(kSummaryText, errorText);
        return true;
    }
    if (detailLinesOut != nullptr)
    {
        *detailLinesOut << (ok
            ? QStringLiteral("[成功] %1").arg(kSummaryText)
            : QStringLiteral("[失败] %1；原因：%2").arg(kSummaryText, errorText));
    }
    return ok;
}

bool RegistryOptimizationPage::executeRegistryWriteAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    if (errorTextOut != nullptr) errorTextOut->clear();
    const QString kKeyPath = jsonString(actionObject, QStringLiteral("Key"));
    const QString kValueName = jsonString(actionObject, QStringLiteral("Value"));
    const QString kTypeText = jsonString(actionObject, QStringLiteral("Type"), QStringLiteral("REG_DWORD"));
    QString dataText = jsonString(actionObject, QStringLiteral("Data"));
    const QString kOperatorText = jsonString(actionObject, QStringLiteral("Operator"));
    const REGSAM kViewFlags = actionRegistryViewFlags(actionObject);

    if (kKeyPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("RegWrite 缺少 Key。");
        return false;
    }

    DWORD valueType = REG_NONE;
    if (!parseRegistryType(kTypeText, &valueType))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("不支持注册表类型：%1").arg(kTypeText);
        return false;
    }

    if (dataText == QStringLiteral("?ColorDialog()"))
    {
        const QColor kColor = QColorDialog::getColor(Qt::white, this, QStringLiteral("选择注册表颜色值"));
        if (!kColor.isValid())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("用户取消颜色选择。");
            return false;
        }
        const quint32 kColorValue = 0xFF000000U |
            (static_cast<quint32>(kColor.blue()) << 16) |
            (static_cast<quint32>(kColor.green()) << 8) |
            static_cast<quint32>(kColor.red());
        dataText = QStringLiteral("%1").arg(kColorValue, 8, 16, QLatin1Char('0')).toUpper();
    }

    QByteArray newData;
    QString conversionError;
    if (!registryDataFromJsonText(valueType, dataText, &newData, &conversionError))
    {
        if (errorTextOut != nullptr) *errorTextOut = conversionError;
        return false;
    }

    if (!kOperatorText.isEmpty())
    {
        DWORD currentType = valueType;
        QByteArray currentData;
        readRegistryValue(kKeyPath, kValueName, kViewFlags, &currentType, &currentData, nullptr);
        if (valueType == REG_DWORD)
        {
            const quint64 kCurrentValue = currentData.size() >= 4 ? readUnsignedLittleEndian(currentData, 4) : 0;
            const quint64 kMaskValue = readUnsignedLittleEndian(newData, 4);
            const quint64 kUpdatedValue = kOperatorText == QStringLiteral("|")
                ? (kCurrentValue | kMaskValue)
                : (kCurrentValue & kMaskValue);
            newData = writeUnsignedLittleEndian(kUpdatedValue, 4);
        }
        else if (valueType == REG_QWORD)
        {
            const quint64 kCurrentValue = currentData.size() >= 8 ? readUnsignedLittleEndian(currentData, 8) : 0;
            const quint64 kMaskValue = readUnsignedLittleEndian(newData, 8);
            const quint64 kUpdatedValue = kOperatorText == QStringLiteral("|")
                ? (kCurrentValue | kMaskValue)
                : (kCurrentValue & kMaskValue);
            newData = writeUnsignedLittleEndian(kUpdatedValue, 8);
        }
        else if (valueType == REG_BINARY)
        {
            if (currentData.size() < newData.size())
            {
                const int kOldSize = currentData.size();
                currentData.resize(newData.size());
                std::fill(currentData.begin() + kOldSize, currentData.end(), '\0');
            }
            for (int index = 0; index < newData.size(); ++index)
            {
                const unsigned char kCurrentByte = index < currentData.size() ? static_cast<unsigned char>(currentData.at(index)) : 0U;
                const unsigned char kMaskByte = static_cast<unsigned char>(newData.at(index));
                currentData[index] = static_cast<char>(kOperatorText == QStringLiteral("|")
                    ? (kCurrentByte | kMaskByte)
                    : (kCurrentByte & kMaskByte));
            }
            newData = currentData.left(newData.size());
        }
        else
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("Operator 仅支持 REG_DWORD/REG_QWORD/REG_BINARY。");
            return false;
        }
    }

    return writeRegistryValue(kKeyPath, kValueName, valueType, newData, kViewFlags, errorTextOut);
}

bool RegistryOptimizationPage::executeRegistryDeleteAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    const QString kKeyPath = jsonString(actionObject, QStringLiteral("Key"));
    const QString kValueName = jsonString(actionObject, QStringLiteral("Value"));
    if (kKeyPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("RegDelete 缺少 Key。");
        return false;
    }
    const bool kHasValueName = actionObject.contains(QStringLiteral("Value"));
    return deleteRegistryValueOrKey(kKeyPath, kValueName, kHasValueName, actionRegistryViewFlags(actionObject), errorTextOut);
}

bool RegistryOptimizationPage::executeRegistryMoveAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    const QString kKeyPath = jsonString(actionObject, QStringLiteral("Key"));
    const QString kNewKeyPath = jsonString(actionObject, QStringLiteral("NewKey"));
    const QString kValueName = jsonString(actionObject, QStringLiteral("Value"));
    const QString kNewValueName = jsonString(actionObject, QStringLiteral("NewValue"));
    const REGSAM kViewFlags = actionRegistryViewFlags(actionObject);

    if (!kValueName.isEmpty() || !kNewValueName.isEmpty())
    {
        DWORD type = REG_NONE;
        QByteArray data;
        if (!readRegistryValue(kKeyPath, kValueName, kViewFlags, &type, &data, errorTextOut)) return false;
        const QString kTargetKey = kNewKeyPath.isEmpty() ? kKeyPath : kNewKeyPath;
        if (!writeRegistryValue(kTargetKey, kNewValueName, type, data, kViewFlags, errorTextOut)) return false;
        return deleteRegistryValueOrKey(kKeyPath, kValueName, true, kViewFlags, errorTextOut);
    }

    if (kKeyPath.isEmpty() || kNewKeyPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("RegMove 缺少 Key 或 NewKey。");
        return false;
    }
    return renameRegistryKeySameParent(kKeyPath, kNewKeyPath, kViewFlags, errorTextOut);
}

bool RegistryOptimizationPage::executeServiceStartAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    const QString kServiceName = jsonString(actionObject, QStringLiteral("Name"));
    const QString kTypeText = jsonString(actionObject, QStringLiteral("Type"));
    if (kServiceName.isEmpty() || kTypeText.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("SetServiceStart 缺少 Name 或 Type。");
        return false;
    }

    bool ok = false;
    const DWORD kStartType = kTypeText.toULong(&ok, 10);
    if (!ok)
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("服务启动类型无效：%1").arg(kTypeText);
        return false;
    }

    SC_HANDLE managerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (managerHandle == nullptr)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(static_cast<LONG>(::GetLastError()));
        return false;
    }
    SC_HANDLE serviceHandle = ::OpenServiceW(
        managerHandle,
        reinterpret_cast<const wchar_t*>(kServiceName.utf16()),
        SERVICE_CHANGE_CONFIG);
    if (serviceHandle == nullptr)
    {
        const DWORD kErrorCode = ::GetLastError();
        ::CloseServiceHandle(managerHandle);
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(static_cast<LONG>(kErrorCode));
        return false;
    }

    const BOOL kChangeOk = ::ChangeServiceConfigW(
        serviceHandle,
        SERVICE_NO_CHANGE,
        kStartType,
        SERVICE_NO_CHANGE,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    const DWORD kErrorCode = kChangeOk ? ERROR_SUCCESS : ::GetLastError();
    ::CloseServiceHandle(serviceHandle);
    ::CloseServiceHandle(managerHandle);
    if (!kChangeOk)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(static_cast<LONG>(kErrorCode));
        return false;
    }
    return true;
}

bool RegistryOptimizationPage::executeExplorerNotifyAction(const QJsonObject& actionObject, QString* errorTextOut)
{
    const QString kTypeText = jsonString(actionObject, QStringLiteral("Type"));
    if (kTypeText.compare(QStringLiteral("Cmd"), Qt::CaseInsensitive) == 0)
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("ExplorerNotify Cmd 必须通过异步外部动作执行。");
        return false;
    }

    // The normal paths for AssocChanged / Custom have been redirected to a background thread by continueStateApply;
    // Here, only the synchronous fallback is retained (COM is not re-initialized; the UI thread apartment is managed by Qt).
    const ExplorerNotifyOutcome kOutcome = runExplorerNotifyBroadcast(actionObject, false);
    if (!kOutcome.succeeded && errorTextOut != nullptr)
    {
        *errorTextOut = kOutcome.errorTextValue;
    }
    return kOutcome.succeeded;
}

bool RegistryOptimizationPage::evaluateConditionText(const QString& conditionText)
{
    const QString kTrimmedCondition = conditionText.trimmed();
    if (kTrimmedCondition.isEmpty()) return false;
    ConditionParser parser(kTrimmedCondition);
    return parser.evaluate();
}
