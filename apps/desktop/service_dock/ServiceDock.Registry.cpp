#include "ServiceDock.Internal.h"

#include <vector>

namespace
{
    // kServicesRegistryPath: Unified registry root path for SCM service configurations.
    constexpr wchar_t kServicesRegistryPath[] = L"SYSTEM\\CurrentControlSet\\Services";

    // clearRegistryErrorOutputs: Clears optional error output before each registry operation.
    // Input parameters: errorTextOut/errorCodeOut are optional output pointers provided by the caller.
    // Returns: Nothing.
    void clearRegistryErrorOutputs(QString* errorTextOut, DWORD* errorCodeOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
    }

    // setRegistryError: Unify Win32 registry errors into UI-readable text.
    // Input: operationText is the operation phase; errorCode is the Win32 error code.
    // Returns: Always returns false to allow callers to directly return.
    bool setRegistryError(
        const QString& operationText,
        const DWORD errorCode,
        QString* errorTextOut,
        DWORD* errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = errorCode;
        }
        if (errorTextOut != nullptr)
        {
            const QString kWin32Text = QString::fromUtf8(
                ks::service::formatWin32ErrorText(errorCode).c_str());
            *errorTextOut = QStringLiteral("%1失败：%2")
                .arg(operationText, kWin32Text);
        }
        return false;
    }

    // isValidServiceName: Restricts the registry deletion target to direct subkeys of the Services root key.
    // Input: serviceNameText is the short name of the service selected by the UI.
    // Returns: true if the string is non-empty and contains no path traversal characters.
    bool isValidServiceName(const QString& serviceNameText)
    {
        const QString kNormalizedNameText = serviceNameText.trimmed();
        return !kNormalizedNameText.isEmpty()
            && kNormalizedNameText != QStringLiteral(".")
            && kNormalizedNameText != QStringLiteral("..")
            && !kNormalizedNameText.contains(QLatin1Char('\\'))
            && !kNormalizedNameText.contains(QLatin1Char('/'));
    }

    // queryRegistryString purpose: reads REG_SZ/REG_EXPAND_SZ, preserving the original unexpanded text.
    // Parameters: openedKey is an already opened key; valueName is the value name; valueTextOut receives the string.
    // Returns: true if the value exists and its type is acceptable.
    bool queryRegistryString(
        const HKEY openedKey,
        const wchar_t* valueName,
        QString* valueTextOut)
    {
        if (openedKey == nullptr || valueName == nullptr || valueTextOut == nullptr)
        {
            return false;
        }
        valueTextOut->clear();

        DWORD valueType = 0;
        DWORD requiredBytes = 0;
        LONG queryResult = ::RegQueryValueExW(
            openedKey,
            valueName,
            nullptr,
            &valueType,
            nullptr,
            &requiredBytes);
        if (queryResult != ERROR_SUCCESS
            || requiredBytes == 0
            || (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return false;
        }

        std::vector<wchar_t> valueBuffer(
            static_cast<std::size_t>(requiredBytes / sizeof(wchar_t)) + 2,
            L'\0');
        queryResult = ::RegQueryValueExW(
            openedKey,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer.data()),
            &requiredBytes);
        if (queryResult != ERROR_SUCCESS)
        {
            return false;
        }

        valueBuffer.back() = L'\0';
        *valueTextOut = QString::fromWCharArray(valueBuffer.data()).trimmed();
        return true;
    }

    // queryRegistryDword purpose: Reads a REG_DWORD configuration value.
    // Input parameters: openedKey/valueName specify the target; valueOut receives the DWORD.
    // Returns: true if the value exists and has the correct length and type.
    bool queryRegistryDword(
        const HKEY openedKey,
        const wchar_t* valueName,
        DWORD* valueOut)
    {
        if (openedKey == nullptr || valueName == nullptr || valueOut == nullptr)
        {
            return false;
        }

        DWORD valueType = 0;
        DWORD valueBytes = sizeof(DWORD);
        DWORD value = 0;
        const LONG kQueryResult = ::RegQueryValueExW(
            openedKey,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(&value),
            &valueBytes);
        if (kQueryResult != ERROR_SUCCESS
            || valueType != REG_DWORD
            || valueBytes != sizeof(DWORD))
        {
            return false;
        }

        *valueOut = value;
        return true;
    }

    // populateRegistrySnapshot purpose: Read basic configuration fields from an opened service key.
    // Input parameters: openedKey is Services\\<name>; snapshotOut is pre-populated with the service name.
    // Returns: None; each has* flag precisely describes whether the corresponding field exists.
    void populateRegistrySnapshot(
        const HKEY openedKey,
        service_dock_detail::RegistryServiceSnapshot* snapshotOut)
    {
        if (openedKey == nullptr || snapshotOut == nullptr)
        {
            return;
        }

        snapshotOut->keyReadable = true;
        (void)queryRegistryString(openedKey, L"DisplayName", &snapshotOut->displayNameText);
        (void)queryRegistryString(openedKey, L"Description", &snapshotOut->descriptionText);
        (void)queryRegistryString(openedKey, L"ImagePath", &snapshotOut->binaryPathText);
        (void)queryRegistryString(openedKey, L"ObjectName", &snapshotOut->accountText);

        HKEY parametersKey = nullptr;
        const LONG kOpenParametersResult = ::RegOpenKeyExW(
            openedKey,
            L"Parameters",
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &parametersKey);
        if (kOpenParametersResult == ERROR_SUCCESS && parametersKey != nullptr)
        {
            (void)queryRegistryString(
                parametersKey,
                L"ServiceDll",
                &snapshotOut->serviceDllPathText);
            ::RegCloseKey(parametersKey);
        }

        snapshotOut->hasServiceType = queryRegistryDword(
            openedKey,
            L"Type",
            &snapshotOut->serviceTypeValue);
        snapshotOut->hasStartType = queryRegistryDword(
            openedKey,
            L"Start",
            &snapshotOut->startTypeValue);
        snapshotOut->hasErrorControl = queryRegistryDword(
            openedKey,
            L"ErrorControl",
            &snapshotOut->errorControlValue);

        DWORD delayedAutoStartValue = 0;
        snapshotOut->delayedAutoStart = queryRegistryDword(
            openedKey,
            L"DelayedAutostart",
            &delayedAutoStartValue)
            && delayedAutoStartValue != 0;
    }
}

bool service_dock_detail::enumerateRegistryServiceSnapshots(
    std::vector<RegistryServiceSnapshot>* snapshotListOut,
    QString* errorTextOut,
    DWORD* errorCodeOut)
{
    clearRegistryErrorOutputs(errorTextOut, errorCodeOut);
    if (snapshotListOut == nullptr)
    {
        return setRegistryError(
            QStringLiteral("准备注册表服务扫描"),
            ERROR_INVALID_PARAMETER,
            errorTextOut,
            errorCodeOut);
    }
    snapshotListOut->clear();

    HKEY servicesRootKey = nullptr;
    const LONG kOpenRootResult = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kServicesRegistryPath,
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &servicesRootKey);
    if (kOpenRootResult != ERROR_SUCCESS || servicesRootKey == nullptr)
    {
        return setRegistryError(
            QStringLiteral("打开 Services 注册表根键"),
            static_cast<DWORD>(kOpenRootResult),
            errorTextOut,
            errorCodeOut);
    }

    DWORD subKeyCount = 0;
    DWORD maximumSubKeyLength = 0;
    const LONG kInfoResult = ::RegQueryInfoKeyW(
        servicesRootKey,
        nullptr,
        nullptr,
        nullptr,
        &subKeyCount,
        &maximumSubKeyLength,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    if (kInfoResult != ERROR_SUCCESS)
    {
        ::RegCloseKey(servicesRootKey);
        return setRegistryError(
            QStringLiteral("读取 Services 注册表根键信息"),
            static_cast<DWORD>(kInfoResult),
            errorTextOut,
            errorCodeOut);
    }

    snapshotListOut->reserve(subKeyCount);
    std::vector<wchar_t> nameBuffer(
        static_cast<std::size_t>(maximumSubKeyLength) + 2,
        L'\0');
    for (DWORD subKeyIndex = 0;; ++subKeyIndex)
    {
        DWORD serviceNameLength = static_cast<DWORD>(nameBuffer.size() - 1);
        FILETIME lastWriteTime{};
        LONG enumerateResult = ::RegEnumKeyExW(
            servicesRootKey,
            subKeyIndex,
            nameBuffer.data(),
            &serviceNameLength,
            nullptr,
            nullptr,
            nullptr,
            &lastWriteTime);
        if (enumerateResult == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        if (enumerateResult == ERROR_MORE_DATA)
        {
            nameBuffer.resize(nameBuffer.size() * 2, L'\0');
            --subKeyIndex;
            continue;
        }
        if (enumerateResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(servicesRootKey);
            return setRegistryError(
                QStringLiteral("枚举 Services 注册表子键"),
                static_cast<DWORD>(enumerateResult),
                errorTextOut,
                errorCodeOut);
        }

        RegistryServiceSnapshot snapshot;
        snapshot.serviceNameText = QString::fromWCharArray(
            nameBuffer.data(),
            static_cast<qsizetype>(serviceNameLength)).trimmed();

        HKEY serviceKey = nullptr;
        const LONG kOpenServiceResult = ::RegOpenKeyExW(
            servicesRootKey,
            nameBuffer.data(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &serviceKey);
        if (kOpenServiceResult == ERROR_SUCCESS && serviceKey != nullptr)
        {
            populateRegistrySnapshot(serviceKey, &snapshot);
            ::RegCloseKey(serviceKey);
        }
        snapshotListOut->push_back(std::move(snapshot));
    }

    ::RegCloseKey(servicesRootKey);
    return true;
}

bool service_dock_detail::queryRegistryServiceSnapshot(
    const QString& serviceNameText,
    RegistryServiceSnapshot* snapshotOut,
    QString* errorTextOut,
    DWORD* errorCodeOut)
{
    clearRegistryErrorOutputs(errorTextOut, errorCodeOut);
    if (snapshotOut == nullptr || !isValidServiceName(serviceNameText))
    {
        return setRegistryError(
            QStringLiteral("校验服务注册表目标"),
            ERROR_INVALID_PARAMETER,
            errorTextOut,
            errorCodeOut);
    }

    const QString kNormalizedNameText = serviceNameText.trimmed();
    const QString kRelativePathText = QStringLiteral("%1\\%2")
        .arg(QString::fromWCharArray(kServicesRegistryPath), kNormalizedNameText);
    HKEY serviceKey = nullptr;
    const LONG kOpenResult = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        reinterpret_cast<LPCWSTR>(kRelativePathText.utf16()),
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &serviceKey);
    if (kOpenResult != ERROR_SUCCESS || serviceKey == nullptr)
    {
        return setRegistryError(
            QStringLiteral("打开服务注册表键"),
            static_cast<DWORD>(kOpenResult),
            errorTextOut,
            errorCodeOut);
    }

    RegistryServiceSnapshot snapshot;
    snapshot.serviceNameText = kNormalizedNameText;
    populateRegistrySnapshot(serviceKey, &snapshot);
    ::RegCloseKey(serviceKey);

    *snapshotOut = std::move(snapshot);
    return true;
}

bool service_dock_detail::deleteRegistryServiceKey(
    const QString& serviceNameText,
    QString* errorTextOut,
    DWORD* errorCodeOut)
{
    clearRegistryErrorOutputs(errorTextOut, errorCodeOut);
    if (!isValidServiceName(serviceNameText))
    {
        return setRegistryError(
            QStringLiteral("校验待删除服务注册表目标"),
            ERROR_INVALID_PARAMETER,
            errorTextOut,
            errorCodeOut);
    }

    HKEY servicesRootKey = nullptr;
    const LONG kOpenRootResult = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kServicesRegistryPath,
        0,
        KEY_WRITE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
        &servicesRootKey);
    if (kOpenRootResult != ERROR_SUCCESS || servicesRootKey == nullptr)
    {
        return setRegistryError(
            QStringLiteral("打开可写 Services 注册表根键"),
            static_cast<DWORD>(kOpenRootResult),
            errorTextOut,
            errorCodeOut);
    }

    const std::wstring kServiceNameWide = serviceNameText.trimmed().toStdWString();
    const LONG kDeleteResult = ::RegDeleteTreeW(
        servicesRootKey,
        kServiceNameWide.c_str());
    ::RegCloseKey(servicesRootKey);
    if (kDeleteResult != ERROR_SUCCESS && kDeleteResult != ERROR_FILE_NOT_FOUND)
    {
        return setRegistryError(
            QStringLiteral("删除服务注册表键树"),
            static_cast<DWORD>(kDeleteResult),
            errorTextOut,
            errorCodeOut);
    }
    return true;
}
