#include "NetworkDock.InternalCommon.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include <cmath>
#include <limits>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace
{
    constexpr wchar_t kRecoveryParentPath[] =
        L"Software\\KSword\\NetworkDock";
    constexpr wchar_t kRecoverySubKey[] = L"HttpsProxyRecovery";
    constexpr wchar_t kRecoveryPath[] =
        L"Software\\KSword\\NetworkDock\\HttpsProxyRecovery";
    constexpr wchar_t kPendingValueName[] = L"Pending";
    constexpr wchar_t kSnapshotValueName[] = L"Snapshot";
    constexpr int kRecoveryFormatVersion = 1;
    constexpr DWORD kMaxSnapshotBytes = 128 * 1024;

    constexpr char kSchemaKey[] = "schema";
    constexpr char kSchemaValue[] = "ksword-https-proxy-recovery";
    constexpr char kVersionKey[] = "version";
    constexpr char kPresentKey[] = "present";
    constexpr char kValueKey[] = "value";
    constexpr char kProxyEnableKey[] = "proxy_enable";
    constexpr char kAutoDetectKey[] = "auto_detect";
    constexpr char kProxyServerKey[] = "proxy_server";
    constexpr char kProxyOverrideKey[] = "proxy_override";
    constexpr char kAutoConfigUrlKey[] = "auto_config_url";

    // setRecoveryError: Combine the persistent phase with the Win32 status to avoid errors being reduced to just numbers.
    void setRecoveryError(
        QString* errorTextOut,
        const QString& operationText,
        const LONG resultCode)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("%1，Win32=%2")
                .arg(operationText)
                .arg(resultCode);
        }
    }

    // optionalDwordToJson: Preserves whether the value exists, distinguishing between a missing value and DWORD 0.
    QJsonObject optionalDwordToJson(
        const std::optional<std::uint32_t>& value)
    {
        QJsonObject object;
        object.insert(
            QString::fromLatin1(kPresentKey),
            value.has_value());
        if (value.has_value())
        {
            object.insert(
                QString::fromLatin1(kValueKey),
                static_cast<qint64>(*value));
        }
        return object;
    }

    // optionalStringToJson: Preserves both the existence of the value and distinguishes between default and empty string.
    QJsonObject optionalStringToJson(
        const std::optional<QString>& value)
    {
        QJsonObject object;
        object.insert(
            QString::fromLatin1(kPresentKey),
            value.has_value());
        if (value.has_value())
        {
            object.insert(QString::fromLatin1(kValueKey), *value);
        }
        return object;
    }

    // parseOptionalDword: Strictly validates the existence flag, integer range, and JSON type.
    bool parseOptionalDword(
        const QJsonObject& rootObject,
        const char* fieldName,
        std::optional<std::uint32_t>* valueOut,
        QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        const QJsonValue kFieldValue =
            rootObject.value(QString::fromLatin1(fieldName));
        if (!kFieldValue.isObject())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照缺少 DWORD 字段：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }

        const QJsonObject kFieldObject = kFieldValue.toObject();
        const QJsonValue kPresentValue =
            kFieldObject.value(QString::fromLatin1(kPresentKey));
        if (!kPresentValue.isBool())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照存在标记无效：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }
        if (!kPresentValue.toBool())
        {
            valueOut->reset();
            return true;
        }

        const QJsonValue kDataValue =
            kFieldObject.value(QString::fromLatin1(kValueKey));
        if (!kDataValue.isDouble())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照 DWORD 值无效：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }

        const double kNumericValue = kDataValue.toDouble();
        if (!std::isfinite(kNumericValue)
            || kNumericValue < 0.0
            || kNumericValue
                > static_cast<double>(
                    std::numeric_limits<std::uint32_t>::max())
            || std::floor(kNumericValue) != kNumericValue)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照 DWORD 超出范围：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }

        *valueOut = static_cast<std::uint32_t>(kNumericValue);
        return true;
    }

    // parseOptionalString: Strictly validates the existence flag and string type.
    bool parseOptionalString(
        const QJsonObject& rootObject,
        const char* fieldName,
        std::optional<QString>* valueOut,
        QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        const QJsonValue kFieldValue =
            rootObject.value(QString::fromLatin1(fieldName));
        if (!kFieldValue.isObject())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照缺少字符串字段：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }

        const QJsonObject kFieldObject = kFieldValue.toObject();
        const QJsonValue kPresentValue =
            kFieldObject.value(QString::fromLatin1(kPresentKey));
        if (!kPresentValue.isBool())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照存在标记无效：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }
        if (!kPresentValue.toBool())
        {
            valueOut->reset();
            return true;
        }

        const QJsonValue kDataValue =
            kFieldObject.value(QString::fromLatin1(kValueKey));
        if (!kDataValue.isString())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "HTTPS 代理恢复快照字符串值无效：%1")
                    .arg(QString::fromLatin1(fieldName));
            }
            return false;
        }

        *valueOut = kDataValue.toString();
        return true;
    }
}

bool NetworkDock::persistHttpsSystemProxyRecoveryTransaction(
    const std::optional<std::uint32_t>& proxyEnable,
    const std::optional<std::uint32_t>& autoDetect,
    const std::optional<QString>& proxyServer,
    const std::optional<QString>& proxyOverride,
    const std::optional<QString>& autoConfigUrl,
    QString* errorTextOut) const
{
    // Published transactions must be consumed by the startup recovery chain and cannot be overwritten by new snapshots.
    HKEY existingKey = nullptr;
    LONG resultCode = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kRecoveryPath,
        0,
        KEY_READ,
        &existingKey);
    if (resultCode == ERROR_SUCCESS && existingKey != nullptr)
    {
        DWORD pendingValue = 0;
        DWORD valueType = REG_NONE;
        DWORD byteCount = sizeof(pendingValue);
        const LONG kPendingResult = ::RegQueryValueExW(
            existingKey,
            kPendingValueName,
            nullptr,
            &valueType,
            reinterpret_cast<BYTE*>(&pendingValue),
            &byteCount);
        ::RegCloseKey(existingKey);
        const bool kValidPendingValue = kPendingResult == ERROR_SUCCESS
            && valueType == REG_DWORD
            && byteCount == sizeof(pendingValue)
            && (pendingValue == 0 || pendingValue == 1);
        if (kValidPendingValue && pendingValue == 1)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral(
                    "检测到尚未完成的 HTTPS 代理恢复事务，拒绝覆盖原始快照。");
            }
            return false;
        }
        if (kPendingResult != ERROR_FILE_NOT_FOUND && !kValidPendingValue)
        {
            setRecoveryError(
                errorTextOut,
                QStringLiteral("现有 HTTPS 代理恢复事务标记损坏"),
                kPendingResult == ERROR_SUCCESS
                    ? ERROR_INVALID_DATA
                    : kPendingResult);
            return false;
        }
    }
    else if (resultCode != ERROR_FILE_NOT_FOUND)
    {
        setRecoveryError(
            errorTextOut,
            QStringLiteral("检查 HTTPS 代理恢复事务失败"),
            resultCode);
        return false;
    }

    // Unpublished partial work can be safely cleaned up because the system proxy has not yet entered the rewrite phase.
    if (!clearHttpsSystemProxyRecoveryTransaction(errorTextOut))
    {
        return false;
    }

    QJsonObject snapshotObject;
    snapshotObject.insert(
        QString::fromLatin1(kSchemaKey),
        QString::fromLatin1(kSchemaValue));
    snapshotObject.insert(
        QString::fromLatin1(kVersionKey),
        kRecoveryFormatVersion);
    snapshotObject.insert(
        QString::fromLatin1(kProxyEnableKey),
        optionalDwordToJson(proxyEnable));
    snapshotObject.insert(
        QString::fromLatin1(kAutoDetectKey),
        optionalDwordToJson(autoDetect));
    snapshotObject.insert(
        QString::fromLatin1(kProxyServerKey),
        optionalStringToJson(proxyServer));
    snapshotObject.insert(
        QString::fromLatin1(kProxyOverrideKey),
        optionalStringToJson(proxyOverride));
    snapshotObject.insert(
        QString::fromLatin1(kAutoConfigUrlKey),
        optionalStringToJson(autoConfigUrl));
    const QByteArray kSnapshotBytes =
        QJsonDocument(snapshotObject).toJson(QJsonDocument::Compact);
    if (kSnapshotBytes.isEmpty()
        || kSnapshotBytes.size() > static_cast<qsizetype>(kMaxSnapshotBytes))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "HTTPS 代理恢复快照大小无效：%1 字节")
                .arg(kSnapshotBytes.size());
        }
        return false;
    }

    HKEY recoveryKey = nullptr;
    resultCode = ::RegCreateKeyExW(
        HKEY_CURRENT_USER,
        kRecoveryPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &recoveryKey,
        nullptr);
    if (resultCode != ERROR_SUCCESS || recoveryKey == nullptr)
    {
        setRecoveryError(
            errorTextOut,
            QStringLiteral("创建 HTTPS 代理恢复事务失败"),
            resultCode);
        return false;
    }

    bool pendingPublished = false;
    resultCode = ::RegSetValueExW(
        recoveryKey,
        kSnapshotValueName,
        0,
        REG_BINARY,
        reinterpret_cast<const BYTE*>(kSnapshotBytes.constData()),
        static_cast<DWORD>(kSnapshotBytes.size()));
    if (resultCode == ERROR_SUCCESS)
    {
        const DWORD kPendingValue = 1;
        resultCode = ::RegSetValueExW(
            recoveryKey,
            kPendingValueName,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&kPendingValue),
            sizeof(kPendingValue));
        pendingPublished = resultCode == ERROR_SUCCESS;
    }
    if (resultCode == ERROR_SUCCESS)
    {
        // Pending must be flushed to disk first; callers are then allowed to write Internet Settings.
        resultCode = ::RegFlushKey(recoveryKey);
    }
    ::RegCloseKey(recoveryKey);

    if (resultCode != ERROR_SUCCESS)
    {
        setRecoveryError(
            errorTextOut,
            pendingPublished
                ? QStringLiteral("持久化 HTTPS 代理恢复事务失败")
                : QStringLiteral("写入 HTTPS 代理恢复事务失败"),
            resultCode);
        if (!pendingPublished)
        {
            QString cleanupError;
            (void)clearHttpsSystemProxyRecoveryTransaction(&cleanupError);
        }
        return false;
    }
    return true;
}

bool NetworkDock::loadHttpsSystemProxyRecoveryTransaction(
    bool* pendingOut,
    std::optional<std::uint32_t>* proxyEnableOut,
    std::optional<std::uint32_t>* autoDetectOut,
    std::optional<QString>* proxyServerOut,
    std::optional<QString>* proxyOverrideOut,
    std::optional<QString>* autoConfigUrlOut,
    QString* errorTextOut) const
{
    if (pendingOut == nullptr
        || proxyEnableOut == nullptr
        || autoDetectOut == nullptr
        || proxyServerOut == nullptr
        || proxyOverrideOut == nullptr
        || autoConfigUrlOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("HTTPS 代理恢复事务输出对象为空。");
        }
        return false;
    }

    *pendingOut = false;
    proxyEnableOut->reset();
    autoDetectOut->reset();
    proxyServerOut->reset();
    proxyOverrideOut->reset();
    autoConfigUrlOut->reset();

    HKEY recoveryKey = nullptr;
    LONG resultCode = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kRecoveryPath,
        0,
        KEY_READ,
        &recoveryKey);
    if (resultCode == ERROR_FILE_NOT_FOUND)
    {
        return true;
    }
    if (resultCode != ERROR_SUCCESS || recoveryKey == nullptr)
    {
        setRecoveryError(
            errorTextOut,
            QStringLiteral("打开 HTTPS 代理恢复事务失败"),
            resultCode);
        return false;
    }

    DWORD pendingValue = 0;
    DWORD valueType = REG_NONE;
    DWORD byteCount = sizeof(pendingValue);
    resultCode = ::RegQueryValueExW(
        recoveryKey,
        kPendingValueName,
        nullptr,
        &valueType,
        reinterpret_cast<BYTE*>(&pendingValue),
        &byteCount);
    if (resultCode == ERROR_FILE_NOT_FOUND)
    {
        ::RegCloseKey(recoveryKey);
        return true;
    }
    if (resultCode != ERROR_SUCCESS
        || valueType != REG_DWORD
        || byteCount != sizeof(pendingValue)
        || pendingValue != 1)
    {
        ::RegCloseKey(recoveryKey);
        setRecoveryError(
            errorTextOut,
            QStringLiteral("HTTPS 代理恢复事务 Pending 标记无效"),
            resultCode == ERROR_SUCCESS ? ERROR_INVALID_DATA : resultCode);
        return false;
    }
    *pendingOut = true;

    valueType = REG_NONE;
    byteCount = 0;
    resultCode = ::RegQueryValueExW(
        recoveryKey,
        kSnapshotValueName,
        nullptr,
        &valueType,
        nullptr,
        &byteCount);
    if (resultCode != ERROR_SUCCESS
        || valueType != REG_BINARY
        || byteCount == 0
        || byteCount > kMaxSnapshotBytes)
    {
        ::RegCloseKey(recoveryKey);
        setRecoveryError(
            errorTextOut,
            QStringLiteral("读取 HTTPS 代理恢复快照失败"),
            resultCode == ERROR_SUCCESS ? ERROR_INVALID_DATA : resultCode);
        return false;
    }

    std::vector<char> snapshotBuffer(
        static_cast<std::size_t>(byteCount));
    resultCode = ::RegQueryValueExW(
        recoveryKey,
        kSnapshotValueName,
        nullptr,
        &valueType,
        reinterpret_cast<BYTE*>(snapshotBuffer.data()),
        &byteCount);
    ::RegCloseKey(recoveryKey);
    if (resultCode != ERROR_SUCCESS)
    {
        setRecoveryError(
            errorTextOut,
            QStringLiteral("读取 HTTPS 代理恢复快照失败"),
            resultCode);
        return false;
    }

    const QByteArray kSnapshotBytes(
        snapshotBuffer.data(),
        static_cast<qsizetype>(byteCount));
    QJsonParseError parseError;
    const QJsonDocument kSnapshotDocument =
        QJsonDocument::fromJson(kSnapshotBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError
        || !kSnapshotDocument.isObject())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "解析 HTTPS 代理恢复快照失败：%1")
                .arg(parseError.errorString());
        }
        return false;
    }

    const QJsonObject kSnapshotObject = kSnapshotDocument.object();
    const QJsonValue kSchemaValueValue =
        kSnapshotObject.value(QString::fromLatin1(kSchemaKey));
    const QJsonValue kVersionValue =
        kSnapshotObject.value(QString::fromLatin1(kVersionKey));
    if (!kSchemaValueValue.isString()
        || kSchemaValueValue.toString() != QString::fromLatin1(kSchemaValue)
        || !kVersionValue.isDouble()
        || kVersionValue.toInt(-1) != kRecoveryFormatVersion)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "HTTPS 代理恢复快照格式或版本不受支持。");
        }
        return false;
    }

    return parseOptionalDword(
            kSnapshotObject,
            kProxyEnableKey,
            proxyEnableOut,
            errorTextOut)
        && parseOptionalDword(
            kSnapshotObject,
            kAutoDetectKey,
            autoDetectOut,
            errorTextOut)
        && parseOptionalString(
            kSnapshotObject,
            kProxyServerKey,
            proxyServerOut,
            errorTextOut)
        && parseOptionalString(
            kSnapshotObject,
            kProxyOverrideKey,
            proxyOverrideOut,
            errorTextOut)
        && parseOptionalString(
            kSnapshotObject,
            kAutoConfigUrlKey,
            autoConfigUrlOut,
            errorTextOut);
}

bool NetworkDock::clearHttpsSystemProxyRecoveryTransaction(
    QString* errorTextOut) const
{
    HKEY parentKey = nullptr;
    LONG resultCode = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        kRecoveryParentPath,
        0,
        DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE,
        &parentKey);
    if (resultCode == ERROR_FILE_NOT_FOUND)
    {
        return true;
    }
    if (resultCode != ERROR_SUCCESS || parentKey == nullptr)
    {
        setRecoveryError(
            errorTextOut,
            QStringLiteral("打开 HTTPS 代理恢复事务父键失败"),
            resultCode);
        return false;
    }

    resultCode = ::RegDeleteTreeW(parentKey, kRecoverySubKey);
    if (resultCode == ERROR_SUCCESS || resultCode == ERROR_FILE_NOT_FOUND)
    {
        resultCode = ::RegFlushKey(parentKey);
    }
    ::RegCloseKey(parentKey);
    if (resultCode == ERROR_SUCCESS)
    {
        return true;
    }
    setRecoveryError(
        errorTextOut,
        QStringLiteral("清除 HTTPS 代理恢复事务失败"),
        resultCode);
    return false;
}

bool NetworkDock::recoverPendingHttpsSystemProxyTransaction(
    bool* recoveredOut,
    QString* errorTextOut)
{
    if (recoveredOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("HTTPS 代理恢复结果输出对象为空。");
        }
        httpsProxyRecoveryRequired_ = true;
        return false;
    }
    *recoveredOut = false;

    bool pending = false;
    std::optional<std::uint32_t> previousProxyEnable;
    std::optional<std::uint32_t> previousAutoDetect;
    std::optional<QString> previousProxyServer;
    std::optional<QString> previousProxyOverride;
    std::optional<QString> previousAutoConfigUrl;
    QString errorText;
    if (!loadHttpsSystemProxyRecoveryTransaction(
            &pending,
            &previousProxyEnable,
            &previousAutoDetect,
            &previousProxyServer,
            &previousProxyOverride,
            &previousAutoConfigUrl,
            &errorText))
    {
        httpsProxyRecoveryRequired_ = true;
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }
    if (!pending)
    {
        return true;
    }

    httpsPreviousProxyEnable_ = previousProxyEnable;
    httpsPreviousAutoDetect_ = previousAutoDetect;
    httpsPreviousProxyServer_ = previousProxyServer;
    httpsPreviousProxyOverride_ = previousProxyOverride;
    httpsPreviousAutoConfigUrl_ = previousAutoConfigUrl;
    httpsSystemProxySnapshotCaptured_ = true;
    httpsProxyRecoveryRequired_ = true;
    if (!restoreHttpsSystemProxySnapshot(&errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    *recoveredOut = true;
    return true;
}
