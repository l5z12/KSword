#include "RegistryDock.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../internationalization/LanguageManager.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "RegistryOptimizationPage.h"

// ============================================================
// RegistryDock.cpp
// Notes:
// 1) Provides key tree navigation and key-value editing similar to regedit;
// 2) Support import/export of .reg files;
// 3) Support background search to avoid blocking the UI.
// ============================================================

#include "../Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

namespace
{
    // Unified button style: consistent with the main interface theme.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // Unified input style: path and search bars reuse the same style.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // Header style: improves readability for information-dense lists.
    QString blueHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // TreeItem role constants: Store path and lazy-load status.
    constexpr int kRolePath = Qt::UserRole + 1;
    constexpr int kRoleLoaded = Qt::UserRole + 2;
    constexpr int kRolePlaceholder = Qt::UserRole + 3;
    // kRoleLoadToken: Lazy-loading token for subkeys; non-0 indicates a background enumeration is already in progress for that node.
    // Use this to discard stale results replaced by new requests when background results are dispatched to the UI thread.
    constexpr int kRoleLoadToken = Qt::UserRole + 4;

    // Sub-key lazy-load throttling: maximum number of sub-nodes created per UI thread event loop iteration.
    // Huge keys like HKCR have tens of thousands of subkeys; constructing them all at once would freeze the UI for several seconds.
    constexpr int kSubKeyItemBatchSize = 300;

    // kPendingTreeSelectionProperty：
    // - Purpose: Attach the "pending tree selection path" to the dynamic property of the key tree control;
    // - Note: After changing subkey loading to asynchronous, path resolution must proceed incrementally; after background commit, continue descending using this property.
    //         Use dynamic properties instead of member variables to avoid modifying shared headers for asynchronous lookups.
    constexpr const char* kPendingTreeSelectionProperty = "kswordPendingTreeSelectionPath";

    // g_nextSubKeyLoadToken：
    // - Purpose: A globally monotonically increasing lazy-load token generator that ensures new requests for the same node always evict old requests.
    std::atomic<quint64> gNextSubKeyLoadToken{ 1 };

    // Search result throttling: limit background backlog and table object count to ensure UI remains interactive even with a large number of hits.
    constexpr std::size_t kMaxPendingSearchRows = 4096;
    constexpr std::size_t kSearchFlushBatchSize = 160;
    constexpr int kMaxSearchResultRows = 20000;

    // Search result roles: display text varies by language and default value format, so handling must use raw metadata.
    constexpr int kSearchResultRoleTargetKind = Qt::UserRole + 40;
    constexpr int kSearchResultRoleRawValueName = Qt::UserRole + 41;
    constexpr int kSearchResultTargetKey = 1;
    constexpr int kSearchResultTargetValue = 2;

    // Root key mapping structure: supports both full name and abbreviation inputs.
    struct RootEntry
    {
        const wchar_t* fullName = nullptr;
        const wchar_t* shortName = nullptr;
        HKEY root = nullptr;
    };

    const std::array<RootEntry, 5> kRootMap{
        RootEntry{ L"HKEY_CLASSES_ROOT", L"HKCR", HKEY_CLASSES_ROOT },
        RootEntry{ L"HKEY_CURRENT_USER", L"HKCU", HKEY_CURRENT_USER },
        RootEntry{ L"HKEY_LOCAL_MACHINE", L"HKLM", HKEY_LOCAL_MACHINE },
        RootEntry{ L"HKEY_USERS", L"HKU", HKEY_USERS },
        RootEntry{ L"HKEY_CURRENT_CONFIG", L"HKCC", HKEY_CURRENT_CONFIG }
    };

    // trimDefaultValueName: maps the UI "Default Value" to the WinAPI empty name.
    QString trimDefaultValueName(const QString& valueName)
    {
        const QString kTrimmed = valueName.trimmed();
        if (kTrimmed.isEmpty() || kTrimmed == QStringLiteral("(默认)"))
        {
            return QString();
        }
        return kTrimmed;
    }

    // queryCurrentUserSidText：
    // - Purpose: parses the text representation of the SID for the user to which the current process belongs (used for HKCU -> \REGISTRY\USER\<SID> mapping);
    // - Return an empty string on failure, allowing the caller to follow a conservative fallback path.
    QString queryCurrentUserSidText()
    {
        HANDLE tokenHandle = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            return QString();
        }

        DWORD tokenInfoBytes = 0;
        ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenInfoBytes);
        if (tokenInfoBytes == 0)
        {
            ::CloseHandle(tokenHandle);
            return QString();
        }

        QByteArray tokenBuffer(static_cast<int>(tokenInfoBytes), 0);
        if (!::GetTokenInformation(tokenHandle, TokenUser, tokenBuffer.data(), tokenInfoBytes, &tokenInfoBytes))
        {
            ::CloseHandle(tokenHandle);
            return QString();
        }
        ::CloseHandle(tokenHandle);

        const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
        if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
        {
            return QString();
        }

        LPWSTR sidTextBuffer = nullptr;
        if (!::ConvertSidToStringSidW(tokenUser->User.Sid, &sidTextBuffer) || sidTextBuffer == nullptr)
        {
            return QString();
        }

        const QString kSidText = QString::fromWCharArray(sidTextBuffer).trimmed();
        ::LocalFree(sidTextBuffer);
        return kSidText;
    }

    // buildKernelRegistryPath：
    // - Purpose: Convert HK* or HKEY_* paths to the kernel namespace \REGISTRY\...;
    // - Returns: Path text ready for driver/kernel callback rules.
    QString buildKernelRegistryPath(const QString& registryPathText)
    {
        QString normalizedPath = registryPathText.trimmed();
        normalizedPath.replace('/', '\\');
        while (normalizedPath.contains(QStringLiteral("\\\\")))
        {
            normalizedPath.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (normalizedPath.endsWith('\\'))
        {
            normalizedPath.chop(1);
        }
        if (normalizedPath.isEmpty())
        {
            return QString();
        }

        if (normalizedPath.startsWith(QStringLiteral("\\REGISTRY\\"), Qt::CaseInsensitive)
            || normalizedPath.compare(QStringLiteral("\\REGISTRY"), Qt::CaseInsensitive) == 0)
        {
            return normalizedPath;
        }

        auto restPathAfterRoot = [&normalizedPath](const QString& rootText) {
            QString restPath = normalizedPath.mid(rootText.size());
            while (restPath.startsWith('\\'))
            {
                restPath.remove(0, 1);
            }
            return restPath;
        };

        auto buildWithRoot = [](const QString& kernelRootPath, const QString& restPath) {
            if (restPath.isEmpty())
            {
                return kernelRootPath;
            }
            return QStringLiteral("%1\\%2").arg(kernelRootPath, restPath);
        };

        if (normalizedPath.startsWith(QStringLiteral("HKLM"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKLM")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_LOCAL_MACHINE"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKEY_LOCAL_MACHINE")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKU"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKU")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_USERS"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKEY_USERS")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCR"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKCR")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKEY_CLASSES_ROOT")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCC"), Qt::CaseInsensitive))
        {
            return buildWithRoot(
                QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current"),
                restPathAfterRoot(QStringLiteral("HKCC")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_CURRENT_CONFIG"), Qt::CaseInsensitive))
        {
            return buildWithRoot(
                QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current"),
                restPathAfterRoot(QStringLiteral("HKEY_CURRENT_CONFIG")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive)
            || normalizedPath.startsWith(QStringLiteral("HKEY_CURRENT_USER"), Qt::CaseInsensitive))
        {
            static const QString kCachedUserSid = queryCurrentUserSidText();
            const QString kUserRootPath = kCachedUserSid.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(kCachedUserSid);
            const QString kRestPath = normalizedPath.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive)
                ? restPathAfterRoot(QStringLiteral("HKCU"))
                : restPathAfterRoot(QStringLiteral("HKEY_CURRENT_USER"));
            return buildWithRoot(kUserRootPath, kRestPath);
        }

        return normalizedPath;
    }

    // bytesToHex: Converts binary data to a hexadecimal string.
    QString bytesToHex(const QByteArray& bytes, int maxCount)
    {
        QStringList parts;
        const int kShowCount = std::min<int>(maxCount, bytes.size());
        for (int i = 0; i < kShowCount; ++i)
        {
            parts << QStringLiteral("%1").arg(static_cast<unsigned char>(bytes.at(i)), 2, 16, QLatin1Char('0')).toUpper();
        }
        if (bytes.size() > kShowCount)
        {
            parts << QStringLiteral("...");
        }
        return parts.join(' ');
    }

    // formatNtStatus: Formats the R0 returned NTSTATUS into a fixed-width hexadecimal string.
    QString formatNtStatus(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(statusValue)), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // registryDataToByteArray：
    // - Purpose: Convert ArkDriverClient's byte vector to Qt raw data;
    // - Return: QByteArray; returns an empty array if the input vector is empty.
    QByteArray registryDataToByteArray(const std::vector<std::uint8_t>& dataBytes)
    {
        if (dataBytes.empty())
        {
            return QByteArray();
        }
        return QByteArray(
            reinterpret_cast<const char*>(dataBytes.data()),
            static_cast<int>(dataBytes.size()));
    }

    // byteArrayToRegistryData：
    // - Purpose: Converts Qt raw data to std::vector<uint8_t> required by R0 protocol.
    // - Returns: vector after copying byte-by-byte.
    std::vector<std::uint8_t> byteArrayToRegistryData(const QByteArray& rawData)
    {
        if (rawData.isEmpty())
        {
            return {};
        }
        const auto* begin = reinterpret_cast<const std::uint8_t*>(rawData.constData());
        return std::vector<std::uint8_t>(begin, begin + rawData.size());
    }

    // registryIoFailureText：
    // - Purpose: Convert DeviceIoControl layer failures into user-readable text.
    // - Returns: Win32 error, NTSTATUS, and ArkDriverClient details.
    QString registryIoMessageText(const std::string& rawMessage)
    {
        // registryIoMessageText：
        // - Input: Raw io.message returned by ArkDriverClient;
        // - Processing: normalize low-level logs such as DeviceIoControl, unsupported, and capability messages into Chinese descriptions.
        // - Return: A short sentence suitable for QMessageBox and status text display.
        const QString kRawText = QString::fromStdString(rawMessage).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("驱动未提供额外说明。");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动通信失败或 R3/R0 协议不匹配，请确认驱动已加载且版本一致。");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动或协议暂不支持该注册表 R0 操作。");
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动能力或动态偏移未满足，无法完成该注册表 R0 操作。");
        }
        if (kRawText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R3/R0/shared 协议版本不一致，请同步后重试。");
        }
        return kRawText;
    }

    QString registryIoFailureText(const QString& actionText, const ksword::ark::IoResult& ioResult)
    {
        return QStringLiteral("%1失败：驱动通信失败，Win32=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(ioResult.win32Error)
            .arg(formatNtStatus(ioResult.ntStatus))
            .arg(registryIoMessageText(ioResult.message));
    }

    // registryReadFailureText：
    // - Purpose: Convert R0 read failure into a unified error message.
    // - Returns: Text containing the aggregated status and the underlying Zw* status.
    QString registryReadFailureText(const QString& actionText, const ksword::ark::RegistryReadResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryEnumFailureText：
    // - Purpose: Converts R0 enumeration failures into a unified error message.
    // - Returns: Aggregated status, NTSTATUS, and communication details.
    QString registryEnumFailureText(const QString& actionText, const ksword::ark::RegistryEnumResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryOperationFailureText：
    // - Purpose: Convert R0 write operation failures into a unified error message.
    // - Returns: Contains operation status, NTSTATUS, and communication details.
    QString registryOperationFailureText(const QString& actionText, const ksword::ark::RegistryOperationResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryEnumUsable：
    // - Purpose: Determine if the R0 enumeration response is usable for UI display.
    // - Returns: Success and partial success are displayable; hard failures are not.
    bool registryEnumUsable(const ksword::ark::RegistryEnumResult& result)
    {
        return result.io.ok &&
            (result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ||
                result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL);
    }

    // registryOperationSucceeded：
    // - Purpose: Determine if the R0 write operation has completed.
    // - Returns: Communication succeeded and the aggregated status is SUCCESS.
    bool registryOperationSucceeded(const ksword::ark::RegistryOperationResult& result)
    {
        return result.io.ok &&
            result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
    }

    // SubKeyEnumOutcome：
    // - Purpose: Pure value-type result returned from background thread enumeration to the UI thread, containing no QWidget references;
    // - Parameters: None;
    // - Return: None. If enumerationOk is false, output the failure reason via win32ErrorCode / failureText.
    struct SubKeyEnumOutcome
    {
        QStringList subKeyNames;                // Enumerated subkey names, preserving the order returned by the registry.
        bool enumerationOk = false;             // Whether enumeration completed successfully.
        LONG win32ErrorCode = ERROR_SUCCESS;    // Win32 branch open failure code.
        QString failureText;                    // R0 branch failure description.
    };

    // collectSubKeyNamesByWin32：
    // - Purpose: enumerate all subkey names of a registry key using Win32 APIs in a background thread.
    // - Parameter rootKey: handle to the root key; subPath: relative path under the root key. An empty value indicates the root key itself.
    // - Returns: enumeration result value object; sets enumerationOk to false with the Win32 error code if opening fails.
    SubKeyEnumOutcome collectSubKeyNamesByWin32(HKEY rootKey, const QString& subPath)
    {
        SubKeyEnumOutcome outcome;

        HKEY openedKey = nullptr;
        const LONG kOpenResult = ::RegOpenKeyExW(
            rootKey,
            subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()),
            0,
            KEY_ENUMERATE_SUB_KEYS,
            &openedKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            outcome.win32ErrorCode = kOpenResult;
            return outcome;
        }

        wchar_t nameBuffer[512] = {};
        DWORD enumerationIndex = 0;
        DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
        while (::RegEnumKeyExW(openedKey, enumerationIndex, nameBuffer, &nameLength, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
        {
            outcome.subKeyNames.push_back(QString::fromWCharArray(nameBuffer, static_cast<int>(nameLength)));
            ++enumerationIndex;
            nameLength = static_cast<DWORD>(std::size(nameBuffer));
        }

        ::RegCloseKey(openedKey);
        outcome.enumerationOk = true;
        return outcome;
    }

    // collectSubKeyNamesByR0：
    // - Purpose: enumerate all sub-key names of a registry key in a background thread via the KswordARK driver;
    // - Input parameter kernelKeyPath: kernel path in the format \REGISTRY\...;
    // - Returns: Enumeration result value object; enumerationOk is false if the driver is unavailable or a hard failure occurs.
    SubKeyEnumOutcome collectSubKeyNamesByR0(const QString& kernelKeyPath)
    {
        SubKeyEnumOutcome outcome;

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryEnumResult kEnumResult = kDriverClient.enumerateRegistryKey(
            kernelKeyPath.toStdWString(),
            KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS);
        if (!registryEnumUsable(kEnumResult))
        {
            outcome.failureText = registryEnumFailureText(QStringLiteral("R0枚举子键"), kEnumResult);
            return outcome;
        }

        for (const ksword::ark::RegistrySubKeyEntry& subKeyEntry : kEnumResult.subKeys)
        {
            const QString kSubKeyName = QString::fromStdWString(subKeyEntry.name);
            if (kSubKeyName.trimmed().isEmpty())
            {
                continue;
            }
            outcome.subKeyNames.push_back(kSubKeyName);
        }

        outcome.enumerationOk = true;
        return outcome;
    }

    // resolveTreeItemByPath：
    // - Purpose: Locate nodes in the key tree by registry path level-by-level, querying only existing nodes without triggering any loading.
    // - Parameters treeWidget: key tree control; registryPath: full registry path.
    // - Returns: Pointer to the matched node; returns nullptr if any level in the path is missing.
    //   When backfilling results in the background, use the path instead of a raw pointer to re-locate the node, completely avoiding dangling access to destroyed nodes.
    QTreeWidgetItem* resolveTreeItemByPath(QTreeWidget* treeWidget, const QString& registryPath)
    {
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        const QStringList kSegments = registryPath.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
        if (kSegments.isEmpty())
        {
            return nullptr;
        }

        QTreeWidgetItem* currentItem = nullptr;
        for (int topLevelIndex = 0; topLevelIndex < treeWidget->topLevelItemCount(); ++topLevelIndex)
        {
            QTreeWidgetItem* candidateItem = treeWidget->topLevelItem(topLevelIndex);
            if (candidateItem != nullptr && candidateItem->text(0).compare(kSegments.first(), Qt::CaseInsensitive) == 0)
            {
                currentItem = candidateItem;
                break;
            }
        }
        if (currentItem == nullptr)
        {
            return nullptr;
        }

        for (int segmentIndex = 1; segmentIndex < kSegments.size(); ++segmentIndex)
        {
            QTreeWidgetItem* nextItem = nullptr;
            for (int childIndex = 0; childIndex < currentItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = currentItem->child(childIndex);
                if (childItem == nullptr || childItem->data(0, kRolePlaceholder).toBool())
                {
                    continue;
                }
                if (childItem->text(0).compare(kSegments.at(segmentIndex), Qt::CaseInsensitive) == 0)
                {
                    nextItem = childItem;
                    break;
                }
            }
            if (nextItem == nullptr)
            {
                return nullptr;
            }
            currentItem = nextItem;
        }

        return currentItem;
    }

    // appendSubKeyItemsBatched：
    // - Purpose: Batch-insert sub-key names enumerated from the background into the key tree. Each event loop iteration inserts at most kSubKeyItemBatchSize nodes
    //         to avoid constructing tens of thousands of QTreeWidgetItem objects at once, which would trigger an equivalent number of model signals and freeze the UI.
    // - Input guardedTree: weak reference to the key tree; parentPath: target parent node path; requestToken: token for this load operation;
    //         subKeyNames: Shared list of subkey names; startIndex: Starting index for this batch; onFinished: UI thread callback after all insertions complete.
    // - Returns: None. Aborts remaining insertions immediately if the parent node is destroyed or the token has expired.
    void appendSubKeyItemsBatched(
        const QPointer<QTreeWidget>& guardedTree,
        const QString& parentPath,
        const quint64 requestToken,
        const std::shared_ptr<const QStringList>& subKeyNames,
        const int startIndex,
        const std::function<void()>& onFinished)
    {
        if (guardedTree.isNull() || subKeyNames == nullptr)
        {
            return;
        }

        QTreeWidgetItem* parentItem = resolveTreeItemByPath(guardedTree.data(), parentPath);
        if (parentItem == nullptr)
        {
            return;
        }
        if (parentItem->data(0, kRoleLoadToken).toULongLong() != requestToken)
        {
            return;
        }

        const int kTotalCount = static_cast<int>(subKeyNames->size());
        const int kEndIndex = std::min(startIndex + kSubKeyItemBatchSize, kTotalCount);
        for (int nameIndex = startIndex; nameIndex < kEndIndex; ++nameIndex)
        {
            const QString& subKeyName = subKeyNames->at(nameIndex);
            QTreeWidgetItem* childItem = new QTreeWidgetItem(parentItem);
            childItem->setText(0, subKeyName);
            childItem->setData(0, kRolePath, parentPath + QStringLiteral("\\") + subKeyName);
            childItem->setData(0, kRoleLoaded, false);
            childItem->setData(0, kRolePlaceholder, false);
            childItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
            // Use the expand indicator policy instead of placeholder items: avoids a second batch of QTreeWidgetItem objects equal to the number of subkeys.
            childItem->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        }

        if (kEndIndex < kTotalCount)
        {
            QTimer::singleShot(0, guardedTree.data(),
                [guardedTree, parentPath, requestToken, subKeyNames, kEndIndex, onFinished]()
                {
                    appendSubKeyItemsBatched(guardedTree, parentPath, requestToken, subKeyNames, kEndIndex, onFinished);
                });
            return;
        }

        parentItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        parentItem->setData(0, kRoleLoaded, true);
        parentItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
        if (onFinished)
        {
            onFinished();
        }
    }

    // NewRegistryValueInput:
    // - Carries the output results of the 'New Value' dialog;
    // - Passed by the caller to writeRegistryValue for writing to the registry.
    struct NewRegistryValueInput
    {
        QString valueName;       // valueName: Value name; empty string indicates the default value.
        DWORD valueType = REG_SZ; // valueType: Registry value type (REG_*).
        QByteArray valueData;    // valueData: Raw byte data organized according to WinAPI write format.
    };

    // parseUnsignedIntegerText:
    // - Supports parsing strings into unsigned integers (decimal or hexadecimal).
    // - Returns true if parsing succeeded; numericOut contains the parsed value.
    bool parseUnsignedIntegerText(
        const QString& text,
        const int base,
        quint64* numericOut)
    {
        if (numericOut == nullptr)
        {
            return false;
        }

        QString normalized = text.trimmed();
        if (base == 16 && normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2).trimmed();
        }
        normalized.remove(' ');
        if (normalized.isEmpty())
        {
            return false;
        }

        bool parseOk = false;
        const quint64 kNumericValue = normalized.toULongLong(&parseOk, base);
        if (!parseOk)
        {
            return false;
        }

        *numericOut = kNumericValue;
        return true;
    }

    // NewRegistryValueDialog:
    // - Provides a complete input interface for 'value name + type + data'.
    // - Provides dual decimal/hex input boxes for numeric types with automatic synchronization.
    class NewRegistryValueDialog final : public QDialog
    {
    public:
        // Constructor:
        // - parent: Qt parent window;
        // - Default to REG_SZ, allowing the user to switch types if needed.
        explicit NewRegistryValueDialog(QWidget* parent)
            : QDialog(parent)
        {
            setWindowTitle(QStringLiteral("新建注册表值"));
            resize(560, 320);

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            QFormLayout* formLayout = new QFormLayout();
            rootLayout->addLayout(formLayout);

            valueNameEdit_ = new QLineEdit(this);
            valueNameEdit_->setPlaceholderText(QStringLiteral("留空表示默认值"));
            valueNameEdit_->setToolTip(QStringLiteral("注册表值名称，留空表示(默认)"));
            formLayout->addRow(QStringLiteral("值名称"), valueNameEdit_);

            valueTypeCombo_ = new QComboBox(this);
            valueTypeCombo_->addItem(QStringLiteral("REG_SZ"), static_cast<int>(REG_SZ));
            valueTypeCombo_->addItem(QStringLiteral("REG_EXPAND_SZ"), static_cast<int>(REG_EXPAND_SZ));
            valueTypeCombo_->addItem(QStringLiteral("REG_MULTI_SZ"), static_cast<int>(REG_MULTI_SZ));
            valueTypeCombo_->addItem(QStringLiteral("REG_DWORD"), static_cast<int>(REG_DWORD));
            valueTypeCombo_->addItem(QStringLiteral("REG_QWORD"), static_cast<int>(REG_QWORD));
            valueTypeCombo_->addItem(QStringLiteral("REG_BINARY"), static_cast<int>(REG_BINARY));
            valueTypeCombo_->setToolTip(QStringLiteral("选择要创建的注册表值类型"));
            formLayout->addRow(QStringLiteral("值类型"), valueTypeCombo_);

            valueStack_ = new QStackedWidget(this);
            rootLayout->addWidget(valueStack_, 1);

            // String page: Used for REG_SZ and REG_EXPAND_SZ.
            QWidget* stringPage = new QWidget(this);
            QVBoxLayout* stringLayout = new QVBoxLayout(stringPage);
            stringLayout->setContentsMargins(0, 0, 0, 0);
            stringEdit_ = new QLineEdit(stringPage);
            stringEdit_->setPlaceholderText(QStringLiteral("输入字符串值"));
            stringEdit_->setToolTip(QStringLiteral("字符串类型数据"));
            stringLayout->addWidget(new QLabel(QStringLiteral("字符串数据"), stringPage));
            stringLayout->addWidget(stringEdit_);
            valueStack_->addWidget(stringPage);

            // Multi-string page: each line contains a substring, which is automatically assembled into a MULTI_SZ internally.
            QWidget* multiStringPage = new QWidget(this);
            QVBoxLayout* multiLayout = new QVBoxLayout(multiStringPage);
            multiLayout->setContentsMargins(0, 0, 0, 0);
            multiStringEdit_ = new QTextEdit(multiStringPage);
            multiStringEdit_->setPlaceholderText(QStringLiteral("每行一个字符串，空行将忽略"));
            multiStringEdit_->setToolTip(QStringLiteral("多字符串类型数据（每行一个）"));
            multiLayout->addWidget(new QLabel(QStringLiteral("多字符串数据（逐行输入）"), multiStringPage));
            multiLayout->addWidget(multiStringEdit_, 1);
            valueStack_->addWidget(multiStringPage);

            // Numeric page: decimal and hexadecimal input fields synchronize in real-time to meet audit and debugging habits.
            QWidget* numericPage = new QWidget(this);
            QFormLayout* numericLayout = new QFormLayout(numericPage);
            decimalEdit_ = new QLineEdit(numericPage);
            decimalEdit_->setPlaceholderText(QStringLiteral("十进制，例如 123456"));
            decimalEdit_->setToolTip(QStringLiteral("十进制输入，自动同步到十六进制"));
            hexEdit_ = new QLineEdit(numericPage);
            hexEdit_->setPlaceholderText(QStringLiteral("十六进制，例如 0x1E240"));
            hexEdit_->setToolTip(QStringLiteral("十六进制输入，自动同步到十进制"));
            numericLayout->addRow(QStringLiteral("十进制"), decimalEdit_);
            numericLayout->addRow(QStringLiteral("十六进制"), hexEdit_);
            valueStack_->addWidget(numericPage);

            // Binary page: enter hexadecimal text byte-by-byte, supporting space-separated values.
            QWidget* binaryPage = new QWidget(this);
            QVBoxLayout* binaryLayout = new QVBoxLayout(binaryPage);
            binaryLayout->setContentsMargins(0, 0, 0, 0);
            binaryEdit_ = new QLineEdit(binaryPage);
            binaryEdit_->setPlaceholderText(QStringLiteral("例如：4D 5A 90 00"));
            binaryEdit_->setToolTip(QStringLiteral("按字节输入十六进制，使用空格分隔"));
            binaryLayout->addWidget(new QLabel(QStringLiteral("二进制字节（十六进制）"), binaryPage));
            binaryLayout->addWidget(binaryEdit_);
            valueStack_->addWidget(binaryPage);

            QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
            rootLayout->addWidget(buttonBox);
            connect(buttonBox, &QDialogButtonBox::accepted, this, [this]() {
                QString errorText;
                if (!validateInput(&errorText))
                {
                    QMessageBox::warning(this, QStringLiteral("新建值"), errorText);
                    return;
                }
                accept();
            });
            connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

            connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
                updateDataPageByType();
            });
            connect(decimalEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
                syncNumericText(true);
            });
            connect(hexEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
                syncNumericText(false);
            });

            decimalEdit_->setText(QStringLiteral("0"));
            updateDataPageByType();
        }

        // buildOutput:
        // - Output a structure directly writable to WinAPI after the dialog accepts.
        // - Ensure validateInput has passed before calling.
        NewRegistryValueInput buildOutput() const
        {
            NewRegistryValueInput output;
            output.valueName = valueNameEdit_->text().trimmed();
            output.valueType = static_cast<DWORD>(valueTypeCombo_->currentData().toInt());

            if (output.valueType == REG_SZ || output.valueType == REG_EXPAND_SZ)
            {
                QString textValue = stringEdit_->text();
                textValue.append(QChar::Null);
                output.valueData = QByteArray(
                    reinterpret_cast<const char*>(textValue.utf16()),
                    textValue.size() * static_cast<int>(sizeof(char16_t)));
                return output;
            }

            if (output.valueType == REG_MULTI_SZ)
            {
                QStringList lineList = multiStringEdit_->toPlainText().split('\n');
                QString mergedText;
                for (QString line : lineList)
                {
                    line = line.trimmed();
                    if (line.isEmpty())
                    {
                        continue;
                    }
                    mergedText.append(line);
                    mergedText.append(QChar::Null);
                }
                mergedText.append(QChar::Null);
                output.valueData = QByteArray(
                    reinterpret_cast<const char*>(mergedText.utf16()),
                    mergedText.size() * static_cast<int>(sizeof(char16_t)));
                return output;
            }

            if (output.valueType == REG_DWORD || output.valueType == REG_QWORD)
            {
                quint64 numericValue = 0;
                if (!parseUnsignedIntegerText(decimalEdit_->text(), 10, &numericValue))
                {
                    parseUnsignedIntegerText(hexEdit_->text(), 16, &numericValue);
                }
                if (output.valueType == REG_DWORD)
                {
                    const quint32 kDwordValue = static_cast<quint32>(numericValue & 0xFFFFFFFFULL);
                    output.valueData = QByteArray(
                        reinterpret_cast<const char*>(&kDwordValue),
                        static_cast<int>(sizeof(kDwordValue)));
                }
                else
                {
                    output.valueData = QByteArray(
                        reinterpret_cast<const char*>(&numericValue),
                        static_cast<int>(sizeof(numericValue)));
                }
                return output;
            }

            const QStringList kByteTextList = binaryEdit_->text().split(
                QRegularExpression(QStringLiteral("[,\\s]+")),
                Qt::SkipEmptyParts);
            for (const QString& byteText : kByteTextList)
            {
                bool parseOk = false;
                const int kByteValue = byteText.toInt(&parseOk, 16);
                if (!parseOk || kByteValue < 0 || kByteValue > 255)
                {
                    continue;
                }
                output.valueData.push_back(static_cast<char>(kByteValue));
            }
            return output;
        }

    private:
        // validateInput:
        // - Validate field completeness and format validity upon clicking OK;
        // - errorTextOut returns error text ready for direct display to the user.
        bool validateInput(QString* errorTextOut) const
        {
            auto setError = [errorTextOut](const QString& text) {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = text;
                }
            };

            const DWORD kValueType = static_cast<DWORD>(valueTypeCombo_->currentData().toInt());
            if (kValueType == REG_DWORD || kValueType == REG_QWORD)
            {
                quint64 numericValue = 0;
                bool parseOk = parseUnsignedIntegerText(decimalEdit_->text(), 10, &numericValue);
                if (!parseOk)
                {
                    parseOk = parseUnsignedIntegerText(hexEdit_->text(), 16, &numericValue);
                }
                if (!parseOk)
                {
                    setError(QStringLiteral("数值格式无效，请输入十进制或十六进制数字。"));
                    return false;
                }
                if (kValueType == REG_DWORD && numericValue > 0xFFFFFFFFULL)
                {
                    setError(QStringLiteral("DWORD 范围应在 0 ~ 0xFFFFFFFF。"));
                    return false;
                }
                return true;
            }

            if (kValueType == REG_BINARY)
            {
                const QStringList kByteTextList = binaryEdit_->text().split(
                    QRegularExpression(QStringLiteral("[,\\s]+")),
                    Qt::SkipEmptyParts);
                for (const QString& byteText : kByteTextList)
                {
                    bool parseOk = false;
                    const int kByteValue = byteText.toInt(&parseOk, 16);
                    if (!parseOk || kByteValue < 0 || kByteValue > 255)
                    {
                        setError(QStringLiteral("二进制字节格式无效：%1").arg(byteText));
                        return false;
                    }
                }
                return true;
            }

            return true;
        }

        // updateDataPageByType:
        // - Switch the input page based on the REG type.
        // - Ensures input controls are consistent with the target data model.
        void updateDataPageByType()
        {
            const DWORD kValueType = static_cast<DWORD>(valueTypeCombo_->currentData().toInt());
            if (kValueType == REG_SZ || kValueType == REG_EXPAND_SZ)
            {
                valueStack_->setCurrentIndex(0);
                return;
            }
            if (kValueType == REG_MULTI_SZ)
            {
                valueStack_->setCurrentIndex(1);
                return;
            }
            if (kValueType == REG_DWORD || kValueType == REG_QWORD)
            {
                valueStack_->setCurrentIndex(2);
                return;
            }
            valueStack_->setCurrentIndex(3);
        }

        // syncNumericText:
        // - Bidirectional sync between decimal and hexadecimal.
        // - fromDecimal=true indicates the user just edited the decimal box; otherwise, synchronize the hexadecimal box.
        void syncNumericText(const bool fromDecimal)
        {
            if (syncingNumberText_)
            {
                return;
            }

            syncingNumberText_ = true;
            quint64 numericValue = 0;
            bool parseOk = false;
            if (fromDecimal)
            {
                parseOk = parseUnsignedIntegerText(decimalEdit_->text(), 10, &numericValue);
                if (parseOk)
                {
                    QSignalBlocker blocker(hexEdit_);
                    hexEdit_->setText(QStringLiteral("0x%1").arg(numericValue, 0, 16).toUpper());
                }
            }
            else
            {
                parseOk = parseUnsignedIntegerText(hexEdit_->text(), 16, &numericValue);
                if (parseOk)
                {
                    QSignalBlocker blocker(decimalEdit_);
                    decimalEdit_->setText(QString::number(numericValue));
                }
            }
            syncingNumberText_ = false;
        }

    private:
        QLineEdit* valueNameEdit_ = nullptr;      // m_valueNameEdit: Input box for the value name.
        QComboBox* valueTypeCombo_ = nullptr;     // m_valueTypeCombo: The value type dropdown.
        QStackedWidget* valueStack_ = nullptr;    // m_valueStack: Data input pages for different types.
        QLineEdit* stringEdit_ = nullptr;         // m_stringEdit: String input field.
        QTextEdit* multiStringEdit_ = nullptr;    // m_multiStringEdit: Multi-string input box.
        QLineEdit* decimalEdit_ = nullptr;        // m_decimalEdit: Decimal input box.
        QLineEdit* hexEdit_ = nullptr;            // m_hexEdit: Hex input box.
        QLineEdit* binaryEdit_ = nullptr;         // m_binaryEdit: Binary byte input field.
        bool syncingNumberText_ = false;          // m_syncingNumberText: Prevents recursive triggering of bidirectional synchronization.
    };
}

RegistryDock::RegistryDock(QWidget* parent)
    : QWidget(parent)
{
    {
        KLogEvent event;
        info << event << "[RegistryDock] 构造开始，准备初始化注册表模块。" << eol;
    }

    initializeUi();
    initializeConnections();
    initializeRootItems();
    navigateToPath(QStringLiteral("HKEY_CURRENT_USER"), true);

    {
        KLogEvent event;
        info << event << "[RegistryDock] 构造完成，默认定位到 HKEY_CURRENT_USER。" << eol;
    }
}

RegistryDock::~RegistryDock()
{
    KLogEvent event;
    info << event << "[RegistryDock] 析构开始，准备停止搜索线程。" << eol;

    stopSearch(true);
    if (searchFlushTimer_ != nullptr)
    {
        searchFlushTimer_->stop();
    }

    KLogEvent finishEvent;
    info << finishEvent << "[RegistryDock] 析构完成，后台资源已回收。" << eol;
}

void RegistryDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    registryTabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(registryTabWidget_, 1);

    registryEditorPage_ = new QWidget(registryTabWidget_);
    registryEditorLayout_ = new QVBoxLayout(registryEditorPage_);
    registryEditorLayout_->setContentsMargins(0, 0, 0, 0);
    registryEditorLayout_->setSpacing(6);

    toolBarWidget_ = new QWidget(registryEditorPage_);
    toolBarLayout_ = new QHBoxLayout(toolBarWidget_);
    toolBarLayout_->setContentsMargins(0, 0, 0, 0);
    toolBarLayout_->setSpacing(4);

    // Navigation icons match the file manager to unify the visual semantics of 'Back/Forward'.
    backButton_ = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), toolBarWidget_);
    forwardButton_ = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), toolBarWidget_);
    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolBarWidget_);
    newKeyButton_ = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), toolBarWidget_);
    newValueButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), toolBarWidget_);
    renameButton_ = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), toolBarWidget_);
    deleteButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), toolBarWidget_);
    importButton_ = new QPushButton(QIcon(":/Icon/reg_import.svg"), QString(), toolBarWidget_);
    exportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), toolBarWidget_);
    searchButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), toolBarWidget_);
    stopSearchButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), toolBarWidget_);

    backButton_->setToolTip(QStringLiteral("后退"));
    forwardButton_->setToolTip(QStringLiteral("前进"));
    refreshButton_->setToolTip(QStringLiteral("刷新"));
    newKeyButton_->setToolTip(QStringLiteral("新建子键"));
    newValueButton_->setToolTip(QStringLiteral("新建值"));
    renameButton_->setToolTip(QStringLiteral("重命名"));
    deleteButton_->setToolTip(QStringLiteral("删除"));
    importButton_->setToolTip(QStringLiteral("导入 .reg"));
    exportButton_->setToolTip(QStringLiteral("导出 .reg"));
    searchButton_->setToolTip(QStringLiteral("开始搜索"));
    stopSearchButton_->setToolTip(QStringLiteral("停止搜索"));

    for (QPushButton* button : { backButton_, forwardButton_, refreshButton_, newKeyButton_, newValueButton_,
            renameButton_, deleteButton_, importButton_, exportButton_, searchButton_, stopSearchButton_ })
    {
        button->setStyleSheet(blueButtonStyle());
        button->setFixedWidth(34);
    }

    pathEdit_ = new QLineEdit(toolBarWidget_);
    pathEdit_->setStyleSheet(blueInputStyle());
    pathEdit_->setPlaceholderText(QStringLiteral("输入路径后回车，例如 HKEY_LOCAL_MACHINE\\SOFTWARE"));

    driverRegistryModeLabel_ = new QLabel(toolBarWidget_);
    driverRegistryModeLabel_->setMinimumWidth(118);
    driverRegistryModeLabel_->setAlignment(Qt::AlignCenter);
    driverRegistryModeLabel_->setToolTip(QStringLiteral("驱动可用时启用增强的注册表浏览与编辑。"));

    searchEdit_ = new QLineEdit(toolBarWidget_);
    searchEdit_->setStyleSheet(blueInputStyle());
    searchEdit_->setPlaceholderText(QStringLiteral("搜索键/值/数据"));
    searchEdit_->setMaximumWidth(320);

    toolBarLayout_->addWidget(backButton_);
    toolBarLayout_->addWidget(forwardButton_);
    toolBarLayout_->addWidget(refreshButton_);
    toolBarLayout_->addWidget(newKeyButton_);
    toolBarLayout_->addWidget(newValueButton_);
    toolBarLayout_->addWidget(renameButton_);
    toolBarLayout_->addWidget(deleteButton_);
    toolBarLayout_->addWidget(importButton_);
    toolBarLayout_->addWidget(exportButton_);
    toolBarLayout_->addWidget(pathEdit_, 1);
    toolBarLayout_->addWidget(driverRegistryModeLabel_, 0);
    toolBarLayout_->addWidget(searchEdit_, 0);
    toolBarLayout_->addWidget(searchButton_);
    toolBarLayout_->addWidget(stopSearchButton_);

    registryEditorLayout_->addWidget(toolBarWidget_, 0);

    mainSplitter_ = new QSplitter(Qt::Horizontal, registryEditorPage_);
    registryEditorLayout_->addWidget(mainSplitter_, 1);

    keyTree_ = new QTreeWidget(mainSplitter_);
    keyTree_->setColumnCount(1);
    keyTree_->setHeaderLabel(QStringLiteral("注册表键"));
    keyTree_->header()->setStyleSheet(blueHeaderStyle());
    keyTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    keyTree_->setMinimumWidth(360);

    rightTabWidget_ = new QTabWidget(mainSplitter_);

    valueTable_ = new ks::ui::VisibleTableWidget(rightTabWidget_);
    valueTable_->setColumnCount(3);
    valueTable_->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("类型"), QStringLiteral("数据") });
    valueTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    valueTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    valueTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // Disable the corner button to prevent the default white cell from appearing in the top-left corner.
    valueTable_->setCornerButtonEnabled(false);
    valueTable_->setAlternatingRowColors(true);
    valueTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    valueTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    valueTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    valueTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    valueTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    searchResultTable_ = new ks::ui::VisibleTableWidget(rightTabWidget_);
    searchResultTable_->setColumnCount(5);
    searchResultTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("键路径"), QStringLiteral("值名"), QStringLiteral("类型"), QStringLiteral("数据预览"), QStringLiteral("命中来源")
        });
    searchResultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    searchResultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    searchResultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    searchResultTable_->setCornerButtonEnabled(false);
    searchResultTable_->setAlternatingRowColors(true);
    searchResultTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    searchResultTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    searchResultTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    searchResultTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

    rightTabWidget_->addTab(valueTable_, QStringLiteral("值列表"));
    rightTabWidget_->addTab(searchResultTable_, QStringLiteral("搜索结果"));
    ks::i18n::LanguageManager::instance().bindTab(
        rightTabWidget_, valueTable_, QStringLiteral("registry.tab.values"), QStringLiteral("值列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        rightTabWidget_, searchResultTable_, QStringLiteral("registry.tab.search_results"), QStringLiteral("搜索结果"));

    mainSplitter_->setStretchFactor(0, 1);
    mainSplitter_->setStretchFactor(1, 2);

    statusBar_ = new QStatusBar(registryEditorPage_);
    pathStatusLabel_ = new QLabel(QStringLiteral("路径: -"), statusBar_);
    summaryStatusLabel_ = new QLabel(QStringLiteral("状态: 就绪"), statusBar_);
    statusBar_->addWidget(pathStatusLabel_, 1);
    statusBar_->addPermanentWidget(summaryStatusLabel_, 0);
    registryEditorLayout_->addWidget(statusBar_, 0);

    searchFlushTimer_ = new QTimer(this);
    searchFlushTimer_->setInterval(100);
    stopSearchButton_->setEnabled(false);
    refreshRegistryDriverModeIndicator();

    optimizationPage_ = new RegistryOptimizationPage(registryTabWidget_);
    registryTabWidget_->addTab(registryEditorPage_, QStringLiteral("注册表编辑"));
    registryTabWidget_->addTab(optimizationPage_, QStringLiteral("系统优化"));
    ks::i18n::LanguageManager::instance().bindTab(
        registryTabWidget_, registryEditorPage_, QStringLiteral("registry.tab.editor"), QStringLiteral("注册表编辑"));
    ks::i18n::LanguageManager::instance().bindTab(
        registryTabWidget_, optimizationPage_, QStringLiteral("registry.tab.optimization"), QStringLiteral("系统优化"));
}

void RegistryDock::initializeConnections()
{
    connect(backButton_, &QPushButton::clicked, this, [this]() {
        if (navigationIndex_ <= 0 || navigationHistory_.empty()) return;
        navigationIndex_ -= 1;
        navigateToPath(navigationHistory_[static_cast<std::size_t>(navigationIndex_)], false);
    });

    connect(forwardButton_, &QPushButton::clicked, this, [this]() {
        if (navigationHistory_.empty()) return;
        const int kNextIndex = navigationIndex_ + 1;
        if (kNextIndex < 0 || kNextIndex >= static_cast<int>(navigationHistory_.size())) return;
        navigationIndex_ = kNextIndex;
        navigateToPath(navigationHistory_[static_cast<std::size_t>(navigationIndex_)], false);
    });

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshCurrentKey(true); });
    connect(pathEdit_, &QLineEdit::returnPressed, this, [this]() { navigateToPath(pathEdit_->text().trimmed(), true); });

    connect(keyTree_, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { ensureTreeItemLoaded(item); });
    connect(keyTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
        const QString kPath = item->data(0, kRolePath).toString();
        if (!kPath.isEmpty() && kPath.compare(currentPath_, Qt::CaseInsensitive) != 0) navigateToPath(kPath, true);
    });

    connect(keyTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showTreeContextMenu(pos); });
    connect(valueTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showValueContextMenu(pos); });
    connect(valueTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) { editSelectedValue(); });

    connect(newKeyButton_, &QPushButton::clicked, this, [this]() { createSubKey(); });
    connect(newValueButton_, &QPushButton::clicked, this, [this]() { createValue(); });
    connect(renameButton_, &QPushButton::clicked, this, [this]() { renameSelectedObject(); });
    connect(deleteButton_, &QPushButton::clicked, this, [this]() { deleteSelectedObject(); });
    connect(importButton_, &QPushButton::clicked, this, [this]() { importRegFileAsync(); });
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportCurrentKeyAsync(); });
    connect(searchButton_, &QPushButton::clicked, this, [this]() { startSearchAsync(); });
    connect(stopSearchButton_, &QPushButton::clicked, this, [this]() { stopSearch(false); });
    connect(searchEdit_, &QLineEdit::returnPressed, this, [this]() { startSearchAsync(); });
    connect(searchFlushTimer_, &QTimer::timeout, this, [this]() { flushPendingSearchRows(); });

    connect(searchResultTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        // Search results menu:
        // - Input: User's right-click position in the search results table;
        // - Processing: Synchronize the current row to support copying; if a value matches, delete the original target value stored by row.
        // - Return: None. Deletion follows the existing R0-priority / R3-fallback path.
        const QModelIndex kHit = searchResultTable_->indexAt(pos);
        if (kHit.isValid()) searchResultTable_->setCurrentCell(kHit.row(), kHit.column());

        const int kRow = searchResultTable_->currentRow();
        const QTableWidgetItem* pathItem = kRow >= 0 ? searchResultTable_->item(kRow, 0) : nullptr;
        const QTableWidgetItem* valueNameItem = kRow >= 0 ? searchResultTable_->item(kRow, 1) : nullptr;
        const bool kIsKeyResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetKey;
        const bool kIsValueResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetValue;

        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* copyRowAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(kRow >= 0);
        QAction* deleteValueAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该值"));
        deleteValueAction->setEnabled(kIsValueResult && valueNameItem != nullptr);
        QAction* deleteKeyAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该键（含子项）"));
        deleteKeyAction->setEnabled(kIsKeyResult);

        const QAction* action = menu.exec(searchResultTable_->viewport()->mapToGlobal(pos));
        if (action == deleteKeyAction)
        {
            if (pathItem != nullptr)
            {
                deleteSearchResultKey(pathItem->text());
            }
            return;
        }
        if (action == deleteValueAction)
        {
            if (pathItem == nullptr || valueNameItem == nullptr)
            {
                return;
            }
            deleteSearchResultValue(
                pathItem->text(),
                valueNameItem->data(kSearchResultRoleRawValueName).toString());
            return;
        }
        if (action != copyRowAction) return;

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr || kRow < 0 || kRow >= searchResultTable_->rowCount()) return;

        QStringList fields;
        fields.reserve(searchResultTable_->columnCount());
        for (int column = 0; column < searchResultTable_->columnCount(); ++column)
        {
            const QTableWidgetItem* item = searchResultTable_->item(kRow, column);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        clipboard->setText(fields.join(QLatin1Char('\t')));
    });

    connect(searchResultTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) return;
        QTableWidgetItem* pathItem = searchResultTable_->item(item->row(), 0);
        if (pathItem == nullptr) return;
        navigateToPath(pathItem->text().trimmed(), true);
        rightTabWidget_->setCurrentWidget(valueTable_);
    });
}

void RegistryDock::initializeRootItems()
{
    keyTree_->clear();
    for (const RootEntry& entry : kRootMap)
    {
        QTreeWidgetItem* item = new QTreeWidgetItem(keyTree_);
        item->setText(0, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRolePath, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRoleLoaded, false);
        item->setData(0, kRolePlaceholder, false);
        item->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        // Root keys are always expandable: use indicator policies instead of placeholder child items, and asynchronously enumerate real child keys only upon expansion.
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    }
}
bool RegistryDock::parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut)
{
    if (rootKeyOut == nullptr || subPathOut == nullptr) return false;

    QString text = pathText.trimmed();
    text.replace('/', '\\');
    while (text.contains(QStringLiteral("\\\\"))) text.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
    if (text.endsWith('\\')) text.chop(1);
    if (text.isEmpty()) return false;

    const int kSplit = text.indexOf('\\');
    const QString kRootText = kSplit < 0 ? text : text.left(kSplit);
    const QString kSubPath = kSplit < 0 ? QString() : text.mid(kSplit + 1);

    for (const RootEntry& entry : kRootMap)
    {
        const QString kFull = QString::fromWCharArray(entry.fullName);
        const QString kShortName = QString::fromWCharArray(entry.shortName);
        if (kRootText.compare(kFull, Qt::CaseInsensitive) == 0 || kRootText.compare(kShortName, Qt::CaseInsensitive) == 0)
        {
            *rootKeyOut = entry.root;
            *subPathOut = kSubPath;
            return true;
        }
    }
    return false;
}

QString RegistryDock::normalizeRegistryPath(const QString& pathText)
{
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(pathText, &root, &subPath)) return QString();
    QString output = rootKeyToText(root);
    if (!subPath.isEmpty()) output += QStringLiteral("\\") + subPath;
    return output;
}

QString RegistryDock::rootKeyToText(HKEY rootKey)
{
    for (const RootEntry& entry : kRootMap)
    {
        if (entry.root == rootKey) return QString::fromWCharArray(entry.fullName);
    }
    return QStringLiteral("<Unknown>");
}

QString RegistryDock::valueTypeToText(DWORD type)
{
    switch (type)
    {
    case REG_NONE: return QStringLiteral("REG_NONE");
    case REG_SZ: return QStringLiteral("REG_SZ");
    case REG_EXPAND_SZ: return QStringLiteral("REG_EXPAND_SZ");
    case REG_BINARY: return QStringLiteral("REG_BINARY");
    case REG_DWORD: return QStringLiteral("REG_DWORD");
    case REG_MULTI_SZ: return QStringLiteral("REG_MULTI_SZ");
    case REG_QWORD: return QStringLiteral("REG_QWORD");
    default: return QStringLiteral("REG_%1").arg(type);
    }
}

QString RegistryDock::formatValueData(DWORD type, const QByteArray& data)
{
    if (data.isEmpty()) return QStringLiteral("<empty>");

    if (type == REG_SZ || type == REG_EXPAND_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        text.remove(QChar::Null);
        return text;
    }
    if (type == REG_MULTI_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        return text.split(QChar::Null, Qt::SkipEmptyParts).join(QStringLiteral(" | "));
    }
    if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD)))
    {
        const DWORD kValue = *reinterpret_cast<const DWORD*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(kValue, 8, 16, QLatin1Char('0')).arg(kValue);
    }
    if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64)))
    {
        const quint64 kValue = *reinterpret_cast<const quint64*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(static_cast<qulonglong>(kValue), 16, 16, QLatin1Char('0')).arg(static_cast<qulonglong>(kValue));
    }
    return bytesToHex(data, 64);
}

QString RegistryDock::winErrorText(LONG code)
{
    wchar_t* buffer = nullptr;
    const DWORD kSize = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    QString text = QStringLiteral("错误码 %1").arg(code);
    if (kSize > 0 && buffer != nullptr)
    {
        text += QStringLiteral(": ") + QString::fromWCharArray(buffer, static_cast<int>(kSize)).trimmed();
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    return text;
}

bool RegistryDock::readRegistryValueRaw(HKEY root, const QString& subPath, const QString& valueName, DWORD* typeOut, QByteArray* dataOut, QString* errorOut)
{
    if (typeOut == nullptr || dataOut == nullptr) return false;
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString kRealName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = kRealName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealName.utf16());

    DWORD type = REG_NONE;
    DWORD size = 0;
    LONG queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, nullptr, &size);
    if (queryResult != ERROR_SUCCESS)
    {
        ::RegCloseKey(key);
        if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
        return false;
    }

    QByteArray data;
    data.resize(static_cast<int>(size));
    if (size > 0)
    {
        queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, reinterpret_cast<LPBYTE>(data.data()), &size);
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(key);
            if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
            return false;
        }
    }

    ::RegCloseKey(key);
    *typeOut = type;
    *dataOut = data;
    return true;
}

bool RegistryDock::writeRegistryValue(HKEY root, const QString& subPath, const QString& valueName, DWORD type, const QByteArray& rawData, QString* errorOut)
{
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString kRealName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = kRealName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealName.utf16());
    LONG setResult = ::RegSetValueExW(
        key,
        valuePtr,
        0,
        type,
        reinterpret_cast<const BYTE*>(rawData.constData()),
        static_cast<DWORD>(rawData.size()));
    ::RegCloseKey(key);

    if (setResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(setResult);
        return false;
    }
    return true;
}

void RegistryDock::refreshRegistryDriverModeIndicator()
{
    // Purpose: Refresh the R0 registry read/write indicator next to the path input field.
    // Returns: None; only updates the QLabel text, color, and tooltip.
    if (driverRegistryModeLabel_ == nullptr)
    {
        return;
    }

    const bool kEnabled = shouldUseRegistryR0();
    if (kEnabled)
    {
        driverRegistryModeLabel_->setText(QStringLiteral("R0读写: 开启"));
        driverRegistryModeLabel_->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:3px;"
            "background:%2;color:%1;padding:2px 6px;font-weight:600;}"
        ).arg(ksword_theme::successColor().name(QColor::HexRgb))
         .arg(ksword_theme::rgbaColorName(ksword_theme::successColor(), 41)));
        driverRegistryModeLabel_->setToolTip(QStringLiteral("驱动可用时启用增强的注册表浏览与编辑。"));
        return;
    }

    driverRegistryModeLabel_->setText(QStringLiteral("R0读写: 关闭"));
    // In the disabled state, no semantic colors apply; borders and text use the dynamic palette, and the capsule no longer has its own background color.
    driverRegistryModeLabel_->setStyleSheet(QStringLiteral(
        "QLabel{border:1px solid %1;border-radius:3px;"
        "background:transparent;/* %3 */color:%2;padding:2px 6px;font-weight:600;}"
    ).arg(ksword_theme::borderHex())
     .arg(ksword_theme::textSecondaryHex())
     .arg(ksword_theme::rgbaColorName(ksword_theme::surfaceAltColor(), 36)));
    driverRegistryModeLabel_->setToolTip(QStringLiteral("驱动不可用，当前使用标准注册表模式。"));
}

bool RegistryDock::shouldUseRegistryR0() const
{
    // Purpose: Open the device via ArkDriverClient to determine if the driver is online.
    // Returns: true indicates subsequent registry operations should use R0; false indicates falling back to Win32.
    const ksword::ark::DriverClient kDriverClient;
    ksword::ark::DriverHandle handle = kDriverClient.open(GENERIC_READ | GENERIC_WRITE);
    return handle.isValid();
}

bool RegistryDock::readRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    DWORD* typeOut,
    QByteArray* dataOut,
    QString* errorTextOut)
{
    // Purpose: Encapsulate registry value read strategy; when R0 is online, do not use Win32 for reading.
    // Returns: true on successful read, filling typeOut/dataOut.
    if (typeOut == nullptr || dataOut == nullptr)
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("读取参数无效。");
        return false;
    }
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(keyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryReadResult kReadResult = kDriverClient.readRegistryValue(
            kKernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString(),
            KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
        if (kReadResult.io.ok && kReadResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS)
        {
            *typeOut = static_cast<DWORD>(kReadResult.valueType);
            *dataOut = registryDataToByteArray(kReadResult.data);
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryReadFailureText(QStringLiteral("R0读取注册表值"), kReadResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }
    return readRegistryValueRaw(root, subPath, valueName, typeOut, dataOut, errorTextOut);
}

bool RegistryDock::writeRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    DWORD valueType,
    const QByteArray& rawData,
    QString* errorTextOut)
{
    // Purpose: Encapsulate registry value write policies; when R0 is online, all writes are executed via the driver.
    // Returns: true on successful write.
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(keyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryOperationResult kOperationResult = kDriverClient.setRegistryValue(
            kKernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString(),
            static_cast<std::uint32_t>(valueType),
            byteArrayToRegistryData(rawData));
        if (registryOperationSucceeded(kOperationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0写入注册表值"), kOperationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }
    return writeRegistryValue(root, subPath, valueName, valueType, rawData, errorTextOut);
}

bool RegistryDock::createRegistryKeyAny(const QString& fullKeyPath, QString* errorTextOut)
{
    // Purpose: Create a registry key; when R0 is online, pass the full kernel key path directly to the driver.
    // Returns: true if creation succeeds or the key already exists.
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("目标路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryOperationResult kOperationResult =
            kDriverClient.createRegistryKey(kKernelPath.toStdWString());
        if (registryOperationSucceeded(kOperationResult) ||
            (kOperationResult.io.ok && kOperationResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0创建注册表键"), kOperationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(fullKeyPath);
        return false;
    }

    HKEY created = nullptr;
    const LONG kCreateResult = ::RegCreateKeyExW(
        root,
        subPath.isEmpty() ? L"" : reinterpret_cast<const wchar_t*>(subPath.utf16()),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &created,
        nullptr);
    if (created != nullptr)
    {
        ::RegCloseKey(created);
    }
    if (kCreateResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(kCreateResult);
        return false;
    }
    return true;
}

bool RegistryDock::deleteRegistryKeyByR0Recursive(
    const QString& kernelKeyPath,
    QString* errorTextOut) const
{
    // Purpose: Recursively clear and delete the specified key, relying solely on R0 enumeration and deletion.
    // Returns: true if the entire subtree was deleted successfully.
    if (errorTextOut != nullptr) errorTextOut->clear();
    if (kernelKeyPath.trimmed().isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("内核注册表路径为空。");
        return false;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::RegistryEnumResult kEnumResult = kDriverClient.enumerateRegistryKey(
        kernelKeyPath.toStdWString(),
        KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
    if (!registryEnumUsable(kEnumResult))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryEnumFailureText(QStringLiteral("R0枚举待删除注册表键"), kEnumResult);
        }
        return false;
    }

    for (const ksword::ark::RegistrySubKeyEntry& childEntry : kEnumResult.subKeys)
    {
        const QString kChildName = QString::fromStdWString(childEntry.name);
        if (kChildName.trimmed().isEmpty())
        {
            continue;
        }
        const QString kChildKernelPath = kernelKeyPath + QStringLiteral("\\") + kChildName;
        if (!deleteRegistryKeyByR0Recursive(kChildKernelPath, errorTextOut))
        {
            return false;
        }
    }

    for (const ksword::ark::RegistryValueEntry& valueEntry : kEnumResult.values)
    {
        const QString kValueName = QString::fromStdWString(valueEntry.name);
        const ksword::ark::RegistryOperationResult kDeleteValueResult = kDriverClient.deleteRegistryValue(
            kernelKeyPath.toStdWString(),
            trimDefaultValueName(kValueName).toStdWString());
        if (!registryOperationSucceeded(kDeleteValueResult) &&
            !(kDeleteValueResult.io.ok && kDeleteValueResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表值"), kDeleteValueResult);
            }
            return false;
        }
    }

    const ksword::ark::RegistryOperationResult kDeleteKeyResult =
        kDriverClient.deleteRegistryKey(kernelKeyPath.toStdWString());
    if (registryOperationSucceeded(kDeleteKeyResult) ||
        (kDeleteKeyResult.io.ok && kDeleteKeyResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND))
    {
        return true;
    }

    if (errorTextOut != nullptr)
    {
        *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表键"), kDeleteKeyResult);
    }
    return false;
}

bool RegistryDock::deleteRegistryKeyAny(const QString& fullKeyPath, QString* errorTextOut)
{
    // Purpose: Delete the registry key tree; do not call RegDeleteTreeW when R0 is online.
    // Returns: true on successful deletion.
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("目标路径无法转换为内核路径。");
            return false;
        }
        return deleteRegistryKeyByR0Recursive(kKernelPath, errorTextOut);
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表键路径无效或指向根键。");
        return false;
    }

    const LONG kDeleteResult = ::RegDeleteTreeW(
        root,
        reinterpret_cast<const wchar_t*>(subPath.utf16()));
    if (kDeleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(kDeleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::deleteRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    QString* errorTextOut)
{
    // Purpose: Delete a registry value; when R0 is online, delete the default or named value via the driver.
    // Returns: true on successful deletion.
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(keyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryOperationResult kOperationResult = kDriverClient.deleteRegistryValue(
            kKernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString());
        if (registryOperationSucceeded(kOperationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表值"), kOperationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }

    const QString kRealName = trimDefaultValueName(valueName);
    LONG deleteResult = ::RegDeleteValueW(key, kRealName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kRealName.utf16()));
    ::RegCloseKey(key);
    if (deleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(deleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::renameRegistryValueAny(
    const QString& keyPath,
    const QString& oldValueName,
    const QString& newValueName,
    QString* errorTextOut)
{
    // Purpose: Rename the registry value; when R0 is online, the driver handles the read/write/delete sequence.
    // Returns: true if the rename operation succeeds.
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(keyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryOperationResult kOperationResult = kDriverClient.renameRegistryValue(
            kKernelPath.toStdWString(),
            oldValueName.toStdWString(),
            newValueName.toStdWString());
        if (registryOperationSucceeded(kOperationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0重命名注册表值"), kOperationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }

    DWORD type = REG_NONE;
    QByteArray data;
    if (!readRegistryValueRaw(root, subPath, oldValueName, &type, &data, errorTextOut))
    {
        return false;
    }
    if (!writeRegistryValue(root, subPath, newValueName, type, data, errorTextOut))
    {
        return false;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }
    const LONG kDeleteResult = ::RegDeleteValueW(key, reinterpret_cast<const wchar_t*>(oldValueName.utf16()));
    ::RegCloseKey(key);
    if (kDeleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(kDeleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::renameRegistryKeyAny(
    const QString& fullKeyPath,
    const QString& newKeyName,
    QString* newFullKeyPathOut,
    QString* errorTextOut)
{
    // Action: Rename the current key; when R0 is online, directly call the driver's ZwRenameKey wrapper.
    // Returns: true on successful rename, with the new UI path output.
    if (errorTextOut != nullptr) errorTextOut->clear();
    if (newFullKeyPathOut != nullptr) newFullKeyPathOut->clear();

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("根键不可重命名或路径无效。");
        return false;
    }

    const int kSlashPos = subPath.lastIndexOf('\\');
    const QString kParentPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
    QString newPath = rootKeyToText(root);
    if (!kParentPath.isEmpty())
    {
        newPath += QStringLiteral("\\") + kParentPath;
    }
    newPath += QStringLiteral("\\") + newKeyName;

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kKernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryOperationResult kOperationResult = kDriverClient.renameRegistryKey(
            kKernelPath.toStdWString(),
            newKeyName.toStdWString());
        if (registryOperationSucceeded(kOperationResult))
        {
            if (newFullKeyPathOut != nullptr) *newFullKeyPathOut = newPath;
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0重命名注册表键"), kOperationResult);
        }
        return false;
    }

    HKEY parentKey = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, kParentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(kParentPath.utf16()), 0, KEY_WRITE, &parentKey);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }

    using RegRenameKeyFunc = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
    const HMODULE kAdvapiModule = ::GetModuleHandleW(L"Advapi32.dll");
    RegRenameKeyFunc renameKey = kAdvapiModule != nullptr
        ? reinterpret_cast<RegRenameKeyFunc>(::GetProcAddress(kAdvapiModule, "RegRenameKey"))
        : nullptr;
    if (renameKey == nullptr)
    {
        ::RegCloseKey(parentKey);
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("系统不支持 RegRenameKey。");
        return false;
    }

    const QString kOldKeyName = kSlashPos < 0 ? subPath : subPath.mid(kSlashPos + 1);
    LONG renameResult = renameKey(parentKey, reinterpret_cast<const wchar_t*>(kOldKeyName.utf16()), reinterpret_cast<const wchar_t*>(newKeyName.utf16()));
    ::RegCloseKey(parentKey);
    if (renameResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(renameResult);
        return false;
    }
    if (newFullKeyPathOut != nullptr) *newFullKeyPathOut = newPath;
    return true;
}

void RegistryDock::updateStatusBar(const QString& message)
{
    pathStatusLabel_->setText(QStringLiteral("路径: %1").arg(currentPath_));
    summaryStatusLabel_->setText(message);
}

void RegistryDock::navigateToPath(const QString& path, bool recordHistory)
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 导航请求, input="
            << path.toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    const QString kNormalized = normalizeRegistryPath(path);
    if (kNormalized.isEmpty())
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 导航失败：无效路径, input=" << path.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("注册表"), QStringLiteral("无效路径：%1").arg(path));
        return;
    }

    currentPath_ = kNormalized;
    pathEdit_->setText(kNormalized);

    if (recordHistory)
    {
        if (navigationIndex_ + 1 < static_cast<int>(navigationHistory_.size()))
        {
            navigationHistory_.erase(navigationHistory_.begin() + navigationIndex_ + 1, navigationHistory_.end());
        }
        if (navigationHistory_.empty() || navigationHistory_.back().compare(kNormalized, Qt::CaseInsensitive) != 0)
        {
            navigationHistory_.push_back(kNormalized);
        }
        navigationIndex_ = static_cast<int>(navigationHistory_.size()) - 1;
    }

    backButton_->setEnabled(navigationIndex_ > 0);
    forwardButton_->setEnabled(navigationIndex_ >= 0 && (navigationIndex_ + 1) < static_cast<int>(navigationHistory_.size()));
    refreshRegistryDriverModeIndicator();

    selectTreeItemByPath(kNormalized);
    refreshCurrentKey(true);

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 导航成功, normalized="
            << kNormalized.toStdString()
            << ", historySize="
            << navigationHistory_.size()
            << ", historyIndex="
            << navigationIndex_
            << eol;
    }
}

void RegistryDock::selectTreeItemByPath(const QString& path)
{
    const QString kNormalized = normalizeRegistryPath(path);
    if (kNormalized.isEmpty()) return;

    const QStringList kSegments = kNormalized.split('\\', Qt::SkipEmptyParts);
    if (kSegments.isEmpty()) return;

    // Record the pending path: Subkey loading is now asynchronous; this call can only reach the deepest level that is already
    // loaded. Remaining levels will be re-entered by the background enumeration callback after landing to continue descending.
    keyTree_->setProperty(kPendingTreeSelectionProperty, kNormalized);

    QTreeWidgetItem* current = nullptr;
    for (int i = 0; i < keyTree_->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = keyTree_->topLevelItem(i);
        if (item->text(0).compare(kSegments.first(), Qt::CaseInsensitive) == 0)
        {
            current = item;
            break;
        }
    }
    if (current == nullptr)
    {
        keyTree_->setProperty(kPendingTreeSelectionProperty, QString());
        return;
    }

    bool waitingForSubKeyLoad = false;
    for (int i = 1; i < kSegments.size(); ++i)
    {
        if (!current->data(0, kRoleLoaded).toBool())
        {
            // This level has no subkey data yet: dispatch a background enumeration once, and pause here for this round.
            ensureTreeItemLoaded(current);
            waitingForSubKeyLoad = current->data(0, kRoleLoadToken).toULongLong() != 0;
            break;
        }

        QTreeWidgetItem* next = nullptr;
        for (int childIndex = 0; childIndex < current->childCount(); ++childIndex)
        {
            QTreeWidgetItem* child = current->child(childIndex);
            if (child == nullptr || child->data(0, kRolePlaceholder).toBool()) continue;
            if (child->text(0).compare(kSegments.at(i), Qt::CaseInsensitive) == 0)
            {
                next = child;
                break;
            }
        }
        if (next == nullptr) break;
        current = next;
    }

    if (!waitingForSubKeyLoad)
    {
        keyTree_->setProperty(kPendingTreeSelectionProperty, QString());
    }

    QSignalBlocker blocker(keyTree_);
    keyTree_->setCurrentItem(current);
    keyTree_->scrollToItem(current);
}

void RegistryDock::ensureTreeItemLoaded(QTreeWidgetItem* item)
{
    if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
    if (item->data(0, kRoleLoaded).toBool()) return;
    // A background enumeration is already in progress: do not dispatch again; wait for it to complete.
    if (item->data(0, kRoleLoadToken).toULongLong() != 0) return;

    const QString kItemPath = item->data(0, kRolePath).toString();
    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 展开节点并加载子键, path=" << kItemPath.toStdString() << eol;
    }

    // Enum parameters are computed on the UI thread and passed by value to the background thread: the background thread performs only pure data collection and touches no controls.
    const bool kUseRegistryR0 = shouldUseRegistryR0();
    QString kernelPath;
    HKEY rootKey = nullptr;
    QString subPath;
    bool enumerationSourceReady = false;
    if (kUseRegistryR0)
    {
        kernelPath = buildKernelRegistryPath(kItemPath);
        enumerationSourceReady = !kernelPath.isEmpty();
    }
    else
    {
        enumerationSourceReady = parseRegistryPath(kItemPath, &rootKey, &subPath);
    }

    if (!enumerationSourceReady)
    {
        qDeleteAll(item->takeChildren());
        item->setData(0, kRoleLoaded, true);
        item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
        return;
    }

    // Keep a placeholder item during background enumeration to maintain the expand arrow and provide 'loading' visual feedback.
    qDeleteAll(item->takeChildren());
    QTreeWidgetItem* loadingPlaceholder = new QTreeWidgetItem(item);
    loadingPlaceholder->setText(0, QStringLiteral("..."));
    loadingPlaceholder->setData(0, kRolePlaceholder, true);
    // Placeholder item is not selectable: it will be removed upon result commit to avoid triggering unnecessary navigation when deleting the current item.
    loadingPlaceholder->setFlags(Qt::ItemIsEnabled);

    const quint64 kRequestToken = gNextSubKeyLoadToken.fetch_add(1, std::memory_order_relaxed);
    item->setData(0, kRoleLoadToken, static_cast<qulonglong>(kRequestToken));
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);

    const QPointer<RegistryDock> kGuardedSelf(this);
    const QPointer<QTreeWidget> kGuardedTree(keyTree_);
    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kGuardedTree, kRequestToken, kItemPath, kernelPath, subPath, rootKey, kUseRegistryR0]()
        {
            const SubKeyEnumOutcome kCollected = kUseRegistryR0
                ? collectSubKeyNamesByR0(kernelPath)
                : collectSubKeyNamesByWin32(rootKey, subPath);

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr) { return; }

            QMetaObject::invokeMethod(kAppInstance,
                [kGuardedSelf, kGuardedTree, kRequestToken, kItemPath, kCollected]()
                {
                    if (kGuardedTree.isNull()) { return; }

                    // Re-locate using the path instead of a raw pointer: the node may have been destroyed or rebuilt during the wait.
                    QTreeWidgetItem* targetItem = resolveTreeItemByPath(kGuardedTree.data(), kItemPath);
                    if (targetItem == nullptr) { return; }
                    if (targetItem->data(0, kRoleLoadToken).toULongLong() != kRequestToken) { return; }

                    qDeleteAll(targetItem->takeChildren());

                    if (!kCollected.enumerationOk)
                    {
                        {
                            KLogEvent event;
                            warn << event
                                << "[RegistryDock] 加载子键失败, path="
                                << kItemPath.toStdString()
                                << ", error="
                                << (kCollected.failureText.isEmpty()
                                    ? winErrorText(kCollected.win32ErrorCode).toStdString()
                                    : kCollected.failureText.toStdString())
                                << eol;
                        }
                        targetItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
                        targetItem->setData(0, kRoleLoaded, true);
                        targetItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
                        return;
                    }

                    const int kLoadedChildCount = static_cast<int>(kCollected.subKeyNames.size());
                    const std::shared_ptr<const QStringList> kSharedSubKeyNames =
                        std::make_shared<const QStringList>(kCollected.subKeyNames);
                    const std::function<void()> kOnSubKeysApplied =
                        [kGuardedSelf, kGuardedTree, kItemPath, kLoadedChildCount]()
                        {
                            {
                                KLogEvent event;
                                info << event
                                    << "[RegistryDock] 子键加载完成, path="
                                    << kItemPath.toStdString()
                                    << ", childCount="
                                    << kLoadedChildCount
                                    << eol;
                            }

                            // Path resolution proceeds level-by-level asynchronously: once the current sub-key is ready, continue descending to the target path.
                            if (kGuardedSelf.isNull() || kGuardedTree.isNull()) { return; }
                            const QString kPendingSelectionPath =
                                kGuardedTree->property(kPendingTreeSelectionProperty).toString();
                            if (kPendingSelectionPath.isEmpty()) { return; }
                            kGuardedSelf->selectTreeItemByPath(kPendingSelectionPath);
                        };

                    appendSubKeyItemsBatched(
                        kGuardedTree,
                        kItemPath,
                        kRequestToken,
                        kSharedSubKeyNames,
                        0,
                        kOnSubKeysApplied);
                });
        });
}

void RegistryDock::refreshCurrentKey(bool)
{
    KLogEvent event;
    info << event << "[RegistryDock] 刷新当前键, path=" << currentPath_.toStdString() << eol;
    refreshRegistryDriverModeIndicator();
    refreshValueTable();
}

void RegistryDock::refreshValueTable()
{
    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 开始刷新值列表, path=" << currentPath_.toStdString() << eol;
    }

    valueTable_->setRowCount(0);

    if (shouldUseRegistryR0())
    {
        const QString kKernelPath = buildKernelRegistryPath(currentPath_);
        if (kKernelPath.isEmpty())
        {
            KLogEvent event;
            warn << event << "[RegistryDock] R0刷新失败：内核路径无效, path=" << currentPath_.toStdString() << eol;
            updateStatusBar(QStringLiteral("状态: 内核路径无效"));
            return;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::RegistryEnumResult kEnumResult = kDriverClient.enumerateRegistryKey(
            kKernelPath.toStdWString(),
            KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
        if (!registryEnumUsable(kEnumResult))
        {
            const QString kErrorText = registryEnumFailureText(QStringLiteral("R0刷新值列表"), kEnumResult);
            KLogEvent event;
            warn << event << "[RegistryDock] R0刷新值列表失败, path=" << currentPath_.toStdString() << ", error=" << kErrorText.toStdString() << eol;
            updateStatusBar(QStringLiteral("状态: R0打开失败 - %1").arg(kErrorText));
            return;
        }

        for (const ksword::ark::RegistryValueEntry& valueEntry : kEnumResult.values)
        {
            const QString kValueName = QString::fromStdWString(valueEntry.name);
            const QByteArray kBytes = registryDataToByteArray(valueEntry.data);
            const int kRow = valueTable_->rowCount();
            valueTable_->insertRow(kRow);

            QTableWidgetItem* nameItem = new QTableWidgetItem(kValueName.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("(默认)"))
                : kValueName);
            nameItem->setData(Qt::UserRole, kValueName);
            valueTable_->setItem(kRow, 0, nameItem);
            valueTable_->setItem(kRow, 1, new QTableWidgetItem(valueTypeToText(static_cast<DWORD>(valueEntry.valueType))));

            QString dataText = formatValueData(static_cast<DWORD>(valueEntry.valueType), kBytes);
            if (valueEntry.requiredBytes > valueEntry.dataBytes)
            {
                dataText += QStringLiteral("  <R0预览截断 %1/%2 字节>")
                    .arg(valueEntry.dataBytes)
                    .arg(valueEntry.requiredBytes);
            }
            valueTable_->setItem(kRow, 2, new QTableWidgetItem(dataText));
        }

        updateStatusBar(QStringLiteral("状态: R0已加载 %1/%2 个值")
            .arg(kEnumResult.returnedValueCount)
            .arg(kEnumResult.valueCount));

        KLogEvent finishEvent;
        info << finishEvent
            << "[RegistryDock] R0值列表刷新完成, path="
            << currentPath_.toStdString()
            << ", returned="
            << kEnumResult.returnedValueCount
            << ", total="
            << kEnumResult.valueCount
            << eol;
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath))
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 刷新失败：路径无效, path=" << currentPath_.toStdString() << eol;
        updateStatusBar(QStringLiteral("状态: 路径无效"));
        return;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        KLogEvent event;
        warn << event
            << "[RegistryDock] 打开键失败, path="
            << currentPath_.toStdString()
            << ", error="
            << winErrorText(openResult).toStdString()
            << eol;
        updateStatusBar(QStringLiteral("状态: 打开失败 - %1").arg(winErrorText(openResult)));
        return;
    }

    DWORD valueCount = 0;
    DWORD maxNameLength = 0;
    DWORD maxDataLength = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxNameLength, &maxDataLength, nullptr, nullptr);

    DWORD defaultType = REG_NONE;
    DWORD defaultSize = 0;
    LONG defaultQuery = ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, nullptr, &defaultSize);
    if (defaultQuery == ERROR_SUCCESS)
    {
        QByteArray defaultData;
        defaultData.resize(static_cast<int>(defaultSize));
        if (defaultSize > 0)
        {
            ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, reinterpret_cast<LPBYTE>(defaultData.data()), &defaultSize);
        }

        valueTable_->insertRow(0);
        QTableWidgetItem* nameItem = new QTableWidgetItem(
            ks::i18n::sourceText(QStringLiteral("(默认)")));
        nameItem->setData(Qt::UserRole, QString());
        valueTable_->setItem(0, 0, nameItem);
        valueTable_->setItem(0, 1, new QTableWidgetItem(valueTypeToText(defaultType)));
        valueTable_->setItem(0, 2, new QTableWidgetItem(formatValueData(defaultType, defaultData)));
    }

    std::vector<wchar_t> nameBuffer(static_cast<std::size_t>(maxNameLength + 4), L'\0');
    std::vector<unsigned char> dataBuffer(static_cast<std::size_t>(maxDataLength + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        DWORD nameLength = static_cast<DWORD>(nameBuffer.size() - 1);
        DWORD dataLength = static_cast<DWORD>(dataBuffer.size());
        DWORD type = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, nameBuffer.data(), &nameLength, nullptr, &type, dataBuffer.data(), &dataLength);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString kValueName = QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameLength));
        if (kValueName.isEmpty()) continue;

        const QByteArray kBytes(reinterpret_cast<const char*>(dataBuffer.data()), static_cast<int>(dataLength));
        const int kRow = valueTable_->rowCount();
        valueTable_->insertRow(kRow);
        QTableWidgetItem* nameItem = new QTableWidgetItem(kValueName);
        nameItem->setData(Qt::UserRole, kValueName);
        valueTable_->setItem(kRow, 0, nameItem);
        valueTable_->setItem(kRow, 1, new QTableWidgetItem(valueTypeToText(type)));
        valueTable_->setItem(kRow, 2, new QTableWidgetItem(formatValueData(type, kBytes)));
    }

    ::RegCloseKey(key);
    updateStatusBar(QStringLiteral("状态: 已加载 %1 个值").arg(valueTable_->rowCount()));

    KLogEvent finishEvent;
    info << finishEvent
        << "[RegistryDock] 值列表刷新完成, path="
        << currentPath_.toStdString()
        << ", valueCount="
        << valueTable_->rowCount()
        << eol;
}
void RegistryDock::showTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = keyTree_->itemAt(pos);
    if (item != nullptr && !item->data(0, kRolePlaceholder).toBool()) keyTree_->setCurrentItem(item);

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* newKeyAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建子键"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    menu.addSeparator();
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadDefaultAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取默认值"));
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新"));
    menu.addSeparator();
    QAction* exportAction = menu.addAction(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出 .reg"));
    QAction* importAction = menu.addAction(QIcon(":/Icon/reg_import.svg"), QStringLiteral("导入 .reg"));

    QAction* action = menu.exec(keyTree_->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 树右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << currentPath_.toStdString()
            << eol;
    }
    if (action == newKeyAction) createSubKey();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copyCurrentKernelPathToClipboard();
    else if (action == r0ReadDefaultAction) readDefaultValueByR0();
    else if (action == refreshAction) refreshCurrentKey(true);
    else if (action == exportAction) exportCurrentKeyAsync();
    else if (action == importAction) importRegFileAsync();
}

void RegistryDock::showValueContextMenu(const QPoint& pos)
{
    const QModelIndex kHit = valueTable_->indexAt(pos);
    if (kHit.isValid()) valueTable_->setCurrentCell(kHit.row(), kHit.column());

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* editAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("修改"));
    QAction* newAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("新建值"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取该值"));

    QAction* action = menu.exec(valueTable_->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 值右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << currentPath_.toStdString()
            << eol;
    }
    if (action == editAction) editSelectedValue();
    else if (action == newAction) createValue();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copySelectedValueKernelPathToClipboard();
    else if (action == r0ReadAction) readSelectedValueByR0();
}

void RegistryDock::createSubKey()
{
    bool ok = false;
    const QString kKeyName = QInputDialog::getText(this, QStringLiteral("新建子键"), QStringLiteral("请输入子键名称："), QLineEdit::Normal, QStringLiteral("New Key"), &ok).trimmed();
    if (!ok || kKeyName.isEmpty()) return;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 新建子键请求, parentPath="
            << currentPath_.toStdString()
            << ", keyName="
            << kKeyName.toStdString()
            << eol;
    }

    QString errorText;
    const QString kFullKeyPath = currentPath_ + QStringLiteral("\\") + kKeyName;
    if (!createRegistryKeyAny(kFullKeyPath, &errorText))
    {
        // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表子键"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 新建子键失败, error=" << errorText.toStdString() << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新建子键"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 新建子键成功, fullPath=" << kFullKeyPath.toStdString() << eol;
    navigateToPath(kFullKeyPath, true);
}

void RegistryDock::createValue()
{
    // Use a detailed dialog for unified input: value name, value type, and value data are completed in one step.
    NewRegistryValueDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
    {
        KLogEvent event;
        dbg << event
            << "[RegistryDock] 新建值取消：用户关闭输入对话框。"
            << eol;
        return;
    }

    const NewRegistryValueInput kInputValue = dialog.buildOutput();
    const QString kValueName = kInputValue.valueName;
    const DWORD kType = kInputValue.valueType;
    const QByteArray kData = kInputValue.valueData;

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 新建值请求, path="
            << currentPath_.toStdString()
            << ", valueName="
            << kValueName.toStdString()
            << ", type="
            << valueTypeToText(kType).toStdString()
            << ", dataSize="
            << kData.size()
            << eol;
    }

    QString errorText;
    if (!writeRegistryValueAny(currentPath_, kValueName, kType, kData, &errorText))
    {
        // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表值"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 新建值失败, path=" << currentPath_.toStdString() << ", error=" << errorText.toStdString() << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新建值"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 新建值成功, path=" << currentPath_.toStdString() << ", valueName=" << kValueName.toStdString() << eol;
    refreshValueTable();
}

void RegistryDock::renameSelectedObject()
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 重命名请求, path="
            << currentPath_.toStdString()
            << ", valueTableFocus="
            << (valueTable_->hasFocus() ? "true" : "false")
            << eol;
    }

    if (valueTable_->hasFocus() && valueTable_->currentRow() >= 0)
    {
        const int kRow = valueTable_->currentRow();
        QTableWidgetItem* nameItem = valueTable_->item(kRow, 0);
        if (nameItem == nullptr) return;

        const QString kOldName = nameItem->data(Qt::UserRole).toString();
        if (kOldName.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("重命名"), QStringLiteral("默认值不支持重命名。"));
            return;
        }

        bool ok = false;
        const QString kNewName = QInputDialog::getText(this, QStringLiteral("重命名值"), QStringLiteral("新名称："), QLineEdit::Normal, kOldName, &ok).trimmed();
        if (!ok || kNewName.isEmpty() || kNewName.compare(kOldName, Qt::CaseInsensitive) == 0) return;

        QString errorText;
        if (!renameRegistryValueAny(currentPath_, kOldName, kNewName, &errorText))
        {
            // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
            const bool kPrivilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表值"), errorText);
            KLogEvent event;
            warn << event << "[RegistryDock] 重命名值失败, error=" << errorText.toStdString() << eol;
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(this, QStringLiteral("重命名值"), errorText);
            }
            return;
        }

        KLogEvent event;
        info << event
            << "[RegistryDock] 重命名值成功, oldName="
            << kOldName.toStdString()
            << ", newName="
            << kNewName.toStdString()
            << eol;

        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("重命名键"), QStringLiteral("根键不可重命名。"));
        return;
    }

    const int kSlashPos = subPath.lastIndexOf('\\');
    const QString kParentPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
    const QString kOldKeyName = kSlashPos < 0 ? subPath : subPath.mid(kSlashPos + 1);

    bool ok = false;
    const QString kNewKeyName = QInputDialog::getText(this, QStringLiteral("重命名键"), QStringLiteral("新键名："), QLineEdit::Normal, kOldKeyName, &ok).trimmed();
    if (!ok || kNewKeyName.isEmpty() || kNewKeyName.compare(kOldKeyName, Qt::CaseInsensitive) == 0) return;

    QString newPath;
    QString errorText;
    if (!renameRegistryKeyAny(currentPath_, kNewKeyName, &newPath, &errorText))
    {
        // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表键"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 重命名键失败, error=" << errorText.toStdString() << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("重命名键"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[RegistryDock] 重命名键成功, oldKey="
        << kOldKeyName.toStdString()
        << ", newKey="
        << kNewKeyName.toStdString()
        << ", newPath="
        << newPath.toStdString()
        << eol;
    navigateToPath(newPath, true);
}

void RegistryDock::deleteSelectedObject()
{
    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 删除请求, path="
            << currentPath_.toStdString()
            << ", valueTableFocus="
            << (valueTable_->hasFocus() ? "true" : "false")
            << eol;
    }

    if (valueTable_->hasFocus() && valueTable_->currentRow() >= 0)
    {
        QTableWidgetItem* nameItem = valueTable_->item(valueTable_->currentRow(), 0);
        if (nameItem == nullptr) return;
        const QString kValueName = nameItem->data(Qt::UserRole).toString();

        QMessageBox::StandardButton choice = QMessageBox::question(
            this,
            QStringLiteral("删除值"),
            QStringLiteral("确定删除值“%1”吗？").arg(kValueName.isEmpty() ? QStringLiteral("(默认)") : kValueName),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes) return;

        QString errorText;
        if (!deleteRegistryValueAny(currentPath_, kValueName, &errorText))
        {
            // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
            const bool kPrivilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), errorText);
            KLogEvent event;
            warn << event << "[RegistryDock] 删除值失败, error=" << errorText.toStdString() << eol;
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(this, QStringLiteral("删除值"), errorText);
            }
            return;
        }

        KLogEvent event;
        info << event << "[RegistryDock] 删除值成功, valueName=" << kValueName.toStdString() << eol;
        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(currentPath_, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("删除键"), QStringLiteral("根键不可删除。"));
        return;
    }

    QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("删除键"),
        QStringLiteral("确定删除键“%1”及其子项吗？").arg(currentPath_),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes) return;

    const int kSlashPos = subPath.lastIndexOf('\\');
    const QString kParentPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
    const QString kKeyName = kSlashPos < 0 ? subPath : subPath.mid(kSlashPos + 1);

    QString errorText;
    if (!deleteRegistryKeyAny(currentPath_, &errorText))
    {
        // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 删除键失败, error=" << errorText.toStdString() << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除键"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event << "[RegistryDock] 删除键成功, keyName=" << kKeyName.toStdString() << eol;

    QString parentFullPath = rootKeyToText(root);
    if (!kParentPath.isEmpty()) parentFullPath += QStringLiteral("\\") + kParentPath;
    navigateToPath(parentFullPath, true);
}

void RegistryDock::deleteSearchResultValue(const QString& keyPath, const QString& rawValueName)
{
    // Search result handling cannot borrow the current tree selection: the user may have navigated to a different key during the search.
    const QString kNormalizedKeyPath = keyPath.trimmed();
    if (kNormalizedKeyPath.isEmpty())
    {
        return;
    }

    const QString kDisplayValueName = rawValueName.isEmpty() ? QStringLiteral("(默认)") : rawValueName;
    const QMessageBox::StandardButton kChoice = QMessageBox::question(
        this,
        QStringLiteral("删除值"),
        QStringLiteral("确定删除注册表值“%1”吗？\n\n键路径：%2")
            .arg(kDisplayValueName, kNormalizedKeyPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!deleteRegistryValueAny(kNormalizedKeyPath, rawValueName, &errorText))
    {
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), errorText);
        KLogEvent event;
        warn << event
            << "[RegistryDock] 搜索结果删除值失败, keyPath="
            << kNormalizedKeyPath.toStdString()
            << ", valueName="
            << rawValueName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除值"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[RegistryDock] 搜索结果删除值成功, keyPath="
        << kNormalizedKeyPath.toStdString()
        << ", valueName="
        << rawValueName.toStdString()
        << eol;

    // After successful deletion, only remove the exact match; other search evidence within the same key remains valid.
    if (searchResultTable_ != nullptr)
    {
        for (int row = searchResultTable_->rowCount() - 1; row >= 0; --row)
        {
            const QTableWidgetItem* pathItem = searchResultTable_->item(row, 0);
            const QTableWidgetItem* valueNameItem = searchResultTable_->item(row, 1);
            if (pathItem == nullptr || valueNameItem == nullptr
                || pathItem->data(kSearchResultRoleTargetKind).toInt() != kSearchResultTargetValue)
            {
                continue;
            }
            if (pathItem->text().compare(kNormalizedKeyPath, Qt::CaseInsensitive) == 0
                && valueNameItem->data(kSearchResultRoleRawValueName).toString() == rawValueName)
            {
                searchResultTable_->removeRow(row);
            }
        }
    }
    refreshValueTable();
}

void RegistryDock::deleteSearchResultKey(const QString& keyPath)
{
    // Search result handling cannot borrow the current tree selection: the user may have navigated to a different key during the search.
    const QString kNormalizedKeyPath = keyPath.trimmed();
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(kNormalizedKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("删除键"), QStringLiteral("根键不可删除。"));
        return;
    }

    const QMessageBox::StandardButton kChoice = QMessageBox::question(
        this,
        QStringLiteral("删除键"),
        QStringLiteral("确定删除注册表键“%1”及其所有子项吗？").arg(kNormalizedKeyPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!deleteRegistryKeyAny(kNormalizedKeyPath, &errorText))
    {
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), errorText);
        KLogEvent event;
        warn << event
            << "[RegistryDock] 搜索结果删除键失败, keyPath="
            << kNormalizedKeyPath.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除键"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[RegistryDock] 搜索结果删除键成功, keyPath="
        << kNormalizedKeyPath.toStdString()
        << eol;

    const QString kTargetPrefix = kNormalizedKeyPath + QStringLiteral("\\");
    if (searchResultTable_ != nullptr)
    {
        // Deleting a key removes all its subkeys and values; these expired audit rows cannot be preserved.
        for (int row = searchResultTable_->rowCount() - 1; row >= 0; --row)
        {
            const QTableWidgetItem* pathItem = searchResultTable_->item(row, 0);
            if (pathItem == nullptr)
            {
                continue;
            }
            const QString kResultKeyPath = pathItem->text();
            if (kResultKeyPath.compare(kNormalizedKeyPath, Qt::CaseInsensitive) == 0
                || kResultKeyPath.startsWith(kTargetPrefix, Qt::CaseInsensitive))
            {
                searchResultTable_->removeRow(row);
            }
        }
    }

    const bool kCurrentPathWasDeleted = currentPath_.compare(kNormalizedKeyPath, Qt::CaseInsensitive) == 0
        || currentPath_.startsWith(kTargetPrefix, Qt::CaseInsensitive);
    if (kCurrentPathWasDeleted)
    {
        const int kSlashPos = subPath.lastIndexOf('\\');
        const QString kParentSubPath = kSlashPos < 0 ? QString() : subPath.left(kSlashPos);
        QString parentFullPath = rootKeyToText(root);
        if (!kParentSubPath.isEmpty())
        {
            parentFullPath += QStringLiteral("\\") + kParentSubPath;
        }
        navigateToPath(parentFullPath, true);
    }
    else
    {
        refreshValueTable();
    }
}

void RegistryDock::editSelectedValue()
{
    const int kRow = valueTable_->currentRow();
    {
        KLogEvent event;
        info << event << "[RegistryDock] 编辑值请求, path=" << currentPath_.toStdString() << ", row=" << kRow << eol;
    }
    if (kRow < 0) return;
    QTableWidgetItem* nameItem = valueTable_->item(kRow, 0);
    if (nameItem == nullptr) return;

    const QString kValueName = nameItem->data(Qt::UserRole).toString();

    DWORD type = REG_NONE;
    QByteArray data;
    QString errorText;
    if (!readRegistryValueAny(currentPath_, kValueName, &type, &data, &errorText))
    {
        KLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：读取原值失败, error=" << errorText.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        return;
    }

    bool ok = false;
    QByteArray outputData = data;

    if (type == REG_DWORD || type == REG_QWORD)
    {
        qulonglong oldValue = 0;
        if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD))) oldValue = *reinterpret_cast<const DWORD*>(data.constData());
        if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64))) oldValue = *reinterpret_cast<const quint64*>(data.constData());

        const QString kText = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入新数值："), QLineEdit::Normal, QString::number(oldValue), &ok).trimmed();
        if (!ok) return;

        bool parseOk = false;
        const qulonglong kParsed = kText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? kText.mid(2).toULongLong(&parseOk, 16)
            : kText.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("数值格式无效。"));
            return;
        }

        if (type == REG_DWORD)
        {
            const DWORD kV = static_cast<DWORD>(kParsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&kV), sizeof(kV));
        }
        else
        {
            const quint64 kV = static_cast<quint64>(kParsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&kV), sizeof(kV));
        }
    }
    else if (type == REG_BINARY)
    {
        const QString kText = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入十六进制字节："), QLineEdit::Normal, bytesToHex(data, 512), &ok).trimmed();
        if (!ok) return;

        outputData.clear();
        const QStringList kParts = kText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const QString& part : kParts)
        {
            bool parseOk = false;
            const int kByteValue = part.toInt(&parseOk, 16);
            if (!parseOk || kByteValue < 0 || kByteValue > 255)
            {
                QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("字节无效：%1").arg(part));
                return;
            }
            outputData.push_back(static_cast<char>(kByteValue));
        }
    }
    else
    {
        QString text = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入字符串："), QLineEdit::Normal, formatValueData(type, data), &ok);
        if (!ok) return;
        text.append(QChar::Null);
        outputData = QByteArray(reinterpret_cast<const char*>(text.utf16()), text.size() * sizeof(char16_t));
    }

    if (!writeRegistryValueAny(currentPath_, kValueName, type, outputData, &errorText))
    {
        // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("编辑注册表值"), errorText);
        KLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：写入失败, error=" << errorText.toStdString() << eol;
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        }
        return;
    }

    KLogEvent event;
    info << event
        << "[RegistryDock] 编辑值成功, valueName="
        << kValueName.toStdString()
        << ", type="
        << valueTypeToText(type).toStdString()
        << eol;
    refreshValueTable();
}

void RegistryDock::copyCurrentPathToClipboard()
{
    QApplication::clipboard()->setText(currentPath_);

    KLogEvent event;
    info << event << "[RegistryDock] 复制路径到剪贴板, path=" << currentPath_.toStdString() << eol;
}

void RegistryDock::copyCurrentKernelPathToClipboard()
{
    const QString kKernelPath = buildKernelRegistryPath(currentPath_);
    if (kKernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kKernelPath);

    KLogEvent event;
    info << event
        << "[RegistryDock] 复制内核模式地址到剪贴板, path="
        << currentPath_.toStdString()
        << ", kernelPath="
        << kKernelPath.toStdString()
        << eol;
}

void RegistryDock::copySelectedValueKernelPathToClipboard()
{
    QString targetPath = currentPath_;
    const int kSelectedRow = valueTable_->currentRow();
    if (kSelectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = valueTable_->item(kSelectedRow, 0);
        if (valueNameItem != nullptr)
        {
            const QString kValueName = valueNameItem->data(Qt::UserRole).toString().trimmed();
            if (!kValueName.isEmpty())
            {
                targetPath += QStringLiteral("\\") + kValueName;
            }
        }
    }

    const QString kKernelPath = buildKernelRegistryPath(targetPath);
    if (kKernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kKernelPath);

    KLogEvent event;
    info << event
        << "[RegistryDock] 复制值内核模式地址到剪贴板, path="
        << targetPath.toStdString()
        << ", kernelPath="
        << kKernelPath.toStdString()
        << eol;
}

void RegistryDock::readSelectedValueByR0()
{
    const int kSelectedRow = valueTable_->currentRow();
    QString valueName;
    if (kSelectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = valueTable_->item(kSelectedRow, 0);
        if (valueNameItem != nullptr)
        {
            valueName = valueNameItem->data(Qt::UserRole).toString();
        }
    }

    readRegistryValueByR0(valueName);
}

void RegistryDock::readDefaultValueByR0()
{
    readRegistryValueByR0(QString());
}

void RegistryDock::readRegistryValueByR0(const QString& valueName)
{
    // Function: Converts the current UI path to \REGISTRY\... and queries the value via a read-only R0 IOCTL.
    // Returns: None; results are displayed via dialog and status bar.
    const QString kKernelPath = buildKernelRegistryPath(currentPath_);
    if (kKernelPath.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), QStringLiteral("当前注册表路径无效。"));
        return;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::RegistryReadResult kReadResult = kDriverClient.readRegistryValue(
        kKernelPath.toStdWString(),
        valueName.toStdWString(),
        KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);

    QByteArray rawData;
    if (!kReadResult.data.empty())
    {
        rawData = QByteArray(
            reinterpret_cast<const char*>(kReadResult.data.data()),
            static_cast<int>(kReadResult.data.size()));
    }

    const QString kValueDisplayName = valueName.trimmed().isEmpty()
        ? QStringLiteral("(默认)")
        : valueName;
    const QString kFormattedData = kReadResult.data.empty()
        ? QStringLiteral("<空>")
        : formatValueData(static_cast<DWORD>(kReadResult.valueType), rawData);
    const QString kStatusText = QStringLiteral(
        "路径：%1\n"
        "值名：%2\n"
        "状态：%3\n"
        "类型：%4\n"
        "数据长度：%5 / 需要：%6\n"
        "NTSTATUS：0x%7\n\n"
        "数据：\n%8")
        .arg(kKernelPath)
        .arg(kValueDisplayName)
        .arg(kReadResult.io.ok ? QString::number(kReadResult.status) : QStringLiteral("IOCTL失败"))
        .arg(valueTypeToText(static_cast<DWORD>(kReadResult.valueType)))
        .arg(kReadResult.dataBytes)
        .arg(kReadResult.requiredBytes)
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(kReadResult.lastStatus)), 8, 16, QChar('0'))
        .arg(kFormattedData);

    KLogEvent event;
    (kReadResult.io.ok && kReadResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS ? info : warn)
        << event
        << "[RegistryDock] R0读取注册表完成, path="
        << kKernelPath.toStdString()
        << ", valueName="
        << valueName.toStdString()
        << ", ok="
        << (kReadResult.io.ok ? "true" : "false")
        << ", status="
        << kReadResult.status
        << ", detail="
        << registryIoMessageText(kReadResult.io.message).toStdString()
        << eol;

    updateStatusBar(QStringLiteral("R0读取注册表：%1").arg(kReadResult.io.ok ? QStringLiteral("完成") : QStringLiteral("失败")));
    if (kReadResult.io.ok && kReadResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS)
    {
        QMessageBox::information(this, QStringLiteral("R0读取注册表"), kStatusText);
    }
    else
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), kStatusText + QStringLiteral("\n\n详情：%1").arg(registryIoMessageText(kReadResult.io.message)));
    }
}

void RegistryDock::exportCurrentKeyAsync()
{
    if (currentPath_.isEmpty()) return;

    KLogEvent event;
    info << event << "[RegistryDock] 导出请求, keyPath=" << currentPath_.toStdString() << eol;

    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 .reg"),
        QStringLiteral("registry_%1.reg").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("REG 文件 (*.reg)"));
    if (kOutputPath.trimmed().isEmpty()) return;

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "导出");
    kPro.set(progressPid_, "导出中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    const QString kKeyPath = currentPath_;
    std::thread([guardThis, kKeyPath, kOutputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("export"), kKeyPath, kOutputPath, QStringLiteral("/y") });
        process.waitForFinished(-1);

        const bool kOk = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString kErrText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, kOk, kErrText, kOutputPath]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->progressPid_, "导出完成", 0, 100.0f);
            if (kOk)
            {
                KLogEvent event;
                info << event << "[RegistryDock] 导出成功, outputPath=" << kOutputPath.toStdString() << eol;
                QMessageBox::information(guardThis, QStringLiteral("导出 .reg"), QStringLiteral("导出成功：%1").arg(kOutputPath));
            }
            else
            {
                // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
                const bool kPrivilegePromptHandled =
                    ks::ui::promptForPrivilegeFailure(guardThis, QStringLiteral("导出注册表文件"), kErrText);
                KLogEvent event;
                warn << event << "[RegistryDock] 导出失败, error=" << kErrText.toStdString() << eol;
                if (!kPrivilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导出 .reg"),
                        QStringLiteral("导出失败：\n%1").arg(kErrText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void RegistryDock::importRegFileAsync()
{
    const QString kInputPath = QFileDialog::getOpenFileName(this, QStringLiteral("导入 .reg"), QString(), QStringLiteral("REG 文件 (*.reg)"));
    if (kInputPath.trimmed().isEmpty()) return;

    KLogEvent event;
    info << event << "[RegistryDock] 导入请求, inputPath=" << kInputPath.toStdString() << eol;

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "导入");
    kPro.set(progressPid_, "导入中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    std::thread([guardThis, kInputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("import"), kInputPath });
        process.waitForFinished(-1);

        const bool kOk = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString kErrText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, kOk, kErrText]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->progressPid_, "导入完成", 0, 100.0f);
            if (kOk)
            {
                KLogEvent event;
                info << event << "[RegistryDock] 导入成功。" << eol;
                QMessageBox::information(guardThis, QStringLiteral("导入 .reg"), QStringLiteral("导入成功。"));
                guardThis->refreshCurrentKey(true);
            }
            else
            {
                // privilegePromptHandled: Suppresses the old failure dialog when the privilege recovery prompt has been displayed.
                const bool kPrivilegePromptHandled =
                    ks::ui::promptForPrivilegeFailure(guardThis, QStringLiteral("导入注册表文件"), kErrText);
                KLogEvent event;
                warn << event << "[RegistryDock] 导入失败, error=" << kErrText.toStdString() << eol;
                if (!kPrivilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导入 .reg"),
                        QStringLiteral("导入失败：\n%1").arg(kErrText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}
void RegistryDock::startSearchAsync()
{
    if (searchRunning_.load())
    {
        KLogEvent event;
        dbg << event << "[RegistryDock] 搜索请求被忽略：已有搜索在运行。" << eol;
        return;
    }

    const QString kKeyword = searchEdit_->text().trimmed();
    if (kKeyword.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("搜索"), QStringLiteral("请输入关键字。"));
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[RegistryDock] 启动搜索, path="
            << currentPath_.toStdString()
            << ", keyword="
            << kKeyword.toStdString()
            << eol;
    }

    const bool kUseR0Search = shouldUseRegistryR0();
    HKEY root = nullptr;
    QString subPath;
    QString kernelStartPath;
    QString displayStartPath = currentPath_;
    if (kUseR0Search)
    {
        kernelStartPath = buildKernelRegistryPath(currentPath_);
        if (kernelStartPath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("搜索"), QStringLiteral("当前路径无法转换为内核注册表路径。"));
            return;
        }
    }
    else if (!parseRegistryPath(currentPath_, &root, &subPath))
    {
        return;
    }

    searchRunning_.store(true);
    searchStopFlag_.store(false);
    searchScannedKeys_ = 0;
    searchHitCount_ = 0;
    searchResultTable_->setRowCount(0);
    rightTabWidget_->setCurrentWidget(searchResultTable_);
    searchButton_->setEnabled(false);
    stopSearchButton_->setEnabled(true);

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.clear();
    }

    if (progressPid_ == 0) progressPid_ = kPro.addReusable(this, "注册表", "搜索");
    kPro.set(progressPid_, "搜索开始", 0, 5.0f);
    searchFlushTimer_->start();

    QPointer<RegistryDock> guardThis(this);
    SearchOptions options;
    searchThread_ = std::make_unique<std::thread>([guardThis, root, subPath, kKeyword, options, kUseR0Search, kernelStartPath, displayStartPath]() {
        if (guardThis == nullptr) return;

        std::size_t scanned = 0;
        std::size_t hits = 0;
        if (kUseR0Search)
        {
            guardThis->searchRegistryRecursiveByR0(kernelStartPath, displayStartPath, kKeyword, options, &scanned, &hits);
        }
        else
        {
            guardThis->searchRegistryRecursive(root, subPath, kKeyword, options, &scanned, &hits);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, scanned, hits]() {
            if (guardThis == nullptr) return;
            // Reading the stop flag must occur before resetting it to ensure the interaction stop state differs from the natural completion display state.
            const bool kWasStopped = guardThis->searchStopFlag_.load();
            guardThis->searchRunning_.store(false);
            guardThis->searchStopFlag_.store(false);
            if (guardThis->searchThread_ != nullptr && guardThis->searchThread_->joinable())
            {
                guardThis->searchThread_->join();
                guardThis->searchThread_.reset();
            }
            guardThis->flushPendingSearchRows();
            guardThis->searchButton_->setEnabled(true);
            guardThis->stopSearchButton_->setEnabled(false);
            guardThis->updateStatusBar(kWasStopped
                ? QStringLiteral("状态: 搜索已停止")
                : QStringLiteral("状态: 搜索完成，扫描 %1 键，命中 %2 项").arg(scanned).arg(hits));
            kPro.set(guardThis->progressPid_, kWasStopped ? "搜索停止" : "搜索完成", 0, 100.0f);

            KLogEvent event;
            info << event
                << (kWasStopped ? "[RegistryDock] 搜索已停止, scanned=" : "[RegistryDock] 搜索完成, scanned=")
                << scanned
                << ", hits="
                << hits
                << eol;
        }, Qt::QueuedConnection);
    });
}

void RegistryDock::stopSearch(bool waitForThread)
{
    KLogEvent event;
    info << event
        << "[RegistryDock] 停止搜索请求, waitForThread="
        << (waitForThread ? "true" : "false")
        << eol;

    searchStopFlag_.store(true);

    if (searchThread_ == nullptr || !searchThread_->joinable())
    {
        searchThread_.reset();
        searchRunning_.store(false);
        searchButton_->setEnabled(true);
        stopSearchButton_->setEnabled(false);
        if (searchFlushTimer_ != nullptr) searchFlushTimer_->stop();
        return;
    }

    if (waitForThread)
    {
        searchThread_->join();
        searchThread_.reset();
        searchRunning_.store(false);
        searchButton_->setEnabled(true);
        stopSearchButton_->setEnabled(false);
        if (searchFlushTimer_ != nullptr) searchFlushTimer_->stop();
        return;
    }

    // Interaction stop cannot transfer sole thread ownership: the destruction path needs it to synchronize
    // and wait, ensuring recursive search does not access members after RegistryDock is released.
    stopSearchButton_->setEnabled(false);
    updateStatusBar(QStringLiteral("状态: 搜索已停止"));
}

void RegistryDock::enqueuePendingSearchRow(PendingSearchRow&& row)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    if (pendingRows_.size() < kMaxPendingSearchRows)
    {
        pendingRows_.push_back(std::move(row));
    }
}

void RegistryDock::flushPendingSearchRows()
{
    // The search thread is responsible only for enqueueing; the queue is not consumed when the menu
    // is open to avoid batch expansion causing drift in result rows saved by right-click actions.
    const QPointer<RegistryDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("registry-search-result-flush"),
        {searchResultTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->flushPendingSearchRows();
            }
        }))
    {
        return;
    }

    std::vector<PendingSearchRow> rows;
    bool hasPendingRows = false;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        const std::size_t kCount = std::min<std::size_t>(kSearchFlushBatchSize, pendingRows_.size());
        rows.reserve(kCount);
        for (std::size_t i = 0; i < kCount; ++i)
        {
            rows.push_back(std::move(pendingRows_.front()));
            pendingRows_.pop_front();
        }
        hasPendingRows = !pendingRows_.empty();
    }

    const int kAvailableRows = std::max(0, kMaxSearchResultRows - searchResultTable_->rowCount());
    const int kRowsToAppend = std::min(kAvailableRows, static_cast<int>(rows.size()));
    if (kRowsToAppend > 0)
    {
        const int kFirstRow = searchResultTable_->rowCount();
        const bool kUpdatesEnabled = searchResultTable_->updatesEnabled();
        searchResultTable_->setUpdatesEnabled(false);
        searchResultTable_->setRowCount(kFirstRow + kRowsToAppend);
        for (int index = 0; index < kRowsToAppend; ++index)
        {
            const PendingSearchRow& row = rows[static_cast<std::size_t>(index)];
            const int kTableRow = kFirstRow + index;
            QTableWidgetItem* keyPathItem = new QTableWidgetItem(row.keyPathText);
            keyPathItem->setData(
                kSearchResultRoleTargetKind,
                row.isKeyResult ? kSearchResultTargetKey : kSearchResultTargetValue);
            QTableWidgetItem* valueNameItem = new QTableWidgetItem(row.valueNameText);
            if (!row.isKeyResult)
            {
                // Default display text and the actual empty Win32 name are stored separately to avoid ambiguity when display values share the same name.
                valueNameItem->setData(kSearchResultRoleRawValueName, row.rawValueName);
            }
            searchResultTable_->setItem(kTableRow, 0, keyPathItem);
            searchResultTable_->setItem(kTableRow, 1, valueNameItem);
            searchResultTable_->setItem(kTableRow, 2, new QTableWidgetItem(row.valueTypeText));
            searchResultTable_->setItem(kTableRow, 3, new QTableWidgetItem(row.valueDataPreviewText));
            searchResultTable_->setItem(kTableRow, 4, new QTableWidgetItem(row.hitSourceText));
        }
        searchResultTable_->setUpdatesEnabled(kUpdatesEnabled);
        if (kUpdatesEnabled) searchResultTable_->viewport()->update();
    }

    if (!searchRunning_.load() && !hasPendingRows && searchFlushTimer_ != nullptr)
    {
        searchFlushTimer_->stop();
    }
}

void RegistryDock::searchRegistryRecursive(HKEY root, const QString& subPath, const QString& keyword, const SearchOptions& options, std::size_t* scanned, std::size_t* hit)
{
    if (searchStopFlag_.load()) return;

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key);
    if (openResult != ERROR_SUCCESS) return;

    if (scanned != nullptr) *scanned += 1;

    const QString kFullPath = rootKeyToText(root) + (subPath.isEmpty() ? QString() : QStringLiteral("\\") + subPath);
    const QString kKeyName = subPath.isEmpty() ? rootKeyToText(root) : subPath.mid(subPath.lastIndexOf('\\') + 1);

    auto containsText = [&keyword, &options](const QString& text) {
        return options.caseSensitive ? text.contains(keyword) : text.contains(keyword, Qt::CaseInsensitive);
    };

    if (options.searchKeyName && containsText(kKeyName))
    {
        PendingSearchRow row;
        row.keyPathText = kFullPath;
        row.valueNameText = QStringLiteral("<Key>");
        row.valueTypeText = QStringLiteral("<Key>");
        row.valueDataPreviewText = QStringLiteral("-");
        row.hitSourceText = QStringLiteral("KeyName");
        row.isKeyResult = true;
        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    DWORD valueCount = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueDataLen = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);

    std::vector<wchar_t> valueNameBuffer(static_cast<std::size_t>(maxValueNameLen + 4), L'\0');
    std::vector<unsigned char> valueDataBuffer(static_cast<std::size_t>(maxValueDataLen + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        if (searchStopFlag_.load()) break;

        DWORD valueNameLen = static_cast<DWORD>(valueNameBuffer.size() - 1);
        DWORD valueDataLen = static_cast<DWORD>(valueDataBuffer.size());
        DWORD valueType = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, valueNameBuffer.data(), &valueNameLen, nullptr, &valueType, valueDataBuffer.data(), &valueDataLen);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString kValueName = QString::fromWCharArray(valueNameBuffer.data(), static_cast<int>(valueNameLen));
        const QByteArray kValueData(reinterpret_cast<const char*>(valueDataBuffer.data()), static_cast<int>(valueDataLen));
        const QString kValueText = formatValueData(valueType, kValueData);

        bool matched = false;
        QString sourceText;
        if (options.searchValueName && containsText(kValueName))
        {
            matched = true;
            sourceText = QStringLiteral("ValueName");
        }
        if (!matched && options.searchValueData && containsText(kValueText))
        {
            matched = true;
            sourceText = QStringLiteral("ValueData");
        }
        if (!matched) continue;

        PendingSearchRow row;
        row.keyPathText = kFullPath;
        row.valueNameText = kValueName.isEmpty() ? QStringLiteral("(默认)") : kValueName;
        row.rawValueName = kValueName;
        row.valueTypeText = valueTypeToText(valueType);
        row.valueDataPreviewText = kValueText;
        row.hitSourceText = sourceText;

        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    if (scanned != nullptr && (*scanned % 64 == 0))
    {
        const std::size_t kScannedSnapshot = *scanned;
        const std::size_t kHitSnapshot = (hit == nullptr) ? 0 : *hit;
        QPointer<RegistryDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis, kScannedSnapshot, kHitSnapshot]() {
            if (guardThis == nullptr) return;
            guardThis->updateStatusBar(QStringLiteral("状态: 搜索中，扫描 %1 键，命中 %2 项").arg(kScannedSnapshot).arg(kHitSnapshot));
            const float kProgress = 5.0f + static_cast<float>(std::min<std::size_t>(kScannedSnapshot, 4000)) / 50.0f;
            kPro.set(guardThis->progressPid_, "搜索中", 0, std::min(kProgress, 95.0f));
        }, Qt::QueuedConnection);
    }

    std::vector<wchar_t> subNameBuffer(static_cast<std::size_t>(maxSubKeyLen + 4), L'\0');
    for (DWORD subIndex = 0; subIndex < subKeyCount; ++subIndex)
    {
        if (searchStopFlag_.load()) break;

        DWORD subNameLen = static_cast<DWORD>(subNameBuffer.size() - 1);
        LONG subResult = ::RegEnumKeyExW(key, subIndex, subNameBuffer.data(), &subNameLen, nullptr, nullptr, nullptr, nullptr);
        if (subResult != ERROR_SUCCESS) continue;

        const QString kChildName = QString::fromWCharArray(subNameBuffer.data(), static_cast<int>(subNameLen));
        const QString kChildPath = subPath.isEmpty() ? kChildName : subPath + QStringLiteral("\\") + kChildName;
        searchRegistryRecursive(root, kChildPath, keyword, options, scanned, hit);
    }

    ::RegCloseKey(key);
}

void RegistryDock::searchRegistryRecursiveByR0(
    const QString& kernelKeyPath,
    const QString& displayKeyPath,
    const QString& keyword,
    const SearchOptions& options,
    std::size_t* scanned,
    std::size_t* hit)
{
    // Purpose: Recursively enumerate registry keys and values via the driver to match keywords.
    // Returns: Nothing; results are asynchronously flushed into the search table via m_pendingRows.
    if (searchStopFlag_.load())
    {
        return;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::RegistryEnumResult kEnumResult = kDriverClient.enumerateRegistryKey(
        kernelKeyPath.toStdWString(),
        KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
    if (!registryEnumUsable(kEnumResult))
    {
        KLogEvent event;
        warn << event
            << "[RegistryDock] R0搜索枚举失败, kernelPath="
            << kernelKeyPath.toStdString()
            << ", detail="
            << registryEnumFailureText(QStringLiteral("R0搜索枚举"), kEnumResult).toStdString()
            << eol;
        return;
    }

    if (scanned != nullptr)
    {
        *scanned += 1;
    }

    auto containsText = [&keyword, &options](const QString& text) {
        return options.caseSensitive ? text.contains(keyword) : text.contains(keyword, Qt::CaseInsensitive);
    };

    const int kLastSlash = displayKeyPath.lastIndexOf('\\');
    const QString kKeyName = kLastSlash < 0 ? displayKeyPath : displayKeyPath.mid(kLastSlash + 1);
    if (options.searchKeyName && containsText(kKeyName))
    {
        PendingSearchRow row;
        row.keyPathText = displayKeyPath;
        row.valueNameText = QStringLiteral("<Key>");
        row.valueTypeText = QStringLiteral("<Key>");
        row.valueDataPreviewText = QStringLiteral("-");
        row.hitSourceText = QStringLiteral("KeyName/R0");
        row.isKeyResult = true;
        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    for (const ksword::ark::RegistryValueEntry& valueEntry : kEnumResult.values)
    {
        if (searchStopFlag_.load())
        {
            break;
        }

        const QString kValueName = QString::fromStdWString(valueEntry.name);
        const QByteArray kValueData = registryDataToByteArray(valueEntry.data);
        QString valueText = formatValueData(static_cast<DWORD>(valueEntry.valueType), kValueData);
        if (valueEntry.requiredBytes > valueEntry.dataBytes)
        {
            valueText += QStringLiteral(" <R0预览截断 %1/%2>").arg(valueEntry.dataBytes).arg(valueEntry.requiredBytes);
        }

        bool matched = false;
        QString sourceText;
        if (options.searchValueName && containsText(kValueName))
        {
            matched = true;
            sourceText = QStringLiteral("ValueName/R0");
        }
        if (!matched && options.searchValueData && containsText(valueText))
        {
            matched = true;
            sourceText = QStringLiteral("ValueData/R0");
        }
        if (!matched)
        {
            continue;
        }

        PendingSearchRow row;
        row.keyPathText = displayKeyPath;
        row.valueNameText = kValueName.isEmpty() ? QStringLiteral("(默认)") : kValueName;
        row.rawValueName = kValueName;
        row.valueTypeText = valueTypeToText(static_cast<DWORD>(valueEntry.valueType));
        row.valueDataPreviewText = valueText;
        row.hitSourceText = sourceText;

        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    if (scanned != nullptr && (*scanned % 64 == 0))
    {
        const std::size_t kScannedSnapshot = *scanned;
        const std::size_t kHitSnapshot = (hit == nullptr) ? 0 : *hit;
        QPointer<RegistryDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis, kScannedSnapshot, kHitSnapshot]() {
            if (guardThis == nullptr) return;
            guardThis->updateStatusBar(QStringLiteral("状态: R0搜索中，扫描 %1 键，命中 %2 项").arg(kScannedSnapshot).arg(kHitSnapshot));
            const float kProgress = 5.0f + static_cast<float>(std::min<std::size_t>(kScannedSnapshot, 4000)) / 50.0f;
            kPro.set(guardThis->progressPid_, "R0搜索中", 0, std::min(kProgress, 95.0f));
        }, Qt::QueuedConnection);
    }

    for (const ksword::ark::RegistrySubKeyEntry& childEntry : kEnumResult.subKeys)
    {
        if (searchStopFlag_.load())
        {
            break;
        }

        const QString kChildName = QString::fromStdWString(childEntry.name);
        if (kChildName.trimmed().isEmpty())
        {
            continue;
        }
        searchRegistryRecursiveByR0(
            kernelKeyPath + QStringLiteral("\\") + kChildName,
            displayKeyPath + QStringLiteral("\\") + kChildName,
            keyword,
            options,
            scanned,
            hit);
    }
}
