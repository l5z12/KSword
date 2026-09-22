#include "HandleDock.h"

// ============================================================
// HandleDock.Icon.cpp
// Purpose:
// - Hosts the "process icon resolution and caching" logic within the Handle module.
// - Cache strictly bound snapshot row PID + creation time to avoid treating a process with a reused PID as the original instance.
// - If an instance cannot be verified, display the default icon rather than an incorrect process path or icon.
// ============================================================

#include <QFileIconProvider>
#include <QFileInfo>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <array>

namespace
{
    QString buildProcessInstanceCacheKey(
        const std::uint32_t processId,
        const std::uint64_t processCreationTime)
    {
        if (processId == 0U || processCreationTime == 0U)
        {
            return {};
        }
        return QStringLiteral("%1|%2")
            .arg(static_cast<qulonglong>(processId))
            .arg(static_cast<qulonglong>(processCreationTime));
    }

    std::uint64_t fileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER value{};
        value.LowPart = fileTimeValue.dwLowDateTime;
        value.HighPart = fileTimeValue.dwHighDateTime;
        return value.QuadPart;
    }

    QString queryProcessImagePathIfIdentityMatches(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime)
    {
        if (processId == 0U || expectedCreationTime == 0U)
        {
            return {};
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(processId));
        if (kProcessHandle == nullptr)
        {
            return {};
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const bool kIdentityMatches =
            ::GetProcessTimes(
                kProcessHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE
            && fileTimeToUint64(creationTime) == expectedCreationTime;
        if (!kIdentityMatches)
        {
            ::CloseHandle(kProcessHandle);
            return {};
        }

        std::array<wchar_t, 32768> imagePathBuffer{};
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        QString processImagePath;
        if (::QueryFullProcessImageNameW(
            kProcessHandle,
            0,
            imagePathBuffer.data(),
            &imagePathLength) != FALSE
            && imagePathLength > 0U)
        {
            processImagePath = QString::fromWCharArray(
                imagePathBuffer.data(),
                static_cast<int>(imagePathLength));
        }
        ::CloseHandle(kProcessHandle);
        return processImagePath;
    }
}

QIcon HandleDock::resolveProcessIconForRow(const HandleRow& row)
{
    const QString kCacheKey =
        buildProcessInstanceCacheKey(row.processId, row.processCreationTime);
    if (kCacheKey.isEmpty())
    {
        return QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    const auto kIconIt = processIconCacheByIdentity_.constFind(kCacheKey);
    if (kIconIt != processIconCacheByIdentity_.constEnd())
    {
        return kIconIt.value();
    }

    const QString kProcessImagePath =
        queryProcessImagePathCached(row.processId, row.processCreationTime);
    QIcon processIcon;
    if (!kProcessImagePath.trimmed().isEmpty())
    {
        processIcon = QIcon(kProcessImagePath);
        if (processIcon.isNull())
        {
            QFileIconProvider iconProvider;
            processIcon = iconProvider.icon(QFileInfo(kProcessImagePath));
        }
    }

    if (processIcon.isNull())
    {
        processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    processIconCacheByIdentity_.insert(kCacheKey, processIcon);
    return processIcon;
}

QString HandleDock::queryProcessImagePathCached(
    const std::uint32_t processId,
    const std::uint64_t expectedCreationTime)
{
    const QString kCacheKey =
        buildProcessInstanceCacheKey(processId, expectedCreationTime);
    if (kCacheKey.isEmpty())
    {
        return {};
    }

    const auto kPathIt = processImagePathCacheByIdentity_.constFind(kCacheKey);
    if (kPathIt != processImagePathCacheByIdentity_.constEnd())
    {
        return kPathIt.value();
    }

    const QString kProcessImagePath =
        queryProcessImagePathIfIdentityMatches(processId, expectedCreationTime);
    if (!kProcessImagePath.isEmpty())
    {
        processImagePathCacheByIdentity_.insert(kCacheKey, kProcessImagePath);
    }
    return kProcessImagePath;
}
