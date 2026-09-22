#include "FileDock.h"

// ============================================================
// FileDock.HandleUsage.cpp
// Purpose:
// - Hosts the entry logic for FileDock's "handle usage scan".
// - Redirect the old unlocker entry to the 'File Usage and Unlock' page in file properties.
// - Avoid further bloating the main FileDock.cpp file.
// ============================================================

#include "FileMappedProcessWindow.h"

#include <QFileInfo>
#include <QMetaObject>

#include <algorithm>

void FileDock::openHandleUsageScanWindow(const std::vector<QString>& scanPaths)
{
    // Step 1: Clean and deduplicate target paths, retaining only file/directory entities.
    std::vector<QString> validPaths;
    validPaths.reserve(scanPaths.size());
    for (const QString& pathText : scanPaths)
    {
        QFileInfo fileInfo(pathText);
        if (!fileInfo.exists())
        {
            continue;
        }
        if (!fileInfo.isFile() && !fileInfo.isDir())
        {
            continue;
        }

        const QString kAbsolutePath = fileInfo.absoluteFilePath();
        if (std::find(validPaths.begin(), validPaths.end(), kAbsolutePath) == validPaths.end())
        {
            validPaths.push_back(kAbsolutePath);
        }
    }

    if (validPaths.empty())
    {
        KLogEvent emptyEvent;
        warn << emptyEvent
            << "[FileDock] 扫描占用句柄取消：未选中有效文件或目录。"
            << eol;
        return;
    }

    // The property window represents only one target at a time. All existing entries are restricted to single selection; taking the
    // first item here is solely for backward compatibility with legacy internal signatures, and no second result page is created.
    showFileDetailDialog(validPaths.front(), QStringLiteral("usage"));

    KLogEvent openWindowEvent;
    info << openWindowEvent
        << "[FileDock] openHandleUsageScanWindow: opened unified property usage page, targetCount="
        << validPaths.size()
        << eol;
}

void FileDock::openMappedProcessScanWindow(const std::vector<QString>& scanPaths)
{
    // Step 1: Retain only file paths. Note: The first version of ControlArea reverse lookup targeted
    // file DataSection/ImageSection; directories lack a stable, displayable mapping semantics.
    std::vector<QString> validPaths;
    validPaths.reserve(scanPaths.size());
    for (const QString& pathText : scanPaths)
    {
        QFileInfo fileInfo(pathText);
        if (!fileInfo.exists() || !fileInfo.isFile())
        {
            continue;
        }

        const QString kAbsolutePath = fileInfo.absoluteFilePath();
        if (std::find(validPaths.begin(), validPaths.end(), kAbsolutePath) == validPaths.end())
        {
            validPaths.push_back(kAbsolutePath);
        }
    }

    if (validPaths.empty())
    {
        KLogEvent emptyEvent;
        warn << emptyEvent
            << "[FileDock] 扫描映射进程取消：未选中有效文件。"
            << eol;
        return;
    }

    // Step 2: Create an independent window and reuse the process detail navigation bridge used by the handle usage window.
    auto* scanWindow = new FileMappedProcessWindow(validPaths, this);
    scanWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    scanWindow->setOpenProcessDetailCallback([this](const std::uint32_t processId)
        {
            const quint32 kPidValue = static_cast<quint32>(processId);
            QObject* topWindowObject = this->window();
            if (topWindowObject == nullptr)
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                topWindowObject,
                "openProcessDetailByPid",
                Qt::QueuedConnection,
                Q_ARG(quint32, kPidValue));
            if (kInvokeOk)
            {
                return;
            }

            (void)QMetaObject::invokeMethod(
                topWindowObject,
                "focusHandleDockByPid",
                Qt::QueuedConnection,
                Q_ARG(quint32, kPidValue));
        });

    // Step 3: Display the window and log the action.
    scanWindow->show();
    scanWindow->raise();
    scanWindow->activateWindow();

    KLogEvent openWindowEvent;
    info << openWindowEvent
        << "[FileDock] openMappedProcessScanWindow: targetCount="
        << validPaths.size()
        << eol;
}
