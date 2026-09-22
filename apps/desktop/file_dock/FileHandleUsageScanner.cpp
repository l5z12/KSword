#include "FileHandleUsageScanner.h"

// ============================================================
// FileHandleUsageScanner.cpp
// Purpose:
// - Retain the Qt-facing data structures used by FileDock;
// - Delegate path conversion, handle scanning, and process/module usage analysis entirely to ks::file.
// - The UI layer continues to handle KProgress bridging and QString result display.
// ============================================================

#include "../../../shared/platform/file/FileHandleTools.h"

#include <QString>

#include <string>
#include <vector>

namespace filedock::handleusage
{
    namespace
    {
        // toWidePathList function: Convert the QString path collection passed from the UI into a std::wstring collection.
        // Input: absolutePaths, the paths collected by FileDock selection or right-click actions; Returns: a wide-string path list consumable by the backend.
        std::vector<std::wstring> toWidePathList(const std::vector<QString>& absolutePaths)
        {
            std::vector<std::wstring> pathList;
            pathList.reserve(absolutePaths.size());
            for (const QString& pathText : absolutePaths)
            {
                if (pathText.trimmed().isEmpty())
                {
                    continue;
                }
                pathList.push_back(pathText.toStdWString());
            }
            return pathList;
        }

        // toQString purpose: Converts backend std::wstring text into a QString for direct UI display.
        // Input textValue: backend wide string; returns QString, preserving empty strings as empty.
        QString toQString(const std::wstring& textValue)
        {
            return QString::fromStdWString(textValue);
        }

        // convertEntry: Converts ks::file backend hit entries into the original FileDock table row model.
        // Input: backendEntry (backend scan result); Output: HandleUsageEntry, containing no control or color state.
        HandleUsageEntry convertEntry(const ks::file::HandleUsageEntry& backendEntry)
        {
            HandleUsageEntry entry{};
            entry.processId = backendEntry.processId;
            entry.processCreationTime = backendEntry.processCreationTime;
            entry.processName = toQString(backendEntry.processName);
            entry.processImagePath = toQString(backendEntry.processImagePath);
            entry.handleValue = backendEntry.handleValue;
            entry.typeIndex = backendEntry.typeIndex;
            entry.typeName = toQString(backendEntry.typeName);
            entry.objectName = toQString(backendEntry.objectName);
            entry.grantedAccess = backendEntry.grantedAccess;
            entry.attributes = backendEntry.attributes;
            entry.matchedTargetPath = toQString(backendEntry.matchedTargetPath);
            entry.matchedByDirectoryRule = backendEntry.matchedByDirectoryRule;
            entry.matchRuleText = toQString(backendEntry.matchRuleText);
            entry.enumerationSource = toQString(backendEntry.enumerationSource);
            return entry;
        }

        // convertResult: Converts ks::file scan results to the result type consumed by the existing FileDock window.
        // Input: backendResult (complete backend result); Returns: HandleUsageScanResult containing QString text.
        HandleUsageScanResult convertResult(const ks::file::HandleUsageScanResult& backendResult)
        {
            HandleUsageScanResult result{};
            result.entries.reserve(backendResult.entries.size());
            for (const ks::file::HandleUsageEntry& backendEntry : backendResult.entries)
            {
                result.entries.push_back(convertEntry(backendEntry));
            }
            result.totalHandleCount = backendResult.totalHandleCount;
            result.fileLikeHandleCount = backendResult.fileLikeHandleCount;
            result.matchedHandleCount = backendResult.matchedHandleCount;
            result.processImageMatchCount = backendResult.processImageMatchCount;
            result.loadedModuleMatchCount = backendResult.loadedModuleMatchCount;
            result.kernelHandleMatchCount = backendResult.kernelHandleMatchCount;
            result.kernelHandleTableAttempted = backendResult.kernelHandleTableAttempted;
            result.kernelHandleTableUsed = backendResult.kernelHandleTableUsed;
            result.r3HandleFallbackUsed = backendResult.r3HandleFallbackUsed;
            result.elapsedMs = backendResult.elapsedMs;
            result.diagnosticText = toQString(backendResult.diagnosticText);
            return result;
        }
    }

    HandleUsageScanResult scanHandleUsageByPaths(
        const std::vector<QString>& absolutePaths,
        const int progressPid,
        const bool tryKernelHandleTable,
        const std::function<bool()>& cancellationCallback,
        const HandleUsageProgressCallback& progressCallback)
    {
        ks::file::HandleUsageScanOptions options{};
        options.tryKernelHandleTable = tryKernelHandleTable;
        options.cancellationCallback = cancellationCallback;
        if (progressPid > 0 || progressCallback)
        {
            // ProgressCallback only forwards plain text and percentage; the progress bar's lifecycle is still controlled by the FileDock window.
            options.progressCallback = [progressPid, progressCallback](const std::string& stepText, const float progressValue)
            {
                if (progressPid > 0)
                {
                    kPro.set(progressPid, stepText, 0, progressValue);
                }
                if (progressCallback)
                {
                    progressCallback(QString::fromStdString(stepText), progressValue);
                }
            };
        }

        const std::vector<std::wstring> kPathList = toWidePathList(absolutePaths);
        const ks::file::HandleUsageScanResult kBackendResult = ks::file::scanHandleUsageByPaths(kPathList, options);
        return convertResult(kBackendResult);
    }
}
