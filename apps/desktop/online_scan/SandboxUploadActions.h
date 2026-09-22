#pragma once

// ============================================================
// SandboxUploadActions.h
// Purpose:
// - Provide a unified 'Upload to Sandbox -> VT-*' entry point for the right-click menus of all Docks.
// - The caller is only responsible for parsing the current row into a local file path or PID;
// - This file does not store the API Key; VirusTotalOnlineScan continues to read virustotal_api_key from settings.
// ============================================================

#include <cstdint>
#include <functional>

#include <QString>

#include "VirusTotalOnlineScan.h"

class QAction;
class QMenu;
class QWidget;

namespace ks::online_scan
{
    // SandboxUploadTarget:
    // - Carries the parsing result of a right-click menu upload action;
    // - filePath is the local file path to be uploaded; sourceText is the source description displayed at the top of the results window.
    struct SandboxUploadTarget
    {
        QString filePath;   // filePath: The local sample path resolved by the caller.
        QString sourceText; // sourceText: Upload source description, e.g., "Process list PID=1234".
        QString errorText;  // errorText: explicit reason when path resolution fails; if non-empty, the menu trigger displays it directly.
    };

    // QFilePathResolver:
    // - Delay resolution of the current row's path upon menu trigger to avoid reading volatile states during menu construction.
    // - Returns SandboxUploadTarget; if the path is empty, a unified helper dialog prompts the user.
    using QFilePathResolver = std::function<SandboxUploadTarget()>;

    // addVirusTotalSandboxMenu:
    // - Add a "Upload to Sandbox" submenu and 5 VT analysis sub-items to the specified menu.
    // - After a child item is triggered, the resolver is called to parse the path and initiate the VirusTotal upload.
    // - ThreatBook does not add or display grayed-out items in this round.
    // Input parameter menu: the target context menu.
    // Input parameter parentWidget: Parent widget for error messages and result windows.
    // Input parameter resolver: callback to resolve file path and source text when clicking VT.
    // Returns: VT QAction pointer; returns nullptr if menu is null.
    QAction* addVirusTotalSandboxMenu(QMenu* menu, QWidget* parentWidget, QFilePathResolver resolver);

    // uploadFileToVirusTotal:
    // - Perform local normalization of the file path and validate existence, readability, and size.
    // - After validation, create a VirusTotalOnlineScan instance and upload asynchronously.
    // - The API Key is still read by VirusTotalOnlineScan from settings.
    // Input parameter filePath: local file path, may include quotes or simple command-line arguments.
    // Input parameter sourceText: description of the upload source.
    // Parameter parentWidget: Parent widget for the popup.
    // Return: None; errors are shown via a unified popup, and results are displayed in the real-time results window.
    void uploadFileToVirusTotal(const QString& filePath, const QString& sourceText, QWidget* parentWidget);

    // uploadFileToVirusTotal:
    // - Multi-API entry version;
    // - After validating the file, open the corresponding VT Tab based on initialApi and start the corresponding analysis.
    // Input parameter initialApi: shallow analysis, file profiling, IOC, sandbox, or all APIs.
    // Returns: Nothing.
    void uploadFileToVirusTotal(
        const QString& filePath,
        const QString& sourceText,
        VirusTotalOnlineScan::VtApiKind initialApi,
        QWidget* parentWidget);

    // uploadProcessImageByPid:
    // - Parse the EXE by calling ks::process::queryProcessPathByPid based on PID.
    // - Displays a popup prompt if the path is empty or the file is unreadable.
    // - On success, delegate to uploadFileToVirusTotal.
    // Input parameter pid: The target process PID.
    // Input parameter sourceText: description of the upload source.
    // Parameter parentWidget: Parent widget for the popup.
    // Returns: Nothing.
    void uploadProcessImageByPid(std::uint32_t pid, const QString& sourceText, QWidget* parentWidget);

    // normalizeKernelImagePathForUpload:
    // Converts common kernel/R0 paths to Win32-readable paths;
    // - Support \SystemRoot, SystemRoot, %SystemRoot%, \??\C:\, and \Device\HarddiskVolume...;
    // - File existence is not guaranteed; the caller must still call validateReadableFile.
    // Input rawPathText: original path text.
    // Returns: normalized path; returns the cleaned original text if conversion fails.
    QString normalizeKernelImagePathForUpload(const QString& rawPathText);

    // extractExistingFilePathForUpload:
    // - Extract existing file path from file path or common command-line fragments;
    // - Reuse this function for startup items, service paths, and partial UI tables to reduce mis-parsing.
    // Input rawPathText: Path or command-line text.
    // Returns: Existing file path; returns normalized candidate text if extraction fails.
    QString extractExistingFilePathForUpload(const QString& rawPathText);

    // tryParsePidFromText:
    // - Parse a decimal PID from table cell text.
    // - Lightweight parser for event columns such as PID, PID/TID, and RootPid.
    // Parameter pidText: text to parse.
    // Parameter pidOut: PID written upon successful parsing.
    // Returns: true if a non-zero PID was parsed; false if no valid PID was parsed.
    bool tryParsePidFromText(const QString& pidText, std::uint32_t* pidOut);
}
