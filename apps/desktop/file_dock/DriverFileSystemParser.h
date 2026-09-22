#pragma once

// ============================================================
// DriverFileSystemParser.h
// Purpose:
// 1) Provide an explicit R0 directory parsing entry point for FileDock;
// 2) Consume only the structured paginated results from ArkDriverClient.
// 3) Prevent Dock UI from directly calling KswordARK DeviceIoControl.
// ============================================================

#include "ManualFileSystemParser.h"

namespace ks::file
{
    // DriverFileSystemParser:
    // - Query file system directories via kernel calls through KswordARK.
    // - Convert fixed-protocol lines into the existing ManualDirectoryEntry model in FileDock.
    class DriverFileSystemParser final
    {
    public:
        // enumerateDirectory:
        // - Use driver-based paged enumeration for mounted directories, without falling back to QFileSystemModel/WinAPI enumeration.
        // Call method:
        // - Called in a background thread after FileDock selects "R0 driver parsing".
        // Input parameter pathText:
        // - Windows local, volume GUID, or UNC directory paths.
        // Output parameter entriesOut:
        // - Returns the directory rows enumerated by the driver.
        // Output parameter fsTypeOut:
        // - Map the file system name returned by R0 to NTFS/FAT32/exFAT; retain Unknown for unknown types.
        // Output parameter errorTextOut:
        // - Returns communication, protocol, or NTSTATUS diagnostics on failure.
        // Output parameter partialOut:
        // - true indicates the driver returned partial pages, truncated names, or reached the R3 total line budget.
        // Output parameter sourceDetailOut:
        // - Returns the R0 source summary for the status bar.
        // Return value:
        // - Return true when at least a trusted complete or partial directory result is obtained; return false on complete failure.
        static bool enumerateDirectory(
            const QString& pathText,
            std::vector<ManualDirectoryEntry>& entriesOut,
            ManualFsType& fsTypeOut,
            QString& errorTextOut,
            bool* partialOut = nullptr,
            QString* sourceDetailOut = nullptr);
    };
}
