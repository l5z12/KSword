#pragma once

// ============================================================
// IrpFileSystemParser.h
// Purpose:
// 1) Provides a directory parsing entry point for FileDock to send 'R0 self-built IRPs directly to the file system stack'.
// 2) Simultaneously retrieve both the "bypass layer" and "stack top" views, reporting the difference set as suspected hidden entries;
// 3) Only consume structured results from ArkDriverClient; prevent Dock UI from directly constructing IRP protocol packets.
// ============================================================

#include "ManualFileSystemParser.h"

namespace ks::file
{
    // IrpScanDiagnostics:
    // - Records enumeration differences for the same directory across two stack layers.
    // - bypassOnlyNames is the core output: entries visible only by bypassing the filter layer.
    // - If layerBypassed is false, it indicates R0 has backtracked the request to the stack top. In this case, both views share the same
    //   source, so the difference set is always empty. The UI must not interpret "no difference" as "confirmation of no hidden items".
    struct IrpScanDiagnostics
    {
        bool comparisonAvailable = false;   // Whether the stack-top comparison succeeded.
        bool layerBypassed = false;         // Whether this was actually dispatched to a deeper layer.
        unsigned long requestedLayer = 0;   // Requested stack layer.
        unsigned long resolvedLayer = 0;    // R0: Actual effective stack layer
        int bypassEntryCount = 0;           // Bypass layer view entry count.
        int topLayerEntryCount = 0;         // Count of top-layer view entries.
        QStringList bypassOnlyNames;        // Entries visible only to the bypass layer.
        QStringList topLayerOnlyNames;      // Entries visible only from the stack top.
        QString bypassDriverName;           // Driver name receiving bypass-layer requests.
        QString topLayerDriverName;         // Name of the driver receiving the top-layer request.
    };

    // IrpFileSystemParser:
    // - enumerate directories via self-built IRP in KswordARK; optionally dispatch to basic file system devices.
    // - Convert fixed-protocol lines to FileDock's existing ManualDirectoryEntry model.
    // Capability boundary:
    // - Only directory queries (IRP_MJ_DIRECTORY_CONTROL) bypass the filter layer; opens (IRP_MJ_CREATE) still follow
    //   the normal path. Therefore, hiding by 'removing entries from directory query results' is detectable, while
    //   'intercepting only on open' is not; an empty difference set does not confirm the absence of hidden items.
    class IrpFileSystemParser final
    {
    public:
        // enumerateDirectory:
        // - Uses custom IRPs to enumerate directories, defaulting dispatch to the base file system device to bypass filter layers.
        // Call method:
        // - Called in a background thread after FileDock selects "R0 IRP Parsing".
        // Input parameter pathText:
        // - Windows local, volume GUID, or UNC directory paths.
        // Output parameter entriesOut:
        // - Bypass layer view directory rows.
        // Output parameter fsTypeOut:
        // - Map file system names returned by R0; retain Unknown for unknown types.
        // Output parameter errorTextOut:
        // - Returns communication, protocol, or NTSTATUS diagnostics on failure.
        // Output parameter partialOut:
        // - true indicates the driver returned partial pages, truncated names, or reached the R3 total line budget.
        // Output parameter sourceDetailOut:
        // - Returns a source summary for the status bar (including the effective stack layer and receiving driver).
        // Output parameter diagnosticsOut:
        // - Optional: Receives the difference statistics with the stack top view.
        // Return value:
        // - Returns true when obtaining a trusted complete or partial directory result; returns false on complete failure.
        static bool enumerateDirectory(
            const QString& pathText,
            std::vector<ManualDirectoryEntry>& entriesOut,
            ManualFsType& fsTypeOut,
            QString& errorTextOut,
            bool* partialOut = nullptr,
            QString* sourceDetailOut = nullptr,
            IrpScanDiagnostics* diagnosticsOut = nullptr);

        // layerDisplayText:
        // - Map KSWORD_ARK_FILE_IRP_LAYER_* to user-readable display text.
        static QString layerDisplayText(unsigned long layerValue);
    };
}
