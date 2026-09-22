#pragma once

// ============================================================
// StartupDock.Internal.h
// Purpose:
// 1) Unify common includes across multiple implementation files for StartupDock;
// 2) Declare internal utility functions to avoid duplicate implementations across .cpp files;
// 3) Maintain decoupling of implementations within the StartupDock directory.
// ============================================================

#include "StartupDock.h"
#include "../Theme.h"
#include "../internationalization/LanguageManager.h"
#include "../../../shared/platform/startup/Startup.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QVBoxLayout>

#include <Windows.h>
#include <Shellapi.h>

#include <algorithm>  // std::sort/std::clamp: Result sorting and range control.
#include <array>      // std::array: Fixed-size registry key list.
#include <cstdint>    // std::uint*_t: System status fields.
#include <memory>     // std::unique_ptr: Local object management.
#include <optional>   // std::optional: Optional field check.
#include <string>     // std::string: Win32/Qt text bridging.
#include <utility>    // std::pair/std::move: Batched table write targets and cache transfers.
#include <vector>     // std::vector: Startup item cache.

namespace startup_dock_detail
{
    // startupText:
    // - Read Chinese/English text based on specific startup item UI scenarios;
    // - In Chinese mode, retains fallback text at call sites; in English mode, reads scenario translations.
    QString startupText(const char* key, const QString& sourceText);

    // startupTableHeaders:
    // - Generate localized headers shared by the startup items table and the advanced registry tree;
    // - After a language switch, StartupDock re-applies the settings to all views.
    QStringList startupTableHeaders();

    // StartupTreeNodeKind：
    // - Purpose: Distinguish between 'location nodes', 'entry nodes', and 'placeholder nodes' in the registry tree.
    enum class StartupTreeNodeKind : int
    {
        kGroup = 0,      // Group: Level 1 registry location node.
        kEntry,          // Entry: actual startup item leaf node.
        kPlaceholder     // Placeholder: Placeholder node for no entries or no matches.
    };

    // Tree node data roles:
    // - Unify saving entry index, node type, and registry path.
    // - Shared between UI and interaction logic to avoid scattered magic numbers.
    inline constexpr int kStartupEntryIndexRole = Qt::UserRole;
    inline constexpr int kStartupTreeNodeKindRole = Qt::UserRole + 1;
    inline constexpr int kStartupTreeLocationRole = Qt::UserRole + 2;

    // createBlueIcon:
    // - Generate blue SVG icons consistent with existing Dock icons.
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize = QSize(16, 16));

    // createReadOnlyItem:
    // - Unified creation of non-editable table cells.
    QTableWidgetItem* createReadOnlyItem(const QString& textValue);

    // winErrorText:
    // - Convert Win32 error codes to human-readable text.
    QString winErrorText(DWORD errorCode);


    // buildStatusText:
    // - Converts the enabled state to a unified text string.
    QString buildStatusText(bool enabled);
    QString buildStatusText(const ks::startup::StartupEntry& entry);

    // startupRiskReasonText:
    // - Prioritize reading localized text based on the backend's stable reason code.
    // - Backend diagnostic text serves as a fallback when the language key is not configured.
    QString startupRiskReasonText(const ks::startup::StartupEntry& backendEntry);

    // startupLocalizedDetailText:
    // - Translate startup item descriptions with dynamic backup indicators/paths;
    // - Other static descriptions are left to sourceText for processing.
    QString startupLocalizedDetailText(const QString& detailText);

    // parseCsvLine:
    // - Parse a CSV line, supporting escaped quotes.
    // - Purpose: Reused for parsing `schtasks` output.
    QStringList parseCsvLine(const QString& csvLineText);

    // buildKnownStartupRegistryLocationList:
    // - Returns the list of known Autoruns-style locations to display in the registry tree;
    // - The registry tree creates default expanded top-level nodes in this order.
    QStringList buildKnownStartupRegistryLocationList();

    // appendBackendStartupEntries:
    // - Convert UTF-8 records from the ks::startup backend to StartupDock's Qt UI records;
    // - Input entryListOut: append target; allows null pointer and returns immediately.
    // - Input backendEntryList: backend enumeration results; perform read-only conversion without copying the entire container batch;
    // - Return value: None; appends converted records directly to entryListOut.
    void appendBackendStartupEntries(
        std::vector<StartupDock::StartupEntry>* entryListOut,
        const std::vector<ks::startup::StartupEntry>& backendEntryList);
}
