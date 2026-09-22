#pragma once

// ============================================================
// ProcessDetailWindow.InternalCommon.h
// Purpose:
// - Provides a unified include entry point for multiple implementation .cpp files of ProcessDetailWindow.
// - Centralizes declarations of internal helper types, column definitions, and style utilities reused across files.
// - Avoid falling back to .inc aggregate implementations again.
// ============================================================

#include "ProcessDetailWindow.h"
#include "ThreadStackWindow.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/UiSupport.h"
#include "../../../shared/driver/KswordArkDynDataIoctl.h"

#include <QAbstractScrollArea>
#include <QAbstractButton>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QDirIterator>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QFontMetrics>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPalette>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QPlainTextEdit>
#include <QPoint>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScreen>
#include <QScrollArea>
#include <QSet>
#include <QSizePolicy>
#include <QStringList>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTabBar>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QtGlobal>
#include <QVBoxLayout>
#include <QWindow>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <ShlObj.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <sddl.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Uuid.lib")

namespace process_detail_window_internal
{
    // ThreadRowColumn:
    // - Unify the column order for thread detail tables.
    // - Shared between UI initialization and result backfilling.
    enum class ThreadRowColumn : int
    {
        kThreadId = 0,    // Thread ID.
        kState,           // State
        kPriority,        // Priority.
        kSwitchCount,     // Context switch counter.
        kStartAddress,    // Start address.
        kTebAddress,      // TEB address.
        kAffinity,        // Affinity information.
        kRegisterSummary, // Register summary.
        kStackBoundary,   // R0/User stack boundary summary
        kRuntimeDetail,   // R0 runtime details: Fixed field coverage and diagnostics for the detail IOCTL.
        kCount            // Total columns.
    };

    // ThreadInspectHeaders: Constant text for thread detail table headers.
    extern const QStringList kThreadInspectHeaders;

    // toThreadColumnIndex: Converts the thread column enum to a table index.
    int toThreadColumnIndex(ThreadRowColumn column);

    // ModuleColumn:
    // - Unify module table column order.
    // - Avoid using magic numbers when reading/writing UserRole data on the module page.
    enum class ModuleColumn : int
    {
        kPath = 0,      // Module path (including icon).
        kSize,          // Module size.
        kSignature,     // Digital signature status.
        kEntryOffset,   // Entry offset (RVA).
        kState,         // Runtime state.
        kThreadId,      // ThreadID information.
        kCount          // Total columns.
    };

    // ModuleHeaders purpose: Module header text constants.
    extern const QStringList kModuleHeaders;

    // toModuleColumnIndex purpose: Convert module column enum to table index.
    int toModuleColumnIndex(ModuleColumn column);

    // buildBlueButtonStyle: Generates a unified blue button style.
    QString buildBlueButtonStyle();

    // buildProcessDetailRootStyle: Generates the root style for the detail window.
    QString buildProcessDetailRootStyle();

    // buildProcessDetailMenuStyle:
    // - Generate explicit opaque styles for the detail page button popup menu/right-click menu;
    // - No input; reads the current theme color during processing.
    // - Returns style text directly usable with QMenu::setStyleSheet.
    QString buildProcessDetailMenuStyle();

    // buildProcessDetailR0ActionIcon:
    // - Input iconPath is the qrc business icon path;
    // - Returns a QIcon of uniform size for buttons and menu items explicitly marked as R0.
    QIcon buildProcessDetailR0ActionIcon(const QString& iconPath);

    // buildStateLabelStyle: Generates status label style text.
    QString buildStateLabelStyle(const QColor& textColor, int fontWeight);

    // statusIdleColor: Returns the text color for the idle state.
    QColor statusIdleColor();

    // statusWarningColor: Returns the text color for the warning state.
    QColor statusWarningColor();

    // statusErrorColor: Returns the text color for the error state.
    QColor statusErrorColor();

    // statusSecondaryColor: Returns the neutral text color.
    QColor statusSecondaryColor();

    // signatureTrustedColor: Returns the color for trusted signature text.
    QColor signatureTrustedColor();

    // signatureUntrustedColor: Returns the color for untrusted signature text.
    QColor signatureUntrustedColor();

    // formatDoubleText: Formats a floating-point number into text with a fixed number of decimal places.
    QString formatDoubleText(double value, int precision);

    // uint64ToHex: Formats a 64-bit value as a hexadecimal string.
    QString uint64ToHex(std::uint64_t value);

    // convertSidToText: Converts a SID to human-readable text in the format 'Account Name + SID'.
    QString convertSidToText(PSID sid);

    // readRemoteUnicodeString: Reads the content of a UNICODE_STRING from a remote process.
    QString readRemoteUnicodeString(HANDLE processHandle, const UNICODE_STRING& remoteUnicode);

    // buildPdbRuntimeCatalogPreview:
    // - Input domainName is the runtimeDetailCatalog domain, e.g., process_detail/thread_detail;
    // - Processing reads only the ntkrnlmp deep JSON from Release/source profiles\pdb_deep_offsets.
    // - Returns an offset directory preview intended for the detail page display; returns explicit diagnostic text if the JSON is not found.
    QString buildPdbRuntimeCatalogPreview(const QString& domainName, int maxTypes, int maxFieldsPerType);

    // pdbRuntimeCatalogMatchesKernelIdentity:
    // - Inputs: current R0 DynData-reported ntoskrnl TimeDateStamp and SizeOfImage;
    // - During processing, reverse-lookup the local v4 pack profile using the deep JSON PDB GUID/Age, then compare the PE identity.
    // - Returns true if deep offset is usable for the local runtime sampler; if false, detailTextOut specifies the skip reason.
    bool pdbRuntimeCatalogMatchesKernelIdentity(
        std::uint32_t timeDateStamp,
        std::uint32_t sizeOfImage,
        QString* detailTextOut);

    // buildPdbRuntimeSampleItems:
    // - Input domainName is process_detail/thread_detail; maxItems is the maximum number of sample fields.
    // - During processing, select safe small fields (<=16 bytes) from the deep offset JSON for R0 sampler requests.
    // - Returns a list of runtime field sample items directly submittable by ArkDriverClient.
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildPdbRuntimeSampleItems(const QString& domainName, int maxItems);

    // calculateStandaloneWindowInitialWidth:
    // - Input candidateParent: preferred client area widget; fallbackWindow: current standalone window;
    // - When processing, first locate the target screen, then take the available value from the parent control, active window, or screen available width.
    // - Returns the initial window width calculated by ratio; returns fallbackWidth if undeterminable; does not set a maximum size.
    int calculateStandaloneWindowInitialWidth(QWidget* candidateParent, QWidget* fallbackWindow, double ratio, int fallbackWidth);
}
