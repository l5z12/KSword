#pragma once

// ============================================================
// DriverDock.Internal.h
// Purpose:
// - Aggregates Qt/Win32 includes and internal tool declarations shared across multiple .cpp files in DriverDock.
// - Replaces the old text-concatenation implementation to keep overview, operation, and R0 debug capture logic independently compilable.
// - For DriverDock internal implementation only; does not alter DriverDock's external interface.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#include "DriverDock.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../internationalization/LanguageManager.h"
#include "../../../shared/ark_client/ArkDriverEvidence.h"

#include <QAbstractItemView>
#include <QAction>
#include <QBrush>
#include <QButtonGroup>
#include <QChar>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QModelIndex>
#include <QModelIndexList>
#include <QSignalBlocker>
#include <QPlainTextEdit>
#include <QPoint>
#include <QPointer>
#include <QPixmap>
#include <QPushButton>
#include <QRadioButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QShowEvent>
#include <QSplitter>
#include <QSpinBox>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <Psapi.h>
#include <winsvc.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

namespace ksword::driver_dock_internal
{
    // driverText：
    // - Input: Stable context key and Chinese source text.
    // - Handling: Keep Chinese text as-is at call sites; parse English text in the DriverDock context for translation.
    // - Returns: UI text in the current language.
    QString driverText(const char* contextKey, const QString& sourceText);

    // swapDriverEvidenceSourceTextMode：
    // - When the background evidence thread is enabled, driverText returns only the call-site source text without accessing LanguageManager.
    // - Return the mode before the call, allowing RAII to restore it when leaving the worker thread's collection scope.
    bool swapDriverEvidenceSourceTextMode(bool sourceTextOnly);

    // DriverDock table header factory: Centralizes column semantics for all read-only tables to facilitate repainting during language switching.
    QStringList driverServiceTableHeaders();
    QStringList driverModuleTableHeaders();
    QStringList driverObjectEvidenceTableHeaders();
    QStringList driverDeviceObjectTableHeaders();
    QStringList driverEvidenceTableHeaders();
    QStringList driverIntegrityTableHeaders();
    QStringList driverMajorFunctionTableHeaders();
    QStringList driverModuleCrossViewTableHeaders();
    QStringList driverUnloadedDriverTableHeaders();

    // ModuleRecordIndexRole：
    // - Input: First column cell of the loaded modules table to write to;
    // - Handling: Save the source index corresponding to the row in m_loadedModuleCache/m_loadedModuleEvidenceCache.
    // - Return: The constant itself has no return value; it is used to reverse-lookup the cache from the UI row when read.
    constexpr int kModuleRecordIndexRole = Qt::UserRole + 41;
    constexpr int kModuleNameColumn = 0;       // ModuleNameColumn: Module name column.
    constexpr int kModuleBaseColumn = 1;       // ModuleBaseColumn: Module base address column.
    constexpr int kModuleSignatureColumn = 2;  // ModuleSignatureColumn: The column for the digital signature trust chain.
    constexpr int kModuleEvidenceFirstColumn = 3; // ModuleEvidenceFirstColumn: The starting evidence column for DriverObject.
    constexpr int kModuleEvidenceLastColumn = 8; // ModuleEvidenceLastColumn: The last evidence column at the end of the callback.
    constexpr int kModuleImagePathColumn = 9;  // ModuleImagePathColumn: Column for the module disk image path.
    constexpr int kModuleTableColumnCount = 10; // ModuleTableColumnCount: Total column count of the loaded module table.

    // DriverDock internal tool: accepts UI/Win32 input, returns formatted text or operation status.
    std::wstring toWideString(const QString& textValue);
    QTableWidgetItem* createReadOnlyItem(const QString& textValue);
    QString formatAddress(std::uint64_t addressValue);
    QString formatCompactAddress(std::uint64_t addressValue);
    QString formatHex32(std::uint32_t value);
    QString formatNtStatusText(long statusValue);
    QString friendlyDriverIoMessage(const std::string& rawMessage);
    // describeDriverCollection: UI rendering entry point for the F-05 collection status normalization layer.
    // The status is determined by toCollectionOutcome in ArkDriverEvidence.h, eliminating the need to guess based on diagnostic text substrings.
    // Original NTSTATUS/Win32 codes are always preserved in the output.
    QString describeDriverCollection(const ksword::ark::IoResult& ioResult,
                                     bool unsupported = false,
                                     bool partial = false);
    bool isDriverSignatureLoadError(DWORD errorCode);
    QString formatWin32ErrorTextForAdvice(DWORD errorCode);
    QString buildDriverSignatureLoadAdvice(DWORD errorCode, const QString& serviceNameText, const QString& binaryPathText);
    QString driverObjectQueryStatusText(std::uint32_t statusValue);
    QString driverForceUnloadStatusText(std::uint32_t statusValue);
    QString driverMajorFunctionName(std::uint32_t majorFunction);
    QString driverDeviceTypeText(std::uint32_t deviceType);
    QString driverDispatchLocationText(std::uint32_t flags);
}
