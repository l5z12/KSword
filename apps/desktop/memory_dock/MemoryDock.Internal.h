#pragma once

// ============================================================
// MemoryDock.Internal.h
// Purpose:
// - Aggregates Qt/Win32 includes and internal tool declarations shared across multiple .cpp files in MemoryDock.
// - Replaces the old aggregated source structure to make UI, process region, search, and viewer logic independently compilable.
// - Serves only MemoryDock internal implementation; do not expand the public API.
// ============================================================

#include "MemoryDock.h"
#include "../Theme.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/HexEditorWidget.h"
#include "../ui/VisibleTableWidget.h" // ks::ui::VisibleTableWidget: Unified base class for long tables such as disassembly tables.

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QChar>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIODevice>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPlainTextEdit>
#include <QPoint>
#include <QProgressBar>
#include <QPushButton>
#include <QPointer>
#include <QSignalBlocker>
#include <QSize>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <type_traits>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

namespace ksword::memory_dock_internal
{
    // UI style functions: if input is empty, return theme stylesheet text.
    // These three functions are merely thin wrappers around the global theme implementation; the header styles have been fully delegated to GlobalUiBaseStyle.
    QString buildBlueButtonStyle();
    QString buildBlueComboStyle();
    QString buildBlueInputStyle();

    // Hex viewer pagination constants: each page is fixed at 16 * 32 = 512 bytes.
    extern const int kHexBytesPerRow;
    extern const int kHexRowCount;
    extern const std::uint64_t kHexPageBytes;

    // ModuleTreeColumn: process module tree column definition, aligned with the ProcessDetailWindow module page.
    enum class ModuleTreeColumn : int
    {
        kPath = 0,
        kSize,
        kSignature,
        kEntryOffset,
        kState,
        kThreadId,
        kCount
    };

    // ModuleTreeHeaders: Text for module tree headers, used by UI construction code.
    extern const QStringList kModuleTreeHeaders;

    // Internal conversion and parsing utilities: accept business values and return auxiliary results required by Qt/Win32.
    int toModuleTreeColumnIndex(ModuleTreeColumn column);
    DWORD toDwordPid(std::uint32_t pid);
    bool isReadableProtect(std::uint32_t protectValue);
    bool parseHexByte(const QString& text, std::uint8_t& valueOut);
    QIcon resolveIconByPath(const QString& absolutePath, QHash<QString, QIcon>& cache);
}
