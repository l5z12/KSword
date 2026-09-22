#pragma once

// ============================================================
// NetworkDock.InternalCommon.h
// Purpose:
// 1) Unifies private includes across multiple .cpp files in NetworkDock;
// 2) Avoid duplicating maintenance of the same set of system/Qt headers across implementation files;
// 3) Serves as the 'compilation context base' for the split implementation file.
// ============================================================

#include "NetworkDock.h"
#include "NetworkDock.InternalHelpers.h"

#include "../process_dock/ProcessDetailWindow.h"
#include "../ui/HexEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/network/NetworkDiagnosticsTools.h"
#include "../../../shared/platform/network/NetworkDownloadTools.h"
#include "../../../shared/platform/network/NetworkFormatTools.h"

#include <QAction>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QProgressBar>
#include <QProcess>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThreadPool>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm> // std::min/std::max: Preview length and range normalization.
#include <atomic>    // std::atomic_bool: Cross-thread status gating.
#include <chrono>    // std::chrono: Short sleep cycle for polling wait during download pause.
#include <limits>    // std::numeric_limits: Expresses the packet length upper bound range.
#include <set>       // std::set: Deduplicate table multi-select row indices.
#include <string>    // std::string: Log bridge text type.
#include <thread>    // std::thread: Execute long-running requests in the background.
#include <unordered_set> // std::unordered_set: Deduplicate ARP interface indices.
#include <vector>    // std::vector: Temporary container for batch refresh queue.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <IcmpAPI.h>
#include <Iphlpapi.h>
#include <Windns.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")
