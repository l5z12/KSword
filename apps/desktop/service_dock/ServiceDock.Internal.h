#pragma once

// ============================================================
// ServiceDock.Internal.h
// Purpose:
// 1) Unify shared includes for multiple ServiceDock implementation files;
// 2) Declare internal utility functions to avoid duplicate implementations across files.
// 3) Constrain internal role constants to reduce scattered magic values.
// ============================================================

#include "ServiceDock.h"
#include "../ui/CodeEditorWidget.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPoint>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QSpinBox>
#include <QSvgRenderer>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

#include <Windows.h>
#include <Objbase.h>

#include <algorithm>  // std::sort: Sort after filtering.
#include <cstdint>    // std::uint8_t: Win32 buffer byte container.
#include <optional>   // std::optional: Returns optional error text.
#include <string>     // std::string: Log and Win32 text bridging.
#include <utility>    // std::pair: Detail page key-value construction.

namespace service_dock_detail
{
    // RegistryServiceSnapshot:
    // - Independent snapshot representing a single key under HKLM\SYSTEM\CurrentControlSet\Services;
    // - Decoupled from SCM ServiceRecord to ensure ghost service detection retains independent data sources.
    struct RegistryServiceSnapshot
    {
        QString serviceNameText;       // serviceNameText: Sub-key name under the Services root key.
        QString displayNameText;       // displayNameText: Original text of the registry DisplayName.
        QString descriptionText;       // descriptionText: Original text from the registry Description.
        QString binaryPathText;        // binaryPathText: Original text of the registry ImagePath.
        QString serviceDllPathText;    // serviceDllPathText: Raw text for Parameters\\ServiceDll.
        QString accountText;           // accountText: Original text of the registry ObjectName.
        DWORD serviceTypeValue = 0;    // serviceTypeValue: Type DWORD value.
        DWORD startTypeValue = 0;      // startTypeValue: Start DWORD value.
        DWORD errorControlValue = 0;   // errorControlValue: The ErrorControl DWORD value.
        bool delayedAutoStart = false; // delayedAutoStart: The DelayedAutostart DWORD status.
        bool keyReadable = false;      // keyReadable: Whether the subkey was successfully opened with KEY_READ access.
        bool hasServiceType = false;   // hasServiceType: Whether the Type value exists and is of the correct type.
        bool hasStartType = false;     // hasStartType: Start value exists and has the correct type.
        bool hasErrorControl = false;  // hasErrorControl: Whether the ErrorControl value exists and is of the correct type.
    };

    // List row binding role definition:
    // - kServiceNameRole: stores the service short name on the first column item for mapping selection.
    inline constexpr int kServiceNameRole = Qt::UserRole;

    // createBlueIcon:
    // - Render SVG as a unified blue-themed icon.
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize = QSize(16, 16));

    // createReadOnlyItem:
    // - Constructs a read-only table item with a tooltip.
    QTableWidgetItem* createReadOnlyItem(const QString& textValue);

    // winErrorText:
    // - Converts Win32 error codes to readable strings.
    QString winErrorText(DWORD errorCode);

    // serviceStateToText:
    // - Convert service running state value to Chinese text.
    QString serviceStateToText(DWORD stateValue);

    // startTypeToText:
    // - Convert the start type value and delayed auto-start flag to Chinese text.
    QString startTypeToText(DWORD startTypeValue, bool delayedAutoStart);

    // serviceTypeToText:
    // - Convert service type bitmask to Chinese text.
    QString serviceTypeToText(DWORD serviceTypeValue);

    // errorControlToText:
    // - Convert error control values to Chinese text.
    QString errorControlToText(DWORD errorControlValue);

    // isServiceStatePending:
    // - Check if the service is in a Pending transition state.
    bool isServiceStatePending(DWORD stateValue);

    // normalizeServiceImagePath:
    // - Extract executable path from BinaryPath text.
    QString normalizeServiceImagePath(const QString& rawBinaryPathText);

    // enumerateRegistryServiceSnapshots: Independently enumerate the Services registry root key.
    // Input parameters: snapshotListOut receives all subkeys; errorTextOut/errorCodeOut receives root scan errors.
    // Return: true on full enumeration success; individual protected subkeys retain their names with keyReadable=false.
    bool enumerateRegistryServiceSnapshots(
        std::vector<RegistryServiceSnapshot>* snapshotListOut,
        QString* errorTextOut = nullptr,
        DWORD* errorCodeOut = nullptr);

    // queryRegistryServiceSnapshot purpose: reads a snapshot of a single service's registry configuration.
    // Input: serviceNameText is the short service name without path separators; snapshotOut receives the snapshot.
    // Return: true if the key exists and is readable.
    bool queryRegistryServiceSnapshot(
        const QString& serviceNameText,
        RegistryServiceSnapshot* snapshotOut,
        QString* errorTextOut = nullptr,
        DWORD* errorCodeOut = nullptr);

    // deleteRegistryServiceKey: Delete the entire registry key tree for a service that is not visible to SCM.
    // Input parameters: serviceNameText is the validated short service name; error output is used for UI privilege escalation recovery prompts.
    // Return: true if the key was deleted or did not exist.
    bool deleteRegistryServiceKey(
        const QString& serviceNameText,
        QString* errorTextOut = nullptr,
        DWORD* errorCodeOut = nullptr);

    // querySingleServiceSnapshot: Background refresh of a single SCM/registry service snapshot.
    // The input parameters sourceScmRecordPresent and sourceRegistryScanCompleted preserve the full cross-scan semantics.
    // Returns: true if any trusted source can still provide the target snapshot.
    bool querySingleServiceSnapshot(
        const QString& serviceNameText,
        bool sourceScmRecordPresent,
        bool sourceRegistryScanCompleted,
        ServiceDock::ServiceEntry* entryOut,
        QString* errorTextOut);
}
