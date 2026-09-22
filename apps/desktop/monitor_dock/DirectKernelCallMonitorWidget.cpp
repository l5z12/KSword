#include "DirectKernelCallMonitorWidget.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// DirectKernelCallMonitorWidget.cpp
// Purpose:
// 1) Collect system call events using the ETW System Syscall Provider;
// 2) Decode event fields via TDH, correlating PID, call number, and call address.
// 3) Parse ntdll/win32u export stubs to assist in converting system call numbers to service names.
// ============================================================

#include "MonitorTextViewer.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/ThemeStatusRole.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstring>
#include <optional>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <TlHelp32.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

// Compatible with legacy SDKs: EVENT_TRACE_FLAG_SYSTEMCALL is the legacy kernel flag for PERF_SYSCALL.
// If the header file does not expose this macro, use the long-standing system call event flag from evntrace.h.
#ifndef EVENT_TRACE_FLAG_SYSTEMCALL
#define EVENT_TRACE_FLAG_SYSTEMCALL 0x00000080
#endif

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")

namespace
{
    constexpr int kRoleGlobalSearchText = Qt::UserRole;
    constexpr int kRoleProcessSearchText = Qt::UserRole + 1;
    constexpr int kRoleServiceSearchText = Qt::UserRole + 2;
    constexpr int kRoleDetailText = Qt::UserRole + 3;
    constexpr int kRoleProcessCreationTime100ns = Qt::UserRole + 4;

    constexpr GUID kKswordDirectKernelCallSessionGuid =
        { 0xd22e25bd, 0x51fe, 0x4219, { 0x9a, 0xcf, 0x81, 0xc8, 0xaa, 0x73, 0xc7, 0x8d } };

    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    QPushButton* createIconButton(QWidget* parentWidget, const QString& iconPath, const QString& tooltipText)
    {
        QPushButton* buttonPointer = new QPushButton(QIcon(iconPath), QString(), parentWidget);
        buttonPointer->setToolTip(tooltipText);
        buttonPointer->setFixedSize(QSize(30, 28));
        buttonPointer->setStyleSheet(blueButtonStyle());
        return buttonPointer;
    }

    QTableWidgetItem* createReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString guidToText(const GUID& guidValue)
    {
        wchar_t buffer[64] = {};
        if (::StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(buffer);
    }

    QString formatAddress(const std::uint64_t addressValue)
    {
        if (addressValue == 0)
        {
            return QStringLiteral("<未知>");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar(u'0'))
            .toUpper();
    }

    bool isKernelModeAddress(const std::uint64_t addressValue)
    {
        // Notes:
        // - The SysCallAddress in SysCallEnter is the kernel service routine address, not the user-mode syscall instruction location;
        // - x64 kernel addresses typically reside in the canonical high-half; x86-compatible addresses typically start from 0x80000000.
        // - This check is only used to avoid misidentifying kernel addresses as 'user-mode direct syscalls'.
        return addressValue >= 0xFFFF000000000000ULL
            || (addressValue <= 0xFFFFFFFFULL && addressValue >= 0x80000000ULL);
    }

    QString normalizeName(const QString& text)
    {
        QString normalized = text.toLower();
        normalized.remove(QRegularExpression(QStringLiteral("[^a-z0-9]")));
        return normalized;
    }

    bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        const bool useRegex,
        const Qt::CaseSensitivity caseSensitivity)
    {
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        if (!useRegex)
        {
            return sourceText.contains(patternText, caseSensitivity);
        }

        QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
        if (caseSensitivity == Qt::CaseInsensitive)
        {
            options |= QRegularExpression::CaseInsensitiveOption;
        }
        const QRegularExpression kRegex(patternText, options);
        return kRegex.isValid() && kRegex.match(sourceText).hasMatch();
    }

    QString trimmedWideString(const wchar_t* textPointer, const int characterCount)
    {
        if (textPointer == nullptr || characterCount <= 0)
        {
            return QString();
        }

        QString text = QString::fromWCharArray(textPointer, characterCount);
        while (text.endsWith(QChar(u'\0')))
        {
            text.chop(1);
        }
        return text.trimmed();
    }

    QString trimmedAnsiString(const char* textPointer, const int byteCount)
    {
        if (textPointer == nullptr || byteCount <= 0)
        {
            return QString();
        }

        QByteArray bytes(textPointer, byteCount);
        while (!bytes.isEmpty() && bytes.endsWith('\0'))
        {
            bytes.chop(1);
        }
        return QString::fromLocal8Bit(bytes).trimmed();
    }

    QString decodedValueText(
        const unsigned char* dataPointer,
        const ULONG dataSize,
        const USHORT inType,
        std::uint64_t* numericValueOut,
        bool* hasNumericValueOut)
    {
        if (numericValueOut != nullptr)
        {
            *numericValueOut = 0;
        }
        if (hasNumericValueOut != nullptr)
        {
            *hasNumericValueOut = false;
        }
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QString();
        }

        auto setNumeric = [&](const std::uint64_t value) {
            if (numericValueOut != nullptr)
            {
                *numericValueOut = value;
            }
            if (hasNumericValueOut != nullptr)
            {
                *hasNumericValueOut = true;
            }
        };

        switch (inType)
        {
        case TDH_INTYPE_UNICODESTRING:
            return trimmedWideString(
                reinterpret_cast<const wchar_t*>(dataPointer),
                static_cast<int>(dataSize / sizeof(wchar_t)));
        case TDH_INTYPE_ANSISTRING:
            return trimmedAnsiString(reinterpret_cast<const char*>(dataPointer), static_cast<int>(dataSize));
        case TDH_INTYPE_INT8:
        {
            const std::int8_t kValue = *reinterpret_cast<const std::int8_t*>(dataPointer);
            setNumeric(static_cast<std::uint64_t>(static_cast<std::int64_t>(kValue)));
            return QString::number(kValue);
        }
        case TDH_INTYPE_UINT8:
        {
            const std::uint8_t kValue = *reinterpret_cast<const std::uint8_t*>(dataPointer);
            setNumeric(kValue);
            return QString::number(kValue);
        }
        case TDH_INTYPE_INT16:
        {
            std::int16_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            setNumeric(static_cast<std::uint64_t>(static_cast<std::int64_t>(value)));
            return QString::number(value);
        }
        case TDH_INTYPE_UINT16:
        {
            std::uint16_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            setNumeric(value);
            return QString::number(value);
        }
        case TDH_INTYPE_INT32:
        {
            std::int32_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            setNumeric(static_cast<std::uint64_t>(static_cast<std::int64_t>(value)));
            return QString::number(value);
        }
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_HEXINT32:
        {
            std::uint32_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            setNumeric(value);
            return inType == TDH_INTYPE_HEXINT32
                ? QStringLiteral("0x%1").arg(value, 8, 16, QChar(u'0')).toUpper()
                : QString::number(value);
        }
        case TDH_INTYPE_INT64:
        {
            std::int64_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            setNumeric(static_cast<std::uint64_t>(value));
            return QString::number(static_cast<qlonglong>(value));
        }
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_HEXINT64:
        case TDH_INTYPE_POINTER:
        {
            std::uint64_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            else if (dataSize >= sizeof(std::uint32_t))
            {
                std::uint32_t value32 = 0;
                std::memcpy(&value32, dataPointer, sizeof(value32));
                value = value32;
            }
            setNumeric(value);
            return (inType == TDH_INTYPE_UINT64)
                ? QString::number(static_cast<qulonglong>(value))
                : formatAddress(value);
        }
        case TDH_INTYPE_BOOLEAN:
        {
            std::uint32_t value = 0;
            if (dataSize >= sizeof(value))
            {
                std::memcpy(&value, dataPointer, sizeof(value));
            }
            else
            {
                value = dataPointer[0];
            }
            setNumeric(value);
            return value != 0 ? QStringLiteral("true") : QStringLiteral("false");
        }
        case TDH_INTYPE_GUID:
            if (dataSize >= sizeof(GUID))
            {
                GUID guidValue{};
                std::memcpy(&guidValue, dataPointer, sizeof(guidValue));
                return guidToText(guidValue);
            }
            break;
        default:
            break;
        }

        QStringList byteList;
        const ULONG kVisibleBytes = std::min<ULONG>(dataSize, 32);
        for (ULONG indexValue = 0; indexValue < kVisibleBytes; ++indexValue)
        {
            byteList << QStringLiteral("%1").arg(dataPointer[indexValue], 2, 16, QChar(u'0')).toUpper();
        }
        if (dataSize > kVisibleBytes)
        {
            byteList << QStringLiteral("...");
        }
        return byteList.join(QStringLiteral(" "));
    }

    QString eventNameFromInfo(const unsigned char* infoBuffer, const TRACE_EVENT_INFO* traceInfo)
    {
        if (infoBuffer == nullptr || traceInfo == nullptr)
        {
            return QString();
        }

        auto textAtOffset = [&](const ULONG offsetValue) -> QString {
            if (offsetValue == 0)
            {
                return QString();
            }
            const wchar_t* textPointer = reinterpret_cast<const wchar_t*>(infoBuffer + offsetValue);
            return QString::fromWCharArray(textPointer).trimmed();
        };

        QString eventName = textAtOffset(traceInfo->EventNameOffset);
        if (!eventName.isEmpty())
        {
            return eventName;
        }
        eventName = textAtOffset(traceInfo->TaskNameOffset);
        if (!eventName.isEmpty())
        {
            return eventName;
        }
        return textAtOffset(traceInfo->OpcodeNameOffset);
    }

    std::optional<std::uint32_t> tryReadSyscallNumberFromStub(const unsigned char* functionPointer)
    {
        if (functionPointer == nullptr)
        {
            return std::nullopt;
        }

        for (std::size_t offsetValue = 0; offsetValue + sizeof(std::uint32_t) < 32; ++offsetValue)
        {
            if (functionPointer[offsetValue] != 0xB8)
            {
                continue;
            }

            std::uint32_t syscallNumber = 0;
            std::memcpy(&syscallNumber, functionPointer + offsetValue + 1, sizeof(syscallNumber));
            if (syscallNumber < 0x10000U)
            {
                return syscallNumber;
            }
        }
        return std::nullopt;
    }

    bool serviceNameAllowed(const QString& exportName, const QStringList& prefixList)
    {
        for (const QString& prefixText : prefixList)
        {
            if (exportName.startsWith(prefixText, Qt::CaseSensitive))
            {
                return true;
            }
        }
        return false;
    }

    void appendSyscallExportsFromModule(
        const wchar_t* moduleName,
        const QStringList& prefixList,
        std::unordered_map<std::uint32_t, DirectKernelCallMonitorWidget::SyscallMapEntry>* mapPointer)
    {
        if (moduleName == nullptr || mapPointer == nullptr)
        {
            return;
        }

        HMODULE moduleHandle = ::GetModuleHandleW(moduleName);
        if (moduleHandle == nullptr)
        {
            moduleHandle = ::LoadLibraryW(moduleName);
        }
        if (moduleHandle == nullptr)
        {
            return;
        }

        const auto* basePointer = reinterpret_cast<const unsigned char*>(moduleHandle);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(basePointer);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(basePointer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return;
        }

        const IMAGE_DATA_DIRECTORY& exportDirectoryInfo =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirectoryInfo.VirtualAddress == 0 || exportDirectoryInfo.Size == 0)
        {
            return;
        }

        const auto* exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            basePointer + exportDirectoryInfo.VirtualAddress);
        const auto* nameRvaArray = reinterpret_cast<const DWORD*>(basePointer + exportDirectory->AddressOfNames);
        const auto* ordinalArray = reinterpret_cast<const WORD*>(basePointer + exportDirectory->AddressOfNameOrdinals);
        const auto* functionRvaArray = reinterpret_cast<const DWORD*>(basePointer + exportDirectory->AddressOfFunctions);
        const QString kModuleText = QString::fromWCharArray(moduleName);

        for (DWORD indexValue = 0; indexValue < exportDirectory->NumberOfNames; ++indexValue)
        {
            const char* exportNamePointer = reinterpret_cast<const char*>(basePointer + nameRvaArray[indexValue]);
            const QString kExportName = QString::fromLatin1(exportNamePointer);
            if (!serviceNameAllowed(kExportName, prefixList))
            {
                continue;
            }

            const WORD kOrdinalValue = ordinalArray[indexValue];
            if (kOrdinalValue >= exportDirectory->NumberOfFunctions)
            {
                continue;
            }

            const DWORD kFunctionRva = functionRvaArray[kOrdinalValue];
            if (kFunctionRva >= exportDirectoryInfo.VirtualAddress
                && kFunctionRva < exportDirectoryInfo.VirtualAddress + exportDirectoryInfo.Size)
            {
                continue;
            }

            const unsigned char* functionPointer = basePointer + kFunctionRva;
            const std::optional<std::uint32_t> kSyscallNumber = tryReadSyscallNumberFromStub(functionPointer);
            if (!kSyscallNumber.has_value())
            {
                continue;
            }

            DirectKernelCallMonitorWidget::SyscallMapEntry& entry = (*mapPointer)[*kSyscallNumber];
            entry.syscallNumber = *kSyscallNumber;
            if (entry.serviceName.isEmpty())
            {
                entry.serviceName = kExportName;
                entry.sourceModule = kModuleText;
            }
            else if (!entry.serviceName.split(QStringLiteral(" / ")).contains(kExportName))
            {
                entry.serviceName += QStringLiteral(" / %1").arg(kExportName);
                entry.sourceModule += QStringLiteral(" / %1").arg(kModuleText);
            }
        }
    }

    void stopActiveKswordTraceSessionsByPrefix(const QStringList& sessionPrefixList)
    {
        constexpr ULONG kQuerySessionCapacity = 96;
        constexpr ULONG kTraceNameChars = 1024;
        constexpr ULONG kLogFileChars = 1024;
        constexpr ULONG kPropertyBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES)
            + (kTraceNameChars + kLogFileChars) * sizeof(wchar_t);

        std::vector<std::vector<unsigned char>> propertyBufferList(
            kQuerySessionCapacity,
            std::vector<unsigned char>(kPropertyBufferSize, 0));
        std::vector<EVENT_TRACE_PROPERTIES*> propertyPointerList(kQuerySessionCapacity, nullptr);

        for (ULONG indexValue = 0; indexValue < kQuerySessionCapacity; ++indexValue)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBufferList[indexValue].data());
            properties->Wnode.BufferSize = kPropertyBufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameChars * sizeof(wchar_t);
            propertyPointerList[indexValue] = properties;
        }

        ULONG sessionCount = kQuerySessionCapacity;
        const ULONG kQueryStatus = ::QueryAllTracesW(
            propertyPointerList.data(),
            kQuerySessionCapacity,
            &sessionCount);
        if (kQueryStatus != ERROR_SUCCESS && kQueryStatus != ERROR_MORE_DATA)
        {
            return;
        }

        for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < kQuerySessionCapacity; ++indexValue)
        {
            const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
            if (properties == nullptr || properties->LoggerNameOffset == 0)
            {
                continue;
            }

            const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
            const QString kLoggerNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
            if (kLoggerNameText.isEmpty())
            {
                continue;
            }

            const bool kShouldStop = std::any_of(
                sessionPrefixList.begin(),
                sessionPrefixList.end(),
                [&kLoggerNameText](const QString& prefixText) {
                    return !prefixText.trimmed().isEmpty()
                        && kLoggerNameText.startsWith(prefixText, Qt::CaseInsensitive);
                });
            if (!kShouldStop)
            {
                continue;
            }

            const std::wstring kLoggerNameWide = kLoggerNameText.toStdWString();
            std::vector<unsigned char> stopBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (kLoggerNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* stopProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBuffer.data());
            stopProperties->Wnode.BufferSize = static_cast<ULONG>(stopBuffer.size());
            stopProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* stopLoggerNamePointer = reinterpret_cast<wchar_t*>(
                stopBuffer.data() + stopProperties->LoggerNameOffset);
            ::wcscpy_s(stopLoggerNamePointer, kLoggerNameWide.size() + 1, kLoggerNameWide.c_str());
            ::ControlTraceW(0, stopLoggerNamePointer, stopProperties, EVENT_TRACE_CONTROL_STOP);
        }
    }
}

DirectKernelCallMonitorWidget::DirectKernelCallMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    KLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 初始化直接内核调用监控页。" << eol;

    initializeUi();
    initializeConnections();
    reloadSyscallMap();
    updateActionState();
    updateStatusLabel();
}

DirectKernelCallMonitorWidget::~DirectKernelCallMonitorWidget()
{
    stopCaptureInternal(true);
    if (uiUpdateTimer_ != nullptr)
    {
        uiUpdateTimer_->stop();
    }
    if (filterDebounceTimer_ != nullptr)
    {
        filterDebounceTimer_->stop();
    }

    KLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 直接内核调用监控页已析构。" << eol;
}

void DirectKernelCallMonitorWidget::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    controlPanel_ = new QWidget(this);
    QGridLayout* controlLayout = new QGridLayout(controlPanel_);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setHorizontalSpacing(6);
    controlLayout->setVerticalSpacing(6);

    controlLayout->addWidget(new QLabel(QStringLiteral("目标 PID"), controlPanel_), 0, 0);
    targetPidEdit_ = new QLineEdit(controlPanel_);
    targetPidEdit_->setPlaceholderText(QStringLiteral("多个 PID 用逗号/空格分隔；留空需勾选全局采集"));
    targetPidEdit_->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(targetPidEdit_, 0, 1, 1, 3);

    globalCaptureCheck_ = new QCheckBox(QStringLiteral("全局采集"), controlPanel_);
    globalCaptureCheck_->setToolTip(QStringLiteral("采集全系统 syscall 事件，事件量可能很大"));
    controlLayout->addWidget(globalCaptureCheck_, 0, 4);

    resolveAddressCheck_ = new QCheckBox(QStringLiteral("解析调用地址"), controlPanel_);
    resolveAddressCheck_->setChecked(true);
    resolveAddressCheck_->setToolTip(QStringLiteral("尝试把事件中的调用地址映射到进程模块，用于识别疑似直接 syscall"));
    controlLayout->addWidget(resolveAddressCheck_, 0, 5);

    controlLayout->addWidget(new QLabel(QStringLiteral("最大行数"), controlPanel_), 1, 0);
    maxRowsSpin_ = new QSpinBox(controlPanel_);
    maxRowsSpin_->setRange(1000, 20000);
    maxRowsSpin_->setSingleStep(1000);
    maxRowsSpin_->setValue(12000);
    maxRowsSpin_->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(maxRowsSpin_, 1, 1);

    controlLayout->addWidget(new QLabel(QStringLiteral("缓冲区(KB)"), controlPanel_), 1, 2);
    bufferSizeSpin_ = new QSpinBox(controlPanel_);
    bufferSizeSpin_->setRange(64, 4096);
    bufferSizeSpin_->setSingleStep(64);
    bufferSizeSpin_->setValue(512);
    bufferSizeSpin_->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(bufferSizeSpin_, 1, 3);

    reloadMapButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/process_refresh.svg"),
        QStringLiteral("重新解析 ntdll/win32u syscall 号映射"));
    startButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/process_start.svg"),
        QStringLiteral("开始直接内核调用监控"));
    stopButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("停止监控"));
    pauseButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/process_pause.svg"),
        QStringLiteral("暂停事件入表"));
    clearButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空当前事件表"));
    exportButton_ = createIconButton(
        controlPanel_,
        QStringLiteral(":/Icon/log_export.svg"),
        QStringLiteral("导出当前可见事件为 TSV"));

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(6);
    buttonLayout->addWidget(reloadMapButton_);
    buttonLayout->addWidget(startButton_);
    buttonLayout->addWidget(stopButton_);
    buttonLayout->addWidget(pauseButton_);
    buttonLayout->addWidget(clearButton_);
    buttonLayout->addWidget(exportButton_);
    buttonLayout->addStretch(1);
    controlLayout->addLayout(buttonLayout, 1, 4, 1, 2);

    mapStatusLabel_ = new QLabel(QStringLiteral("syscall 映射：待解析"), controlPanel_);
    ks::ui::applyStatusRole(mapStatusLabel_, ks::ui::StatusRole::kIdle);
    controlLayout->addWidget(mapStatusLabel_, 2, 0, 1, 3);

    statusLabel_ = new QLabel(QStringLiteral("● 空闲"), controlPanel_);
    ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
    controlLayout->addWidget(statusLabel_, 2, 3, 1, 3);
    rootLayout_->addWidget(controlPanel_, 0);

    filterPanel_ = new QWidget(this);
    QGridLayout* filterLayout = new QGridLayout(filterPanel_);
    filterLayout->setContentsMargins(6, 6, 6, 6);
    filterLayout->setHorizontalSpacing(6);
    filterLayout->setVerticalSpacing(6);

    filterLayout->addWidget(new QLabel(QStringLiteral("进程"), filterPanel_), 0, 0);
    processFilterEdit_ = new QLineEdit(filterPanel_);
    processFilterEdit_->setPlaceholderText(QStringLiteral("PID / TID / 进程名"));
    processFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(processFilterEdit_, 0, 1);

    filterLayout->addWidget(new QLabel(QStringLiteral("服务"), filterPanel_), 0, 2);
    serviceFilterEdit_ = new QLineEdit(filterPanel_);
    serviceFilterEdit_->setPlaceholderText(QStringLiteral("Nt/Zw/NtUser/NtGdi 或调用号"));
    serviceFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(serviceFilterEdit_, 0, 3);

    filterLayout->addWidget(new QLabel(QStringLiteral("详情"), filterPanel_), 0, 4);
    detailFilterEdit_ = new QLineEdit(filterPanel_);
    detailFilterEdit_->setPlaceholderText(QStringLiteral("调用地址 / 判定 / 字段详情"));
    detailFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(detailFilterEdit_, 0, 5);

    filterLayout->addWidget(new QLabel(QStringLiteral("全字段"), filterPanel_), 1, 0);
    globalFilterEdit_ = new QLineEdit(filterPanel_);
    globalFilterEdit_->setPlaceholderText(QStringLiteral("对整行文本做统一过滤"));
    globalFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(globalFilterEdit_, 1, 1, 1, 3);

    regexCheck_ = new QCheckBox(QStringLiteral("正则"), filterPanel_);
    caseCheck_ = new QCheckBox(QStringLiteral("区分大小写"), filterPanel_);
    invertCheck_ = new QCheckBox(QStringLiteral("反向"), filterPanel_);
    keepBottomCheck_ = new QCheckBox(QStringLiteral("保持贴底"), filterPanel_);
    keepBottomCheck_->setChecked(true);
    filterLayout->addWidget(regexCheck_, 1, 4);
    filterLayout->addWidget(caseCheck_, 1, 5);
    filterLayout->addWidget(invertCheck_, 2, 0);
    filterLayout->addWidget(keepBottomCheck_, 2, 1);

    clearFilterButton_ = createIconButton(
        filterPanel_,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空筛选条件"));
    filterLayout->addWidget(clearFilterButton_, 2, 2);

    filterStatusLabel_ = new QLabel(QStringLiteral("筛选结果：0 / 0"), filterPanel_);
    ks::ui::applyStatusRole(filterStatusLabel_, ks::ui::StatusRole::kIdle);
    filterLayout->addWidget(filterStatusLabel_, 2, 3, 1, 3);
    rootLayout_->addWidget(filterPanel_, 0);

    eventTable_ = new ks::ui::VisibleTableWidget(this);
    eventTable_->setColumnCount(kEventColumnCount);
    eventTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间(100ns)"),
        QStringLiteral("PID / TID"),
        QStringLiteral("进程"),
        QStringLiteral("调用号"),
        QStringLiteral("服务名"),
        QStringLiteral("判定"),
        QStringLiteral("调用地址"),
        QStringLiteral("事件名"),
        QStringLiteral("详情")
    });
    eventTable_->setAlternatingRowColors(true);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    eventTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    eventTable_->verticalHeader()->setVisible(false);
    eventTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    eventTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventTable_->setColumnWidth(kEventColumnTime100ns, 160);
    eventTable_->setColumnWidth(kEventColumnPidTid, 100);
    eventTable_->setColumnWidth(kEventColumnProcess, 180);
    eventTable_->setColumnWidth(kEventColumnSyscallNumber, 84);
    eventTable_->setColumnWidth(kEventColumnServiceName, 220);
    eventTable_->setColumnWidth(kEventColumnVerdict, 96);
    eventTable_->setColumnWidth(kEventColumnCallAddress, 164);
    eventTable_->setColumnWidth(kEventColumnEventName, 150);
    eventTable_->setColumnWidth(kEventColumnDetail, 440);
    rootLayout_->addWidget(eventTable_, 1);

    uiUpdateTimer_ = new QTimer(this);
    uiUpdateTimer_->setInterval(100);

    filterDebounceTimer_ = new QTimer(this);
    filterDebounceTimer_->setInterval(180);
    filterDebounceTimer_->setSingleShot(true);
}

void DirectKernelCallMonitorWidget::initializeConnections()
{
    connect(reloadMapButton_, &QPushButton::clicked, this, [this]() {
        reloadSyscallMap();
    });
    connect(startButton_, &QPushButton::clicked, this, [this]() {
        startCapture();
    });
    connect(stopButton_, &QPushButton::clicked, this, [this]() {
        stopCapture();
    });
    connect(pauseButton_, &QPushButton::clicked, this, [this]() {
        setCapturePaused(!capturePaused_.load());
    });
    connect(clearButton_, &QPushButton::clicked, this, [this]() {
        if (eventTable_ != nullptr)
        {
            eventTable_->clearContents();
            eventTable_->setRowCount(0);
        }
        updateActionState();
        updateStatusLabel();
        applyFilter();
    });
    connect(exportButton_, &QPushButton::clicked, this, [this]() {
        exportVisibleRowsToTsv();
    });

    const auto kBindFilterEdit = [this](QLineEdit* editPointer) {
        if (editPointer != nullptr)
        {
            connect(editPointer, &QLineEdit::textChanged, this, [this]() {
                scheduleFilterApply();
            });
        }
    };
    kBindFilterEdit(processFilterEdit_);
    kBindFilterEdit(serviceFilterEdit_);
    kBindFilterEdit(detailFilterEdit_);
    kBindFilterEdit(globalFilterEdit_);

    connect(regexCheck_, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(caseCheck_, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(invertCheck_, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(clearFilterButton_, &QPushButton::clicked, this, [this]() {
        clearFilter();
    });

    connect(eventTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showEventContextMenu(position);
    });
    connect(eventTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer != nullptr)
        {
            openEventDetailViewerForRow(itemPointer->row());
        }
    });
    connect(uiUpdateTimer_, &QTimer::timeout, this, [this]() {
        flushPendingRows();
    });
    connect(filterDebounceTimer_, &QTimer::timeout, this, [this]() {
        applyFilter();
    });
}

void DirectKernelCallMonitorWidget::reloadSyscallMap()
{
    std::unordered_map<std::uint32_t, SyscallMapEntry> newMap;
    appendSyscallExportsFromModule(
        L"ntdll.dll",
        QStringList{ QStringLiteral("Nt"), QStringLiteral("Zw") },
        &newMap);
    appendSyscallExportsFromModule(
        L"win32u.dll",
        QStringList{ QStringLiteral("NtUser"), QStringLiteral("NtGdi") },
        &newMap);

    {
        std::lock_guard<std::mutex> lock(syscallMapMutex_);
        syscallMap_ = std::move(newMap);
    }

    if (mapStatusLabel_ != nullptr)
    {
        mapStatusLabel_->setText(QStringLiteral("syscall 映射：%1 项（ntdll/win32u）")
            .arg(static_cast<qulonglong>(syscallMap_.size())));
        ks::ui::applyStatusRole(mapStatusLabel_,
            syscallMap_.empty() ? ks::ui::StatusRole::kWarning : ks::ui::StatusRole::kSuccess);
    }

    KLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 已解析 syscall 映射, count="
        << syscallMap_.size() << eol;
}

void DirectKernelCallMonitorWidget::startCapture()
{
    if (captureRunning_.load())
    {
        if (capturePaused_.load())
        {
            setCapturePaused(false);
        }
        return;
    }

    if (captureThread_ != nullptr && captureThread_->joinable())
    {
        captureThread_->join();
        captureThread_.reset();
    }

    const std::set<std::uint32_t> kPidSet = parsePidSet(targetPidEdit_ != nullptr ? targetPidEdit_->text() : QString());
    const bool kCaptureAll = globalCaptureCheck_ != nullptr && globalCaptureCheck_->isChecked();
    if (kPidSet.empty() && !kCaptureAll)
    {
        QMessageBox::information(
            this,
            QStringLiteral("直接内核调用监控"),
            QStringLiteral("请先输入目标 PID，或勾选“全局采集”。"));
        return;
    }

    if (kCaptureAll)
    {
        const QMessageBox::StandardButton kAnswer = QMessageBox::question(
            this,
            QStringLiteral("直接内核调用监控"),
            QStringLiteral("全局 syscall 事件量可能极大，建议只在短时间窗口内采集。是否继续？"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kAnswer != QMessageBox::Yes)
        {
            return;
        }
    }

    if (eventTable_ != nullptr)
    {
        eventTable_->clearContents();
        eventTable_->setRowCount(0);
    }
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.clear();
        pendingDroppedRows_ = 0;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        processNameCache_.clear();
        moduleRangeCache_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(captureConfigMutex_);
        capturePidSet_ = kPidSet;
    }

    const int kBufferSizeKb = bufferSizeSpin_ != nullptr ? bufferSizeSpin_->value() : 512;
    captureAllProcesses_.store(kCaptureAll);
    resolveCallAddress_.store(resolveAddressCheck_ == nullptr || resolveAddressCheck_->isChecked());
    captureRunning_.store(true);
    capturePaused_.store(false);
    captureStopFlag_.store(false);
    sessionHandle_.store(0);
    traceHandle_.store(0);
    sessionName_ = QStringLiteral("KswordDirectKernelCall");
    stopActiveKswordTraceSessionsByPrefix(QStringList{ sessionName_ });

    if (captureProgressPid_ == 0)
    {
        captureProgressPid_ = kPro.addReusable(this, "监控", "直接内核调用监控");
    }
    kPro.set(captureProgressPid_, "准备 System Syscall ETW 会话", 0, 10.0f);

    if (uiUpdateTimer_ != nullptr && !uiUpdateTimer_->isActive())
    {
        uiUpdateTimer_->start();
    }
    updateActionState();
    updateStatusLabel();

    QPointer<DirectKernelCallMonitorWidget> guardThis(this);
    captureThread_ = std::make_unique<std::thread>([guardThis, kBufferSizeKb]() {
        if (guardThis == nullptr)
        {
            return;
        }

        const auto kReportStopped = [guardThis]()
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                if (guardThis->uiUpdateTimer_ != nullptr)
                {
                    guardThis->flushPendingRows();
                }
                if (guardThis->statusLabel_ != nullptr)
                {
                    guardThis->statusLabel_->setText(QStringLiteral("● 已停止"));
                    ks::ui::applyStatusRole(guardThis->statusLabel_, ks::ui::StatusRole::kIdle);
                }
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
                kPro.set(guardThis->captureProgressPid_, "直接内核调用监控结束", 0, 100.0f);
            }, Qt::QueuedConnection);
        };

        const std::wstring kSessionNameWide = guardThis->sessionName_.toStdWString();
        const ULONG kTraceNameBytes = static_cast<ULONG>((kSessionNameWide.size() + 1) * sizeof(wchar_t));
        const ULONG kPropertyBufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameBytes);
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->Wnode.ClientContext = 2;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // Private SystemTraceProvider sessions cannot use SystemTraceControlGuid.
        // If a private logger name is paired with SystemTraceControlGuid, StartTraceW returns 87.
        properties->Wnode.Guid = kKswordDirectKernelCallSessionGuid;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        // Use legacy EnableFlags to enable syscall events, avoiding ERROR_INVALID_PARAMETER returns
        // from the newer System Provider EnableTraceEx2 path on certain OS/SDK combinations.
        properties->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        properties->FlushTimer = 1;
        properties->BufferSize = static_cast<ULONG>(kBufferSizeKb);
        properties->MinimumBuffers = 32;
        properties->MaximumBuffers = 128;

        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            ::ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        }

        if (startStatus != ERROR_SUCCESS)
        {
            QMetaObject::invokeMethod(qApp, [guardThis, startStatus]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                guardThis->statusLabel_->setText(QStringLiteral("● StartTrace失败:%1").arg(startStatus));
                ks::ui::applyStatusRole(guardThis->statusLabel_, ks::ui::StatusRole::kError);
                guardThis->updateActionState();
                kPro.set(guardThis->captureProgressPid_, "System Syscall 会话启动失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->sessionHandle_.store(static_cast<std::uint64_t>(sessionHandle));
        if (guardThis->captureStopFlag_.load())
        {
            const std::uint64_t kOwnedSessionHandle = guardThis->sessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            kReportStopped();
            return;
        }
        kPro.set(guardThis->captureProgressPid_, "已启用 syscall kernel flag", 0, 30.0f);

        EVENT_TRACE_LOGFILEW traceLogFile{};
        traceLogFile.LoggerName = loggerNamePointer;
        traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLogFile.EventRecordCallback = &DirectKernelCallMonitorWidget::eventRecordCallback;
        traceLogFile.Context = guardThis.data();

        TRACEHANDLE traceHandle = ::OpenTraceW(&traceLogFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            ::ControlTraceW(sessionHandle, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->sessionHandle_.store(0);
            const ULONG kLastError = ::GetLastError();
            QMetaObject::invokeMethod(qApp, [guardThis, kLastError]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                guardThis->statusLabel_->setText(QStringLiteral("● OpenTrace失败:%1").arg(kLastError));
                ks::ui::applyStatusRole(guardThis->statusLabel_, ks::ui::StatusRole::kError);
                guardThis->updateActionState();
                kPro.set(guardThis->captureProgressPid_, "OpenTrace 失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->traceHandle_.store(static_cast<std::uint64_t>(traceHandle));
        if (guardThis->captureStopFlag_.load())
        {
            const std::uint64_t kOwnedTraceHandle = guardThis->traceHandle_.exchange(0);
            if (kOwnedTraceHandle != 0)
            {
                ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
            }
            const std::uint64_t kOwnedSessionHandle = guardThis->sessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            kReportStopped();
            return;
        }
        kPro.set(guardThis->captureProgressPid_, "接收 syscall 事件", 0, 55.0f);

        const ULONG kProcessStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        const std::uint64_t kOwnedTraceHandle = guardThis->traceHandle_.exchange(0);
        if (kOwnedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
        }

        const std::uint64_t kOwnedSessionHandle = guardThis->sessionHandle_.exchange(0);
        if (kOwnedSessionHandle != 0)
        {
            ::ControlTraceW(
                static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                loggerNamePointer,
                properties,
                EVENT_TRACE_CONTROL_STOP);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, kProcessStatus]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->captureRunning_.store(false);
            guardThis->capturePaused_.store(false);
            if (guardThis->uiUpdateTimer_ != nullptr)
            {
                guardThis->flushPendingRows();
            }
            if (kProcessStatus == ERROR_SUCCESS)
            {
                guardThis->statusLabel_->setText(QStringLiteral("● 已停止"));
                ks::ui::applyStatusRole(guardThis->statusLabel_, ks::ui::StatusRole::kIdle);
            }
            else
            {
                guardThis->statusLabel_->setText(QStringLiteral("● ProcessTrace结束:%1").arg(kProcessStatus));
                ks::ui::applyStatusRole(guardThis->statusLabel_, ks::ui::StatusRole::kWarning);
            }
            guardThis->updateActionState();
            guardThis->updateStatusLabel();
            kPro.set(guardThis->captureProgressPid_, "直接内核调用监控结束", 0, 100.0f);
        }, Qt::QueuedConnection);
    });
}

void DirectKernelCallMonitorWidget::stopCapture()
{
    stopCaptureInternal(false);
}

void DirectKernelCallMonitorWidget::stopCaptureInternal(bool waitForThread)
{
    captureStopFlag_.store(true);

    const std::uint64_t kOwnedTraceHandle = traceHandle_.exchange(0);
    if (kOwnedTraceHandle != 0)
    {
        ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
    }

    const std::uint64_t kOwnedSessionHandle = sessionHandle_.exchange(0);
    if (kOwnedSessionHandle != 0)
    {
        const std::wstring kSessionNameWide = sessionName_.toStdWString();
        std::vector<unsigned char> propertyBuffer(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t),
            0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(propertyBuffer.size());
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!kSessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        }

        ::ControlTraceW(
            static_cast<TRACEHANDLE>(kOwnedSessionHandle),
            loggerNamePointer,
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (captureThread_ == nullptr || !captureThread_->joinable())
    {
        captureThread_.reset();
        captureRunning_.store(false);
        capturePaused_.store(false);
        if (uiUpdateTimer_ != nullptr)
        {
            uiUpdateTimer_->stop();
        }
        updateActionState();
        updateStatusLabel();
        return;
    }

    if (waitForThread)
    {
        captureThread_->join();
        captureThread_.reset();
        captureRunning_.store(false);
        capturePaused_.store(false);
        if (uiUpdateTimer_ != nullptr)
        {
            uiUpdateTimer_->stop();
        }
        updateActionState();
        updateStatusLabel();
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("● 停止中..."));
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kWarning);
    }
    // The stop button cannot transfer ownership of m_captureThread. This thread holds
    // the raw ETW Context; the destruction path must retain the join handle to wait for
    // ProcessTrace and its callbacks to complete fully before releasing the QWidget.
    updateActionState();
    updateStatusLabel();
}

void DirectKernelCallMonitorWidget::setCapturePaused(bool paused)
{
    if (!captureRunning_.load())
    {
        return;
    }
    capturePaused_.store(paused);
    updateActionState();
    updateStatusLabel();
}

void DirectKernelCallMonitorWidget::updateActionState()
{
    const bool kRunning = captureRunning_.load();
    const bool kPaused = capturePaused_.load();
    const bool kHasRows = eventTable_ != nullptr && eventTable_->rowCount() > 0;

    if (targetPidEdit_ != nullptr)
    {
        targetPidEdit_->setEnabled(!kRunning);
    }
    if (globalCaptureCheck_ != nullptr)
    {
        globalCaptureCheck_->setEnabled(!kRunning);
    }
    if (bufferSizeSpin_ != nullptr)
    {
        bufferSizeSpin_->setEnabled(!kRunning);
    }
    if (reloadMapButton_ != nullptr)
    {
        reloadMapButton_->setEnabled(!kRunning);
    }
    if (startButton_ != nullptr)
    {
        startButton_->setEnabled(!kRunning || kPaused);
        startButton_->setIcon(QIcon(kPaused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        startButton_->setToolTip(kPaused
            ? QStringLiteral("继续直接内核调用监控")
            : QStringLiteral("开始直接内核调用监控"));
    }
    if (stopButton_ != nullptr)
    {
        stopButton_->setEnabled(kRunning);
    }
    if (pauseButton_ != nullptr)
    {
        pauseButton_->setEnabled(kRunning);
        pauseButton_->setIcon(QIcon(kPaused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_pause.svg")));
        pauseButton_->setToolTip(kPaused
            ? QStringLiteral("继续事件入表")
            : QStringLiteral("暂停事件入表"));
    }
    if (clearButton_ != nullptr)
    {
        clearButton_->setEnabled(!kRunning && kHasRows);
    }
    if (exportButton_ != nullptr)
    {
        exportButton_->setEnabled(kHasRows);
    }
}

void DirectKernelCallMonitorWidget::updateStatusLabel()
{
    if (statusLabel_ == nullptr)
    {
        return;
    }
    const int kEventCount = eventTable_ != nullptr ? eventTable_->rowCount() : 0;
    QString targetText;
    if (captureAllProcesses_.load())
    {
        targetText = QStringLiteral("全局");
    }
    else
    {
        std::lock_guard<std::mutex> lock(captureConfigMutex_);
        targetText = QStringLiteral("PID=%1").arg(static_cast<qulonglong>(capturePidSet_.size()));
    }

    if (captureRunning_.load())
    {
        if (capturePaused_.load())
        {
            statusLabel_->setText(QStringLiteral("● 已暂停  %1 | 事件=%2").arg(targetText).arg(kEventCount));
            ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kWarning);
        }
        else
        {
            statusLabel_->setText(QStringLiteral("● 监听中  %1 | 事件=%2").arg(targetText).arg(kEventCount));
            ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kInfo);
        }
    }
    else
    {
        statusLabel_->setText(QStringLiteral("● 空闲  事件=%1").arg(kEventCount));
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
    }
}

void WINAPI DirectKernelCallMonitorWidget::eventRecordCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }
    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord->UserContext == nullptr)
    {
        return;
    }
    auto* widget = reinterpret_cast<DirectKernelCallMonitorWidget*>(eventRecord->UserContext);
    widget->enqueueEventFromRecord(eventRecordPtr);
}

void DirectKernelCallMonitorWidget::enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || captureStopFlag_.load() || capturePaused_.load())
    {
        return;
    }
    const std::uint32_t kPidValue = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    if (!shouldCapturePid(kPidValue))
    {
        return;
    }

    CapturedEventRow row = buildRowFromRecord(eventRecordPtr);
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        if (pendingRows_.size() >= kPendingRowCapacity)
        {
            pendingRows_.pop_front();
            ++pendingDroppedRows_;
        }
        pendingRows_.push_back(std::move(row));
    }
}

DirectKernelCallMonitorWidget::CapturedEventRow DirectKernelCallMonitorWidget::buildRowFromRecord(
    const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    CapturedEventRow row;
    if (eventRecord == nullptr)
    {
        return row;
    }

    row.time100nsText = QString::number(static_cast<qlonglong>(eventRecord->EventHeader.TimeStamp.QuadPart));
    row.pid = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    row.tid = static_cast<std::uint32_t>(eventRecord->EventHeader.ThreadId);
    row.pidTidText = QStringLiteral("%1 / %2").arg(row.pid).arg(row.tid);
    row.processText = processNameForPid(
        row.pid,
        &row.processCreationTime100ns);
    row.eventName = QStringLiteral("Event_%1").arg(eventRecord->EventHeader.EventDescriptor.Id);

    QString decodedEventName;
    const std::vector<DecodedProperty> kPropertyList = decodeEventProperties(eventRecordPtr, &decodedEventName);
    if (!decodedEventName.trimmed().isEmpty())
    {
        row.eventName = decodedEventName.trimmed();
    }

    QStringList propertyLineList;
    std::optional<std::uint32_t> syscallNumber;
    std::optional<std::uint64_t> callAddress;
    for (const DecodedProperty& property : kPropertyList)
    {
        propertyLineList << QStringLiteral("%1=%2").arg(property.name, property.valueText);
        const QString kNormalized = normalizeName(property.name);
        if (property.hasNumericValue)
        {
            const bool kLooksLikeSyscallNumber = kNormalized.contains(QStringLiteral("syscall"))
                || kNormalized.contains(QStringLiteral("systemcall"))
                || kNormalized.contains(QStringLiteral("servicenumber"))
                || kNormalized.contains(QStringLiteral("serviceid"))
                || kNormalized.contains(QStringLiteral("syscallid"));
            if (!syscallNumber.has_value() && kLooksLikeSyscallNumber && property.numericValue < 0x10000ULL)
            {
                syscallNumber = static_cast<std::uint32_t>(property.numericValue);
            }

            const bool kLooksLikeAddress = kNormalized.contains(QStringLiteral("calladdress"))
                || kNormalized.contains(QStringLiteral("returnaddress"))
                || kNormalized.contains(QStringLiteral("instructionpointer"))
                || kNormalized == QStringLiteral("ip")
                || kNormalized == QStringLiteral("pc")
                || kNormalized.contains(QStringLiteral("programcounter"));
            if (!callAddress.has_value() && kLooksLikeAddress && property.numericValue > 0x10000ULL)
            {
                callAddress = property.numericValue;
            }
        }
    }

    if (!syscallNumber.has_value() && eventRecord->UserData != nullptr && eventRecord->UserDataLength >= sizeof(std::uint32_t))
    {
        std::uint32_t candidate = 0;
        std::memcpy(&candidate, eventRecord->UserData, sizeof(candidate));
        if (candidate < 0x10000U)
        {
            syscallNumber = candidate;
            propertyLineList << QStringLiteral("fallback.raw0.syscallCandidate=%1").arg(candidate);
        }
    }

    if (syscallNumber.has_value())
    {
        row.hasSyscallNumber = true;
        row.syscallNumber = *syscallNumber;
        row.syscallNumberText = QStringLiteral("%1 / 0x%2")
            .arg(row.syscallNumber)
            .arg(row.syscallNumber, 4, 16, QChar(u'0'))
            .toUpper();
        row.serviceName = serviceNameForNumber(row.syscallNumber);
    }
    else
    {
        row.syscallNumberText = QStringLiteral("<未知>");
        row.serviceName = QStringLiteral("<未解析>");
    }

    if (callAddress.has_value())
    {
        row.callAddress = *callAddress;
        row.callAddressText = formatAddress(row.callAddress);
    }
    else
    {
        row.callAddressText = QStringLiteral("<未知>");
    }

    QString callModuleText;
    if (row.callAddress != 0 && resolveCallAddress_.load())
    {
        callModuleText = moduleNameForAddress(row.pid, row.callAddress);
    }

    if (row.callAddress == 0)
    {
        row.verdictText = QStringLiteral("待判定");
    }
    else if (isKernelModeAddress(row.callAddress))
    {
        row.verdictText = QStringLiteral("内核服务入口");
    }
    else if (callModuleText.compare(QStringLiteral("ntdll.dll"), Qt::CaseInsensitive) == 0
        || callModuleText.compare(QStringLiteral("win32u.dll"), Qt::CaseInsensitive) == 0)
    {
        row.verdictText = QStringLiteral("常规导出桩");
    }
    else if (!callModuleText.trimmed().isEmpty())
    {
        row.verdictText = QStringLiteral("疑似直接调用:%1").arg(callModuleText);
    }
    else
    {
        row.verdictText = QStringLiteral("疑似直接调用");
    }

    row.detailText = QStringLiteral("%1 | %2 | %3")
        .arg(row.verdictText, row.callAddressText, row.serviceName);
    row.detailAllText = QStringLiteral(
        "Provider: System Syscall (%1)\n"
        "EventId: %2\n"
        "EventName: %3\n"
        "PID/TID: %4\n"
        "Process: %5\n"
        "Syscall: %6\n"
        "Service: %7\n"
        "CallAddress: %8\n"
        "Verdict: %9\n"
        "Properties:\n%10")
        .arg(guidToText(eventRecord->EventHeader.ProviderId))
        .arg(eventRecord->EventHeader.EventDescriptor.Id)
        .arg(row.eventName)
        .arg(row.pidTidText)
        .arg(row.processText)
        .arg(row.syscallNumberText)
        .arg(row.serviceName)
        .arg(callModuleText.isEmpty() ? row.callAddressText : QStringLiteral("%1 (%2)").arg(row.callAddressText, callModuleText))
        .arg(row.verdictText)
        .arg(propertyLineList.isEmpty() ? QStringLiteral("<无 TDH 字段>") : propertyLineList.join(QChar(u'\n')));
    row.globalSearchText = QStringLiteral("%1 | %2 | %3 | %4 | %5 | %6 | %7 | %8")
        .arg(row.time100nsText)
        .arg(row.pidTidText)
        .arg(row.processText)
        .arg(row.syscallNumberText)
        .arg(row.serviceName)
        .arg(row.verdictText)
        .arg(row.callAddressText)
        .arg(row.detailAllText);
    return row;
}

std::vector<DirectKernelCallMonitorWidget::DecodedProperty> DirectKernelCallMonitorWidget::decodeEventProperties(
    const struct _EVENT_RECORD* eventRecordPtr,
    QString* eventNameOut) const
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    std::vector<DecodedProperty> propertyList;
    if (eventRecord == nullptr)
    {
        return propertyList;
    }

    ULONG infoBufferSize = 0;
    ULONG status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        nullptr,
        &infoBufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || infoBufferSize == 0)
    {
        return propertyList;
    }

    std::vector<unsigned char> infoBuffer(infoBufferSize, 0);
    auto* traceInfo = reinterpret_cast<TRACE_EVENT_INFO*>(infoBuffer.data());
    status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        traceInfo,
        &infoBufferSize);
    if (status != ERROR_SUCCESS)
    {
        return propertyList;
    }

    if (eventNameOut != nullptr)
    {
        *eventNameOut = eventNameFromInfo(infoBuffer.data(), traceInfo);
    }

    propertyList.reserve(traceInfo->TopLevelPropertyCount);
    for (ULONG propertyIndex = 0; propertyIndex < traceInfo->TopLevelPropertyCount; ++propertyIndex)
    {
        const EVENT_PROPERTY_INFO& propertyInfo = traceInfo->EventPropertyInfoArray[propertyIndex];
        if ((propertyInfo.Flags & PropertyStruct) != 0 || propertyInfo.NameOffset == 0)
        {
            continue;
        }

        const wchar_t* propertyNamePointer = reinterpret_cast<const wchar_t*>(
            infoBuffer.data() + propertyInfo.NameOffset);
        const QString kPropertyName = QString::fromWCharArray(propertyNamePointer).trimmed();
        if (kPropertyName.isEmpty())
        {
            continue;
        }

        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        status = ::TdhGetPropertySize(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > 4096)
        {
            continue;
        }

        std::vector<unsigned char> propertyBuffer(propertySize, 0);
        status = ::TdhGetProperty(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            propertySize,
            propertyBuffer.data());
        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        DecodedProperty decodedProperty;
        decodedProperty.name = kPropertyName;
        decodedProperty.valueText = decodedValueText(
            propertyBuffer.data(),
            propertySize,
            propertyInfo.nonStructType.InType,
            &decodedProperty.numericValue,
            &decodedProperty.hasNumericValue);
        propertyList.push_back(std::move(decodedProperty));
    }
    return propertyList;
}

QString DirectKernelCallMonitorWidget::serviceNameForNumber(std::uint32_t syscallNumber) const
{
    std::lock_guard<std::mutex> lock(syscallMapMutex_);
    const auto kFound = syscallMap_.find(syscallNumber);
    if (kFound == syscallMap_.end())
    {
        return QStringLiteral("<未命中映射>");
    }
    return kFound->second.serviceName;
}

QString DirectKernelCallMonitorWidget::processNameForPid(
    const std::uint32_t pid,
    std::uint64_t* const creationTime100nsOut)
{
    // creationTime100nsOut: Defaults to 0; only returns a verifiable identity if the cache lookup or real-time query succeeds.
    if (creationTime100nsOut != nullptr)
    {
        *creationTime100nsOut = 0U;
    }
    if (pid == 0U)
    {
        return QStringLiteral("System");
    }

    // nowTime: Use the monotonic clock to determine if this PID needs re-verification.
    const std::chrono::steady_clock::time_point kNowTime =
        std::chrono::steady_clock::now();

    // cachedEntry: Retains the previous cache entry when querying the system outside the lock to avoid holding a mutex during Win32 calls.
    ProcessIdentityCacheEntry cachedEntry;

    // hasCachedEntry: Marks whether cachedEntry originates from a valid cache.
    bool hasCachedEntry = false;
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        const auto kFound = processNameCache_.find(pid);
        if (kFound != processNameCache_.end())
        {
            cachedEntry = kFound->second;
            hasCachedEntry = true;

            // cacheAge: Reuses a validated identity within one second to avoid repeatedly opening handles for high-frequency ETW events.
            const auto kCacheAge = std::chrono::duration_cast<std::chrono::milliseconds>(
                kNowTime - kFound->second.lastValidationTime);
            if (kCacheAge.count() < kProcessIdentityValidationIntervalMs)
            {
                if (creationTime100nsOut != nullptr)
                {
                    *creationTime100nsOut = kFound->second.creationTime100ns;
                }
                return kFound->second.processText;
            }
        }
    }

    // observedCreationTime100ns: The current process creation time obtained during this re-verification round.
    std::uint64_t observedCreationTime100ns = 0U;

    // identityDetailText: Receives low-level query diagnostics; high-frequency capture paths do not directly pop up UI dialogs.
    std::string identityDetailText;

    // identityQueryOk: Determines whether it is safe to update the identity corresponding to the PID.
    const bool kIdentityQueryOk = ks::process::queryProcessCreationTimeByPid(
        pid,
        &observedCreationTime100ns,
        &identityDetailText);

    // identityChanged: A creation time change indicates PID reuse; must re-parse the name and clear the module cache.
    const bool kIdentityChanged = kIdentityQueryOk &&
        (!hasCachedEntry || cachedEntry.creationTime100ns != observedCreationTime100ns);

    // processText: On query failure, retain the old name; on the first failure, display only the PID.
    QString processText = hasCachedEntry
        ? cachedEntry.processText
        : QStringLiteral("PID %1").arg(pid);
    if (kIdentityChanged)
    {
        // processHandle: Query the image name only once upon initial discovery or PID reuse.
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
        if (kProcessHandle != nullptr)
        {
            // pathBuffer/pathLength: Receives the full image path of the target process.
            std::vector<wchar_t> pathBuffer(32768, L'\0');
            DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
            if (::QueryFullProcessImageNameW(
                    kProcessHandle,
                    0,
                    pathBuffer.data(),
                    &pathLength) != FALSE &&
                pathLength > 0U)
            {
                // imagePath/fileName: Convert the full path to a short name in the event table.
                const QString kImagePath = QString::fromWCharArray(
                    pathBuffer.data(),
                    static_cast<int>(pathLength));
                const QString kFileName = QFileInfo(kImagePath).fileName();
                processText = kFileName.isEmpty()
                    ? QStringLiteral("PID %1").arg(pid)
                    : QStringLiteral("%1 (%2)").arg(kFileName).arg(pid);
            }
            ::CloseHandle(kProcessHandle);
        }
    }

    // nextCacheEntry: Retain the old identity on query failure; this limits jump rejections without erroneously opening new processes.
    ProcessIdentityCacheEntry nextCacheEntry;
    nextCacheEntry.processText = processText;
    nextCacheEntry.creationTime100ns = kIdentityQueryOk
        ? observedCreationTime100ns
        : (hasCachedEntry ? cachedEntry.creationTime100ns : 0U);
    nextCacheEntry.lastValidationTime = kNowTime;
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        if (kIdentityChanged)
        {
            moduleRangeCache_.erase(pid);
        }
        processNameCache_[pid] = nextCacheEntry;
    }
    if (creationTime100nsOut != nullptr)
    {
        *creationTime100nsOut = nextCacheEntry.creationTime100ns;
    }
    return processText;
}

QString DirectKernelCallMonitorWidget::moduleNameForAddress(std::uint32_t pid, std::uint64_t addressValue)
{
    if (pid == 0 || addressValue == 0)
    {
        return QString();
    }

    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        if (moduleRangeCache_.find(pid) == moduleRangeCache_.end())
        {
            refreshModuleRangesForPid(pid);
        }
        const auto kFound = moduleRangeCache_.find(pid);
        if (kFound != moduleRangeCache_.end())
        {
            for (const ModuleRange& range : kFound->second)
            {
                if (addressValue >= range.startAddress && addressValue < range.endAddress)
                {
                    return range.moduleName;
                }
            }
        }
    }
    return QString();
}

void DirectKernelCallMonitorWidget::refreshModuleRangesForPid(std::uint32_t pid)
{
    std::vector<ModuleRange> rangeList;
    HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        static_cast<DWORD>(pid));
    if (snapshotHandle != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(snapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                ModuleRange range;
                range.startAddress = reinterpret_cast<std::uint64_t>(moduleEntry.modBaseAddr);
                range.endAddress = range.startAddress + static_cast<std::uint64_t>(moduleEntry.modBaseSize);
                range.moduleName = QString::fromWCharArray(moduleEntry.szModule);
                range.imagePath = QString::fromWCharArray(moduleEntry.szExePath);
                rangeList.push_back(std::move(range));
            } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
    }

    moduleRangeCache_[pid] = std::move(rangeList);
}

std::set<std::uint32_t> DirectKernelCallMonitorWidget::parsePidSet(const QString& text) const
{
    std::set<std::uint32_t> pidSet;
    const QStringList kTokenList = text.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    for (const QString& token : kTokenList)
    {
        QString normalized = token.trimmed();
        bool ok = false;
        std::uint32_t pid = 0;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            pid = normalized.mid(2).toUInt(&ok, 16);
        }
        else
        {
            pid = normalized.toUInt(&ok, 10);
        }
        if (ok && pid != 0)
        {
            pidSet.insert(pid);
        }
    }
    return pidSet;
}

bool DirectKernelCallMonitorWidget::shouldCapturePid(std::uint32_t pid) const
{
    if (captureAllProcesses_.load())
    {
        return true;
    }
    std::lock_guard<std::mutex> lock(captureConfigMutex_);
    return capturePidSet_.find(pid) != capturePidSet_.end();
}

void DirectKernelCallMonitorWidget::flushPendingRows()
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    // QMenu::exec() runs a nested event loop; periodic refresh must enter the table commit gate before reading the
    // pending queue, otherwise frontend clipping causes the menu to capture row numbers pointing to a different event.
    const QPointer<DirectKernelCallMonitorWidget> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("direct-kernel-call-event-flush"),
        { eventTable_ },
        [kGuardThis]()
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->flushPendingRows();
            }
        }))
    {
        return;
    }

    std::vector<CapturedEventRow> rowList;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        const std::size_t kTakeCount = std::min(kUiFlushRowLimit, pendingRows_.size());
        rowList.reserve(kTakeCount);
        for (std::size_t index = 0; index < kTakeCount; ++index)
        {
            rowList.push_back(std::move(pendingRows_.front()));
            pendingRows_.pop_front();
        }
    }
    if (rowList.empty())
    {
        if (!captureRunning_.load() && uiUpdateTimer_ != nullptr)
        {
            uiUpdateTimer_->stop();
        }
        return;
    }

    const bool kUpdatesEnabled = eventTable_->updatesEnabled();
    eventTable_->setUpdatesEnabled(false);
    QElapsedTimer budgetTimer;
    budgetTimer.start();
    std::size_t renderedCount = 0;
    for (const CapturedEventRow& rowValue : rowList)
    {
        appendEventRow(rowValue);
        ++renderedCount;
        if (budgetTimer.elapsed() >= kUiFlushBudgetMs)
        {
            break;
        }
    }
    const int kMaxRows = maxRowsSpin_ != nullptr ? maxRowsSpin_->value() : 12000;
    const int kRemoveCount = std::max(0, eventTable_->rowCount() - kMaxRows);
    if (kRemoveCount > 0 && eventTable_->model() != nullptr)
    {
        eventTable_->model()->removeRows(0, kRemoveCount);
    }
    eventTable_->setUpdatesEnabled(kUpdatesEnabled);
    if (kUpdatesEnabled && eventTable_->viewport() != nullptr)
    {
        eventTable_->viewport()->update();
    }

    if (renderedCount < rowList.size())
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (std::size_t index = rowList.size(); index > renderedCount; --index)
        {
            pendingRows_.push_front(std::move(rowList[index - 1]));
        }
        while (pendingRows_.size() > kPendingRowCapacity)
        {
            pendingRows_.pop_back();
            ++pendingDroppedRows_;
        }
    }

    applyFilter();
    updateActionState();
    updateStatusLabel();

    if (keepBottomCheck_ != nullptr && keepBottomCheck_->isChecked())
    {
        eventTable_->scrollToBottom();
    }
}

void DirectKernelCallMonitorWidget::appendEventRow(const CapturedEventRow& rowValue)
{
    const int kRow = eventTable_->rowCount();
    eventTable_->insertRow(kRow);

    QTableWidgetItem* timeItem = createReadOnlyItem(rowValue.time100nsText);
    timeItem->setData(kRoleProcessSearchText, QStringLiteral("%1 | %2").arg(rowValue.pidTidText, rowValue.processText));
    timeItem->setData(kRoleServiceSearchText, QStringLiteral("%1 | %2").arg(rowValue.syscallNumberText, rowValue.serviceName));
    timeItem->setData(kRoleGlobalSearchText, rowValue.globalSearchText);
    timeItem->setData(kRoleDetailText, rowValue.detailAllText);
    timeItem->setData(
        kRoleProcessCreationTime100ns,
        QVariant::fromValue<qulonglong>(rowValue.processCreationTime100ns));

    eventTable_->setItem(kRow, kEventColumnTime100ns, timeItem);
    eventTable_->setItem(kRow, kEventColumnPidTid, createReadOnlyItem(rowValue.pidTidText));
    eventTable_->setItem(kRow, kEventColumnProcess, createReadOnlyItem(rowValue.processText));
    eventTable_->setItem(kRow, kEventColumnSyscallNumber, createReadOnlyItem(rowValue.syscallNumberText));
    eventTable_->setItem(kRow, kEventColumnServiceName, createReadOnlyItem(rowValue.serviceName));
    eventTable_->setItem(kRow, kEventColumnVerdict, createReadOnlyItem(rowValue.verdictText));
    eventTable_->setItem(kRow, kEventColumnCallAddress, createReadOnlyItem(rowValue.callAddressText));
    eventTable_->setItem(kRow, kEventColumnEventName, createReadOnlyItem(rowValue.eventName));
    eventTable_->setItem(kRow, kEventColumnDetail, createReadOnlyItem(rowValue.detailText));
}

void DirectKernelCallMonitorWidget::scheduleFilterApply()
{
    if (filterDebounceTimer_ != nullptr)
    {
        filterDebounceTimer_->start();
    }
}

void DirectKernelCallMonitorWidget::applyFilter()
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const QString kProcessFilter = processFilterEdit_ != nullptr ? processFilterEdit_->text() : QString();
    const QString kServiceFilter = serviceFilterEdit_ != nullptr ? serviceFilterEdit_->text() : QString();
    const QString kDetailFilter = detailFilterEdit_ != nullptr ? detailFilterEdit_->text() : QString();
    const QString kGlobalFilter = globalFilterEdit_ != nullptr ? globalFilterEdit_->text() : QString();
    const bool kUseRegex = regexCheck_ != nullptr && regexCheck_->isChecked();
    const bool kInvertMatch = invertCheck_ != nullptr && invertCheck_->isChecked();
    const Qt::CaseSensitivity kCaseSensitivity =
        (caseCheck_ != nullptr && caseCheck_->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    const bool kHasTextFilter = !kProcessFilter.trimmed().isEmpty()
        || !kServiceFilter.trimmed().isEmpty()
        || !kDetailFilter.trimmed().isEmpty()
        || !kGlobalFilter.trimmed().isEmpty();
    const bool kRequiresFiltering = kHasTextFilter || kInvertMatch;
    if (!kRequiresFiltering)
    {
        if (filterActive_)
        {
            for (int row = 0; row < eventTable_->rowCount(); ++row)
            {
                eventTable_->setRowHidden(row, false);
            }
        }
        filterActive_ = false;
        if (filterStatusLabel_ != nullptr)
        {
            filterStatusLabel_->setText(QStringLiteral("筛选结果：%1 / %2")
                .arg(eventTable_->rowCount())
                .arg(eventTable_->rowCount()));
            ks::ui::applyStatusRole(filterStatusLabel_,
                eventTable_->rowCount() > 0 ? ks::ui::StatusRole::kSuccess : ks::ui::StatusRole::kIdle);
        }
        return;
    }

    filterActive_ = true;

    int visibleCount = 0;
    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        QTableWidgetItem* timeItem = eventTable_->item(row, kEventColumnTime100ns);
        const QString kProcessText = timeItem != nullptr ? timeItem->data(kRoleProcessSearchText).toString() : QString();
        const QString kServiceText = timeItem != nullptr ? timeItem->data(kRoleServiceSearchText).toString() : QString();
        const QString kGlobalText = timeItem != nullptr ? timeItem->data(kRoleGlobalSearchText).toString() : QString();
        const QString kDetailText = eventTable_->item(row, kEventColumnDetail) != nullptr
            ? eventTable_->item(row, kEventColumnDetail)->text()
            : QString();

        bool matched = textMatch(kProcessText, kProcessFilter, kUseRegex, kCaseSensitivity)
            && textMatch(kServiceText, kServiceFilter, kUseRegex, kCaseSensitivity)
            && textMatch(kDetailText, kDetailFilter, kUseRegex, kCaseSensitivity)
            && textMatch(kGlobalText, kGlobalFilter, kUseRegex, kCaseSensitivity);
        if (kInvertMatch)
        {
            matched = !matched;
        }

        eventTable_->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }

    if (filterStatusLabel_ != nullptr)
    {
        filterStatusLabel_->setText(QStringLiteral("筛选结果：%1 / %2").arg(visibleCount).arg(eventTable_->rowCount()));
        ks::ui::applyStatusRole(filterStatusLabel_,
            visibleCount > 0 ? ks::ui::StatusRole::kSuccess : ks::ui::StatusRole::kIdle);
    }
}

void DirectKernelCallMonitorWidget::clearFilter()
{
    const QSignalBlocker kProcessBlocker(processFilterEdit_);
    const QSignalBlocker kServiceBlocker(serviceFilterEdit_);
    const QSignalBlocker kDetailBlocker(detailFilterEdit_);
    const QSignalBlocker kGlobalBlocker(globalFilterEdit_);
    const QSignalBlocker kRegexBlocker(regexCheck_);
    const QSignalBlocker kCaseBlocker(caseCheck_);
    const QSignalBlocker kInvertBlocker(invertCheck_);

    if (processFilterEdit_ != nullptr)
    {
        processFilterEdit_->clear();
    }
    if (serviceFilterEdit_ != nullptr)
    {
        serviceFilterEdit_->clear();
    }
    if (detailFilterEdit_ != nullptr)
    {
        detailFilterEdit_->clear();
    }
    if (globalFilterEdit_ != nullptr)
    {
        globalFilterEdit_->clear();
    }
    if (regexCheck_ != nullptr)
    {
        regexCheck_->setChecked(false);
    }
    if (caseCheck_ != nullptr)
    {
        caseCheck_->setChecked(false);
    }
    if (invertCheck_ != nullptr)
    {
        invertCheck_->setChecked(false);
    }
    applyFilter();
}

void DirectKernelCallMonitorWidget::exportVisibleRowsToTsv()
{
    if (eventTable_ == nullptr || eventTable_->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    const QString kFilePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出直接内核调用事件"),
        QStringLiteral("direct-kernel-call-events.tsv"),
        QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*.*)"));
    if (kFilePath.isEmpty())
    {
        return;
    }

    QFile outputFile(kFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出"), QStringLiteral("无法写入文件：%1").arg(kFilePath));
        return;
    }

    QTextStream stream(&outputFile);
    QStringList headerList;
    for (int column = 0; column < eventTable_->columnCount(); ++column)
    {
        headerList << eventTable_->horizontalHeaderItem(column)->text();
    }
    stream << headerList.join(QChar(u'\t')) << QChar(u'\n');

    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        if (eventTable_->isRowHidden(row))
        {
            continue;
        }
        QStringList cellList;
        for (int column = 0; column < eventTable_->columnCount(); ++column)
        {
            QString text = eventTable_->item(row, column) != nullptr
                ? eventTable_->item(row, column)->text()
                : QString();
            text.replace(QChar(u'\t'), QChar(u' '));
            text.replace(QChar(u'\n'), QChar(u' '));
            cellList << text;
        }
        stream << cellList.join(QChar(u'\t')) << QChar(u'\n');
    }
    outputFile.close();
}

void DirectKernelCallMonitorWidget::showEventContextMenu(const QPoint& position)
{
    if (eventTable_ == nullptr)
    {
        return;
    }
    QTableWidgetItem* itemPointer = eventTable_->itemAt(position);
    if (itemPointer == nullptr)
    {
        return;
    }

    const int kRow = itemPointer->row();
    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* detailAction = menu.addAction(QStringLiteral("查看详情"));
    QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
    QAction* copyDetailAction = menu.addAction(QStringLiteral("复制详情"));
    const QTableWidgetItem* processIdItem = eventTable_->item(kRow, kEventColumnPidTid);
    std::uint32_t processId = 0;
    const bool kHasProcessId = processIdItem != nullptr &&
        ks::online_scan::tryParsePidFromText(processIdItem->text(), &processId) &&
        processId != 0U;

    // processCreationTime100ns: reads the process identity captured at the time of the event from the event row.
    const QTableWidgetItem* const kIdentityItem =
        eventTable_->item(kRow, kEventColumnTime100ns);
    const quint64 kProcessCreationTime100ns = kIdentityItem != nullptr
        ? kIdentityItem->data(kRoleProcessCreationTime100ns).toULongLong()
        : 0U;

    // hasProcessIdentity: history jump is allowed only when both PID and creation time exist.
    const bool kHasProcessIdentity = kHasProcessId && kProcessCreationTime100ns != 0U;
    QAction* openProcessDetailAction = menu.addAction(QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(kHasProcessIdentity);
    if (kHasProcessId && !kHasProcessIdentity)
    {
        openProcessDetailAction->setToolTip(QStringLiteral(
            "无法验证该历史事件的进程创建时间；为避免 PID 复用后打开无关进程，已禁用跳转。"));
    }
    menu.addSeparator();
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, kRow]() -> ks::online_scan::SandboxUploadTarget {
            // Input: Current right-click row in the direct kernel call event table.
            // Processing: Parse the PID from the PID/TID column and query the process image path for that PID.
            // Returns: the uploadable file path; returns errorText if resolution fails or the process path is unreadable.
            QTableWidgetItem* pidItem = eventTable_ != nullptr
                ? eventTable_->item(kRow, kEventColumnPidTid)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("直接内核调用事件"),
                    QStringLiteral("当前事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue)).trimmed();
            if (kProcessPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("直接内核调用事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                kProcessPath,
                QStringLiteral("直接内核调用事件 PID=%1").arg(pidValue),
                QString()
            };
        });
    QAction* selectedAction = menu.exec(eventTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == detailAction)
    {
        openEventDetailViewerForRow(kRow);
        return;
    }

    if (selectedAction == openProcessDetailAction)
    {
        ks::ui::openProcessDetailByIdentity(
            processId,
            kProcessCreationTime100ns);
        return;
    }

    QString detailText;
    QTableWidgetItem* timeItem = eventTable_->item(kRow, kEventColumnTime100ns);
    if (timeItem != nullptr)
    {
        detailText = timeItem->data(kRoleDetailText).toString();
    }
    if (selectedAction == copyDetailAction)
    {
        QApplication::clipboard()->setText(detailText);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList cellList;
        for (int column = 0; column < eventTable_->columnCount(); ++column)
        {
            cellList << (eventTable_->item(kRow, column) != nullptr ? eventTable_->item(kRow, column)->text() : QString());
        }
        QApplication::clipboard()->setText(cellList.join(QChar(u'\t')));
    }
}

void DirectKernelCallMonitorWidget::openEventDetailViewerForRow(int rowIndex)
{
    if (eventTable_ == nullptr || rowIndex < 0 || rowIndex >= eventTable_->rowCount())
    {
        return;
    }
    QTableWidgetItem* timeItem = eventTable_->item(rowIndex, kEventColumnTime100ns);
    if (timeItem == nullptr)
    {
        return;
    }
    const QString kDetailText = timeItem->data(kRoleDetailText).toString();
    monitor_text_viewer::showReadOnlyTextWindow(
        this,
        QStringLiteral("直接内核调用详情"),
        kDetailText,
        QStringLiteral("monitor/direct-kernel-call/%1.txt").arg(rowIndex + 1));
}
