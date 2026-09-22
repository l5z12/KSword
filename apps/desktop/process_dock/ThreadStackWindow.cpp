#include "ThreadStackWindow.h"

// ============================================================
// ThreadStackWindow.cpp
// Purpose:
// - Capture user-mode call stacks using R3 thread suspension + GetThreadContext + StackWalk64.
// - Uses DbgHelp to parse modules/symbols; falls back to module+offset or raw address on failure.
// - Purpose: Use existing R0 KTHREAD fields to display auxiliary information about kernel stack boundaries.
// ============================================================

#include "../Theme.h"
#include "../ui/UiSupport.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/log/Log.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace
{
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(
        HANDLE,
        THREADINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    struct ThreadBasicInformationNative
    {
        NTSTATUS exitStatus = 0;
        PVOID tebBaseAddress = nullptr;
        CLIENT_ID clientId{};
        ULONG_PTR affinityMask = 0;
        LONG priority = 0;
        LONG basePriority = 0;
    };

    // formatHex purpose: Unified formatting of 64-bit addresses.
    // Parameter value: the numeric value.
    // Parameter zeroAsUnavailable: whether to display 0 as Unavailable.
    // Returns: Formatted text.
    QString formatHex(const std::uint64_t value, const bool zeroAsUnavailable = false)
    {
        if (zeroAsUnavailable && value == 0)
        {
            return QStringLiteral("Unavailable");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // buildOpaqueDialogStyle: Overrides parent transparent styles to ensure stack window readability.
    // Parameter objectName: window objectName.
    // Return: QSS.
    QString buildOpaqueDialogStyle(const QString& objectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(objectName);
    }

    // queryThreadBasicInfo: Queries TEB and ClientId via NtQueryInformationThread.
    // Parameter threadHandle: Thread handle.
    // Parameter target: Target to be completed.
    // Parameter diagnosticOut: Append diagnostics.
    // Returns: true if the query succeeds.
    bool queryThreadBasicInfo(HANDLE threadHandle, ThreadStackTarget& target, QStringList& diagnosticOut)
    {
        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            diagnosticOut << QStringLiteral("ntdll unavailable");
            return false;
        }

        auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(
            ::GetProcAddress(ntdllModule, "NtQueryInformationThread"));
        if (ntQueryInformationThread == nullptr)
        {
            diagnosticOut << QStringLiteral("NtQueryInformationThread unavailable");
            return false;
        }

        ThreadBasicInformationNative basicInfo{};
        const NTSTATUS kStatus = ntQueryInformationThread(
            threadHandle,
            static_cast<THREADINFOCLASS>(0),
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (kStatus < 0)
        {
            diagnosticOut << QStringLiteral("ThreadBasicInformation failed 0x%1")
                .arg(static_cast<quint32>(kStatus), 8, 16, QChar('0')).toUpper();
            return false;
        }

        if (target.tebBaseAddress == 0)
        {
            target.tebBaseAddress = reinterpret_cast<std::uint64_t>(basicInfo.tebBaseAddress);
        }
        return true;
    }

    // readUserStackLimitsFromTeb: Reads user stack boundaries from the remote TEB.NT_TIB.
    // Parameter processHandle: Process handle.
    // Parameter target: Target to be completed.
    // Parameter diagnosticOut: Append diagnostics.
    // Returns: true if reading succeeds.
    bool readUserStackLimitsFromTeb(HANDLE processHandle, ThreadStackTarget& target, QStringList& diagnosticOut)
    {
        if (processHandle == nullptr || target.tebBaseAddress == 0)
        {
            return false;
        }

        NT_TIB tib{};
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(target.tebBaseAddress),
            &tib,
            sizeof(tib),
            &bytesRead);
        if (kReadOk == FALSE || bytesRead < sizeof(PVOID) * 2)
        {
            diagnosticOut << QStringLiteral("Read TEB stack limits failed %1").arg(::GetLastError());
            return false;
        }

        if (target.userStackBase == 0)
        {
            target.userStackBase = reinterpret_cast<std::uint64_t>(tib.StackBase);
        }
        if (target.userStackLimit == 0)
        {
            target.userStackLimit = reinterpret_cast<std::uint64_t>(tib.StackLimit);
        }
        return true;
    }

    // queryModuleNameForAddress: Queries the module name for the address using Psapi.
    // Parameter processHandle: Process handle.
    // Parameter address: Instruction address.
    // Parameter moduleBaseOut: receives the module base address.
    // Return: Module name; on failure, return empty.
    QString queryModuleNameForAddress(HANDLE processHandle, const std::uint64_t address, std::uint64_t* moduleBaseOut)
    {
        if (moduleBaseOut != nullptr)
        {
            *moduleBaseOut = 0;
        }
        if (processHandle == nullptr || address == 0)
        {
            return QString();
        }

        HMODULE moduleHandle = nullptr;
        DWORD neededBytes = 0;
        if (::EnumProcessModules(processHandle, &moduleHandle, sizeof(moduleHandle), &neededBytes) == FALSE)
        {
            return QString();
        }

        const int kModuleCount = static_cast<int>(neededBytes / sizeof(HMODULE));
        if (kModuleCount <= 0)
        {
            return QString();
        }

        std::vector<HMODULE> modules(static_cast<std::size_t>(kModuleCount));
        if (::EnumProcessModules(processHandle, modules.data(), neededBytes, &neededBytes) == FALSE)
        {
            return QString();
        }

        for (HMODULE currentModule : modules)
        {
            MODULEINFO moduleInfo{};
            if (::GetModuleInformation(processHandle, currentModule, &moduleInfo, sizeof(moduleInfo)) == FALSE)
            {
                continue;
            }

            const auto kBase = reinterpret_cast<std::uint64_t>(moduleInfo.lpBaseOfDll);
            const auto kEnd = kBase + static_cast<std::uint64_t>(moduleInfo.SizeOfImage);
            if (address < kBase || address >= kEnd)
            {
                continue;
            }

            wchar_t moduleName[MAX_PATH] = {};
            const DWORD kChars = ::GetModuleBaseNameW(
                processHandle,
                currentModule,
                moduleName,
                static_cast<DWORD>(std::size(moduleName)));
            if (moduleBaseOut != nullptr)
            {
                *moduleBaseOut = kBase;
            }
            return kChars > 0
                ? QString::fromWCharArray(moduleName, static_cast<int>(kChars))
                : QStringLiteral("module+0x%1").arg(static_cast<qulonglong>(address - kBase), 0, 16).toUpper();
        }

        return QString();
    }

    // symbolPathText purpose: Construct the DbgHelp symbol path for this process.
    // Parameters: None.
    // Returns: Symbol path, defaulting to include local cache and Microsoft symbol server.
    QString symbolPathText()
    {
        return QStringLiteral("srv*%TEMP%\\KswordSymbols*https://msdl.microsoft.com/download/symbols");
    }

    // initializeSymbols: Initializes the DbgHelp symbol session.
    // Parameter processHandle: handle to the target process.
    // Parameter diagnosticOut: Append diagnostics.
    // Returns: true if initialization was successful.
    bool initializeSymbols(HANDLE processHandle, QStringList& diagnosticOut)
    {
        if (processHandle == nullptr)
        {
            return false;
        }

        ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
        const std::wstring kPath = symbolPathText().toStdWString();
        if (::SymInitializeW(processHandle, kPath.c_str(), TRUE) == FALSE)
        {
            diagnosticOut << QStringLiteral("SymInitialize failed %1").arg(::GetLastError());
            return false;
        }
        return true;
    }

    // resolveSymbol: Resolves the symbol name and offset for a single address.
    // Parameter processHandle: handle to the target process.
    // Parameter address: The address.
    // Parameter displacementOut: receives the offset.
    // Return: Symbol name; on failure, return empty.
    QString resolveSymbol(HANDLE processHandle, const std::uint64_t address, std::uint64_t* displacementOut)
    {
        if (displacementOut != nullptr)
        {
            *displacementOut = 0;
        }
        if (processHandle == nullptr || address == 0)
        {
            return QString();
        }

        constexpr std::size_t kSymbolBufferSize = sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t));
        alignas(SYMBOL_INFOW) std::array<unsigned char, kSymbolBufferSize> symbolBuffer{};
        auto* symbolInfo = reinterpret_cast<SYMBOL_INFOW*>(symbolBuffer.data());
        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbolInfo->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (::SymFromAddrW(processHandle, static_cast<DWORD64>(address), &displacement, symbolInfo) == FALSE)
        {
            return QString();
        }

        if (displacementOut != nullptr)
        {
            *displacementOut = static_cast<std::uint64_t>(displacement);
        }
        return QString::fromWCharArray(symbolInfo->Name, static_cast<int>(symbolInfo->NameLen));
    }

    // captureThreadStack purpose: Execute actual stack capture and parsing.
    // Parameter inputTarget: Target thread.
    // Return: Capture result.
    ThreadStackWindow::CaptureResult captureThreadStack(const ThreadStackTarget& inputTarget)
    {
        ThreadStackWindow::CaptureResult result{};
        result.enrichedTarget = inputTarget;
        QStringList diagnosticLines;
        const auto kBeginTime = std::chrono::steady_clock::now();

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            inputTarget.processId);
        if (processHandle == nullptr)
        {
            result.diagnosticText = QStringLiteral("OpenProcess failed %1").arg(::GetLastError());
            return result;
        }

        HANDLE threadHandle = ::OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            FALSE,
            inputTarget.threadId);
        if (threadHandle == nullptr)
        {
            result.diagnosticText = QStringLiteral("OpenThread failed %1").arg(::GetLastError());
            ::CloseHandle(processHandle);
            return result;
        }

        (void)queryThreadBasicInfo(threadHandle, result.enrichedTarget, diagnosticLines);
        (void)readUserStackLimitsFromTeb(processHandle, result.enrichedTarget, diagnosticLines);

        const bool kSymbolsReady = initializeSymbols(processHandle, diagnosticLines);
        DWORD suspendResult = ::SuspendThread(threadHandle);
        if (suspendResult == static_cast<DWORD>(-1))
        {
            result.diagnosticText = QStringLiteral("SuspendThread failed %1").arg(::GetLastError());
            if (kSymbolsReady)
            {
                ::SymCleanup(processHandle);
            }
            ::CloseHandle(threadHandle);
            ::CloseHandle(processHandle);
            return result;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (::GetThreadContext(threadHandle, &context) == FALSE)
        {
            diagnosticLines << QStringLiteral("GetThreadContext failed %1").arg(::GetLastError());
            (void)::ResumeThread(threadHandle);
            if (kSymbolsReady)
            {
                ::SymCleanup(processHandle);
            }
            ::CloseHandle(threadHandle);
            ::CloseHandle(processHandle);
            result.diagnosticText = diagnosticLines.join(QStringLiteral(" | "));
            return result;
        }

        STACKFRAME64 stackFrame{};
        DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#if defined(_M_X64)
        machineType = IMAGE_FILE_MACHINE_AMD64;
        stackFrame.AddrPC.Offset = context.Rip;
        stackFrame.AddrPC.Mode = AddrModeFlat;
        stackFrame.AddrFrame.Offset = context.Rbp;
        stackFrame.AddrFrame.Mode = AddrModeFlat;
        stackFrame.AddrStack.Offset = context.Rsp;
        stackFrame.AddrStack.Mode = AddrModeFlat;
#elif defined(_M_IX86)
        machineType = IMAGE_FILE_MACHINE_I386;
        stackFrame.AddrPC.Offset = context.Eip;
        stackFrame.AddrPC.Mode = AddrModeFlat;
        stackFrame.AddrFrame.Offset = context.Ebp;
        stackFrame.AddrFrame.Mode = AddrModeFlat;
        stackFrame.AddrStack.Offset = context.Esp;
        stackFrame.AddrStack.Mode = AddrModeFlat;
#else
        diagnosticLines << QStringLiteral("unsupported architecture");
#endif

        constexpr int kMaxFrames = 128;
        for (int frameIndex = 0; frameIndex < kMaxFrames; ++frameIndex)
        {
            const BOOL kWalkOk = ::StackWalk64(
                machineType,
                processHandle,
                threadHandle,
                &stackFrame,
                &context,
                nullptr,
                SymFunctionTableAccess64,
                SymGetModuleBase64,
                nullptr);
            if (kWalkOk == FALSE || stackFrame.AddrPC.Offset == 0)
            {
                if (frameIndex == 0)
                {
                    diagnosticLines << QStringLiteral("StackWalk64 stopped %1").arg(::GetLastError());
                }
                break;
            }

            ThreadStackWindow::StackFrameRow row{};
            row.index = static_cast<std::uint32_t>(result.frames.size());
            row.address = static_cast<std::uint64_t>(stackFrame.AddrPC.Offset);
            std::uint64_t moduleBase = 0;
            row.moduleName = queryModuleNameForAddress(processHandle, row.address, &moduleBase);
            row.symbolName = kSymbolsReady ? resolveSymbol(processHandle, row.address, &row.displacement) : QString();
            if (row.symbolName.isEmpty())
            {
                row.symbolName = moduleBase != 0
                    ? QStringLiteral("%1+%2").arg(row.moduleName, formatHex(row.address - moduleBase))
                    : QStringLiteral("<no symbol>");
            }
            row.modeText = QStringLiteral("User");
            result.frames.push_back(std::move(row));
        }

        (void)::ResumeThread(threadHandle);
        if (kSymbolsReady)
        {
            ::SymCleanup(processHandle);
        }
        ::CloseHandle(threadHandle);
        ::CloseHandle(processHandle);

        result.ok = !result.frames.empty();
        result.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        result.diagnosticText = diagnosticLines.join(QStringLiteral(" | "));
        return result;
    }

    // columnIndex: Converts the column enum to an integer.
    int columnIndex(const ThreadStackWindow::StackColumn column)
    {
        return static_cast<int>(column);
    }
}

ThreadStackWindow::ThreadStackWindow(const ThreadStackTarget& target, QWidget* parent)
    : QDialog(parent)
    , target_(target)
{
    initializeUi();
    initializeConnections();
    requestAsyncCapture(true);
}

void ThreadStackWindow::initializeUi()
{
    setObjectName(QStringLiteral("ThreadStackWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(buildOpaqueDialogStyle(objectName()));
    setWindowTitle(QStringLiteral("线程调用栈 - TID %1").arg(target_.threadId));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parentWidget(),
        QSize(980, 620),
        QSize(720, 480));

    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(6);

    toolbarLayout_ = new QHBoxLayout();
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(QStringLiteral("重新捕获调用栈"));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    copyButton_ = new QPushButton(QIcon(":/Icon/process_copy_row.svg"), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(copyButton_);
    copyButton_->setToolTip(QStringLiteral("复制全部调用栈"));
    copyButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    targetLabel_ = new QLabel(this);
    targetLabel_->setMinimumWidth(0);
    targetLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    targetLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    targetLabel_->setText(QStringLiteral("PID=%1 TID=%2 进程=%3 Start=%4 Win32Start=%5")
        .arg(target_.processId)
        .arg(target_.threadId)
        .arg(target_.processName.trimmed().isEmpty() ? QStringLiteral("Unknown") : target_.processName)
        .arg(formatHex(target_.startAddress, true))
        .arg(formatHex(target_.win32StartAddress, true)));
    targetLabel_->setToolTip(targetLabel_->text());
    targetLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(copyButton_);
    toolbarLayout_->addWidget(targetLabel_, 1);

    boundaryLabel_ = new QLabel(this);
    boundaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    boundaryLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    statusLabel_ = new QLabel(QStringLiteral("● 等待捕获"), this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    frameTable_ = new QTreeWidget(this);
    frameTable_->setColumnCount(columnIndex(StackColumn::kCount));
    frameTable_->setHeaderLabels(QStringList{
        QStringLiteral("#"),
        QStringLiteral("地址"),
        QStringLiteral("模块"),
        QStringLiteral("符号"),
        QStringLiteral("偏移"),
        QStringLiteral("模式")
        });
    frameTable_->setRootIsDecorated(false);
    frameTable_->setItemsExpandable(false);
    frameTable_->setAlternatingRowColors(true);
    frameTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    frameTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    frameTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    frameTable_->setSortingEnabled(false);
    frameTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    if (frameTable_->header() != nullptr)
    {
        frameTable_->header()->setSectionResizeMode(QHeaderView::Interactive);
        frameTable_->header()->setStretchLastSection(true);
    }

    rootLayout_->addLayout(toolbarLayout_);
    rootLayout_->addWidget(boundaryLabel_);
    rootLayout_->addWidget(statusLabel_);
    rootLayout_->addWidget(frameTable_, 1);
    updateBoundaryText();
    applyAdaptiveColumnWidths();
}

void ThreadStackWindow::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestAsyncCapture(true);
        });
    connect(copyButton_, &QPushButton::clicked, this, [this]()
        {
            copyAllFrames();
        });
    connect(frameTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& position)
        {
            showFrameContextMenu(position);
        });
}

void ThreadStackWindow::requestAsyncCapture(const bool forceRefresh)
{
    if (captureInProgress_)
    {
        if (forceRefresh)
        {
            capturePending_ = true;
        }
        return;
    }

    captureInProgress_ = true;
    const std::uint64_t kTicket = ++captureTicket_;
    statusLabel_->setText(QStringLiteral("● 正在捕获线程调用栈..."));
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }

    if (captureProgressPid_ == 0)
    {
        captureProgressPid_ = kPro.addReusable(this, "线程调用栈", "捕获调用栈");
    }
    kPro.set(captureProgressPid_, "挂起线程并执行 StackWalk64", 0, 25.0f);

    const ThreadStackTarget kTargetSnapshot = target_;
    QPointer<ThreadStackWindow> guardThis(this);
    auto* task = QRunnable::create([guardThis, kTicket, kTargetSnapshot]()
        {
            CaptureResult result = captureThreadStack(kTargetSnapshot);
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicket, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyCaptureResult(kTicket, result);
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ThreadStackWindow::applyCaptureResult(const std::uint64_t ticket, const CaptureResult& result)
{
    if (ticket < captureTicket_)
    {
        return;
    }

    QPointer<ThreadStackWindow> guardThis(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("thread-stack-capture-apply"),
            {frameTable_},
            [guardThis, ticket, result]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyCaptureResult(ticket, result);
                }
            }))
    {
        return;
    }

    captureInProgress_ = false;
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(true);
    }

    target_ = result.enrichedTarget;
    frames_ = result.frames;
    updateBoundaryText();
    rebuildFrameTable();

    QString statusText = QStringLiteral("● 捕获完成 %1 ms | 帧数 %2")
        .arg(result.elapsedMs)
        .arg(frames_.size());
    if (!result.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        KLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[ThreadStackWindow] capture completed with diagnostics, pid="
            << target_.processId
            << ", tid=" << target_.threadId
            << ", frameCount=" << frames_.size()
            << ", detail=" << result.diagnosticText.toStdString()
            << eol;
    }
    statusLabel_->setText(statusText);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg((result.ok ? ksword_theme::successColor() : ksword_theme::warningColor()).name(QColor::HexRgb)));
    kPro.set(captureProgressPid_, "线程调用栈捕获完成", 0, 100.0f);

    if (capturePending_)
    {
        capturePending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncCapture(true);
            }, Qt::QueuedConnection);
    }
}

void ThreadStackWindow::rebuildFrameTable()
{
    if (frameTable_ == nullptr)
    {
        return;
    }

    frameTable_->clear();
    for (const StackFrameRow& frame : frames_)
    {
        auto* item = new QTreeWidgetItem();
        item->setText(columnIndex(StackColumn::kIndex), QString::number(frame.index));
        item->setText(columnIndex(StackColumn::kAddress), formatHex(frame.address));
        item->setText(columnIndex(StackColumn::kModule), frame.moduleName.trimmed().isEmpty() ? QStringLiteral("-") : frame.moduleName);
        item->setText(columnIndex(StackColumn::kSymbol), frame.symbolName);
        item->setText(columnIndex(StackColumn::kOffset), formatHex(frame.displacement));
        item->setText(columnIndex(StackColumn::kMode), frame.modeText);
        frameTable_->addTopLevelItem(item);
    }
    if (frameTable_->topLevelItemCount() > 0)
    {
        frameTable_->setCurrentItem(frameTable_->topLevelItem(0));
    }
    applyAdaptiveColumnWidths();
}

void ThreadStackWindow::updateBoundaryText()
{
    if (boundaryLabel_ == nullptr)
    {
        return;
    }

    boundaryLabel_->setText(QStringLiteral("UserStack=%1 - %2 | TEB=%3 | R0 KernelStack=%4 StackBase=%5 StackLimit=%6 Initial=%7 | R0Status=%8 Cap=0x%9")
        .arg(formatHex(target_.userStackLimit, true))
        .arg(formatHex(target_.userStackBase, true))
        .arg(formatHex(target_.tebBaseAddress, true))
        .arg(formatHex(target_.r0KernelStack, true))
        .arg(formatHex(target_.r0StackBase, true))
        .arg(formatHex(target_.r0StackLimit, true))
        .arg(formatHex(target_.r0InitialStack, true))
        .arg(target_.r0ThreadStatus)
        .arg(static_cast<qulonglong>(target_.r0CapabilityMask), 0, 16));
}

void ThreadStackWindow::copyAllFrames()
{
    QStringList lines;
    lines << QStringLiteral("#\tAddress\tModule\tSymbol\tOffset\tMode");
    for (const StackFrameRow& frame : frames_)
    {
        lines << QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6")
            .arg(frame.index)
            .arg(formatHex(frame.address))
            .arg(frame.moduleName)
            .arg(frame.symbolName)
            .arg(formatHex(frame.displacement))
            .arg(frame.modeText);
    }
    QApplication::clipboard()->setText(lines.join('\n'));
}

void ThreadStackWindow::copyCurrentFrame()
{
    if (frameTable_ == nullptr || frameTable_->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int column = 0; column < columnIndex(StackColumn::kCount); ++column)
    {
        fields.push_back(frameTable_->currentItem()->text(column));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void ThreadStackWindow::showFrameContextMenu(const QPoint& localPosition)
{
    if (frameTable_ == nullptr || frameTable_->itemAt(localPosition) == nullptr)
    {
        return;
    }
    frameTable_->setCurrentItem(frameTable_->itemAt(localPosition));

    QMenu menu(this);
    // Call stack menu style:
    // - Input: Context menu for the current frame table;
    // - Processing: Explicitly apply the theme's opaque style so menu text remains readable inside transparent parent containers;
    // - Return: None. Only affects the copy menu display.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyFrameAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制当前帧"));
    QAction* copyAllAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制全部调用栈"));

    QAction* selectedAction = menu.exec(frameTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyFrameAction)
    {
        copyCurrentFrame();
    }
    else if (selectedAction == copyAllAction)
    {
        copyAllFrames();
    }
}

void ThreadStackWindow::resizeEvent(QResizeEvent* event)
{
    QDialog::resizeEvent(event);
    applyAdaptiveColumnWidths();
}

void ThreadStackWindow::applyAdaptiveColumnWidths()
{
    if (frameTable_ == nullptr)
    {
        return;
    }

    const int kViewportWidth = frameTable_->viewport()->width();
    const int kIndexWidth = 60;
    const int kAddressWidth = 150;
    const int kModuleWidth = 170;
    const int kOffsetWidth = 110;
    const int kModeWidth = 100;
    const int kSymbolWidth = std::max(320, kViewportWidth - kIndexWidth - kAddressWidth - kModuleWidth - kOffsetWidth - kModeWidth - 24);

    frameTable_->setColumnWidth(columnIndex(StackColumn::kIndex), kIndexWidth);
    frameTable_->setColumnWidth(columnIndex(StackColumn::kAddress), kAddressWidth);
    frameTable_->setColumnWidth(columnIndex(StackColumn::kModule), kModuleWidth);
    frameTable_->setColumnWidth(columnIndex(StackColumn::kSymbol), kSymbolWidth);
    frameTable_->setColumnWidth(columnIndex(StackColumn::kOffset), kOffsetWidth);
    frameTable_->setColumnWidth(columnIndex(StackColumn::kMode), kModeWidth);
}
