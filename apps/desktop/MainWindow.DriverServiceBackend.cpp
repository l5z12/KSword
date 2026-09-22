#include "MainWindow.h"

#include <QCoreApplication>
#include <QWidget>
#include <QThreadPool>
#include <QMetaObject>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "../../shared/KswordArkStartupProtocol.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <functional>
#include <utility>
#include <cstring>
#include <TlHelp32.h>

#include "MainWindow.DriverServiceBackendSupport.h"
#include "MainWindow.DriverServiceConstants.h"

namespace ksword::ui::main_window
{
    // r0StartupStageText:
    // - Input: The KswordArkStartStage stage number for driver writing to Parameters;
    // - Processing: Map to stage names that users can directly relay to developers;
    // - Returns: Stage name; returns an empty string for unknown stages.
    QString r0StartupStageText(const DWORD stageValue)
    {
        switch (stageValue)
        {
        case kKswordArkStartStageEnteredDriverEntry:
            return QStringLiteral("进入驱动入口");
        case kKswordArkStartStageOsVersionCheck:
            return QStringLiteral("系统版本检查");
        case kKswordArkStartStageWdfDriverCreate:
            return QStringLiteral("创建 WDF 驱动对象");
        case kKswordArkStartStageControlInitAllocate:
            return QStringLiteral("分配控制设备初始化结构");
        case kKswordArkStartStageDeviceAssignName:
            return QStringLiteral("指派控制设备名");
        case kKswordArkStartStageDeviceCreate:
            return QStringLiteral("创建控制设备");
        case kKswordArkStartStageLogChannel:
            return QStringLiteral("初始化日志通道");
        case kKswordArkStartStageDebugOutput:
            return QStringLiteral("初始化内核调试输出缓冲");
        case kKswordArkStartStageSymbolicLink:
            return QStringLiteral("创建符号链接");
        case kKswordArkStartStageDefaultQueue:
            return QStringLiteral("创建默认 I/O 队列");
        case kKswordArkStartStageCallbackRuntimeAllocate:
            return QStringLiteral("分配回调运行时");
        case kKswordArkStartStageCallbackWaitQueue:
            return QStringLiteral("创建用户询问队列");
        case kKswordArkStartStageRegistryCallback:
            return QStringLiteral("注册注册表回调");
        case kKswordArkStartStageProcessCallback:
            return QStringLiteral("注册进程回调");
        case kKswordArkStartStageThreadCallback:
            return QStringLiteral("注册线程回调");
        case kKswordArkStartStageImageCallback:
            return QStringLiteral("注册映像加载回调");
        case kKswordArkStartStageObjectCallback:
            return QStringLiteral("注册对象句柄回调");
        case kKswordArkStartStageControlDevicePublish:
            return QStringLiteral("发布控制设备");
        case kKswordArkStartStageReady:
            return QStringLiteral("启动完成");
        default:
            return QString();
        }
    }

    // describeR0StartupBreadcrumb:
    // - Input: None; directly reads startup records left by the driver under Services\KswordARK\Parameters;
    // - Processing: Combine the phase number with the original NTSTATUS into a single string ready to paste into an issue.
    // - Returns: diagnostic text; if no records exist, explicitly concludes 'Driver entry was not entered'.
    //
    // SCM only folds kernel failures into Win32 31, unable to distinguish between WDF queue failures and kernel callback
    // registration failures. This logging is the only way to restore 31 to the specific stage and original status.
    QString describeR0StartupBreadcrumb()
    {
        HKEY parametersKey = nullptr;
        const LSTATUS kOpenResult = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            KSWORD_ARK_STARTUP_PARAMETERS_PATH,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &parametersKey);
        if (kOpenResult != ERROR_SUCCESS)
        {
            return QStringLiteral("驱动未留下启动记录，说明本次加载没有进入驱动入口，应优先检查 KswordARK.sys 的签名、Code Integrity 策略与系统版本。");
        }

        const auto kReadDword = [parametersKey](const wchar_t* const valueName, DWORD& valueOut) {
            DWORD valueType = 0;
            DWORD valueData = 0;
            DWORD valueBytes = static_cast<DWORD>(sizeof(valueData));
            const LSTATUS kQueryResult = ::RegQueryValueExW(
                parametersKey,
                valueName,
                nullptr,
                &valueType,
                reinterpret_cast<LPBYTE>(&valueData),
                &valueBytes);
            if (kQueryResult != ERROR_SUCCESS || valueType != REG_DWORD)
            {
                return false;
            }
            valueOut = valueData;
            return true;
        };

        DWORD stageValue = 0;
        DWORD statusValue = 0;
        const bool kHasStage = kReadDword(KSWORD_ARK_STARTUP_VALUE_STAGE, stageValue);
        const bool kHasStatus = kReadDword(KSWORD_ARK_STARTUP_VALUE_STATUS, statusValue);

        wchar_t buildBuffer[128] = {};
        DWORD buildType = 0;
        DWORD buildBytes = static_cast<DWORD>(sizeof(buildBuffer));
        QString buildText;
        if (::RegQueryValueExW(
            parametersKey,
            KSWORD_ARK_STARTUP_VALUE_BUILD,
            nullptr,
            &buildType,
            reinterpret_cast<LPBYTE>(buildBuffer),
            &buildBytes) == ERROR_SUCCESS && buildType == REG_SZ)
        {
            buildBuffer[std::size(buildBuffer) - 1] = L'\0';
            buildText = QString::fromWCharArray(buildBuffer);
        }

        DWORD osBuildValue = 0;
        const bool kHasOsBuild = kReadDword(KSWORD_ARK_STARTUP_VALUE_OS_BUILD, osBuildValue);
        ::RegCloseKey(parametersKey);

        if (!kHasStage)
        {
            return QStringLiteral("驱动留下的启动记录不完整，无法确定失败阶段。");
        }

        const QString kStageName = r0StartupStageText(stageValue);
        QString detailText = QStringLiteral("驱动最后到达的启动阶段：%1（stage=%2）")
            .arg(kStageName.isEmpty() ? QStringLiteral("未知阶段") : kStageName)
            .arg(stageValue);
        if (kHasStatus)
        {
            detailText += QStringLiteral("\n驱动内部状态：0x%1")
                .arg(statusValue, 8, 16, QLatin1Char('0'));
        }
        if (!buildText.isEmpty())
        {
            detailText += QStringLiteral("\n驱动构建：%1").arg(buildText);
        }
        if (kHasOsBuild && osBuildValue != 0)
        {
            detailText += QStringLiteral("\n系统内部版本：%1").arg(osBuildValue);
        }
        return detailText;
    }

    // sharedR0DriverLogEvent:
    // - Unify the GUID carrying the 'driver log forwarding' link within the R3 process.
    // - Satisfy the requirement that all driver output uses the same KLogEvent.
    KLogEvent& sharedR0DriverLogEvent()
    {
        static KLogEvent sharedEvent;
        return sharedEvent;
    }

    // startsWithLiteral:
    // - Check if the text starts with a fixed prefix (case-sensitive);
    // - Used exclusively for log level tag parsing.
    bool startsWithLiteral(const std::string& text, const char* prefixText)
    {
        if (prefixText == nullptr)
        {
            return false;
        }

        const std::size_t kPrefixLength = std::strlen(prefixText);
        if (text.size() < kPrefixLength)
        {
            return false;
        }
        return text.compare(0, kPrefixLength, prefixText) == 0;
    }

    // serviceStateToText:
    // - Input: Win32 service state enumeration value;
    // - Processing: Map raw state codes to stable debug text.
    // - Return: Status name used for UI and log display.
    QString serviceStateToText(const DWORD serviceState);

    QString serviceStateToText(const DWORD serviceState)
    {
        switch (serviceState)
        {
        case SERVICE_STOPPED: return QStringLiteral("STOPPED");
        case SERVICE_START_PENDING: return QStringLiteral("START_PENDING");
        case SERVICE_STOP_PENDING: return QStringLiteral("STOP_PENDING");
        case SERVICE_RUNNING: return QStringLiteral("RUNNING");
        case SERVICE_CONTINUE_PENDING: return QStringLiteral("CONTINUE_PENDING");
        case SERVICE_PAUSE_PENDING: return QStringLiteral("PAUSE_PENDING");
        case SERVICE_PAUSED: return QStringLiteral("PAUSED");
        default: return QStringLiteral("UNKNOWN");
        }
    }

    bool queryServiceStatus(const SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& statusOut, DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        DWORD bytesNeeded = 0;
        if (::QueryServiceStatusEx(
            serviceHandle,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&statusOut),
            sizeof(statusOut),
            &bytesNeeded) == FALSE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        return true;
    }

    bool waitServiceState(
        const SC_HANDLE serviceHandle,
        const DWORD targetState,
        const DWORD timeoutMs,
        SERVICE_STATUS_PROCESS& latestStatusOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        const ULONGLONG kDeadline = ::GetTickCount64() + timeoutMs;
        while (true)
        {
            if (!queryServiceStatus(serviceHandle, latestStatusOut, errorCodeOut))
            {
                return false;
            }
            if (latestStatusOut.dwCurrentState == targetState)
            {
                return true;
            }
            if (::GetTickCount64() >= kDeadline)
            {
                return false;
            }

            DWORD waitMs = latestStatusOut.dwWaitHint / 10;
            if (waitMs < 120)
            {
                waitMs = 120;
            }
            if (waitMs > 500)
            {
                waitMs = 500;
            }
            ::Sleep(waitMs);
        }
    }

    // buildServiceWaitDetailText:
    // - Input: SERVICE_STATUS_PROCESS returned by SCM and total wait duration;
    // - Processing: Aggregate fields required for troubleshooting STOP_PENDING/START_PENDING into stable Chinese text.
    // - Returns: QString ready to be placed in the R0 error dialog's "Details" field.
    QString buildServiceWaitDetailText(
        const SERVICE_STATUS_PROCESS& status,
        const DWORD timeoutMs)
    {
        return QStringLiteral("当前状态：%1\nCheckPoint：%2\nWaitHint：%3 ms\n等待上限：%4 ms\nWin32ExitCode：%5\nServiceSpecificExitCode：%6")
            .arg(serviceStateToText(status.dwCurrentState))
            .arg(status.dwCheckPoint)
            .arg(status.dwWaitHint)
            .arg(timeoutMs)
            .arg(status.dwWin32ExitCode)
            .arg(status.dwServiceSpecificExitCode);
    }

    bool isRunningLikeServiceState(const DWORD serviceState)
    {
        return serviceState == SERVICE_RUNNING ||
            serviceState == SERVICE_START_PENDING ||
            serviceState == SERVICE_CONTINUE_PENDING;
    }

    // enableCurrentProcessPrivilege:
    // - Attempt to enable the specified privilege (e.g., SeLoadDriverPrivilege) for the current process;
    // - Prepare privileges before calling NtUnloadDriver.
    bool enableCurrentProcessPrivilege(const wchar_t* const privilegeName, DWORD* const errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            0,
            nullptr,
            nullptr) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            ::CloseHandle(tokenHandle);
            return false;
        }

        const DWORD kAdjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        if (kAdjustError != ERROR_SUCCESS)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = kAdjustError;
            }
            return false;
        }

        return true;
    }

    // tryNtUnloadDriverByServiceName:
    // - Attempt to unload the driver associated with the specified service name directly via NtUnloadDriver;
    // - Returns true if NTSTATUS is success (>=0).
    bool tryNtUnloadDriverByServiceName(
        const wchar_t* const serviceName,
        long* const ntStatusOut)
    {
        if (ntStatusOut != nullptr)
        {
            *ntStatusOut = 0L;
        }
        if (serviceName == nullptr || serviceName[0] == L'\0')
        {
            return false;
        }

        const HMODULE kNtdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (kNtdllModule == nullptr)
        {
            return false;
        }

        using NtUnloadDriverFn = long (NTAPI*)(PUNICODE_STRING);
        const NtUnloadDriverFn kNtUnloadDriverFn =
            reinterpret_cast<NtUnloadDriverFn>(::GetProcAddress(kNtdllModule, "NtUnloadDriver"));
        if (kNtUnloadDriverFn == nullptr)
        {
            return false;
        }

        std::wstring registryServicePath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        registryServicePath += serviceName;

        UNICODE_STRING registryPathUnicode{};
        registryPathUnicode.Buffer = const_cast<PWSTR>(registryServicePath.c_str());
        registryPathUnicode.Length = static_cast<USHORT>(registryServicePath.size() * sizeof(wchar_t));
        registryPathUnicode.MaximumLength = registryPathUnicode.Length;

        const long kNtStatus = kNtUnloadDriverFn(&registryPathUnicode);
        if (ntStatusOut != nullptr)
        {
            *ntStatusOut = kNtStatus;
        }
        return kNtStatus >= 0;
    }

    // g_r0ServiceOperationInFlight:
    // - Inputs: None;
    // - Handling: After moving R0 start/stop to background execution, use a process-level latch to block concurrent SCM operations caused by repeated clicks;
    //         mainWindow is a single-instance window; file-level static state here covers all entry points.
    // - Returns: void; true indicates a start/stop task is already running in the thread pool.
    std::atomic_bool gR0ServiceOperationInFlight{ false };

    // executeR0ServiceStopOnWorker:
    // - Input: None; the service name is fixed to kR0DriverServiceName;
    // - Handling: Perform the entire SCM connection / ControlService / wait for SERVICE_STOPPED /
    //         DeleteService sequence on any thread without touching any QWidget or reading/writing mainWindow members.
    // - Returns: pure value-type conclusion; failure reason described by stageText / errorCode / detailText.
    R0ServiceOperationOutcome executeR0ServiceStopOnWorker()
    {
        R0ServiceOperationOutcome operationOutcome;

        ScopedServiceHandle scmHandle(::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT));
        if (!scmHandle.isValid())
        {
            operationOutcome.errorCode = ::GetLastError();
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：无法连接服务控制管理器。");
            return operationOutcome;
        }

        ScopedServiceHandle serviceHandle(::OpenServiceW(
            scmHandle.get(),
            kR0DriverServiceName,
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
        if (!serviceHandle.isValid())
        {
            const DWORD kOpenError = ::GetLastError();
            if (kOpenError == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.succeeded = true;
                operationOutcome.alreadyInTargetState = true;
                return operationOutcome;
            }
            operationOutcome.errorCode = kOpenError;
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：无法打开驱动服务。");
            return operationOutcome;
        }

        SERVICE_STATUS_PROCESS currentStatus{};
        DWORD queryError = ERROR_SUCCESS;
        if (!queryServiceStatus(serviceHandle.get(), currentStatus, queryError))
        {
            operationOutcome.errorCode = queryError;
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：读取驱动服务状态失败。");
            return operationOutcome;
        }

        if (currentStatus.dwCurrentState != SERVICE_STOPPED)
        {
            if (currentStatus.dwCurrentState != SERVICE_STOP_PENDING)
            {
                SERVICE_STATUS ignoredStatus{};
                if (::ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &ignoredStatus) == FALSE)
                {
                    const DWORD kStopError = ::GetLastError();
                    if (kStopError != ERROR_SERVICE_NOT_ACTIVE)
                    {
                        // On hitting 1052 (STOP control not accepted), fall back to the direct unload path via NtUnloadDriver.
                        if (kStopError == ERROR_INVALID_SERVICE_CONTROL)
                        {
                            DWORD privilegeError = ERROR_SUCCESS;
                            const bool kPrivilegeOk =
                                enableCurrentProcessPrivilege(SE_LOAD_DRIVER_NAME, &privilegeError);

                            long ntUnloadStatus = 0;
                            const bool kUnloadOk = tryNtUnloadDriverByServiceName(
                                kR0DriverServiceName,
                                &ntUnloadStatus);
                            if (!kUnloadOk)
                            {
                                operationOutcome.errorCode = kStopError;
                                operationOutcome.stageText =
                                    QStringLiteral("R0 卸载失败：ControlService 返回 1052，且 NtUnloadDriver 回退失败。");
                                operationOutcome.detailText =
                                    QStringLiteral("enablePrivilegeOk=%1, privilegeError=%2, ntUnloadStatus=0x%3")
                                    .arg(kPrivilegeOk ? QStringLiteral("true") : QStringLiteral("false"))
                                    .arg(privilegeError)
                                    .arg(static_cast<qulonglong>(static_cast<unsigned long>(ntUnloadStatus)), 8, 16, QChar('0'));
                                return operationOutcome;
                            }

                            operationOutcome.usedDirectNtUnloadFallback = true;
                            currentStatus.dwCurrentState = SERVICE_STOPPED;
                        }
                        else
                        {
                            operationOutcome.errorCode = kStopError;
                            operationOutcome.stageText = QStringLiteral("R0 卸载失败：停止驱动服务失败。");
                            return operationOutcome;
                        }
                    }
                }
            }

            if (!operationOutcome.usedDirectNtUnloadFallback)
            {
                SERVICE_STATUS_PROCESS latestStatus{};
                DWORD waitError = ERROR_SUCCESS;
                if (!waitServiceState(
                    serviceHandle.get(),
                    SERVICE_STOPPED,
                    kR0ServiceStopWaitTimeoutMs,
                    latestStatus,
                    waitError))
                {
                    if (waitError != ERROR_SUCCESS)
                    {
                        operationOutcome.errorCode = waitError;
                        operationOutcome.stageText = QStringLiteral("R0 卸载失败：等待服务停止时查询状态失败。");
                    }
                    else
                    {
                        operationOutcome.errorCode = ERROR_TIMEOUT;
                        operationOutcome.stageText = QStringLiteral("R0 卸载失败：等待服务停止超时。");
                        operationOutcome.detailText =
                            buildServiceWaitDetailText(latestStatus, kR0ServiceStopWaitTimeoutMs);
                    }
                    return operationOutcome;
                }
            }
        }

        if (::DeleteService(serviceHandle.get()) == FALSE)
        {
            const DWORD kDeleteError = ::GetLastError();
            if (kDeleteError != ERROR_SERVICE_MARKED_FOR_DELETE &&
                kDeleteError != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.errorCode = kDeleteError;
                operationOutcome.stageText = QStringLiteral("R0 卸载失败：删除驱动服务失败。");
                return operationOutcome;
            }
        }

        operationOutcome.succeeded = true;
        return operationOutcome;
    }

    // executeR0ServiceStartOnWorker:
    // - Input nativeDriverPath: Local path to KswordARK.sys verified to exist on the UI thread (passed by value to avoid cross-thread sharing);
    // - Handling: Perform the entire SCM connection / CreateService or ChangeServiceConfig /
    //         StartService / wait for SERVICE_RUNNING sequence on any thread without touching any QWidget.
    // - Return: Pure value-type conclusion; when startServiceCallFailed is true, the UI thread determines if it is a signature failure.
    R0ServiceOperationOutcome executeR0ServiceStartOnWorker(const QString& nativeDriverPath)
    {
        R0ServiceOperationOutcome operationOutcome;

        ScopedServiceHandle scmHandle(::OpenSCManagerW(
            nullptr,
            SERVICES_ACTIVE_DATABASE,
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        if (!scmHandle.isValid())
        {
            operationOutcome.errorCode = ::GetLastError();
            operationOutcome.stageText = QStringLiteral("R0 启动失败：无法连接服务控制管理器。");
            return operationOutcome;
        }

        ScopedServiceHandle serviceHandle(::OpenServiceW(
            scmHandle.get(),
            kR0DriverServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE));
        if (!serviceHandle.isValid())
        {
            const DWORD kOpenError = ::GetLastError();
            if (kOpenError != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.errorCode = kOpenError;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：无法打开已有驱动服务。");
                return operationOutcome;
            }

            const std::wstring kDriverPathWide = nativeDriverPath.toStdWString();
            serviceHandle.reset(::CreateServiceW(
                scmHandle.get(),
                kR0DriverServiceName,
                kR0DriverDisplayName,
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                kDriverPathWide.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr));
            if (!serviceHandle.isValid())
            {
                operationOutcome.errorCode = ::GetLastError();
                operationOutcome.stageText = QStringLiteral("R0 启动失败：创建驱动服务失败。");
                operationOutcome.detailText = QStringLiteral("驱动路径：%1").arg(nativeDriverPath);
                return operationOutcome;
            }
        }
        else
        {
            const std::wstring kDriverPathWide = nativeDriverPath.toStdWString();
            if (::ChangeServiceConfigW(
                serviceHandle.get(),
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                kDriverPathWide.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                kR0DriverDisplayName) == FALSE)
            {
                operationOutcome.errorCode = ::GetLastError();
                operationOutcome.stageText = QStringLiteral("R0 启动失败：更新驱动服务配置失败。");
                return operationOutcome;
            }
        }

        SERVICE_STATUS_PROCESS currentStatus{};
        DWORD queryError = ERROR_SUCCESS;
        if (!queryServiceStatus(serviceHandle.get(), currentStatus, queryError))
        {
            operationOutcome.errorCode = queryError;
            operationOutcome.stageText = QStringLiteral("R0 启动失败：读取服务状态失败。");
            return operationOutcome;
        }

        if (isRunningLikeServiceState(currentStatus.dwCurrentState))
        {
            operationOutcome.succeeded = true;
            operationOutcome.alreadyInTargetState = true;
            return operationOutcome;
        }

        if (::StartServiceW(serviceHandle.get(), 0, nullptr) == FALSE)
        {
            const DWORD kStartError = ::GetLastError();
            if (kStartError == ERROR_SERVICE_ALREADY_RUNNING)
            {
                operationOutcome.succeeded = true;
                operationOutcome.alreadyInTargetState = true;
                return operationOutcome;
            }

            // Signature/integrity check failures and ordinary startup failures share the same error code exit;
            // the UI thread determines which message to display using mainWindow::isR0DriverSignatureFailure.
            operationOutcome.errorCode = kStartError;
            operationOutcome.startServiceCallFailed = true;

            // SCM error codes do not distinguish failure causes on their own; driver-specific stage
            // records must be included so users can provide directly locatable information in issues.
            operationOutcome.stageText = QStringLiteral("R0 启动失败：驱动服务启动失败。");
            operationOutcome.detailText = QStringLiteral("驱动路径：%1\n%2")
                .arg(nativeDriverPath)
                .arg(describeR0StartupBreadcrumb());
            return operationOutcome;
        }

        SERVICE_STATUS_PROCESS latestStatus{};
        DWORD waitError = ERROR_SUCCESS;
        if (!waitServiceState(
            serviceHandle.get(),
            SERVICE_RUNNING,
            kR0ServiceStartWaitTimeoutMs,
            latestStatus,
            waitError))
        {
            if (waitError != ERROR_SUCCESS)
            {
                operationOutcome.errorCode = waitError;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：等待服务运行时查询状态失败。");
            }
            else
            {
                operationOutcome.errorCode = ERROR_TIMEOUT;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：等待驱动进入运行态超时。");
                operationOutcome.detailText =
                    QStringLiteral("当前状态：%1").arg(serviceStateToText(latestStatus.dwCurrentState));
            }
            return operationOutcome;
        }

        operationOutcome.succeeded = true;
        return operationOutcome;
    }

    // dispatchR0ServiceStopToWorker:
    // - Input completionCallback: Result handler executed on the UI thread after driver unloading.
    // - Processing: Offload the entire SCM stop/wait/delete sequence to the global thread pool, then return the value-type result to the UI thread upon completion.
    // - Returns: no return value; caller returns immediately, preventing UI freeze from ::Sleep polling in waitServiceState.
    void dispatchR0ServiceStopToWorker(
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback)
    {
        QThreadPool::globalInstance()->start(
            [completionCallback = std::move(completionCallback)]()
            {
                const R0ServiceOperationOutcome kOperationOutcome = executeR0ServiceStopOnWorker();
                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kAppInstance,
                    [completionCallback, kOperationOutcome]()
                    {
                        completionCallback(kOperationOutcome);
                    });
            });
    }

    // dispatchR0ServiceStartToWorker:
    // - Input nativeDriverPath: Verified existing driver file path; completionCallback: UI thread result processing callback;
    // - Processing: Offload the entire SCM create/start/wait-for-running sequence to the global thread pool, then push the value-type result back to the UI thread upon completion.
    // - Returns: No return value; the caller returns immediately, so the startup timeout limit no longer manifests as UI freezing.
    void dispatchR0ServiceStartToWorker(
        const QString& nativeDriverPath,
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback)
    {
        QThreadPool::globalInstance()->start(
            [nativeDriverPath, completionCallback = std::move(completionCallback)]()
            {
                const R0ServiceOperationOutcome kOperationOutcome =
                    executeR0ServiceStartOnWorker(nativeDriverPath);
                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kAppInstance,
                    [completionCallback, kOperationOutcome]()
                    {
                        completionCallback(kOperationOutcome);
                    });
            });
    }
}

using namespace ksword::ui::main_window;
