#include "DriverDock.Internal.h"

namespace ksword::driver_dock_internal
{
    // toWideString：
    // - Purpose: Convert QString to std::wstring.
    std::wstring toWideString(const QString& textValue)
    {
        return textValue.toStdWString();
    }

    // createReadOnlyItem：
    // - Purpose: Create a read-only cell to unify table interaction behavior.
    QTableWidgetItem* createReadOnlyItem(const QString& textValue)
    {
        QTableWidgetItem* tableItem = new QTableWidgetItem(textValue);
        tableItem->setFlags(tableItem->flags() & ~Qt::ItemIsEditable);
        return tableItem;
    }

    // formatAddress：
    // - Purpose: Convert an address to a fixed-width hexadecimal string.
    QString formatAddress(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar('0'))
            .toUpper();
    }

    // formatCompactAddress：
    // - Purpose: Display 'Unavailable' when the address is 0.
    // - Suitable for displaying optional pointers in the DriverObject/DeviceObject diagnostic table.
    QString formatCompactAddress(const std::uint64_t addressValue)
    {
        if (addressValue == 0)
        {
            return QStringLiteral("Unavailable");
        }
        return formatAddress(addressValue);
    }

    // formatHex32：
    // - Purpose: Display 32-bit flags/type/status as fixed-width hexadecimal;
    // - For easy comparison with WinDbg/WDK constants.
    QString formatHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    // formatNtStatusText：
    // - Purpose: Display NTSTATUS in 0xXXXXXXXX format.
    // - Here, only the raw value is displayed; failure codes are not swallowed in the UI.
    QString formatNtStatusText(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    // friendlyDriverIoMessage：
    // - Input: Low-level IO diagnostic string returned by ArkDriverClient;
    // - Handling: Render only the message itself. **Collection status is no longer inferred from substrings
    //   here**; that is determined by the F-05 normalization layer in `describeDriverCollection`, see below.
    // - Returns: Short text suitable for status bars, detail areas, and the last column of tables.
    QString friendlyDriverIoMessage(const std::string& rawMessage)
    {
        const QString kRawText = QString::fromUtf8(rawMessage.data(), static_cast<int>(rawMessage.size())).trimmed();
        if (kRawText.isEmpty())
        {
            return driverText("driver.io.empty", QStringLiteral("无额外驱动消息"));
        }
        // capability/DynData are hints for 'missing capabilities', not collection status; keep them.
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return driverText(
                "driver.io.capability_missing",
                QStringLiteral("动态偏移能力未满足，请查看内核 DynData/Capability 状态"));
        }
        return kRawText;
    }

    // describeDriverCollection (F-05: Collection status and conclusion are separated):
    // - Input: ArkDriverClient's IoResult, along with unsupported/partial flags known by the caller;
    // - Handling: normalize via toCollectionOutcome in ArkDriverEvidence.h. Previously, this relied
    //   on rawMessage.contains("DeviceIoControl") / contains("unsupported") to guess the state, failing
    //   to distinguish between access denied and timeout, and discarding the original error code.
    // - Return format: "<Collection Status> (<Domain> <Original Code>): <Original Message>". The original code is always
    //   preserved; no branch produces a "Normal" conclusion—the conclusion is provided separately by the analysis side.
    QString describeDriverCollection(const ksword::ark::IoResult& ioResult,
                                     const bool unsupported,
                                     const bool partial)
    {
        namespace ev = ksword::evidence;

        ksword::ark::DriverCallShape shape;
        shape.unsupported = unsupported;
        shape.partial = partial;
        const ev::CollectionOutcome kOutcome = ksword::ark::toCollectionOutcome(ioResult, shape);

        QString stateText;
        switch (kOutcome.status)
        {
        case ev::CollectionStatus::kSuccess:
            stateText = driverText("driver.collect.success", QStringLiteral("采集成功"));
            break;
        case ev::CollectionStatus::kPartial:
            stateText = driverText(
                "driver.collect.partial",
                QStringLiteral("采集不完整：结果被截断或未覆盖请求范围"));
            break;
        case ev::CollectionStatus::kNotCollected:
            stateText = driverText("driver.collect.not_collected", QStringLiteral("未采集"));
            break;
        case ev::CollectionStatus::kUnsupported:
            stateText = driverText(
                "driver.io.unsupported",
                QStringLiteral("当前驱动不支持该只读查询入口"));
            break;
        case ev::CollectionStatus::kAccessDenied:
            stateText = driverText("driver.collect.access_denied", QStringLiteral("权限不足，访问被拒绝"));
            break;
        case ev::CollectionStatus::kTimeout:
            stateText = driverText("driver.collect.timeout", QStringLiteral("驱动调用超时"));
            break;
        case ev::CollectionStatus::kError:
            stateText = driverText(
                "driver.io.device_control_failed",
                QStringLiteral("驱动接口调用失败或当前驱动版本不匹配"));
            break;
        }

        QString text = stateText;
        if (kOutcome.nativeCode.present)
        {
            // NTSTATUS uses hexadecimal, Win32 uses decimal, following the conventional reading formats for their respective domains.
            // Both values are taken directly as 64-bit originals, without floating-point conversion.
            const QString kCodeText = (kOutcome.nativeCodeDomain == "NTSTATUS")
                ? QStringLiteral("0x%1")
                      .arg(static_cast<qulonglong>(kOutcome.nativeCode.value), 8, 16, QChar('0'))
                      .toUpper()
                : QString::fromStdString(
                      ev::formatU64(kOutcome.nativeCode.value, ev::U64Format::kDecimal));
            text += QStringLiteral(" (%1 %2)")
                        .arg(QString::fromStdString(kOutcome.nativeCodeDomain), kCodeText);
        }

        const QString kDetail = friendlyDriverIoMessage(kOutcome.message);
        if (!kDetail.isEmpty() && kDetail != stateText)
        {
            text += QStringLiteral("：") + kDetail;
        }
        return text;
    }

    // isDriverSignatureLoadError：
    // - Input: Win32 error code returned by StartServiceW;
    // - Processing: Identify load failures caused by 'image hash/signature/policy blocking'.
    // - Return: true indicates the user should be prompted to check the test signature, rather than just a standard SCM error.
    bool isDriverSignatureLoadError(const DWORD errorCode)
    {
        return errorCode == ERROR_INVALID_IMAGE_HASH ||
            errorCode == ERROR_DRIVER_BLOCKED ||
            errorCode == ERROR_ACCESS_DISABLED_BY_POLICY;
    }

    // formatWin32ErrorTextForAdvice：
    // - Input: Win32 error code;
    // - Processing: Extract system error text via FormatMessageW.
    // - Returns: Short text with decimal error code, for signature repair suggestions.
    QString formatWin32ErrorTextForAdvice(const DWORD errorCode)
    {
        LPWSTR messageBuffer = nullptr;
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);

        QString messageText;
        if (kMessageLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer).trimmed();
            ::LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = driverText("driver.error.unknown", QStringLiteral("未知错误"));
        }

        return driverText("driver.error.code", QStringLiteral("%1：%2"))
            .arg(static_cast<unsigned long>(errorCode))
            .arg(messageText);
    }

    // WindowsReleaseInfo：
    // - Purpose: Store the user-facing Windows version label and kernel build number;
    // - displayVersion is used to distinguish 25H2/26H2 sharing the same service branch; do not rely solely on build number.
    struct WindowsReleaseInfo
    {
        QString displayVersion; // displayVersion: The DisplayVersion from the registry, e.g., 26H2.
        QString buildNumber;    // buildNumber: CurrentBuildNumber from the registry, used for diagnostic display only.
        bool is26H2OrNewer = false; // is26H2OrNewer: whether the version tag reaches 26H2.
    };

    // readWindowsVersionRegistryText：
    // - Input: String value name in the CurrentVersion registry;
    // - Processing: Fixed read of the 64-bit system view to avoid version misjudgment caused by 32-bit redirection.
    // - Returns: The trimmed text upon successful read; returns an empty string on failure.
    QString readWindowsVersionRegistryText(const wchar_t* valueName)
    {
        HKEY versionKey = nullptr;
        const LSTATUS kOpenStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &versionKey);
        if (kOpenStatus != ERROR_SUCCESS || versionKey == nullptr)
        {
            return QString();
        }

        std::array<wchar_t, 64> valueBuffer{};
        DWORD valueType = 0;
        DWORD valueBytes = static_cast<DWORD>(valueBuffer.size() * sizeof(wchar_t));
        const LSTATUS kQueryStatus = ::RegQueryValueExW(
            versionKey,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer.data()),
            &valueBytes);
        ::RegCloseKey(versionKey);
        if (kQueryStatus != ERROR_SUCCESS ||
            (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return QString();
        }

        valueBuffer.back() = L'\0';
        return QString::fromWCharArray(valueBuffer.data()).trimmed();
    }

    // queryWindowsReleaseInfo：
    // - Purpose: Parse Windows annual/half-yearly version based on DisplayVersion.
    // - 26H2 and 25H2 share the service branch, so the build number is displayed but not used for version threshold checks.
    // - Returns: A stable snapshot used for driver load error routing and log display.
    WindowsReleaseInfo queryWindowsReleaseInfo()
    {
        WindowsReleaseInfo releaseInfo;
        releaseInfo.displayVersion =
            readWindowsVersionRegistryText(L"DisplayVersion").toUpper();
        releaseInfo.buildNumber =
            readWindowsVersionRegistryText(L"CurrentBuildNumber");

        const int kHalfMarkerIndex =
            releaseInfo.displayVersion.indexOf(QLatin1Char('H'));
        bool yearValid = false;
        bool halfValid = false;
        const int kReleaseYear = kHalfMarkerIndex > 0
            ? releaseInfo.displayVersion.left(kHalfMarkerIndex).toInt(&yearValid)
            : 0;
        const int kReleaseHalf = kHalfMarkerIndex > 0
            ? releaseInfo.displayVersion.mid(kHalfMarkerIndex + 1).toInt(&halfValid)
            : 0;
        releaseInfo.is26H2OrNewer =
            yearValid &&
            halfValid &&
            (kReleaseYear > 26 || (kReleaseYear == 26 && kReleaseHalf >= 2));
        return releaseInfo;
    }

    // buildDriverSignatureLoadAdvice：
    // - Input: error code, service name, driver path;
    // - Handling: For version 26H2 and above, enter the dedicated branch for new kernel trust policies; other versions retain the generic explanation.
    // - Returns: Multi-line text ready to be appended to the DriverDock operation log.
    QString buildDriverSignatureLoadAdvice(
        const DWORD errorCode,
        const QString& serviceNameText,
        const QString& binaryPathText)
    {
        const QString kResolvedBinaryPath = binaryPathText.trimmed().isEmpty()
            ? driverText(
                "driver.load_advice.path_missing",
                QStringLiteral("<未从表单读取到路径>"))
            : binaryPathText;
        const WindowsReleaseInfo kReleaseInfo = queryWindowsReleaseInfo();
        if (kReleaseInfo.is26H2OrNewer)
        {
            return driverText(
                "driver.load_advice.windows_26h2_policy",
                QStringLiteral(
                    "挂载失败：Windows 拒绝加载驱动（%1）。\n"
                    "系统：Windows %2（Build %3，已按 26H2 或更高版本处理）\n"
                    "服务：%4\n"
                    "驱动路径：%5\n"
                    "此版本使用更严格的内核驱动信任策略。正式环境请换用经 Microsoft Hardware Dev Center "
                    "签名（证明签名/WHQL）的 KswordARK.sys；开发环境也必须给二进制写入有效测试签名，"
                    "启用 TESTSIGNING 后重启。若仍失败，请检查“代码完整性/操作”事件日志以及 "
                    "Secure Boot、内存完整性或 WDAC 策略，不要把策略阻止误判为普通 SCM 故障。"))
                .arg(formatWin32ErrorTextForAdvice(errorCode))
                .arg(kReleaseInfo.displayVersion)
                .arg(kReleaseInfo.buildNumber.isEmpty()
                    ? driverText(
                        "driver.load_advice.build_unknown",
                        QStringLiteral("<未知>"))
                    : kReleaseInfo.buildNumber)
                .arg(serviceNameText)
                .arg(kResolvedBinaryPath);
        }

        QString adviceText = driverText(
            "driver.load_advice.signature_error",
            QStringLiteral(
                "挂载失败：Windows 拒绝加载驱动（%1）。\n"
                "服务：%2\n"
                "驱动路径：%3\n"
                "请使用可信签名的 KswordARK.sys；开发或测试环境可使用测试签名并启用测试模式，随后重启系统。"))
            .arg(formatWin32ErrorTextForAdvice(errorCode))
            .arg(serviceNameText)
            .arg(kResolvedBinaryPath);
        return adviceText;
    }

    // driverObjectQueryStatusText：
    // - Purpose: Convert shared protocol query status to user-readable text.
    // - Retain the original NTSTATUS for display in the summary section.
    QString driverObjectQueryStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NAME_INVALID:
            return QStringLiteral("Name invalid");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND:
            return QStringLiteral("Not found");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED:
            return QStringLiteral("Reference failed");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("Buffer too small");
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_QUERY_FAILED:
            return QStringLiteral("Query failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // driverForceUnloadStatusText：
    // - Purpose: Convert R0 forced unload status to DriverDock log text.
    // - Returns: Chinese status description; original NTSTATUS displayed separately.
    QString driverForceUnloadStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED:
            return driverText("driver.unload.status.called", QStringLiteral("已调用 DriverUnload"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_MISSING:
            return driverText("driver.unload.status.missing_routine", QStringLiteral("缺少 DriverUnload"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED:
            return driverText("driver.unload.status.reference_failed", QStringLiteral("引用 DriverObject 失败"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_THREAD_FAILED:
            return driverText("driver.unload.status.thread_failed", QStringLiteral("系统线程失败"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT:
            return driverText("driver.unload.status.wait_timeout", QStringLiteral("等待超时"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED:
            return driverText("driver.unload.status.operation_failed", QStringLiteral("操作失败"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP:
            return driverText("driver.unload.status.forced_cleanup", QStringLiteral("已强制清理"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_CLEANUP_FAILED:
            return driverText("driver.unload.status.cleanup_failed", QStringLiteral("清理失败"));
        case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_CALLED:
            return driverText("driver.unload.status.routine_called", QStringLiteral("已直接调用 DriverUnload"));
        default:
            return driverText("driver.unload.status.unknown", QStringLiteral("未知状态"));
        }
    }

    // driverMajorFunctionName：
    // - Purpose: Convert IRP_MJ codes to stable names.
    // - Output format preserves the numeric ID to facilitate troubleshooting of custom filter stacks.
    QString driverMajorFunctionName(const std::uint32_t majorFunction)
    {
        switch (majorFunction)
        {
        case 0x00: return QStringLiteral("IRP_MJ_CREATE");
        case 0x01: return QStringLiteral("IRP_MJ_CREATE_NAMED_PIPE");
        case 0x02: return QStringLiteral("IRP_MJ_CLOSE");
        case 0x03: return QStringLiteral("IRP_MJ_READ");
        case 0x04: return QStringLiteral("IRP_MJ_WRITE");
        case 0x05: return QStringLiteral("IRP_MJ_QUERY_INFORMATION");
        case 0x06: return QStringLiteral("IRP_MJ_SET_INFORMATION");
        case 0x07: return QStringLiteral("IRP_MJ_QUERY_EA");
        case 0x08: return QStringLiteral("IRP_MJ_SET_EA");
        case 0x09: return QStringLiteral("IRP_MJ_FLUSH_BUFFERS");
        case 0x0A: return QStringLiteral("IRP_MJ_QUERY_VOLUME_INFORMATION");
        case 0x0B: return QStringLiteral("IRP_MJ_SET_VOLUME_INFORMATION");
        case 0x0C: return QStringLiteral("IRP_MJ_DIRECTORY_CONTROL");
        case 0x0D: return QStringLiteral("IRP_MJ_FILE_SYSTEM_CONTROL");
        case 0x0E: return QStringLiteral("IRP_MJ_DEVICE_CONTROL");
        case 0x0F: return QStringLiteral("IRP_MJ_INTERNAL_DEVICE_CONTROL");
        case 0x10: return QStringLiteral("IRP_MJ_SHUTDOWN");
        case 0x11: return QStringLiteral("IRP_MJ_LOCK_CONTROL");
        case 0x12: return QStringLiteral("IRP_MJ_CLEANUP");
        case 0x13: return QStringLiteral("IRP_MJ_CREATE_MAILSLOT");
        case 0x14: return QStringLiteral("IRP_MJ_QUERY_SECURITY");
        case 0x15: return QStringLiteral("IRP_MJ_SET_SECURITY");
        case 0x16: return QStringLiteral("IRP_MJ_POWER");
        case 0x17: return QStringLiteral("IRP_MJ_SYSTEM_CONTROL");
        case 0x18: return QStringLiteral("IRP_MJ_DEVICE_CHANGE");
        case 0x19: return QStringLiteral("IRP_MJ_QUERY_QUOTA");
        case 0x1A: return QStringLiteral("IRP_MJ_SET_QUOTA");
        case 0x1B: return QStringLiteral("IRP_MJ_PNP");
        default: return QStringLiteral("IRP_MJ_%1").arg(majorFunction);
        }
    }

    // driverDeviceTypeText：
    // - Purpose: Provide name hints for common DEVICE_TYPE values.
    // - Keep unknown values in hexadecimal to avoid misinterpretation.
    QString driverDeviceTypeText(const std::uint32_t deviceType)
    {
        switch (deviceType)
        {
        case FILE_DEVICE_DISK: return QStringLiteral("DISK");
        case FILE_DEVICE_DISK_FILE_SYSTEM: return QStringLiteral("DISK_FILE_SYSTEM");
        case FILE_DEVICE_FILE_SYSTEM: return QStringLiteral("FILE_SYSTEM");
        case FILE_DEVICE_NETWORK: return QStringLiteral("NETWORK");
        case FILE_DEVICE_NETWORK_FILE_SYSTEM: return QStringLiteral("NETWORK_FILE_SYSTEM");
        case FILE_DEVICE_NULL: return QStringLiteral("NULL");
        case FILE_DEVICE_UNKNOWN: return QStringLiteral("UNKNOWN");
        case FILE_DEVICE_KSEC: return QStringLiteral("KSEC");
        default: return formatHex32(deviceType);
        }
    }

    // driverDispatchLocationText：
    // - Purpose: Mark whether the dispatch falls within the DriverObject's own image;
    // - 'External module' is explicitly displayed in text, not relying solely on color.
    QString driverDispatchLocationText(const std::uint32_t flags)
    {
        const bool kResolvedModule = (flags & 0x00000001U) != 0U;
        const bool kInsideOwnImage = (flags & 0x00000002U) != 0U;
        if (kInsideOwnImage)
        {
            return driverText("driver.location.inside_image", QStringLiteral("自身镜像内"));
        }
        if (kResolvedModule)
        {
            return driverText("driver.location.external_module", QStringLiteral("外部模块"));
        }
        return driverText("driver.location.unresolved_module", QStringLiteral("未解析模块"));
    }

}


using namespace ksword::driver_dock_internal;

DriverDock::DriverDock(QWidget* parent)
    : QWidget(parent)
{
    // initEvent usage: Spans the entire construction flow to enable tracking the initialization chain via the same GUID.
    KLogEvent initEvent;
    info << initEvent
        << driverText("driver.log.initializing", QStringLiteral("[DriverDock] 开始初始化驱动页。"))
        << eol;

    initializeUi();
    initializeConnections();
    updateDebugCaptureButtonState();

    info << initEvent
        << driverText("driver.log.initialized", QStringLiteral("[DriverDock] 驱动页初始化完成。"))
        << eol;
}

void DriverDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (initialRefreshDone_)
    {
        return;
    }

    initialRefreshDone_ = true;
    if (overviewStatusLabel_ != nullptr)
    {
        overviewStatusLabel_->setText(
            driverText(
                "driver.status.first_open",
                QStringLiteral("状态：首次打开，正在加载驱动服务与内核模块...")));
    }

    QTimer::singleShot(0, this, [this]()
        {
            refreshDriverServiceRecords();
            refreshLoadedKernelModuleRecords();
            refreshUnloadedDriversAsync();
        });
}

DriverDock::~DriverDock()
{
    stopDebugOutputCapture();

    // The business object for the self-driver page is still held by KernelDock; when DriverDock is independently destroyed, the
    // page is reattached to avoid KernelDock's dynamic offset/state members pointing to controls already deleted by QTabWidget.
    if (kswordSelfDriverPage_ != nullptr && tabWidget_ != nullptr)
    {
        const int kPageIndex = tabWidget_->indexOf(kswordSelfDriverPage_);
        if (kPageIndex >= 0)
        {
            tabWidget_->removeTab(kPageIndex);
        }
        if (!kswordSelfDriverFallbackOwner_.isNull())
        {
            kswordSelfDriverPage_->setParent(kswordSelfDriverFallbackOwner_);
            kswordSelfDriverPage_->hide();
        }
    }

    KLogEvent destroyEvent;
    info << destroyEvent
        << driverText("driver.log.destroyed", QStringLiteral("[DriverDock] 驱动页已析构。"))
        << eol;
}

void DriverDock::attachKswordSelfDriverPage(QWidget* page, QWidget* fallbackOwner)
{
    if (page == nullptr || tabWidget_ == nullptr)
    {
        return;
    }
    if (kswordSelfDriverPage_ == page)
    {
        return;
    }

    // If the caller replaces the page in the future, safely remove the old page from the current Tab and return it to its original owner.
    if (kswordSelfDriverPage_ != nullptr)
    {
        const int kOldPageIndex = tabWidget_->indexOf(kswordSelfDriverPage_);
        if (kOldPageIndex >= 0)
        {
            tabWidget_->removeTab(kOldPageIndex);
        }
        if (!kswordSelfDriverFallbackOwner_.isNull())
        {
            kswordSelfDriverPage_->setParent(kswordSelfDriverFallbackOwner_);
            kswordSelfDriverPage_->hide();
        }
    }

    kswordSelfDriverPage_ = page;
    kswordSelfDriverFallbackOwner_ = fallbackOwner;
    kswordSelfDriverTabIndex_ = tabWidget_->addTab(
        page,
        QIcon(QStringLiteral(":/Icon/process_priority.svg")),
        driverText("driver.tab.self_driver", QStringLiteral("Ksword自身驱动")));
    tabWidget_->setTabToolTip(
        kswordSelfDriverTabIndex_,
        driverText(
            "driver.tab.self_driver.tooltip",
            QStringLiteral("KswordARK 动态偏移与驱动状态")));
}
