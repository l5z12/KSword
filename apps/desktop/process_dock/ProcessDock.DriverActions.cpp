#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // Convert the current steady_clock time to 100ns units (consistent with the difference calculation rule in ks::process).
    std::uint64_t steadyNow100ns()
    {
        const auto kNowDuration = std::chrono::steady_clock::now().time_since_epoch();
        const auto kNowNanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(kNowDuration).count();
        return static_cast<std::uint64_t>(kNowNanoseconds / 100);
    }

    // Map from the strategy dropdown index to the ks::process strategy enumeration.
    ks::process::ProcessEnumStrategy toStrategy(const int strategyIndex)
    {
        switch (strategyIndex)
        {
        case 0:
            return ks::process::ProcessEnumStrategy::kSnapshotProcess32;
        case 1:
            return ks::process::ProcessEnumStrategy::kNtQuerySystemInfo;
        default:
            return ks::process::ProcessEnumStrategy::kNtQuerySystemInfo;
        }
    }

    // Convert strategy enum to readable text: used for refreshing status labels and detailed log output.
    const char* strategyToText(const ks::process::ProcessEnumStrategy strategy)
    {
        switch (strategy)
        {
        case ks::process::ProcessEnumStrategy::kSnapshotProcess32:
            return "Toolhelp Snapshot + Process32First/Next";
        case ks::process::ProcessEnumStrategy::kNtQuerySystemInfo:
            return "NtQuerySystemInformation";
        case ks::process::ProcessEnumStrategy::kAuto:
            return "Auto (NtQuery 优先, 失败回退 Toolhelp)";
        default:
            return "Unknown";
        }
    }

    // processDockIoMessageText：
    // - Input: The raw message text returned by ArkDriverClient to ProcessDock;
    // - Processing: Convert low-level diagnostics like DeviceIoControl/unsupported/DynData/buffer into user-readable prompts.
    // - Returns: Chinese description for the process page status string; avoids directly concatenating IOCTL debug logs into the UI.
    QString processDockIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。");
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持该进程 DynData 查询入口。");
        }
        if (kLowerText.contains(QStringLiteral("dyndata")) ||
            kLowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("DynData 动态偏移能力未满足，请先刷新或应用 PDB profile。");
        }
        if (kLowerText.contains(QStringLiteral("buffer")) &&
            (kLowerText.contains(QStringLiteral("small")) || kLowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，结果可能被截断。");
        }
        return kTrimmedText;
    }

    // processDockIoMessageStdString：
    // - Input: Raw std::string message returned by ArkDriverClient.
    // - Processing: Reuses ProcessDock's user-friendly text conversion and converts the result back to a UTF-8 std::string.
    // - Returns: Human-readable description ready to be passed to the legacy detailTextOut pipeline.
    std::string processDockIoMessageStdString(const std::string& rawMessageText)
    {
        return processDockIoMessageText(QString::fromStdString(rawMessageText)).toStdString();
    }

    // isProcessR0ExtensionVisible:
    // - Determine if a line actually carries the R0 extension field.
    // - When all are Unavailable, the UI automatically hides the kernel-exclusive column to avoid misleading users into thinking the R3 field is abnormal.
    bool isProcessR0ExtensionVisible(const ks::process::ProcessRecord& processRecord)
    {
        if (processRecord.r0Status != KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE)
        {
            return true;
        }

        return (processRecord.r0FieldFlags &
            (KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT |
                KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE |
                KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_VALUE_PRESENT |
                KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE |
                KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_VALUE_PRESENT)) != 0U;
    }

    // terminateProcessByR0Driver:
    // - Send "terminate process" IOCTL via ArkDriverClient;
    // - Dock no longer directly opens the KswordARK device or calls DeviceIoControl.
    bool terminateProcessByR0Driver(
        const std::uint32_t targetPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.terminateProcess(
            targetPid,
            static_cast<long>(0xC0000005u),
            expectedCreationTime100ns);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.message);
        }
        return kResult.ok;
    }

    // suspendProcessByR0Driver:
    // - Send the "Suspend Process" IOCTL via ArkDriverClient;
    // - Preserve the legacy detailText output format to minimize UI behavior changes.
    bool suspendProcessByR0Driver(const std::uint32_t targetPid, std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.suspendProcess(targetPid);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.message);
        }
        return kResult.ok;
    }

    // resumeProcessByR0Driver:
    // - Send the "Resume Process" IOCTL via ArkDriverClient;
    // - Symmetric line-by-line with suspendProcessByR0Driver, including PID lower bound and detailText format.
    bool resumeProcessByR0Driver(const std::uint32_t targetPid, std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.resumeProcess(targetPid);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.message);
        }
        return kResult.ok;
    }

    // setPplProtectionLevelByR0Driver:
    // - Sends the 'Set PPL Protection Level' IOCTL via ArkDriverClient;
    // - protectionLevel must be consistent with the single-byte level encoding of ProcessProtectionInformation.
    bool setPplProtectionLevelByR0Driver(
        const std::uint32_t targetPid,
        const std::uint8_t protectionLevel,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.setProcessProtection(targetPid, protectionLevel);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.message);
        }
        return kResult.ok;
    }

    bool shouldFallbackProcessIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported)
    {
        // Input: ArkDriverClient communication result and unsupported flag.
        // Processing: Classify only 'driver not loaded' or 'old driver lacks this IOCTL' as R3 fallback conditions.
        // Return: true indicates R3 can be attempted; false is returned when R0 communication succeeds but the semantics fail, to avoid masking the cause of the kernel API failure.
        if (io.ok)
        {
            return false;
        }
        if (unsupported)
        {
            return true;
        }

        return io.win32Error == ERROR_FILE_NOT_FOUND ||
            io.win32Error == ERROR_PATH_NOT_FOUND ||
            io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED ||
            io.win32Error == ERROR_INVALID_PARAMETER;
    }

    bool setProcessIntegrityLevelByR0ThenR3(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* const detailText)
    {
        // Input: Target PID and Mandatory Label RID.
        // Handling: First call R0 IOCTL; fall back to R3 SetTokenInformation only if the driver is unavailable or the old driver lacks the entry point.
        // Return: true indicates R0 or fallback R3 success; false preserves R0 semantic failure or R3 failure diagnostics in detailText.
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::ProcessIntegrityResult kR0Result =
            kDriverClient.setProcessIntegrity(static_cast<std::uint32_t>(pid), integrityRid);
        const bool kR0Applied = kR0Result.io.ok &&
            kR0Result.status == KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED &&
            kR0Result.lastStatus >= 0;
        if (kR0Applied)
        {
            if (detailText != nullptr)
            {
                std::ostringstream stream;
                stream << "R0 ok: "
                    << processDockIoMessageStdString(kR0Result.io.message);
                *detailText = stream.str();
            }
            return true;
        }

        if (shouldFallbackProcessIntegrityToR3(kR0Result.io, kR0Result.unsupported))
        {
            std::string r3DetailText;
            const bool kR3Ok = setProcessIntegrityLevelByPid(pid, integrityRid, &r3DetailText);
            if (detailText != nullptr)
            {
                std::ostringstream stream;
                stream << "R0 unavailable/unsupported: "
                    << processDockIoMessageStdString(kR0Result.io.message)
                    << " | R3 "
                    << (kR3Ok ? "ok: " : "failed: ")
                    << (r3DetailText.empty() ? "no detail" : r3DetailText);
                *detailText = stream.str();
            }
            return kR3Ok;
        }

        if (detailText != nullptr)
        {
            std::ostringstream stream;
            stream << "R0 failed: "
                << processDockIoMessageStdString(kR0Result.io.message)
                << ", status=" << kR0Result.status
                << ", nt=0x" << std::hex << static_cast<unsigned long>(kR0Result.lastStatus)
                << ", win32=" << std::dec << kR0Result.io.win32Error;
            *detailText = stream.str();
        }
        return false;
    }
}
