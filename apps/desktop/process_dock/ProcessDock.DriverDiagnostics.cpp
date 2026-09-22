#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    bool setProcessVisibilityByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const unsigned long flags,
        std::string* const detailTextOut)
    {
        // Purpose: Invoke ArkDriverClient to execute an R0 process visibility action.
        // Processing: Hide actions via flags to explicitly select only PID modification, only chain breaking, or legacy dual operations.
        // Returns: true indicates the driver accepted and updated; false indicates IOCTL or R0 status failure.
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE &&
            (targetPid == 0U || targetPid <= 4U))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::ProcessVisibilityResult kResult =
            kDriverClient.setProcessVisibility(targetPid, action, flags);
        const bool kActionSucceeded = kResult.io.ok &&
            kResult.lastStatus >= 0 &&
            (kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN ||
                kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE ||
                kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.io.message);
            if (!kActionSucceeded)
            {
                if (!detailTextOut->empty())
                {
                    *detailTextOut += " | ";
                }
                *detailTextOut += activeProcessLinksDynDataDiagnostic(kDriverClient);
            }
        }
        return kActionSucceeded;
    }

    bool setProcessSpecialFlagsByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut)
    {
        // Purpose: Encapsulates BreakOnTermination/APC insertion control IOCTL.
        // Returns: true indicates R0 action completed; false indicates IOCTL or R0 status failure.
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
        const ksword::ark::ProcessSpecialFlagsResult kResult =
            kDriverClient.setProcessSpecialFlags(
                targetPid,
                action,
                0UL,
                expectedCreationTime100ns);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.io.message);
        }
        return kResult.io.ok &&
            kResult.lastStatus >= 0 &&
            kResult.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
    }

    bool dkomProcessByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        std::string* const detailTextOut)
    {
        // Purpose: Encapsulate the PspCidTable DKOM removal IOCTL.
        // Returns: true if R0 deleted at least one CID entry.
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
        const ksword::ark::ProcessDkomResult kResult =
            kDriverClient.dkomProcess(targetPid, action);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kResult.io.message);
        }
        return kResult.io.ok &&
            kResult.lastStatus >= 0 &&
            kResult.status == KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED &&
            kResult.removedEntries > 0U;
    }

    // r0ActionExpectedCreationTime: The actual creation time is validated by the driver; synthetic placeholder values from old drivers are excluded from object identity checks.
    std::uint64_t r0ActionExpectedCreationTime(const ks::process::ProcessRecord& processRecord)
    {
        return processRecord.creationTime100ns >= kKernelOnlyCreationTimeSeed
            ? 0ULL
            : processRecord.creationTime100ns;
    }

    QString processFieldSourceText(const std::uint32_t sourceValue)
    {
        // sourceValue usage: Field source enumeration in the shared protocol.
        // Return value: Stable, human-readable text for the UI.
        switch (sourceValue)
        {
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API:
            return QStringLiteral("Public API");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA:
            return QStringLiteral("System Informer DynData");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // dynDataFieldSourceText:
    // - Input: KSW_DYN_FIELD_SOURCE_* source values returned by QUERY_DYN_FIELDS;
    // - Processing: Convert to human-readable source text in action failure details.
    // - Returns: PDB profile, System Informer, runtime pattern, or Unavailable.
    QString dynDataFieldSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // dynDataOffsetPresent:
    // - Input: DynData field flags and offset;
    // - Processing: check both PRESENT bit and unavailable sentinel;
    // - Return: true indicates the field is currently available to R0.
    bool dynDataOffsetPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // dynDataOffsetText:
    // - Input: DynData field offset;
    // - Handling: Display <Unavailable> for sentinel values that are unusable; for usable values, display both hex and decimal.
    // - Returns: Offset text from action details.
    QString dynDataOffsetText(const std::uint32_t offset)
    {
        if (offset == 0xFFFFFFFFU || offset == 0x0000FFFFU)
        {
            return QStringLiteral("<不可用>");
        }
        return QStringLiteral("0x%1 (%2)")
            .arg(offset, 8, 16, QChar('0'))
            .arg(offset)
            .toUpper();
    }

    // dynDataStatusFlagText:
    // - Input: KSW_DYN_STATUS_FLAG_* bitmap returned by QUERY_DYN_STATUS;
    // - Processing: List only active/profile flags that explain the offset-applied link.
    // - Returns: Human-readable status flag text from the action failure details.
    QString dynDataStatusFlagText(const std::uint32_t statusFlags)
    {
        QStringList parts;
        if ((statusFlags & KSW_DYN_STATUS_FLAG_INITIALIZED) != 0U)
        {
            parts << QStringLiteral("Initialized");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_NTOS_ACTIVE) != 0U)
        {
            parts << QStringLiteral("NtosActive");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U)
        {
            parts << QStringLiteral("PdbProfileActive");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U)
        {
            parts << QStringLiteral("CallbackProfileActive");
        }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral("|"));
    }

    // activeProcessLinksDynDataDiagnostic:
    // - Input: open DriverClient;
    // - Processing: Perform read-only query of R0 DynData status and field table to determine if _EPROCESS.ActiveProcessLinks has been applied.
    // - Returns: a single-line diagnostic string appended to detailText when R0 visibility actions fail.
    std::string activeProcessLinksDynDataDiagnostic(const ksword::ark::DriverClient& driverClient)
    {
        QStringList diagnosticParts;

        const ksword::ark::DynDataStatusResult kStatusResult = driverClient.queryDynDataStatus();
        if (kStatusResult.io.ok)
        {
            const QString kStatusFlagsText = QStringLiteral("0x%1")
                .arg(kStatusResult.statusFlags, 8, 16, QChar('0'))
                .toUpper();
            const QString kCapabilityText = QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(kStatusResult.capabilityMask), 16, 16, QChar('0'))
                .toUpper();
            const QString kLastStatusText = QStringLiteral("0x%1")
                .arg(static_cast<std::uint32_t>(kStatusResult.lastStatus), 8, 16, QChar('0'))
                .toUpper();
            diagnosticParts << QStringLiteral(
                "DynDataStatus: flags=%1(%2), caps=%3, fields=%4, lastStatus=%5")
                .arg(kStatusFlagsText)
                .arg(dynDataStatusFlagText(kStatusResult.statusFlags))
                .arg(kCapabilityText)
                .arg(kStatusResult.fieldCount)
                .arg(kLastStatusText);
            if ((kStatusResult.statusFlags & KSW_DYN_STATUS_FLAG_NTOS_ACTIVE) != 0U &&
                (kStatusResult.statusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) == 0U)
            {
                diagnosticParts << QStringLiteral("Hint: ntoskrnl DynData is active but PDB profile is not active; refresh Kernel/DynData to apply the v3 profile pack.");
            }
        }
        else
        {
            diagnosticParts << QStringLiteral("DynDataStatus unavailable: %1")
                .arg(processDockIoMessageText(QString::fromStdString(kStatusResult.io.message)));
        }

        const ksword::ark::DynDataFieldsResult kFieldsResult = driverClient.queryDynDataFields();
        if (!kFieldsResult.io.ok)
        {
            diagnosticParts << QStringLiteral("DynData ActiveProcessLinks unavailable: %1")
                .arg(processDockIoMessageText(QString::fromStdString(kFieldsResult.io.message)));
            return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
        }

        for (const ksword::ark::DynDataFieldEntry& entry : kFieldsResult.entries)
        {
            if (entry.fieldId != KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS)
            {
                continue;
            }

            const bool kPresent = dynDataOffsetPresent(entry.flags, entry.offset);
            const QString kFlagsText = QStringLiteral("0x%1")
                .arg(entry.flags, 8, 16, QChar('0'))
                .toUpper();
            const QString kCapabilityText = QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(entry.capabilityMask), 16, 16, QChar('0'))
                .toUpper();
            const QString kDiagnosticText = QStringLiteral(
                "DynData ActiveProcessLinks: present=%1, offset=%2, source=%3, flags=%4, capability=%5")
                .arg(kPresent ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(dynDataOffsetText(entry.offset))
                .arg(dynDataFieldSourceText(entry.source))
                .arg(kFlagsText)
                .arg(kCapabilityText);
            diagnosticParts << kDiagnosticText;
            return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
        }

        diagnosticParts << QStringLiteral("DynData ActiveProcessLinks unavailable: field not returned by R0.");
        return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
    }

    QString processR0StatusText(const std::uint32_t statusValue)
    {
        // statusValue usage: Overall completion status of R0 extended information per line.
        // Return value: Short text, used directly in table columns and detail views.
        switch (statusValue)
        {
        case KSWORD_ARK_PROCESS_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString byteHexText(const std::uint8_t byteValue)
    {
        // byteValue usage: original single-byte value for protection/signature level.
        // Return value: 0xNN format, for easy comparison with raw kernel fields.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(byteValue), 2, 16, QChar('0'))
            .toUpper();
    }

    bool resolvePplSignatureLevelsForUi(
        const std::uint8_t protectionLevel,
        std::uint8_t* const signatureLevelOut,
        std::uint8_t* const sectionSignatureLevelOut)
    {
        // protectionLevel: The original PS_PROTECTION byte passed from the menu.
        // Return value: true indicates the UI can predict the driver-side synchronous write signature level.
        if (signatureLevelOut == nullptr || sectionSignatureLevelOut == nullptr)
        {
            return false;
        }

        const std::uint8_t kSignerType = (protectionLevel == 0U)
            ? static_cast<std::uint8_t>(0U)
            : static_cast<std::uint8_t>((protectionLevel & 0xF0U) >> 4U);
        switch (kSignerType)
        {
        case 0:
            *signatureLevelOut = 0x00U;
            *sectionSignatureLevelOut = 0x00U;
            return true;
        case 1:
            *signatureLevelOut = 0x04U;
            *sectionSignatureLevelOut = 0x04U;
            return true;
        case 2:
            *signatureLevelOut = 0x0BU;
            *sectionSignatureLevelOut = 0x06U;
            return true;
        case 3:
            *signatureLevelOut = 0x07U;
            *sectionSignatureLevelOut = 0x07U;
            return true;
        case 4:
            *signatureLevelOut = 0x0CU;
            *sectionSignatureLevelOut = 0x08U;
            return true;
        case 5:
            *signatureLevelOut = 0x0CU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 6:
            *signatureLevelOut = 0x0EU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 7:
            // WinSystem and WinTcb share a signature level; see the driver side for details.
            // kswordArkDriverResolveSignatureLevelsFromSigner。
            *signatureLevelOut = 0x0EU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 8:
            *signatureLevelOut = 0x06U;
            *sectionSignatureLevelOut = 0x06U;
            return true;
        default:
            return false;
        }
    }

    QString pplMutationCapabilityText(const ks::process::ProcessRecord& processRecord)
    {
        // processRecord purpose: read the current row's DynData capability and field source.
        // Return value: Summary of capability/source in the confirmation dialog.
        const bool kCapabilityPresent =
            (processRecord.r0DynDataCapabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != 0U;
        const bool kProtectionOffsetPresent =
            processRecord.r0ProtectionOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE &&
            processRecord.r0SignatureLevelOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE &&
            processRecord.r0SectionSignatureLevelOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        return QStringLiteral("Capability: %1 | Offsets: %2 | Sources: Protection=%3, Signature=%4, SectionSignature=%5")
            .arg(kCapabilityPresent ? QStringLiteral("KSW_CAP_PROCESS_PROTECTION_PATCH present") : QStringLiteral("missing/unknown"))
            .arg(kProtectionOffsetPresent ? QStringLiteral("present") : QStringLiteral("missing/unknown"))
            .arg(processFieldSourceText(processRecord.r0ProtectionSource))
            .arg(processFieldSourceText(processRecord.r0SignatureLevelSource))
            .arg(processFieldSourceText(processRecord.r0SectionSignatureLevelSource));
    }

    QString pointerAvailabilityText(
        const bool available,
        const std::uint64_t addressValue,
        const std::uint32_t sourceValue)
    {
        // available indicates whether offset/capability is accessible; addressValue is the current field value.
        // Return value includes the source to help users determine if DynData matched.
        if (!available)
        {
            return QStringLiteral("Unavailable (%1)").arg(processFieldSourceText(sourceValue));
        }
        if (addressValue == 0U)
        {
            return QStringLiteral("Available: null (%1)").arg(processFieldSourceText(sourceValue));
        }
        const QString kAddressText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 0, 16)
            .toUpper();
        return QStringLiteral("Available: 0x%1 (%2)")
            .arg(kAddressText.mid(2))
            .arg(processFieldSourceText(sourceValue));
    }
}
