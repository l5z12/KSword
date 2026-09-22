#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QString FileDetailDialog::formatHexValue(const quint64 value, const int digitCount)
        {
            // Purpose: Standardize hexadecimal notation with the 0x prefix.
            // Note: Convert only the numeric part to uppercase. Calling toUpper() on the entire string would convert the prefix to
            //       "0X", which mismatches the format in WinDbg and Microsoft documentation, requiring manual correction when copying.
            // Input parameters: value is the value to format; digitCount is the minimum number of digits to pad with zeros (<=0 means no padding).
            // Returns: e.g., 0x0000A020.
            QString digitsText = QString::number(value, 16).toUpper();
            if (digitCount > 0)
            {
                digitsText = digitsText.rightJustified(digitCount, QLatin1Char('0'));
            }
            return QStringLiteral("0x%1").arg(digitsText);
        }

        QString FileDetailDialog::formatHex64(const std::uint64_t value)
        {
            // Purpose: Uniformly format R0 diagnostic address.
            // Returns: a hexadecimal string with a 0x prefix and uppercase digits.
            return formatHexValue(static_cast<quint64>(value), 0);
        }

        QString FileDetailDialog::formatNtStatus(const long status)
        {
            // Purpose: Display NTSTATUS in both hexadecimal and decimal formats for easy reference with WinDbg.
            // Returns: e.g., 0xC0000034 (-1073741772).
            return QStringLiteral("%1 (%2)")
                .arg(formatHexValue(static_cast<quint64>(static_cast<std::uint32_t>(status)), 8))
                .arg(status);
        }

        QString FileDetailDialog::formatAuditBool(const bool value)
        {
            // Purpose: Uniformly convert R0 audit boolean values to Chinese to avoid mixing true/false across different pages.
            // Returns: 'Yes' or 'No', used for IO status, truncated, and unsupported fields.
            return value ? QStringLiteral("是") : QStringLiteral("否");
        }

        QString FileDetailDialog::friendlyFileIoMessage(const std::string& messageText)
        {
            // Purpose: Translate ArkDriverClient's raw io.message into a human-readable description for the file page.
            // Input: messageText is the UTF-8/ASCII diagnostic text returned by the wrapper.
            // Returns: Chinese description; for UI display only, does not modify the original IO status field.
            if (messageText.empty())
            {
                return QStringLiteral("无额外驱动消息");
            }

            const QString kRawText = QString::fromStdString(messageText).trimmed();
            if (kRawText.isEmpty())
            {
                return QStringLiteral("无额外驱动消息");
            }
            if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该文件审计入口");
            }
            if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
                kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
            {
                return QStringLiteral("当前驱动版本尚未提供该文件审计入口");
            }
            if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
                kRawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动返回数据格式不完整，已保留当前页面其它只读证据");
            }
            if (kRawText == QStringLiteral("empty nt path"))
            {
                return QStringLiteral("缺少可传递给驱动的 NT 路径，R0 文件信息查询已跳过");
            }
            if (kRawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动已返回结构化文件审计数据");
            }
            return kRawText;
        }

        QString FileDetailDialog::fixedWideAuditText(const wchar_t* const textBuffer, const std::size_t maxChars)
        {
            // Purpose: Read the fixed-width character array from shared/driver to prevent the UI from guessing protocol fields.
            // Input: textBuffer is the protocol field's base address, maxChars is the array capacity.
            // Return: QString truncated by NUL; empty fields return <empty>.
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return QStringLiteral("<empty>");
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != L'\0')
            {
                ++length;
            }
            if (length == 0U)
            {
                return QStringLiteral("<empty>");
            }
            return QString::fromWCharArray(textBuffer, static_cast<int>(length));
        }

        QString FileDetailDialog::formatMinifilterInventoryRows(const ksword::ark::MinifilterInventoryResult& result)
        {
            // Purpose: Expand the first few actual rows of the R0 Minifilter inventory.
            // Handling: Display only Name, Altitude, Volume, Frame, object address, and owner hint.
            // Returns: Read-only text to append to the Filter topology page.
            QString content;
            const std::size_t kRowLimit = std::min<std::size_t>(result.entries.size(), 16U);
            for (std::size_t index = 0U; index < kRowLimit; ++index)
            {
                const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY& row = result.entries[index];
                content += QStringLiteral("  #%1 Filter=%2 Altitude=%3 Volume=%4 Instance=%5 VolumeBindings=%6 Frame=%7\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.filterName))
                    .arg(fixedWideAuditText(row.altitude))
                    .arg(fixedWideAuditText(row.volumeName))
                    .arg(row.instanceCount)
                    .arg(row.volumeBindingInstanceCount)
                    .arg(row.frameId);
                content += QStringLiteral("     FilterObject=%1 VolumeObject=%2 CallbackOwner=%3 OwnerStatus=%4 FieldFlags=0x%5 SourceFlags=0x%6 Status=%7\n")
                    .arg(formatHex64(row.filterObject))
                    .arg(formatHex64(row.volumeObject))
                    .arg(fixedWideAuditText(row.callbackOwnerModule))
                    .arg(formatNtStatus(row.callbackOwnerStatus))
                    .arg(row.fieldFlags, 8, 16, QChar('0'))
                    .arg(row.sourceFlags, 8, 16, QChar('0'))
                    .arg(row.status)
                    .toUpper();
            }
            if (result.entries.size() > kRowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.entries.size() - kRowLimit));
            }
            return content;
        }

        QString FileDetailDialog::formatVolumeStackAuditRows(const ksword::ark::StorageVolumeStackAuditResult& result)
        {
            // Purpose: Unwind the first few device stack lines of the R0 VolumeStack audit result.
            // Input: Return value of queryVolumeStackAudit.
            // Returns: read-only text containing DeviceObject, DriverObject, risk, and confidence.
            QString content;
            content += QStringLiteral("fvevolPresent: %1\n").arg(result.fvevolPresent);
            content += QStringLiteral("fvevolPosition: %1\n").arg(result.fvevolPosition);
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t kRowLimit = std::min<std::size_t>(result.rows.size(), 12U);
            for (std::size_t index = 0U; index < kRowLimit; ++index)
            {
                const KSWORD_ARK_VOLUME_STACK_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 StackIndex=%2 Driver=%3 Volume=%4 Confidence=%5 Risk=0x%6\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(row.stackIndex)
                    .arg(fixedWideAuditText(row.driverName))
                    .arg(fixedWideAuditText(row.volumeDeviceName))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     DeviceObject=%1 DriverObject=%2 Attached=%3 Lower=%4 Type=0x%5 Characteristics=0x%6 Status=%7 Detail=%8\n")
                    .arg(formatHex64(row.deviceObjectAddress))
                    .arg(formatHex64(row.driverObjectAddress))
                    .arg(formatHex64(row.attachedDeviceAddress))
                    .arg(formatHex64(row.lowerDeviceAddress))
                    .arg(row.deviceType, 8, 16, QChar('0'))
                    .arg(row.deviceCharacteristics, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
            }
            if (result.rows.size() > kRowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.rows.size() - kRowLimit));
            }
            return content;
        }

        QString FileDetailDialog::formatBitlockerFveAuditRows(const ksword::ark::StorageBitlockerFveAuditResult& result)
        {
            // Purpose: Expand the BitLocker/FVE security status summary, explicitly excluding key material.
            // Input: Return value of queryBitlockerFveAudit.
            // Returns: protection/conversion/lock status, protector type count, and risk text.
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t kRowLimit = std::min<std::size_t>(result.rows.size(), 8U);
            for (std::size_t index = 0U; index < kRowLimit; ++index)
            {
                const KSWORD_ARK_BITLOCKER_FVE_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 Volume=%2 FvePresent=%3 FvePosition=%4 Protection=%5 Conversion=%6 Lock=%7 Confidence=%8 Risk=0x%9\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.volumeDeviceName))
                    .arg(row.fvevolPresent)
                    .arg(row.fvevolStackPosition)
                    .arg(row.protectionStatus)
                    .arg(row.conversionStatus)
                    .arg(row.lockStatus)
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     ProtectorCounts: TPM=%1 TPM+PIN=%2 RecoveryPassword=%3 RecoveryKey=%4 StartupKey=%5 ClearOrSuspended=%6 Status=%7 Detail=%8\n")
                    .arg(row.keyProtectorTypeCountTpm)
                    .arg(row.keyProtectorTypeCountTpmPin)
                    .arg(row.keyProtectorTypeCountRecoveryPassword)
                    .arg(row.keyProtectorTypeCountRecoveryKey)
                    .arg(row.keyProtectorTypeCountStartupKey)
                    .arg(row.keyProtectorTypeCountClearOrSuspended)
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail));
            }
            return content;
        }

        QString FileDetailDialog::formatMountMgrMappingAuditRows(const ksword::ark::StorageMountMgrMappingAuditResult& result)
        {
            // Purpose: Expand MountMgr drive letter/GUID/NT device path mapping audit.
            // Input: Return value of queryMountMgrMappingAudit.
            // Returns: mapped name, risk, confidence, and detail text.
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t kRowLimit = std::min<std::size_t>(result.rows.size(), 16U);
            for (std::size_t index = 0U; index < kRowLimit; ++index)
            {
                const KSWORD_ARK_MOUNTMGR_MAPPING_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 Drive=%2 Guid=%3 NtPath=%4 Confidence=%5 Risk=0x%6 Status=%7 Detail=%8\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.driveLetter))
                    .arg(fixedWideAuditText(row.volumeGuid))
                    .arg(fixedWideAuditText(row.ntDevicePath))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
            }
            if (result.rows.size() > kRowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.rows.size() - kRowLimit));
            }
            return content;
        }

        QString FileDetailDialog::formatFilesystemIntegrityAuditRows(const ksword::ark::StorageFilesystemIntegrityAuditResult& result)
        {
            // Purpose: Unwind the Filesystem DriverObject/FastIo/Dispatch integrity audit line.
            // Input: Return value of queryFilesystemIntegrityAudit.
            // Returns: slot, target address, owner module, risk, and confidence text.
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const auto kByteText = [](const std::vector<std::uint8_t>& bytes) {
                QString text;
                for (const std::uint8_t kByte : bytes)
                {
                    if (!text.isEmpty())
                    {
                        text += QLatin1Char(' ');
                    }
                    text += QStringLiteral("%1").arg(kByte, 2, 16, QLatin1Char('0')).toUpper();
                }
                return text;
            };
            const std::size_t kRowLimit = result.rows.size();
            std::map<std::uint64_t, ks::kernel::CleanImageBaselineResult> baselineCache;
            for (std::size_t index = 0U; index < kRowLimit; ++index)
            {
                const KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW& row = result.rows[index];
                if (row.targetAddress != 0U &&
                    baselineCache.find(row.targetAddress) == baselineCache.end())
                {
                    baselineCache.emplace(
                        row.targetAddress,
                        ks::kernel::KernelCleanImageBaseline::compareAddress(
                            row.targetAddress,
                            16U));
                }
                const ks::kernel::CleanImageBaselineResult kBaseline =
                    row.targetAddress == 0U
                    ? ks::kernel::CleanImageBaselineResult{}
                    : baselineCache.at(row.targetAddress);
                content += QStringLiteral("  #%1 FsKind=%2 SlotType=%3 SlotIndex=%4 Driver=%5 Owner=%6 Confidence=%7 Risk=0x%8\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(row.fileSystemKind)
                    .arg(row.slotType)
                    .arg(row.slotIndex)
                    .arg(fixedWideAuditText(row.driverName))
                    .arg(fixedWideAuditText(row.ownerModuleName))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     DriverObject=%1 DriverStart=%2 DriverSize=0x%3 SlotAddress=%4 Target=%5 OwnerBase=%6 OwnerSize=0x%7 Status=%8 Detail=%9\n")
                    .arg(formatHex64(row.driverObjectAddress))
                    .arg(formatHex64(row.driverStart))
                    .arg(row.driverSize, 8, 16, QChar('0'))
                    .arg(formatHex64(row.slotAddress))
                    .arg(formatHex64(row.targetAddress))
                    .arg(formatHex64(row.ownerModuleBase))
                    .arg(row.ownerModuleSize, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
                content += QStringLiteral("     BaselineScope=TARGET_PROLOGUE_ONLY CleanImageBaseline=%1 IdentityMatched=%2 CodeIntegrityTrusted=%3 SigningLevel=%4 Relocated=%5 Differs=%6 Image=%7 RVA=0x%8\n")
                    .arg(kBaseline.available ? QStringLiteral("AVAILABLE") : QStringLiteral("UNAVAILABLE"))
                    .arg(kBaseline.identityMatched ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(kBaseline.codeIntegrityTrusted ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(kBaseline.signingLevel)
                    .arg(kBaseline.relocationApplied ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(kBaseline.available
                        ? (kBaseline.differs ? QStringLiteral("YES") : QStringLiteral("NO"))
                        : QStringLiteral("UNKNOWN"))
                    .arg(kBaseline.imagePath.isEmpty() ? QStringLiteral("<unavailable>") : kBaseline.imagePath)
                    .arg(kBaseline.relativeVirtualAddress, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     SHA256=%1\n     SigningThumbprint=%2\n     ObservedBytes=%3\n     CleanBytes=%4\n     BaselineDetail=%5\n")
                    .arg(kBaseline.imageSha256.isEmpty() ? QStringLiteral("<unavailable>") : kBaseline.imageSha256)
                    .arg(kBaseline.signingThumbprint.isEmpty() ? QStringLiteral("<unavailable>") : kBaseline.signingThumbprint)
                    .arg(kByteText(kBaseline.observedBytes))
                    .arg(kByteText(kBaseline.cleanBytes))
                    .arg(kBaseline.statusText);
            }
            return content;
        }

        QString FileDetailDialog::fileTimeToText(const std::int64_t fileTimeValue)
        {
            // Purpose: Convert Windows FILETIME semantics (100ns timestamps) to local time text.
            // Returns: Human-readable time; 0 indicates unavailable.
            if (fileTimeValue <= 0)
            {
                return QStringLiteral("<Unavailable>");
            }

            constexpr std::int64_t kWindowsToUnix100Ns = 116444736000000000LL;
            const std::int64_t kUnixMilliseconds = (fileTimeValue - kWindowsToUnix100Ns) / 10000LL;
            if (kUnixMilliseconds <= 0)
            {
                return QStringLiteral("<Invalid:%1>").arg(fileTimeValue);
            }
            // Qt 6.9 deprecated the Qt::TimeSpec overload; explicitly use the UTC timezone
            // here, then convert to local time to preserve the FILETIME display semantics.
            return QDateTime::fromMSecsSinceEpoch(kUnixMilliseconds, QTimeZone::UTC)
                .toLocalTime()
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        }

        QString FileDetailDialog::fileAttributesToText(const std::uint32_t attributes)
        {
            // Purpose: Decompose FILE_ATTRIBUTE_* flags to make R0 and R3 attribute differences readable.
            // Returns: list of attribute names; returns NORMAL/0 if no explicit bits are set.
            QStringList parts;
            if ((attributes & FILE_ATTRIBUTE_READONLY) != 0U) parts << QStringLiteral("READONLY");
            if ((attributes & FILE_ATTRIBUTE_HIDDEN) != 0U) parts << QStringLiteral("HIDDEN");
            if ((attributes & FILE_ATTRIBUTE_SYSTEM) != 0U) parts << QStringLiteral("SYSTEM");
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) parts << QStringLiteral("DIRECTORY");
            if ((attributes & FILE_ATTRIBUTE_ARCHIVE) != 0U) parts << QStringLiteral("ARCHIVE");
            if ((attributes & FILE_ATTRIBUTE_DEVICE) != 0U) parts << QStringLiteral("DEVICE");
            if ((attributes & FILE_ATTRIBUTE_NORMAL) != 0U) parts << QStringLiteral("NORMAL");
            if ((attributes & FILE_ATTRIBUTE_TEMPORARY) != 0U) parts << QStringLiteral("TEMPORARY");
            if ((attributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0U) parts << QStringLiteral("SPARSE_FILE");
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) parts << QStringLiteral("REPARSE_POINT");
            if ((attributes & FILE_ATTRIBUTE_COMPRESSED) != 0U) parts << QStringLiteral("COMPRESSED");
            if ((attributes & FILE_ATTRIBUTE_OFFLINE) != 0U) parts << QStringLiteral("OFFLINE");
            if ((attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) != 0U) parts << QStringLiteral("NOT_CONTENT_INDEXED");
            if ((attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0U) parts << QStringLiteral("ENCRYPTED");
            if ((attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0U) parts << QStringLiteral("INTEGRITY_STREAM");
            if ((attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) != 0U) parts << QStringLiteral("NO_SCRUB_DATA");
            if (parts.isEmpty())
            {
                parts << QStringLiteral("0");
            }
            return QStringLiteral("0x%1 (%2)")
                .arg(attributes, 8, 16, QChar('0'))
                .arg(parts.join(QStringLiteral("|")))
                .toUpper();
        }

        QString FileDetailDialog::fileInfoStatusText(const std::uint32_t status)
        {
            // Purpose: translate shared protocol status codes to UI text.
            // Return: Status name.
            switch (status)
            {
            case KSWORD_ARK_FILE_INFO_STATUS_OK:
                return QStringLiteral("OK");
            case KSWORD_ARK_FILE_INFO_STATUS_PARTIAL:
                return QStringLiteral("Partial");
            case KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED:
                return QStringLiteral("Open Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED:
                return QStringLiteral("Basic Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED:
                return QStringLiteral("Standard Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED:
                return QStringLiteral("Object Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED:
                return QStringLiteral("Name Failed");
            default:
                return QStringLiteral("Unavailable");
            }
        }

        ksword::ark::FileInfoQueryResult FileDetailDialog::queryR0FileInfo(const QFileInfo& info, const QString& ntPathText)
        {
            // Purpose: Invoke R0 file basic information query via ArkDriverClient.
            // Return: ok=false if the driver is unavailable; the regular page automatically falls back to R3 display.
            ksword::ark::FileInfoQueryResult result{};
            if (ntPathText.trimmed().isEmpty())
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_PARAMETER;
                result.io.message = "empty nt path";
                return result;
            }

            unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL;
            if (info.isDir())
            {
                flags |= KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY;
            }

            const ksword::ark::DriverClient kDriverClient;
            return kDriverClient.queryFileInfo(ntPathText.toStdWString(), flags);
        }

        QString FileDetailDialog::formatR0FileInfoText(const ksword::ark::FileInfoQueryResult& result) const
        {
            // Purpose: Generate R0 file info page text.
            // Returns: Multi-line text containing status, size, timestamp, object diagnostic address, and failure reason.
            QString content;
            if (!result.io.ok)
            {
                content += QStringLiteral("状态: Unavailable\n");
                content += QStringLiteral("原因: %1\n").arg(friendlyFileIoMessage(result.io.message));
                content += QStringLiteral("Win32错误: %1\n").arg(result.io.win32Error);
                return content;
            }

            content += QStringLiteral("协议版本: %1\n").arg(result.version);
            content += QStringLiteral("查询状态: %1 (%2)\n").arg(fileInfoStatusText(result.queryStatus)).arg(result.queryStatus);
            content += QStringLiteral("字段标志: 0x%1\n").arg(result.fieldFlags, 8, 16, QChar('0')).toUpper();
            content += QStringLiteral("OpenStatus: %1\n").arg(formatNtStatus(result.openStatus));
            content += QStringLiteral("BasicStatus: %1\n").arg(formatNtStatus(result.basicStatus));
            content += QStringLiteral("StandardStatus: %1\n").arg(formatNtStatus(result.standardStatus));
            content += QStringLiteral("ObjectStatus: %1\n").arg(formatNtStatus(result.objectStatus));
            content += QStringLiteral("NameStatus: %1\n").arg(formatNtStatus(result.nameStatus));
            content += QStringLiteral("大小(EndOfFile): %1 字节\n").arg(static_cast<qlonglong>(result.endOfFile));
            content += QStringLiteral("分配大小: %1 字节\n").arg(static_cast<qlonglong>(result.allocationSize));
            content += QStringLiteral("属性: %1\n").arg(fileAttributesToText(result.fileAttributes));
            content += QStringLiteral("创建时间: %1\n").arg(fileTimeToText(result.creationTime));
            content += QStringLiteral("最后访问: %1\n").arg(fileTimeToText(result.lastAccessTime));
            content += QStringLiteral("最后写入: %1\n").arg(fileTimeToText(result.lastWriteTime));
            content += QStringLiteral("ChangeTime: %1\n").arg(fileTimeToText(result.changeTime));
            content += QStringLiteral("FileObject: %1\n").arg(formatHex64(result.fileObjectAddress));
            content += QStringLiteral("SectionObjectPointers: %1\n").arg(formatHex64(result.sectionObjectPointersAddress));
            content += QStringLiteral("DataSectionObject: %1\n").arg(formatHex64(result.dataSectionObjectAddress));
            content += QStringLiteral("ImageSectionObject: %1\n").arg(formatHex64(result.imageSectionObjectAddress));
            content += QStringLiteral("R0说明: %1\n").arg(friendlyFileIoMessage(result.io.message));
            return content;
        }

        void FileDetailDialog::startR0FileInfoLoad(const QFileInfo& info, const QString& ntPathText)
        {
            // Purpose: Read R0 file basic information in the background to avoid blocking the property window during regular page construction.
            // Input: info/ntPathText is the query target; UI data is stored in members to enable full redraw during language switching.
            // Processing: Worker thread calls ArkDriverClient; UI thread saves results and rebuilds the body according to the current language.
            // Returns: None; results are automatically discarded after the dialog closes or controls are released.
            if (generalPropertyTree_ == nullptr)
            {
                return;
            }

            const std::uint64_t kLoadGeneration = ++generalR0LoadGeneration_;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, info, ntPathText, kLoadGeneration]()
                {
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    const ksword::ark::FileInfoQueryResult kR0Info =
                        FileDetailDialog::queryR0FileInfo(info, ntPathText);
                    targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, kR0Info, kLoadGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->generalR0LoadGeneration_ != kLoadGeneration)
                            {
                                return;
                            }

                            guardThis->generalR0Info_ = kR0Info;
                            guardThis->generalR0Loaded_ = true;
                            guardThis->refreshGeneralTab();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }
}
