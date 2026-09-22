#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // enumerateProcessesByR0Driver:
    // - Only retrieve the kernel-side process list via ArkDriverClient when the KswordARK control device is ready.
    // - For R3 refresh when the driver is unloaded, no enumeration IOCTL is sent, and no R0 permission prompt is triggered.
    // - Output: data usable for comparing the 'R3 list vs R0 list' discrepancy.
    bool enumerateProcessesByR0Driver(
        std::vector<KernelProcessSnapshotEntry>* const processListOut,
        std::string* const detailTextOut)
    {
        if (processListOut == nullptr)
        {
            return false;
        }
        processListOut->clear();
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        const ksword::ark::DriverClient kDriverClient;
        ksword::ark::DriverHandle driverHandle = kDriverClient.openSilently();
        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "R0 driver device is not ready; kernel process comparison skipped";
            }
            return false;
        }

        const ksword::ark::ProcessEnumResult kEnumResult = kDriverClient.enumerateProcesses(
            KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE,
            &driverHandle);
        if (!kEnumResult.io.ok)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = processDockIoMessageStdString(kEnumResult.io.message);
            }
            return false;
        }

        processListOut->reserve(kEnumResult.entries.size());
        for (const ksword::ark::ProcessEntry& entry : kEnumResult.entries)
        {
            KernelProcessSnapshotEntry processEntry{};
            processEntry.processId = entry.processId;
            processEntry.parentProcessId = entry.parentProcessId;
            processEntry.flags = entry.flags;
            processEntry.sessionId = entry.sessionId;
            processEntry.fieldFlags = entry.fieldFlags;
            processEntry.r0Status = entry.r0Status;
            processEntry.sessionSource = entry.sessionSource;
            processEntry.protection = entry.protection;
            processEntry.signatureLevel = entry.signatureLevel;
            processEntry.sectionSignatureLevel = entry.sectionSignatureLevel;
            processEntry.protectionSource = entry.protectionSource;
            processEntry.signatureLevelSource = entry.signatureLevelSource;
            processEntry.sectionSignatureLevelSource = entry.sectionSignatureLevelSource;
            processEntry.objectTableSource = entry.objectTableSource;
            processEntry.sectionObjectSource = entry.sectionObjectSource;
            processEntry.imagePathSource = entry.imagePathSource;
            processEntry.protectionOffset = entry.protectionOffset;
            processEntry.signatureLevelOffset = entry.signatureLevelOffset;
            processEntry.sectionSignatureLevelOffset = entry.sectionSignatureLevelOffset;
            processEntry.objectTableOffset = entry.objectTableOffset;
            processEntry.sectionObjectOffset = entry.sectionObjectOffset;
            processEntry.objectTableAddress = entry.objectTableAddress;
            processEntry.sectionObjectAddress = entry.sectionObjectAddress;
            processEntry.dynDataCapabilityMask = entry.dynDataCapabilityMask;
            processEntry.creationTime100ns = entry.creationTime100ns;
            processEntry.imageName = entry.imageName;
            processEntry.imagePath = entry.imagePath;
            processListOut->push_back(std::move(processEntry));
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(kEnumResult.io.message);
        }
        return true;
    }

    // mergeKernelProcessExtension:
    // - Merge Phase-2 EPROCESS extension fields obtained from R0 enumeration into the R3 process record.
    // - Base path/command line primarily rely on user-mode public APIs; R0 paths serve only as supplementary diagnostic fields.
    void mergeKernelProcessExtension(
        ks::process::ProcessRecord& processRecord,
        const KernelProcessSnapshotEntry& kernelProcess)
    {
        processRecord.r0Flags = kernelProcess.flags;
        processRecord.r0FieldFlags = kernelProcess.fieldFlags;
        processRecord.r0Status = kernelProcess.r0Status;
        processRecord.r0DynDataCapabilityMask = kernelProcess.dynDataCapabilityMask;
        processRecord.r0ImagePath = kernelProcess.imagePath;

        if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT) != 0U)
        {
            processRecord.sessionId = kernelProcess.sessionId;
        }

        processRecord.r0Protection = kernelProcess.protection;
        processRecord.r0SignatureLevel = kernelProcess.signatureLevel;
        processRecord.r0SectionSignatureLevel = kernelProcess.sectionSignatureLevel;
        processRecord.r0SessionSource = kernelProcess.sessionSource;
        processRecord.r0ImagePathSource = kernelProcess.imagePathSource;
        processRecord.r0ProtectionSource = kernelProcess.protectionSource;
        processRecord.r0SignatureLevelSource = kernelProcess.signatureLevelSource;
        processRecord.r0SectionSignatureLevelSource = kernelProcess.sectionSignatureLevelSource;
        processRecord.r0ObjectTableSource = kernelProcess.objectTableSource;
        processRecord.r0SectionObjectSource = kernelProcess.sectionObjectSource;
        processRecord.r0ProtectionOffset = kernelProcess.protectionOffset;
        processRecord.r0SignatureLevelOffset = kernelProcess.signatureLevelOffset;
        processRecord.r0SectionSignatureLevelOffset = kernelProcess.sectionSignatureLevelOffset;
        processRecord.r0ObjectTableOffset = kernelProcess.objectTableOffset;
        processRecord.r0SectionObjectOffset = kernelProcess.sectionObjectOffset;
        processRecord.r0ObjectTableAddress = kernelProcess.objectTableAddress;
        processRecord.r0SectionObjectAddress = kernelProcess.sectionObjectAddress;
    }

    bool enrichProcessRecordWithR0ExtensionByPid(
        ks::process::ProcessRecord& processRecord,
        std::string* const detailTextOut)
    {
        // processRecord usage: The R3 process record currently selected by the caller or about to have its details opened.
        // Return value: true indicates that a process with the same PID was found via R0 enumeration and Phase-2 extension fields were merged.
        std::vector<KernelProcessSnapshotEntry> kernelProcessList;
        std::string queryDetailText;
        const bool kQueryOk = enumerateProcessesByR0Driver(&kernelProcessList, &queryDetailText);
        if (!kQueryOk)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryDetailText.empty()
                    ? std::string("query kernel process list failed")
                    : queryDetailText;
            }
            return false;
        }

        for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
        {
            if (kernelProcess.processId != processRecord.pid)
            {
                continue;
            }

            mergeKernelProcessExtension(processRecord, kernelProcess);
            if (processRecord.processName.empty() && !kernelProcess.imageName.empty())
            {
                processRecord.processName = kernelProcess.imageName;
            }
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryDetailText;
            }
            return true;
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = "target pid not returned by R0 process enumeration";
        }
        return false;
    }
}
