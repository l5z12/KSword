/*++

Module Name:

    hwid_dispatch_hooks.c

Abstract:

    Dispatch-hook completion helpers for the HWID page.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "hwid_dispatch_hooks.h"
#include "../../platform/pool_compat.h"

#include <ata.h>
#include <mountdev.h>
#include <mountmgr.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntstrsafe.h>

NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG seed
    );

typedef struct KswHwidCompletionContext
{
    PVOID systemBuffer;
    PVOID userBuffer;
    PMDL mdlAddress;
    ULONG bufferLength;
    ULONG ioControlCode;
    ULONG targetFlag;
    UCHAR oldControl;
    PVOID oldContext;
    PIO_COMPLETION_ROUTINE oldRoutine;
    KSWORD_ARK_HWID_DISPATCH_PROFILE profile;
} KswHwidCompletionContext, *PkswHwidCompletionContext;

typedef struct KswHwidIdsector
{
    USHORT wGenConfig;
    USHORT wNumCyls;
    USHORT wReserved;
    USHORT wNumHeads;
    USHORT wBytesPerTrack;
    USHORT wBytesPerSector;
    USHORT wSectorsPerTrack;
    USHORT wVendorUnique[3];
    CHAR sSerialNumber[20];
    USHORT wBufferType;
    USHORT wBufferSize;
    USHORT wECCSize;
    CHAR sFirmwareRev[8];
    CHAR sModelNumber[40];
    USHORT wMoreVendorUnique;
    USHORT wDoubleWordIO;
    USHORT wCapabilities;
    USHORT wReserved1;
    USHORT wPIOTiming;
    USHORT wDMATiming;
    USHORT wBS;
    USHORT wNumCurrentCyls;
    USHORT wNumCurrentHeads;
    USHORT wNumCurrentSectorsPerTrack;
    ULONG ulCurrentSectorCapacity;
    USHORT wMultSectorStuff;
    ULONG ulTotalAddressableSectors;
    USHORT wSingleWordDMA;
    USHORT wMultiWordDMA;
    UCHAR bThisReserved[128];
} KswHwidIdsector, *PkswHwidIdsector;

#define KSW_HWID_POOL_TAG 'dHwK'
#define KSW_HWID_NVIDIA_SMIL_IOCTL 0x8DE0008UL
#define KSW_HWID_NVIDIA_SMIL_MAX_BYTES 512UL
#define KSW_HWID_NSI_PROXY_ARP_IOCTL 0x0012001BUL
#define KSW_HWID_ARP_TABLE_IOCTL 0x0012000FUL

static ULONG
kswordArkHwidBoundedAnsiLength(
    _In_reads_bytes_(textBytes) const CHAR* text,
    _In_ ULONG textBytes
    )
{
    ULONG textIndex = 0UL;

    /* Note: Fixed-length hardware strings may not be NUL-terminated, so scan only within bounds here. */
    if (text == NULL || textBytes == 0UL) {
        return 0UL;
    }

    for (textIndex = 0UL; textIndex < textBytes; ++textIndex) {
        if (text[textIndex] == '\0') {
            break;
        }
    }

    return textIndex;
}

static ULONG
kswordArkHwidWideToAnsi(
    _In_reads_(sourceChars) const WCHAR* source,
    _In_ ULONG sourceChars,
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ ULONG destinationBytes
    )
{
    ULONG sourceIndex = 0UL;
    ULONG copiedBytes = 0UL;

    /* Note: Protocol uses WCHAR; driver queries mostly return ASCII fields, so this performs conservative narrowing. */
    if (source == NULL || destination == NULL || destinationBytes == 0UL) {
        return 0UL;
    }

    for (sourceIndex = 0UL; sourceIndex < sourceChars && copiedBytes + 1UL < destinationBytes; ++sourceIndex) {
        WCHAR currentChar = source[sourceIndex];
        if (currentChar == L'\0') {
            break;
        }
        destination[copiedBytes] = currentChar <= 0x7fU ? (CHAR)currentChar : '?';
        ++copiedBytes;
    }

    destination[copiedBytes] = '\0';
    return copiedBytes;
}

static VOID
kswordArkHwidFillRandomAscii(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ ULONG destinationBytes
    )
{
    static const CHAR kAlphabet[] = "QWERTYUIOPASDFGHJKLZXCVBNMzxcvbnmasdfghjklqwertyuiop0123456789";
    LARGE_INTEGER tickCount;
    ULONG seed = 0UL;
    ULONG byteIndex = 0UL;

    /* Note: Randomization applies only to the return buffer; physical devices or memory tables are not modified. */
    if (destination == NULL || destinationBytes == 0UL) {
        return;
    }

    KeQueryTickCount(&tickCount);
    seed = (ULONG)(tickCount.LowPart ^ tickCount.HighPart ^ (ULONG)(ULONG_PTR)destination);
    for (byteIndex = 0UL; byteIndex < destinationBytes; ++byteIndex) {
        destination[byteIndex] = kAlphabet[RtlRandomEx(&seed) % (RTL_NUMBER_OF(kAlphabet) - 1U)];
    }
}

static VOID
kswordArkHwidFillRandomGuid(
    _Out_ GUID* guid
    )
{
    LARGE_INTEGER tickCount;
    ULONG seed = 0UL;
    ULONG* guidWords = (ULONG*)guid;
    ULONG wordIndex = 0UL;

    /* Note: GPT GUID randomization only rewrites the GUID bytes in the output of the current IOCTL. */
    if (guid == NULL) {
        return;
    }

    KeQueryTickCount(&tickCount);
    seed = (ULONG)(tickCount.LowPart ^ tickCount.HighPart ^ (ULONG)(ULONG_PTR)guid);
    for (wordIndex = 0UL; wordIndex < (sizeof(*guid) / sizeof(ULONG)); ++wordIndex) {
        guidWords[wordIndex] = RtlRandomEx(&seed);
    }
}

static VOID
kswordArkHwidRewriteFixedAnsiField(
    _Out_writes_bytes_(fieldBytes) CHAR* field,
    _In_ ULONG fieldBytes,
    _In_reads_(KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) const WCHAR* customText,
    _In_ ULONG diskMode
    )
{
    CHAR temporaryText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    ULONG copiedBytes = 0UL;

    /* Note: ATA/SMART fields are fixed-length; do not rely on strlen to read, as it may cause buffer overruns. */
    if (field == NULL || fieldBytes == 0UL) {
        return;
    }

    if (diskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM) {
        kswordArkHwidFillRandomAscii(field, fieldBytes);
        return;
    }

    RtlZeroMemory(field, fieldBytes);
    if (diskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM) {
        copiedBytes = kswordArkHwidWideToAnsi(
            customText,
            KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
            temporaryText,
            sizeof(temporaryText));
        if (copiedBytes != 0UL) {
            RtlCopyMemory(field, temporaryText, min(copiedBytes, fieldBytes));
        }
    }
}

static VOID
kswordArkHwidRewriteOffsetAnsiField(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ ULONG fieldOffset,
    _In_reads_(KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) const WCHAR* customText,
    _In_ ULONG diskMode
    )
{
    CHAR temporaryText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    CHAR* fieldText = NULL;
    ULONG availableBytes = 0UL;
    ULONG fieldBytes = 0UL;
    ULONG copiedBytes = 0UL;

    /* Note: STORAGE_DEVICE_DESCRIPTOR uses offset values to locate NUL-terminated strings. */
    if (buffer == NULL || fieldOffset == 0UL || fieldOffset >= bufferBytes) {
        return;
    }

    fieldText = (CHAR*)(buffer + fieldOffset);
    availableBytes = bufferBytes - fieldOffset;
    fieldBytes = kswordArkHwidBoundedAnsiLength(fieldText, availableBytes);
    if (fieldBytes == 0UL || fieldBytes >= availableBytes) {
        return;
    }

    if (diskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM) {
        kswordArkHwidFillRandomAscii(fieldText, fieldBytes);
        return;
    }

    RtlZeroMemory(fieldText, fieldBytes);
    if (diskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM) {
        copiedBytes = kswordArkHwidWideToAnsi(
            customText,
            KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
            temporaryText,
            sizeof(temporaryText));
        if (copiedBytes != 0UL) {
            RtlCopyMemory(fieldText, temporaryText, min(copiedBytes, fieldBytes));
        }
    }
}

static ULONG
kswordArkHwidCompletionLength(
    _In_ const KswHwidCompletionContext* context,
    _In_ PIRP irp
    )
{
    ULONG_PTR informationBytes = 0U;

    /* Note: Prioritize IoStatus.Information; fall back to the requested output length if not set. */
    if (context == NULL || irp == NULL) {
        return 0UL;
    }

    informationBytes = irp->IoStatus.Information;
    if (informationBytes != 0U && informationBytes < (ULONG_PTR)context->bufferLength) {
        return (ULONG)informationBytes;
    }

    return context->bufferLength;
}

static VOID
kswordArkHwidRewriteStorageDescriptor(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PSTORAGE_DEVICE_DESCRIPTOR descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)buffer;

    /* Note: The disk serial number path only handles the output descriptor for StorageDeviceProperty. */
    if (buffer == NULL || profile == NULL || bufferBytes < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return;
    }

    kswordArkHwidRewriteOffsetAnsiField(buffer, bufferBytes, descriptor->SerialNumberOffset, profile->diskSerial, profile->diskMode);
    kswordArkHwidRewriteOffsetAnsiField(buffer, bufferBytes, descriptor->ProductIdOffset, profile->diskProduct, profile->diskMode);
    kswordArkHwidRewriteOffsetAnsiField(buffer, bufferBytes, descriptor->ProductRevisionOffset, profile->diskRevision, profile->diskMode);
}

static VOID
kswordArkHwidRewriteAtaPassThrough(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PATA_PASS_THROUGH_EX passThrough = (PATA_PASS_THROUGH_EX)buffer;
    PIDENTIFY_DEVICE_DATA identity = NULL;
    ULONG dataOffset = 0UL;

    /* Note: ATA identify data resides in a fixed-length structure pointed to by DataBufferOffset. */
    if (buffer == NULL || profile == NULL || bufferBytes < sizeof(ATA_PASS_THROUGH_EX)) {
        return;
    }

    dataOffset = (ULONG)passThrough->DataBufferOffset;
    if (dataOffset == 0UL || dataOffset >= bufferBytes || bufferBytes - dataOffset < sizeof(IDENTIFY_DEVICE_DATA)) {
        return;
    }

    identity = (PIDENTIFY_DEVICE_DATA)(buffer + dataOffset);
    kswordArkHwidRewriteFixedAnsiField((CHAR*)identity->SerialNumber, sizeof(identity->SerialNumber), profile->diskSerial, profile->diskMode);
    kswordArkHwidRewriteFixedAnsiField((CHAR*)identity->ModelNumber, sizeof(identity->ModelNumber), profile->diskProduct, profile->diskMode);
    kswordArkHwidRewriteFixedAnsiField((CHAR*)identity->FirmwareRevision, sizeof(identity->FirmwareRevision), profile->diskRevision, profile->diskMode);
}

static VOID
kswordArkHwidRewriteSmartData(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PSENDCMDOUTPARAMS smartOutput = (PSENDCMDOUTPARAMS)buffer;
    PkswHwidIdsector identifyData = NULL;
    ULONG requiredBytes = FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer) + sizeof(KswHwidIdsector);

    /* Note: The identify sector returned by SMART_RCV_DRIVE_DATA uses the legacy fixed-length layout. */
    if (buffer == NULL || profile == NULL || bufferBytes < requiredBytes) {
        return;
    }

    identifyData = (PkswHwidIdsector)smartOutput->bBuffer;
    kswordArkHwidRewriteFixedAnsiField(identifyData->sSerialNumber, sizeof(identifyData->sSerialNumber), profile->diskSerial, profile->diskMode);
    kswordArkHwidRewriteFixedAnsiField(identifyData->sModelNumber, sizeof(identifyData->sModelNumber), profile->diskProduct, profile->diskMode);
    kswordArkHwidRewriteFixedAnsiField(identifyData->sFirmwareRev, sizeof(identifyData->sFirmwareRev), profile->diskRevision, profile->diskMode);
}

static VOID
kswordArkHwidRewritePartitionBuffer(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ ULONG ioControlCode,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PPARTITION_INFORMATION_EX partitionInfo = (PPARTITION_INFORMATION_EX)buffer;
    PDRIVE_LAYOUT_INFORMATION_EX layoutInfo = (PDRIVE_LAYOUT_INFORMATION_EX)buffer;

    /* Note: partmgr path randomizes only the GPT GUID in the query output. */
    if (buffer == NULL || profile == NULL ||
        (profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_DISK_GUID_RANDOM) == 0UL) {
        return;
    }

    if (ioControlCode == IOCTL_DISK_GET_PARTITION_INFO_EX &&
        bufferBytes >= sizeof(PARTITION_INFORMATION_EX) &&
        partitionInfo->PartitionStyle == PARTITION_STYLE_GPT) {
        kswordArkHwidFillRandomGuid(&partitionInfo->Gpt.PartitionId);
    }
    else if (ioControlCode == IOCTL_DISK_GET_DRIVE_LAYOUT_EX &&
        bufferBytes >= sizeof(DRIVE_LAYOUT_INFORMATION_EX) &&
        layoutInfo->PartitionStyle == PARTITION_STYLE_GPT) {
        kswordArkHwidFillRandomGuid(&layoutInfo->Gpt.DiskId);
    }
}

static VOID
kswordArkHwidRewriteMountBuffer(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ ULONG ioControlCode,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PMOUNTMGR_MOUNT_POINTS mountPoints = (PMOUNTMGR_MOUNT_POINTS)buffer;
    PMOUNTDEV_UNIQUE_ID uniqueId = (PMOUNTDEV_UNIQUE_ID)buffer;
    ULONG pointIndex = 0UL;
    ULONG requiredBytes = 0UL;

    /* Note: MountMgr path only clears the return value length field, not the volume boot sector. */
    if (buffer == NULL || profile == NULL ||
        (profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_VOLUME_ID_CLEAN) == 0UL) {
        return;
    }

    if (ioControlCode == IOCTL_MOUNTMGR_QUERY_POINTS && bufferBytes >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
        if (mountPoints->NumberOfMountPoints >
            ((MAXULONG - FIELD_OFFSET(MOUNTMGR_MOUNT_POINTS, MountPoints)) / sizeof(MOUNTMGR_MOUNT_POINT))) {
            return;
        }
        requiredBytes = FIELD_OFFSET(MOUNTMGR_MOUNT_POINTS, MountPoints) +
            (mountPoints->NumberOfMountPoints * sizeof(MOUNTMGR_MOUNT_POINT));
        if (requiredBytes > bufferBytes) {
            return;
        }
        for (pointIndex = 0UL; pointIndex < mountPoints->NumberOfMountPoints; ++pointIndex) {
            mountPoints->MountPoints[pointIndex].UniqueIdLength = 0U;
            mountPoints->MountPoints[pointIndex].SymbolicLinkNameLength = 0U;
        }
    }
    else if (ioControlCode == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID && bufferBytes >= sizeof(MOUNTDEV_UNIQUE_ID)) {
        uniqueId->UniqueIdLength = 0U;
    }
}

static VOID
kswordArkHwidRewriteNvidiaBuffer(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    static const CHAR kGpuPrefix[] = "GPU-";
    CHAR replacementText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    ULONG replacementBytes = 0UL;
    ULONG scanIndex = 0UL;
    ULONG writeBytes = 0UL;

    /* Note: NVIDIA SMIL paths replace only the GPU- prefix text in the returned buffer. */
    if (buffer == NULL || profile == NULL || bufferBytes <= sizeof(kGpuPrefix)) {
        return;
    }

    replacementBytes = kswordArkHwidWideToAnsi(
        profile->gpuSerial,
        KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
        replacementText,
        sizeof(replacementText));
    if (replacementBytes == 0UL) {
        kswordArkHwidFillRandomAscii(replacementText, 16UL);
        replacementText[16] = '\0';
        replacementBytes = 16UL;
    }

    for (scanIndex = 0UL; scanIndex + sizeof(kGpuPrefix) < bufferBytes; ++scanIndex) {
        if (RtlCompareMemory(buffer + scanIndex, kGpuPrefix, sizeof(kGpuPrefix) - 1U) == sizeof(kGpuPrefix) - 1U) {
            writeBytes = min(replacementBytes, bufferBytes - scanIndex - (ULONG)(sizeof(kGpuPrefix) - 1U));
            RtlCopyMemory(buffer + scanIndex + sizeof(kGpuPrefix) - 1U, replacementText, writeBytes);
            break;
        }
    }
}

static VOID
kswordArkHwidRewriteNsiBuffer(
    _Inout_updates_bytes_(bufferBytes) UCHAR* buffer,
    _In_ ULONG bufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    /* Note: NSI/ARP path only clears the returned table when the user selects ARP cleanup. */
    if (buffer == NULL || bufferBytes == 0UL || profile == NULL ||
        (profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_ARP_TABLE_CLEAN) == 0UL) {
        return;
    }

    RtlZeroMemory(buffer, bufferBytes);
}

static VOID
kswordArkHwidRewriteSystemBuffer(
    _In_ const KswHwidCompletionContext* context,
    _In_ PIRP irp
    )
{
    UCHAR* buffer = NULL;
    ULONG bufferBytes = 0UL;

    /* Note: Most target IOCTLs use METHOD_BUFFERED; prioritize SystemBuffer. */
    if (context == NULL || irp == NULL || context->systemBuffer == NULL || !NT_SUCCESS(irp->IoStatus.Status)) {
        return;
    }

    buffer = (UCHAR*)context->systemBuffer;
    bufferBytes = kswordArkHwidCompletionLength(context, irp);
    if (bufferBytes == 0UL) {
        return;
    }

    if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_DISK) {
        if (context->ioControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
            kswordArkHwidRewriteStorageDescriptor(buffer, bufferBytes, &context->profile);
        }
        else if (context->ioControlCode == IOCTL_ATA_PASS_THROUGH) {
            kswordArkHwidRewriteAtaPassThrough(buffer, bufferBytes, &context->profile);
        }
        else if (context->ioControlCode == SMART_RCV_DRIVE_DATA) {
            kswordArkHwidRewriteSmartData(buffer, bufferBytes, &context->profile);
        }
    }
    else if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR) {
        kswordArkHwidRewritePartitionBuffer(buffer, bufferBytes, context->ioControlCode, &context->profile);
    }
    else if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR) {
        kswordArkHwidRewriteMountBuffer(buffer, bufferBytes, context->ioControlCode, &context->profile);
    }
    else if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
        kswordArkHwidRewriteNsiBuffer(buffer, bufferBytes, &context->profile);
    }
}

static VOID
kswordArkHwidRewriteDirectOrUserBuffer(
    _In_ const KswHwidCompletionContext* context,
    _In_ PIRP irp
    )
{
    UCHAR* buffer = NULL;
    ULONG bufferBytes = 0UL;

    /* Note: Certain NVIDIA/NSI paths may return MDL or UserBuffer; access must be protected by exception handling. */
    if (context == NULL || irp == NULL || !NT_SUCCESS(irp->IoStatus.Status)) {
        return;
    }

    bufferBytes = kswordArkHwidCompletionLength(context, irp);
    if (bufferBytes == 0UL) {
        return;
    }

    if (context->mdlAddress != NULL) {
        buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(context->mdlAddress, NormalPagePriority);
        if (buffer != NULL) {
            if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
                kswordArkHwidRewriteNvidiaBuffer(buffer, min(bufferBytes, KSW_HWID_NVIDIA_SMIL_MAX_BYTES), &context->profile);
            }
            else if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
                kswordArkHwidRewriteNsiBuffer(buffer, bufferBytes, &context->profile);
            }
            return;
        }
    }

    if (context->userBuffer != NULL &&
        (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA ||
         context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY)) {
        PEPROCESS requestorProcess = NULL;
        KAPC_STATE apcState;
        BOOLEAN attached = FALSE;

        /* Completion routines can run at DISPATCH_LEVEL; user address probing and attachment are only allowed at <= APC_LEVEL. */
        if (KeGetCurrentIrql() > APC_LEVEL) {
            return;
        }

        if (irp->RequestorMode != KernelMode) {
            requestorProcess = IoGetRequestorProcess(irp);
            if (requestorProcess == NULL) {
                return;
            }
            if (requestorProcess != PsGetCurrentProcess()) {
                KeStackAttachProcess(requestorProcess, &apcState);
                attached = TRUE;
            }
        }

        __try {
            ULONG writableBytes = context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA ?
                min(bufferBytes, KSW_HWID_NVIDIA_SMIL_MAX_BYTES) : bufferBytes;
            if (irp->RequestorMode != KernelMode) {
                ProbeForWrite(context->userBuffer, writableBytes, sizeof(UCHAR));
            }
            buffer = (UCHAR*)context->userBuffer;
            if (context->targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
                kswordArkHwidRewriteNvidiaBuffer(buffer, writableBytes, &context->profile);
            }
            else {
                kswordArkHwidRewriteNsiBuffer(buffer, writableBytes, &context->profile);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NOTHING;
        }

        if (attached != FALSE) {
            KeUnstackDetachProcess(&apcState);
        }
    }
}

static NTSTATUS
kswordArkHwidCompletionRoutine(
    _In_ PDEVICE_OBJECT device,
    _Inout_ PIRP irp,
    _In_opt_ PVOID context
    )
{
    PkswHwidCompletionContext completionContext = (PkswHwidCompletionContext)context;
    PIO_COMPLETION_ROUTINE oldRoutine = NULL;
    PVOID oldContext = NULL;
    UCHAR oldControl = 0U;
    BOOLEAN callOldRoutine = FALSE;
    NTSTATUS completionStatus = STATUS_SUCCESS;

    /* Note: The completion routine first rewrites the return buffer, then restores and calls the original completion routine. */
    if (completionContext != NULL) {
        oldRoutine = completionContext->oldRoutine;
        oldContext = completionContext->oldContext;
        oldControl = completionContext->oldControl;
        /*
         * Note: Rewriting is performed only when the request succeeds. For failed or cancelled IRPs, the output buffer content is meaningless, and the
         * target driver may not have written anything into it at all. However, the context must be released here regardless of success or failure:
         * This is the sole release point for KSW_HWID_POOL_TAG in the entire module; missing one release results in a non-paged pool leak.
         */
        if (irp != NULL && NT_SUCCESS(irp->IoStatus.Status)) {
            kswordArkHwidRewriteSystemBuffer(completionContext, irp);
            kswordArkHwidRewriteDirectOrUserBuffer(completionContext, irp);
        }
        ExFreePoolWithTag(completionContext, KSW_HWID_POOL_TAG);
    }

    if (irp != NULL) {
        completionStatus = irp->IoStatus.Status;
        callOldRoutine =
            (NT_SUCCESS(completionStatus) && ((oldControl & SL_INVOKE_ON_SUCCESS) != 0U)) ||
            (completionStatus == STATUS_CANCELLED && ((oldControl & SL_INVOKE_ON_CANCEL) != 0U)) ||
            (!NT_SUCCESS(completionStatus) && completionStatus != STATUS_CANCELLED && ((oldControl & SL_INVOKE_ON_ERROR) != 0U));
    }

    /*
     * Note: This module overrides the original completion routine at this stack location. IoCompleteRequest has already
     * consumed this location and will not invoke the original routine; therefore, whether to invoke it is determined solely
     * by callOldRoutine, which is reconstructed above based on the OldControl SL_INVOKE_ON_* bits and the completion status.
     * Do not AND with Irp->StackCount: StackCount is the total number of stack locations at IRP allocation time and is unrelated to whether an
     * upper completion routine was installed. Using it as a gate will silently swallow upper-layer callbacks on a single-layer device stack.
     */
    if (oldRoutine != NULL && callOldRoutine != FALSE) {
        return oldRoutine(device, irp, oldContext);
    }

    if (irp != NULL && irp->PendingReturned) {
        IoMarkIrpPending(irp);
    }

    return STATUS_SUCCESS;
}



static BOOLEAN
kswordArkHwidShouldHookIoctl(
    _In_ ULONG targetFlag,
    _In_ ULONG ioControlCode,
    _In_opt_ PVOID systemBuffer,
    _In_ ULONG inputBufferLength
    )
{
    PSTORAGE_PROPERTY_QUERY storageQuery = (PSTORAGE_PROPERTY_QUERY)systemBuffer;

    /* Note: Decide whether to attach a completion routine based on the target driver and IOCTL type. */
    if (targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_DISK) {
        if (ioControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
            return systemBuffer != NULL &&
                inputBufferLength >= sizeof(STORAGE_PROPERTY_QUERY) &&
                storageQuery->PropertyId == StorageDeviceProperty;
        }
        return ioControlCode == IOCTL_ATA_PASS_THROUGH || ioControlCode == SMART_RCV_DRIVE_DATA;
    }

    if (targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR) {
        return ioControlCode == IOCTL_DISK_GET_PARTITION_INFO_EX ||
            ioControlCode == IOCTL_DISK_GET_DRIVE_LAYOUT_EX;
    }

    if (targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR) {
        return ioControlCode == IOCTL_MOUNTMGR_QUERY_POINTS ||
            ioControlCode == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID;
    }

    if (targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
        return ioControlCode == KSW_HWID_NVIDIA_SMIL_IOCTL;
    }

    if (targetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
        return ioControlCode == KSW_HWID_NSI_PROXY_ARP_IOCTL ||
            ioControlCode == KSW_HWID_ARP_TABLE_IOCTL;
    }

    return FALSE;
}

BOOLEAN
kswordArkHwidPrepareDispatchCompletion(
    _Inout_ PIRP irp,
    _Inout_ PIO_STACK_LOCATION ioStack,
    _In_ ULONG targetFlag,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    )
{
    PkswHwidCompletionContext completionContext = NULL;
    ULONG inputBufferLength = 0UL;
    ULONG outputBufferLength = 0UL;
    ULONG ioControlCode = 0UL;

    /* Note: This entry runs inside the dispatch function of the target driver being hooked and installs only the completion routine. */
    if (irp == NULL || ioStack == NULL || profile == NULL) {
        return FALSE;
    }

    ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (!kswordArkHwidShouldHookIoctl(targetFlag, ioControlCode, irp->AssociatedIrp.SystemBuffer, inputBufferLength)) {
        return FALSE;
    }

    completionContext = (PkswHwidCompletionContext)kswordArkAllocateNonPagedPool(
        sizeof(*completionContext),
        KSW_HWID_POOL_TAG);
    if (completionContext == NULL) {
        return FALSE;
    }

    RtlZeroMemory(completionContext, sizeof(*completionContext));
    completionContext->systemBuffer = irp->AssociatedIrp.SystemBuffer;
    completionContext->userBuffer = irp->UserBuffer;
    completionContext->mdlAddress = irp->MdlAddress;
    completionContext->bufferLength = outputBufferLength;
    completionContext->ioControlCode = ioControlCode;
    completionContext->targetFlag = targetFlag;
    completionContext->oldControl = ioStack->Control;
    completionContext->oldContext = ioStack->Context;
    completionContext->oldRoutine = ioStack->CompletionRoutine;
    RtlCopyMemory(&completionContext->profile, profile, sizeof(completionContext->profile));
    completionContext->profile.diskSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    completionContext->profile.diskProduct[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    completionContext->profile.diskRevision[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    completionContext->profile.gpuSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    completionContext->profile.permanentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    completionContext->profile.currentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';

    ioStack->Context = completionContext;
    ioStack->CompletionRoutine = kswordArkHwidCompletionRoutine;
    /*
     * Note: All three SL_INVOKE_ON_* bits must be set. The completionContext has only one release point in the completion
     * routine, which is called only when the corresponding bit in Control matches the completion status. If only
     * SL_INVOKE_ON_SUCCESS is set, the non-paged pool will never be reclaimed if the IRP completes with a non-success status.
     * This is not a rare path: Standard usage of STORAGE_QUERY_PROPERTY / MOUNTMGR_QUERY_POINTS first probes length with
     * a small buffer to get STATUS_BUFFER_OVERFLOW; ATA_PASS_THROUGH commonly returns STATUS_INVALID_DEVICE_REQUEST on
     * NVMe. The original completion routine's invocation conditions are determined by OldControl and remain unaffected.
     */
    ioStack->Control |= SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
    return TRUE;
}
