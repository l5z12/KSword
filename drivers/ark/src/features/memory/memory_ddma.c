/*++

Module Name:

    memory_ddma.c

Abstract:

    DDMA (Disk Direct Memory Access) backend for KswordARK.

    Leverage the ATA_PASS_THROUGH_DIRECT + ATA_FLAGS_USE_DMA mechanism in the \Driver\Disk device stack to enable bus
    mastering DMA by the disk controller on arbitrary physical addresses. Since the data path bypasses the CPU page
    tables and SLAT/EPT, it can read physical pages that have been redirected or hidden by upper-layer virtualization.

    Reference implementation: https://github.com/btbd/ddma (Disks for DMA).

    Three differences from the upstream PoC:
    1. The sector LBA to be cached is explicitly provided by the caller; this module provides
       no default values. The upstream always uses LBA 0, i.e., the MBR/GPT protective sector.
    2. Backup and restore pairs occur within the same request (Session
       Begin/End); the upstream performs backup only once during driver loading.
    3. Supports LBA48; automatically switches to 0x24/0x34 commands when LBA >= 2^28; upstream only supports 28-bit.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL only.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_ddma.h"
#include "driver/KswordArkDdmaPlan.h"
#include "../../platform/pool_compat.h"

#include <ntddscsi.h>
// DISK_GEOMETRY and IOCTL_DISK_GET_DRIVE_GEOMETRY are here; for SCSI passthrough, real sector
// size must be used to convert CDB block counts. If unavailable, that path cannot be attempted.
#include <ntdddisk.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_DDMA_POOL_TAG 'dDsK'

// Timeout in seconds for a single ATA command. The upstream uses 2 seconds, so this is kept consistent: every step of
// DDMA occupies a temporary disk sector; the longer the timeout, the longer the exposure window for dirty sectors.
#define KSWORD_ARK_ATA_IO_TIMEOUT 2UL

/*
 * Header length must always be calculated using FIELD_OFFSET, not "sizeof(struct) - sizeof(trailing member)".
 *
 * They are not equal on structures with trailing arrays: the structure tail includes alignment padding, which sizeof counts.
 * Using this protocol's read response as an example: sizeof - sizeof(data) = 335, while offsetof(data) = 328.
 * If one calculates 'remaining available output buffer' using the former value but writes the payload to ->data, R3 will misinterpret the
 * offset by 7 bytes regardless of which number it uses. The existing physical read protocol has already encountered this pitfall (see comments
 * in ArkDriverMemory.cpp). The new protocol simply makes these two values identical, eliminating this class of misalignment at the source.
 */
#define KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data)

#define KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST, data)

#define KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE, entries)

// The following three routines are declared in ntifs.h but not in ntddk.h; this compilation unit follows project conventions
// by staying with ntddk.h. Add local declarations here to match the public prototypes; do not switch to including ntifs.h.
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING objectName,
    _In_ ULONG attributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Inout_opt_ PVOID parseContext,
    _Out_ PVOID* object
    );

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

NTKERNELAPI
NTSTATUS
IoEnumerateDeviceObjectList(
    _In_ PDRIVER_OBJECT driverObject,
    _Out_writes_bytes_to_opt_(
        DeviceObjectListSize,
        (*ActualNumberDeviceObjects) * sizeof(PDEVICE_OBJECT))
        PDEVICE_OBJECT* deviceObjectList,
    _In_ ULONG deviceObjectListSize,
    _Out_ PULONG actualNumberDeviceObjects
    );

extern POBJECT_TYPE* IoDriverObjectType;

// ============================================================
// Disk device enumeration
// ============================================================

typedef struct KswordArkDdmaDiskList
{
    PDRIVER_OBJECT driverObject;    // \Driver\Disk driver object, holds a reference.
    PDEVICE_OBJECT* devices;        // Array of device objects; each item holds a reference.
    ULONG deviceCount;              // Array length.
} KswordArkDdmaDiskList;

static VOID
kswordArkDdmaReleaseDiskList(
    _Inout_ KswordArkDdmaDiskList* list
    )
/*++

Routine Description:

    Release the disk device list. Note: IoEnumerateDeviceObjectList adds a reference for
    each device object, and the driver object also holds a reference. Both must be released
    in pairs at the same location; otherwise, the device stack can never be unloaded.

Arguments:

    List: The list to be freed; all pointers are cleared after the function returns, allowing safe repeated calls.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (list == NULL) {
        return;
    }

    if (list->devices != NULL) {
        for (index = 0UL; index < list->deviceCount; ++index) {
            if (list->devices[index] != NULL) {
                ObDereferenceObject(list->devices[index]);
                list->devices[index] = NULL;
            }
        }
        ExFreePoolWithTag(list->devices, KSWORD_ARK_DDMA_POOL_TAG);
        list->devices = NULL;
    }
    list->deviceCount = 0UL;

    if (list->driverObject != NULL) {
        ObDereferenceObject(list->driverObject);
        list->driverObject = NULL;
    }
}

static NTSTATUS
kswordArkDdmaAcquireDiskList(
    _Out_ KswordArkDdmaDiskList* list
    )
/*++

Routine Description:

    enumerate all device objects attached to \Driver\Disk. Note: DDMA requires a disk device object
    capable of accepting IOCTL_ATA_PASS_THROUGH_DIRECT. Each physical disk in disk.sys corresponds
    to a device object; this code retrieves all of them for the caller to select by index.

Arguments:

    List - output list; on success, the caller must release it using kswordArkDdmaReleaseDiskList.

Return Value:

    STATUS_SUCCESS indicates the list is valid; other values indicate driver object or device enumeration failure.

--*/
{
    UNICODE_STRING diskDriverName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    PDRIVER_OBJECT driverObject = NULL;
    PDEVICE_OBJECT* devices = NULL;
    ULONG deviceCount = 0UL;
    ULONG allocationBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (list == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(list, sizeof(*list));

    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    status = ObReferenceObjectByName(
        &diskDriverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&driverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // The first call is solely to query the device count; the success path must return BUFFER_TOO_SMALL.
    status = IoEnumerateDeviceObjectList(driverObject, NULL, 0, &deviceCount);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        ObDereferenceObject(driverObject);
        // When count is 0, the above returns SUCCESS; this case is handled as 'no disk'.
        return NT_SUCCESS(status) ? STATUS_NO_SUCH_DEVICE : status;
    }
    if (deviceCount == 0UL) {
        ObDereferenceObject(driverObject);
        return STATUS_NO_SUCH_DEVICE;
    }
    if (deviceCount > KSWORD_ARK_DDMA_DISK_LIMIT_HARD) {
        deviceCount = KSWORD_ARK_DDMA_DISK_LIMIT_HARD;
    }

    allocationBytes = deviceCount * (ULONG)sizeof(PDEVICE_OBJECT);
    devices = (PDEVICE_OBJECT*)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSWORD_ARK_DDMA_POOL_TAG);
    if (devices == NULL) {
        ObDereferenceObject(driverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(devices, allocationBytes);

    status = IoEnumerateDeviceObjectList(driverObject, devices, allocationBytes, &deviceCount);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(devices, KSWORD_ARK_DDMA_POOL_TAG);
        ObDereferenceObject(driverObject);
        return status;
    }

    list->driverObject = driverObject;
    list->devices = devices;
    list->deviceCount = deviceCount;
    return STATUS_SUCCESS;
}

static VOID
kswordArkDdmaQueryDeviceName(
    _In_ PDEVICE_OBJECT device,
    _Out_writes_(nameChars) PWCHAR nameBuffer,
    _In_ ULONG nameChars,
    _Out_ BOOLEAN* namePresentOut
    )
/*++

Routine Description:

    Query the disk device object name, e.g., \Device\Harddisk0\DR0. Note: The name is only used by R3 to confirm "this
    is still the same disk detected last time"; failure to retrieve the name does not affect the read/write path.

Arguments:

    Device - The target device object.
    NameBuffer - Output buffer.
    NameChars: Number of characters the output buffer can hold (including the terminating NUL).
    NamePresentOut - Indicates whether the name was successfully retrieved.

Return Value:

    None. On failure, the name is simply left empty.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (nameBuffer == NULL || nameChars == 0UL || namePresentOut == NULL) {
        return;
    }
    *namePresentOut = FALSE;
    nameBuffer[0] = L'\0';

    if (device == NULL) {
        return;
    }

    status = ObQueryNameString(device, NULL, 0, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_OVERFLOW &&
        status != STATUS_BUFFER_TOO_SMALL) {
        return;
    }
    if (requiredBytes == 0UL || requiredBytes > (64UL * 1024UL)) {
        return;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkAllocateNonPagedPool(
        requiredBytes,
        KSWORD_ARK_DDMA_POOL_TAG);
    if (nameInfo == NULL) {
        return;
    }
    RtlZeroMemory(nameInfo, requiredBytes);

    status = ObQueryNameString(device, nameInfo, requiredBytes, &requiredBytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL && nameInfo->Name.Length > 0) {
        // RtlStringCchCopyNW automatically appends NUL and truncates to the target capacity.
        if (NT_SUCCESS(RtlStringCchCopyNW(
                nameBuffer,
                nameChars,
                nameInfo->Name.Buffer,
                nameInfo->Name.Length / sizeof(WCHAR)))) {

            *namePresentOut = TRUE;
        }
    }

    ExFreePoolWithTag(nameInfo, KSWORD_ARK_DDMA_POOL_TAG);
}

// ============================================================
// Issue ATA command
// ============================================================

static NTSTATUS
kswordArkDdmaIssueAtaCommand(
    _In_ PDEVICE_OBJECT device,
    _In_ USHORT directionFlag,
    _In_ BOOLEAN isWrite,
    _In_ ULONG64 lba,
    _In_ PVOID dataBuffer
    )
/*++

Routine Description:

    Issue an ATA DMA read/write command to the disk device. Note: DataBuffer is the critical component
    here—storport creates an MDL for it and populates the HBA's scatter-gather list with physical
    pages. Thus, as long as DataBuffer points to any physical page returned by MmMapIoSpace, the HBA
    performs real DMA on that physical address, bypassing the CPU page tables and SLAT entirely.

    Use 28-bit commands when LBA < 2^28; LBA registers are distributed in CurrentTaskFile[2..4]
    and the lower 4 bits of the Device register. Otherwise, switch to 48-bit commands; the high
    3 bytes go to PreviousTaskFile, and the Device register no longer carries LBA bits.

Arguments:

    Device - The target disk device object.
    DirectionFlag: ATA_FLAGS_DATA_IN (read) or ATA_FLAGS_DATA_OUT (write).
    IsWrite - TRUE indicates writing to disk, determining which command code to select.
    Lba: Temporary starting LBA of the sector.
    DataBuffer: Non-paged data buffer or physical page mapping with a fixed length equal to one transfer length.

Return Value:

    IRP completion status.

--*/
{
    KEVENT completionEvent;
    ATA_PASS_THROUGH_DIRECT request;
    IO_STATUS_BLOCK ioStatusBlock;
    KSWORD_ARK_DDMA_TASKFILE taskFile;
    PIRP irp = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (device == NULL || dataBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Register encoding is delegated to the shared pure function in KswordArkDdmaPlan.h: unit tests cover
    // this implementation, so there is no need to re-implement the 28/48-bit bitwise operations here.
    taskFile = KswordArkDdmaEncodeTaskFile(
        lba,
        KSWORD_ARK_DDMA_TRANSFER_BYTES / KSWORD_ARK_DDMA_SECTOR_SIZE,
        isWrite ? 1 : 0);
    if (!taskFile.valid) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeEvent(&completionEvent, SynchronizationEvent, FALSE);
    RtlZeroMemory(&request, sizeof(request));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    request.Length = sizeof(request);
    request.AtaFlags = (USHORT)(directionFlag | ATA_FLAGS_USE_DMA | taskFile.extraAtaFlags);
    request.DataTransferLength = KSWORD_ARK_DDMA_TRANSFER_BYTES;
    request.TimeOutValue = KSWORD_ARK_ATA_IO_TIMEOUT;
    request.DataBuffer = dataBuffer;

    RtlCopyMemory(
        request.CurrentTaskFile,
        taskFile.currentTaskFile,
        sizeof(request.CurrentTaskFile));
    RtlCopyMemory(
        request.PreviousTaskFile,
        taskFile.previousTaskFile,
        sizeof(request.PreviousTaskFile));

    irp = IoBuildDeviceIoControlRequest(
        IOCTL_ATA_PASS_THROUGH_DIRECT,
        device,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        FALSE,
        &completionEvent,
        &ioStatusBlock);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&completionEvent, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    return status;
}

// ============================================================
// SCSI passthrough (covering NVMe, SAS, SATA, and synthetic SCSI).
// ============================================================

static NTSTATUS
kswordArkDdmaIssueScsiCommand(
    _In_ PDEVICE_OBJECT device,
    _In_ BOOLEAN isWrite,
    _In_ ULONG64 lba,
    _In_ ULONG sectorSize,
    _In_ PVOID dataBuffer
    )
/*++

Routine Description:

    Use SCSI pass-through read/write to temporarily buffer sectors. Note: This is the second transport channel outside of
    ATA and the only one truly usable on modern machines. DDMA requires a pass-through channel that can designate
    specific physical pages as DMA targets, not "ATA". IOCTL_SCSI_PASS_THROUGH_DIRECT also carries _DIRECT; storport
    builds an MDL for DataBuffer and populates the controller's hash table with physical pages, while stornvme translates
    SCSI READ/WRITE into NVMe commands. Consequently, NVMe, SAS/SATA, and synthetic SCSI disks are all supported.

    The request buffer layout is "SCSI_PASS_THROUGH_DIRECT header + sense area", both residing in the
    same memory block. SenseInfoOffset points to the offset of the sense area relative to the header.

Arguments:

    Device - The target disk device object.
    IsWrite - TRUE indicates a write to disk.
    Lba: Temporary starting logical block number of the sector.
    SectorSize: The logical sector size of the disk; transfer length in the CDB is in blocks and must use the actual value.
    DataBuffer - Non-paged data buffer or physical page mapping, with a length equal to the transfer length for one operation.

Return Value:

    IRP completion status; if the SCSI status is non-zero, convert it to STATUS_IO_DEVICE_ERROR.

--*/
{
    typedef struct KswordArkScsiRequest
    {
        SCSI_PASS_THROUGH_DIRECT header;
        UCHAR sense[32];
    } KswordArkScsiRequest;

    KEVENT completionEvent;
    KswordArkScsiRequest request;
    IO_STATUS_BLOCK ioStatusBlock;
    KSWORD_ARK_DDMA_CDB command;
    PIRP irp = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (device == NULL || dataBuffer == NULL || sectorSize == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    // CDB encoding is delegated to the shared pure function in KswordArkDdmaPlan.h; unit tests cover this specific implementation.
    // Note that the transfer length unit in the CDB is blocks, not bytes; if not divisible, the function will reject it directly.
    command = KswordArkDdmaEncodeCdb(
        lba,
        KSWORD_ARK_DDMA_TRANSFER_BYTES,
        sectorSize,
        isWrite ? 1 : 0);
    if (!command.valid) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeEvent(&completionEvent, SynchronizationEvent, FALSE);
    RtlZeroMemory(&request, sizeof(request));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    request.header.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    request.header.CdbLength = command.cdbLength;
    request.header.SenseInfoLength = (UCHAR)sizeof(request.sense);
    request.header.DataIn = (UCHAR)(isWrite ? SCSI_IOCTL_DATA_OUT : SCSI_IOCTL_DATA_IN);
    request.header.DataTransferLength = KSWORD_ARK_DDMA_TRANSFER_BYTES;
    request.header.TimeOutValue = KSWORD_ARK_ATA_IO_TIMEOUT;
    request.header.DataBuffer = dataBuffer;
    request.header.SenseInfoOffset =
        (ULONG)FIELD_OFFSET(KswordArkScsiRequest, sense);
    RtlCopyMemory(request.header.Cdb, command.cdb, sizeof(request.header.Cdb));

    irp = IoBuildDeviceIoControlRequest(
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        device,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        FALSE,
        &completionEvent,
        &ioStatusBlock);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&completionEvent, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    // IRP success does not equal command success: A non-zero SCSI status indicates the device rejected the command. Treating it
    // as success would mislead the caller into thinking data was transferred, while the buffer actually contains stale content.
    if (NT_SUCCESS(status) && request.header.ScsiStatus != 0U) {
        status = STATUS_IO_DEVICE_ERROR;
    }

    return status;
}

// ============================================================
// Temporary sector session.
// ============================================================

typedef struct KswordArkDdmaSession
{
    PDEVICE_OBJECT device;      // Note: Target disk device object, without holding extra references.
    ULONG64 scratchLba;         // Temporary sector start LBA.
    PVOID backupBuffer;         // Temporarily store original sector content in contiguous non-paged memory.
    BOOLEAN backupValid;        // Whether the backup succeeded determines whether restoration is possible.
    ULONG transport;            // KSWORD_ARK_DDMA_TRANSPORT_*: which transport path this session uses.
    ULONG sectorSize;           // Logical sector size of the disk; SCSI transfers convert block counts based on it.
} KswordArkDdmaSession;

static NTSTATUS
kswordArkDdmaTransfer(
    _In_ PDEVICE_OBJECT device,
    _In_ ULONG transport,
    _In_ ULONG sectorSize,
    _In_ BOOLEAN isWrite,
    _In_ ULONG64 lba,
    _In_ PVOID dataBuffer
    )
/*++

Routine Description:

    Perform a sector read/write operation based on the session-selected transport. Note: Consolidate the choice of 'which passthrough
    path to take' here; upper-layer backup, copy, and restore steps no longer need to concern themselves with ATA vs. SCSI differences.

Arguments:

    Device - The target disk device object.
    Transport: KSWORD_ARK_DDMA_TRANSPORT_ATA or _SCSI.
    SectorSize - Logical sector size, required for the SCSI path.
    IsWrite - TRUE indicates a write to disk.
    Lba: Temporary starting LBA of the sector.
    DataBuffer: Data buffer or physical page mapping.

Return Value:

    The NTSTATUS corresponding to the transport; returns STATUS_INVALID_PARAMETER if the transport identifier is invalid.

--*/
{
    if (transport == KSWORD_ARK_DDMA_TRANSPORT_ATA) {
        return kswordArkDdmaIssueAtaCommand(
            device,
            isWrite ? ATA_FLAGS_DATA_OUT : ATA_FLAGS_DATA_IN,
            isWrite,
            lba,
            dataBuffer);
    }
    if (transport == KSWORD_ARK_DDMA_TRANSPORT_SCSI) {
        return kswordArkDdmaIssueScsiCommand(device, isWrite, lba, sectorSize, dataBuffer);
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
kswordArkDdmaSessionBegin(
    _Inout_ KswordArkDdmaSession* session,
    _In_ PDEVICE_OBJECT device,
    _In_ ULONG64 scratchLba,
    _In_ PVOID backupBuffer,
    _In_ ULONG transport,
    _In_ ULONG sectorSize
    )
/*++

Routine Description:

    Start a DDMA session: read the original content of the temporary sector into the backup buffer. Note: If the backup fails,
    the entire operation must be aborted; otherwise, subsequent writes will irreversibly corrupt the data in these sectors.

Arguments:

    Session - Output session status.
    Device - The target disk device object.
    ScratchLba - The starting LBA of the scratch sector explicitly specified by the caller.
    BackupBuffer: backup buffer; length must equal one transfer length.

Return Value:

    NTSTATUS for the backup command.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (session == NULL || device == NULL || backupBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(session, sizeof(*session));
    session->device = device;
    session->scratchLba = scratchLba;
    session->backupBuffer = backupBuffer;
    session->backupValid = FALSE;
    session->transport = transport;
    session->sectorSize = sectorSize;

    status = kswordArkDdmaTransfer(
        device, transport, sectorSize, FALSE, scratchLba, backupBuffer);
    if (NT_SUCCESS(status)) {
        session->backupValid = TRUE;
    }

    return status;
}

static NTSTATUS
kswordArkDdmaSessionEnd(
    _Inout_ KswordArkDdmaSession* session
    )
/*++

Routine Description:

    Terminate the DDMA session: write the backup content back to the temporary sector. Note: This
    is the only place in this module that writes data back to disk; failure leaves dirty sectors on
    the disk, so the caller must report this state to the user exactly as-is and cannot swallow it.

Arguments:

    Session - Session state.

Return Value:

    Returns the NTSTATUS of the restore command; returns STATUS_UNSUCCESSFUL if the backup was already invalid.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (session == NULL || session->device == NULL || session->backupBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!session->backupValid) {
        // Do not write without a trusted backup: writing uninitialized data is worse than leaving dirty sectors.
        return STATUS_UNSUCCESSFUL;
    }

    status = kswordArkDdmaTransfer(
        session->device,
        session->transport,
        session->sectorSize,
        TRUE,
        session->scratchLba,
        session->backupBuffer);
    return status;
}

static NTSTATUS
kswordArkDdmaCopyPage(
    _In_ KswordArkDdmaSession* session,
    _In_ PVOID destination,
    _In_ PVOID source,
    _Out_ NTSTATUS* stageOutStatusOut,
    _Out_ NTSTATUS* stageInStatusOut
    )
/*++

Routine Description:

    Move one page of content pointed to by Source to Destination via a temporary sector. Note: This is
    the core primitive of DDMA; both ends can be arbitrary physical page mappings from MmMapIoSpace.

    Step 1: Write Source to a temporary disk sector (HBA DMA reads from Source's physical pages). Step
    2: Read the temporary sector back to Destination (HBA DMA writes to Destination's physical pages).
    Both steps are device-side DMA; the CPU never dereferences these two address ranges from start to finish.

Arguments:

    Session - Session that has completed backup.
    Destination: target buffer or physical page mapping.
    Source - Source buffer or physical page mapping.
    StageOutStatusOut - Output the status of the first step (writing to disk).
    StageInStatusOut: Status of the second step (reading back from disk).

Return Value:

    Return the status of the first failed step; return STATUS_SUCCESS if all steps succeed.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (session == NULL || destination == NULL || source == NULL ||
        stageOutStatusOut == NULL || stageInStatusOut == NULL) {

        return STATUS_INVALID_PARAMETER;
    }
    *stageOutStatusOut = STATUS_NOT_SUPPORTED;
    *stageInStatusOut = STATUS_NOT_SUPPORTED;

    status = kswordArkDdmaTransfer(
        session->device,
        session->transport,
        session->sectorSize,
        TRUE,
        session->scratchLba,
        source);
    *stageOutStatusOut = status;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDdmaTransfer(
        session->device,
        session->transport,
        session->sectorSize,
        FALSE,
        session->scratchLba,
        destination);
    *stageInStatusOut = status;
    return status;
}

// ============================================================
// Generic validation
// ============================================================

static ULONG
kswordArkDdmaSelectTransport(
    _In_ PDEVICE_OBJECT device,
    _In_ ULONG64 scratchLba,
    _In_ ULONG sectorSize,
    _In_ PVOID probeBuffer
    )
/*++

Routine Description:

    Before actually moving data, determine which direct path the disk uses. Note: Use a single **read-only**
    command to probe a temporary sector; if the read fails, try the other path; if both fail, return NONE.

    Why re-evaluate capabilities on every request instead of caching the query result? The device may be re-enumerated, the driver may be unloaded,
    and a false negative in transmission verification could lead to commands being rejected while we incorrectly assume data transfer succeeded.
    The cost of a single read-only probe is far less than this risk.

Arguments:

    Device - The target disk device object.
    ScratchLba - Starting LBA of the scratch sector.
    SectorSize - logical sector size; if 0, SCSI is not attempted.
    ProbeBuffer - buffer for probing, length equals one transfer length.

Return Value:

    KSWORD_ARK_DDMA_TRANSPORT_ATA / _SCSI / _NONE。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkDdmaIssueAtaCommand(
        device, ATA_FLAGS_DATA_IN, FALSE, scratchLba, probeBuffer);
    if (NT_SUCCESS(status)) {
        return KSWORD_ARK_DDMA_TRANSPORT_ATA;
    }

    if (sectorSize != 0UL) {
        status = kswordArkDdmaIssueScsiCommand(
            device, FALSE, scratchLba, sectorSize, probeBuffer);
        if (NT_SUCCESS(status)) {
            return KSWORD_ARK_DDMA_TRANSPORT_SCSI;
        }
    }

    return KSWORD_ARK_DDMA_TRANSPORT_NONE;
}

static BOOLEAN
kswordArkDdmaIsPhysicalRangeValid(
    _In_ ULONG64 physicalAddress,
    _In_ ULONG length
    )
/*++

Routine Description:

    Validate the physical range. Note: The core validation logic is a shared inline function in KswordArkDdmaPlan.h; unit tests
    cover that implementation. This function only performs type adaptation and does not re-implement the validation logic.

Arguments:

    PhysicalAddress - Starting physical address.
    Length - Requested length, which must be non-zero.

Return Value:

    TRUE indicates the range is acceptable.

--*/
{
    return KswordArkDdmaIsPhysicalRangeValid(physicalAddress, length) ? TRUE : FALSE;
}

static ULONG
kswordArkDdmaQuerySectorSize(
    _In_ PDEVICE_OBJECT device
    )
/*++

Routine Description:

    Query the logical sector size of the disk. Note: The transfer length unit in SCSI CDB is **blocks**, not bytes. Using 512
    as the default value for 4Kn drives causes the controller to read/write over an eightfold range. Therefore, this value must
    be queried; if it cannot be obtained, return 0 to let the caller handle it as "unavailable" rather than guessing a value.

Arguments:

    Device - The target disk device object.

Return Value:

    Bytes per logical sector; returns 0 if the query fails.

--*/
{
    KEVENT completionEvent;
    DISK_GEOMETRY geometry;
    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (device == NULL) {
        return 0UL;
    }

    KeInitializeEvent(&completionEvent, SynchronizationEvent, FALSE);
    RtlZeroMemory(&geometry, sizeof(geometry));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    irp = IoBuildDeviceIoControlRequest(
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        device,
        NULL,
        0U,
        &geometry,
        sizeof(geometry),
        FALSE,
        &completionEvent,
        &ioStatusBlock);
    if (irp == NULL) {
        return 0UL;
    }

    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&completionEvent, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    if (!NT_SUCCESS(status)) {
        return 0UL;
    }
    return geometry.BytesPerSector;
}

static PVOID
kswordArkDdmaAllocateTransferBuffer(VOID)
/*++

Routine Description:

    Allocate a one-page DMA working buffer. Note: Use MmAllocateContiguousMemory with the highest physical address
    constrained to within 4GB, as some HBAs do not support 64-bit addressing (this is explicitly documented in the
    upstream ddma README). The buffer is naturally page-aligned, satisfying the HBA's alignment requirements.

Arguments:

    None.

Return Value:

    Returns the buffer address on success, NULL on failure. Caller must free using MmFreeContiguousMemory.

--*/
{
    PHYSICAL_ADDRESS highestAddress;
    PVOID buffer = NULL;

    highestAddress.QuadPart = (LONGLONG)MAXULONG32;
    buffer = MmAllocateContiguousMemory(KSWORD_ARK_DDMA_TRANSFER_BYTES, highestAddress);
    if (buffer != NULL) {
        RtlZeroMemory(buffer, KSWORD_ARK_DDMA_TRANSFER_BYTES);
    }
    return buffer;
}

// ============================================================
// IOCTL backend: Capability query
// ============================================================

NTSTATUS
kswordArkDriverDdmaQueryCapability(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate disk devices available for DDMA, and optionally perform a real ATA DMA read probe on each disk.
    Note: Probing issues a read command to the caller-specified scratch LBA (read-only, no write), so FORCE is
    not required; however, SCRATCH_LBA_VALID is still mandatory—without it, only enumeration occurs, no probing.

Arguments:

    OutputBuffer - Response buffer, with an array of disk entries immediately following the header.
    OutputBufferLength - Total length of the response buffer.
    Request - Query request.
    BytesWrittenOut - Actual number of bytes written in the response.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; details are in response->status.

--*/
{
    KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE* response = NULL;
    KswordArkDdmaDiskList diskList;
    PVOID probeBuffer = NULL;
    size_t availableBytes = 0U;
    ULONG capacityEntries = 0UL;
    ULONG maxDisks = 0UL;
    ULONG returnedDisks = 0UL;
    ULONG readyDisks = 0UL;
    ULONG index = 0UL;
    BOOLEAN probeRequested = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if ((request->flags & ~KSWORD_ARK_DDMA_QUERY_FLAG_ALLOWED) != 0UL ||
        request->reserved0 != 0UL || request->reserved1 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_DDMA_PROTOCOL_VERSION;
    response->headerSize = KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE;
    response->status = KSWORD_ARK_DDMA_QUERY_STATUS_UNAVAILABLE;
    response->entrySize = (ULONG)sizeof(KSWORD_ARK_DDMA_DISK_ENTRY);
    response->transferBytes = KSWORD_ARK_DDMA_TRANSFER_BYTES;
    response->scratchSectorCount = KSWORD_ARK_DDMA_SCRATCH_SECTOR_COUNT;
    response->capabilityFlags = KSWORD_ARK_DDMA_CAP_FLAG_LBA48_SUPPORTED;
    response->lastStatus = STATUS_NOT_SUPPORTED;

    // With kernel debugging enabled, MmMapIoSpace reaches MiShowBadMapper and causes a bugcheck. Report
    // this unconditionally instead of letting the user discover it by attempting a read or write.
    if (*KdDebuggerEnabled != FALSE) {
        response->capabilityFlags |= KSWORD_ARK_DDMA_CAP_FLAG_KERNEL_DEBUGGER_ENABLED;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_DDMA_QUERY_STATUS_IRQL_REJECTED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        *bytesWrittenOut = KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    status = kswordArkDdmaAcquireDiskList(&diskList);
    if (!NT_SUCCESS(status)) {
        response->status = (status == STATUS_NO_SUCH_DEVICE)
            ? KSWORD_ARK_DDMA_QUERY_STATUS_NO_SUPPORTED_DISK
            : KSWORD_ARK_DDMA_QUERY_STATUS_DISK_DRIVER_MISSING;
        response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    response->capabilityFlags |= KSWORD_ARK_DDMA_CAP_FLAG_DISK_DRIVER_PRESENT;
    response->totalDisks = diskList.deviceCount;

    // Probe requires two conditions: the caller requests a probe, and an explicit scratch LBA is provided.
    probeRequested =
        ((request->flags & KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER) != 0UL) &&
        ((request->flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) != 0UL) &&
        (request->scratchLba < KSWORD_ARK_DDMA_LBA48_LIMIT);

    if (probeRequested) {
        probeBuffer = kswordArkDdmaAllocateTransferBuffer();
        if (probeBuffer == NULL) {
            probeRequested = FALSE;
            response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        }
        else {
            response->capabilityFlags |= KSWORD_ARK_DDMA_CAP_FLAG_PROBE_PERFORMED;
        }
    }

    availableBytes = outputBufferLength - KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE;
    capacityEntries = (ULONG)(availableBytes / sizeof(KSWORD_ARK_DDMA_DISK_ENTRY));

    maxDisks = request->maxDisks;
    if (maxDisks == 0UL) {
        maxDisks = KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT;
    }
    if (maxDisks > KSWORD_ARK_DDMA_DISK_LIMIT_HARD) {
        maxDisks = KSWORD_ARK_DDMA_DISK_LIMIT_HARD;
    }

    for (index = 0UL; index < diskList.deviceCount; ++index) {
        KSWORD_ARK_DDMA_DISK_ENTRY* entry = NULL;
        BOOLEAN namePresent = FALSE;

        if (returnedDisks >= capacityEntries || returnedDisks >= maxDisks) {
            response->status = KSWORD_ARK_DDMA_QUERY_STATUS_TRUNCATED;
            break;
        }

        entry = &response->entries[returnedDisks];
        entry->entrySize = (ULONG)sizeof(*entry);
        entry->deviceIndex = index;
        entry->probeStatus = STATUS_NOT_SUPPORTED;
        entry->scsiProbeStatus = STATUS_NOT_SUPPORTED;
        entry->diskFlags = 0UL;
        // Sector size must be queried directly: SCSI CDBs count lengths in blocks; using 512 bytes on a 4Kn drive would cause read/write operations to
        // exceed the range by eight times. If the size cannot be queried, leave it as 0; subsequent detection will skip the SCSI path based on this.
        entry->sectorSize = kswordArkDdmaQuerySectorSize(diskList.devices[index]);

        kswordArkDdmaQueryDeviceName(
            diskList.devices[index],
            entry->deviceName,
            KSWORD_ARK_DDMA_DEVICE_NAME_CHARS,
            &namePresent);
        if (namePresent) {
            entry->diskFlags |= KSWORD_ARK_DDMA_DISK_FLAG_NAME_PRESENT;
        }

        if (probeRequested) {
            // Try both transfer paths: DDMA requires a 'direct channel' that allows a specific physical page to serve as a DMA
            // target, not ATA itself. Modern machines are almost all NVMe; attempting only ATA would cause this path to fail
            // on the vast majority of machines. Record the status of each path separately to distinguish which one failed.
            entry->probeStatus = kswordArkDdmaIssueAtaCommand(
                diskList.devices[index],
                ATA_FLAGS_DATA_IN,
                FALSE,
                request->scratchLba,
                probeBuffer);
            if (NT_SUCCESS(entry->probeStatus)) {
                entry->diskFlags |= KSWORD_ARK_DDMA_DISK_FLAG_ATA_DMA_READY;
            }

            // Do not attempt SCSI if the sector size cannot be determined: without the block count in
            // the CDB, hard-coding a default value is a gamble that the disk uses 512-byte sectors.
            if (entry->sectorSize != 0UL) {
                entry->scsiProbeStatus = kswordArkDdmaIssueScsiCommand(
                    diskList.devices[index],
                    FALSE,
                    request->scratchLba,
                    entry->sectorSize,
                    probeBuffer);
                if (NT_SUCCESS(entry->scsiProbeStatus)) {
                    entry->diskFlags |= KSWORD_ARK_DDMA_DISK_FLAG_SCSI_DMA_READY;
                }
            }

            if ((entry->diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_ANY_DMA_READY) != 0UL) {
                ++readyDisks;
            }
            // lastStatus: Reserved for diagnostics: Prefer recording the failed status; if all succeed, record the ATA status.
            response->lastStatus = NT_SUCCESS(entry->probeStatus)
                ? entry->scsiProbeStatus
                : entry->probeStatus;
        }
        else {
            entry->diskFlags |= KSWORD_ARK_DDMA_DISK_FLAG_PROBE_SKIPPED;
        }

        ++returnedDisks;
    }

    if (probeBuffer != NULL) {
        MmFreeContiguousMemory(probeBuffer);
        probeBuffer = NULL;
    }
    kswordArkDdmaReleaseDiskList(&diskList);

    response->returnedDisks = returnedDisks;
    response->readyDisks = readyDisks;
    if (response->status != KSWORD_ARK_DDMA_QUERY_STATUS_TRUNCATED) {
        if (probeRequested && readyDisks == 0UL) {
            response->status = KSWORD_ARK_DDMA_QUERY_STATUS_NO_SUPPORTED_DISK;
        }
        else {
            response->status = KSWORD_ARK_DDMA_QUERY_STATUS_OK;
        }
    }

    *bytesWrittenOut =
        KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE +
        ((size_t)returnedDisks * sizeof(KSWORD_ARK_DDMA_DISK_ENTRY));
    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL backend: Physical read.
// ============================================================

NTSTATUS
kswordArkDriverDdmaReadPhysical(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Read a segment of physical memory via disk DMA. Note: The CPU never dereferences the target physical page along the
    entire path; data is moved by the HBA to a temporary disk sector, then from there into the driver's working buffer.
    This is why it can see the actual content of SLAT-redirected pages.

Arguments:

    OutputBuffer - Response buffer, with read data immediately following the header.
    OutputBufferLength - Total length of the response buffer.
    Request - Read request.
    BytesWrittenOut - Actual number of bytes written in the response.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; details are in response->readStatus.

--*/
{
    KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE* response = NULL;
    KswordArkDdmaDiskList diskList;
    KswordArkDdmaSession session;
    PHYSICAL_ADDRESS pageBase;
    PVOID transferBuffer = NULL;
    PVOID backupBuffer = NULL;
    PVOID mapping = NULL;
    PDEVICE_OBJECT device = NULL;
    size_t availableBytes = 0U;
    ULONG pageOffset = 0UL;
    ULONG bytesToRead = 0UL;
    BOOLEAN diskListAcquired = FALSE;
    BOOLEAN namePresent = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS stageOutStatus = STATUS_NOT_SUPPORTED;
    NTSTATUS stageInStatus = STATUS_NOT_SUPPORTED;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if ((request->flags & ~KSWORD_ARK_DDMA_READ_FLAG_ALLOWED) != 0UL ||
        request->reserved0 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToRead == 0UL ||
        request->bytesToRead > KSWORD_ARK_DDMA_READ_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    bytesToRead = request->bytesToRead;

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_DDMA_PROTOCOL_VERSION;
    response->headerSize = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
    response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_UNAVAILABLE;
    response->mapStatus = STATUS_NOT_SUPPORTED;
    response->backupStatus = STATUS_NOT_SUPPORTED;
    response->stageOutStatus = STATUS_NOT_SUPPORTED;
    response->stageInStatus = STATUS_NOT_SUPPORTED;
    response->restoreStatus = STATUS_NOT_SUPPORTED;
    response->requestedBytes = bytesToRead;
    response->maxBytesPerRequest = KSWORD_ARK_DDMA_READ_MAX_BYTES;
    response->requestedPhysicalAddress = request->physicalAddress;
    response->scratchLba = request->scratchLba;
    response->diskIndex = request->diskIndex;

    // The scratch LBA must be explicitly provided. Since LBA 0 is a valid value, this check uses the flag bit rather
    // than testing if scratchLba is zero; using zero as a sentinel would implicitly select the MBR sector for the user.
    if ((request->flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) == 0UL ||
        request->scratchLba >= KSWORD_ARK_DDMA_LBA48_LIMIT) {

        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    // Reading also overwrites the scratch sector (by writing the target page first), so the acknowledgment flag is equally required.
    if ((request->flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) == 0UL) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_IRQL_REJECTED;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (!kswordArkDdmaIsPhysicalRangeValid(request->physicalAddress, bytesToRead)) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_RANGE_REJECTED;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    availableBytes = outputBufferLength - KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
    if ((size_t)bytesToRead > availableBytes) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_BUFFER_TOO_SMALL;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    status = kswordArkDdmaAcquireDiskList(&diskList);
    if (!NT_SUCCESS(status)) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND;
        response->mapStatus = status;
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    diskListAcquired = TRUE;

    if (request->diskIndex >= diskList.deviceCount) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND;
        response->mapStatus = STATUS_NO_SUCH_DEVICE;
        kswordArkDdmaReleaseDiskList(&diskList);
        *bytesWrittenOut = KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    device = diskList.devices[request->diskIndex];

    // Fill in the device name so R3 can confirm it is using the same disk seen during capability query.
    kswordArkDdmaQueryDeviceName(
        device,
        response->deviceName,
        KSWORD_ARK_DDMA_DEVICE_NAME_CHARS,
        &namePresent);
    if (namePresent) {
        response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_DEVICE_NAME_PRESENT;
    }

    transferBuffer = kswordArkDdmaAllocateTransferBuffer();
    backupBuffer = kswordArkDdmaAllocateTransferBuffer();
    if (transferBuffer == NULL || backupBuffer == NULL) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_MAP_FAILED;
        response->mapStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    pageOffset = (ULONG)(request->physicalAddress & ((ULONG64)PAGE_SIZE - 1ULL));
    pageBase.QuadPart =
        (LONGLONG)(request->physicalAddress & ~((ULONG64)PAGE_SIZE - 1ULL));

    // MmMapIoSpace is only used to provide storport with a kernel virtual address that can build an MDL; the
    // CPU does not read/write the target page via this mapping. The HBA performs the actual data transfer.
    mapping = MmMapIoSpace(pageBase, PAGE_SIZE, MmNonCached);
    if (mapping == NULL) {
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_MAP_FAILED;
        response->mapStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    response->mapStatus = STATUS_SUCCESS;

    {
        // Probe once in read-only mode to determine the direct path (ATA vs. SCSI/NVMe) for this disk.
        // If both paths fail, treat it as no available disk instead of sending a command destined to be rejected.
        const ULONG kSectorSize = kswordArkDdmaQuerySectorSize(device);
        const ULONG kTransport = kswordArkDdmaSelectTransport(
            device, request->scratchLba, kSectorSize, transferBuffer);
        if (kTransport == KSWORD_ARK_DDMA_TRANSPORT_NONE) {
            response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND;
            response->backupStatus = STATUS_NOT_SUPPORTED;
            goto Cleanup;
        }
        status = kswordArkDdmaSessionBegin(
            &session, device, request->scratchLba, backupBuffer, kTransport, kSectorSize);
    }
    response->backupStatus = status;
    if (!NT_SUCCESS(status)) {
        // If backup fails, do not touch the temporary sector at all; better to miss this read than to corrupt user data.
        response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_BACKUP_FAILED;
        goto Cleanup;
    }

    status = kswordArkDdmaCopyPage(
        &session,
        transferBuffer,
        mapping,
        &stageOutStatus,
        &stageInStatus);
    response->stageOutStatus = stageOutStatus;
    response->stageInStatus = stageInStatus;

    // The scratch sector must be restored regardless of whether the copy succeeded.
    response->restoreStatus = kswordArkDdmaSessionEnd(&session);
    if (NT_SUCCESS(response->restoreStatus)) {
        response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED;
    }

    if (!NT_SUCCESS(status)) {
        response->readStatus = NT_SUCCESS(stageOutStatus)
            ? KSWORD_ARK_DDMA_READ_STATUS_STAGE_IN_FAILED
            : KSWORD_ARK_DDMA_READ_STATUS_STAGE_OUT_FAILED;
        goto Cleanup;
    }

    RtlCopyMemory(response->data, (PUCHAR)transferBuffer + pageOffset, bytesToRead);
    response->bytesRead = bytesToRead;
    response->readStatus = KSWORD_ARK_DDMA_READ_STATUS_OK;

Cleanup:

    if (mapping != NULL) {
        MmUnmapIoSpace(mapping, PAGE_SIZE);
        mapping = NULL;
    }
    if (transferBuffer != NULL) {
        MmFreeContiguousMemory(transferBuffer);
        transferBuffer = NULL;
    }
    if (backupBuffer != NULL) {
        MmFreeContiguousMemory(backupBuffer);
        backupBuffer = NULL;
    }
    if (diskListAcquired) {
        kswordArkDdmaReleaseDiskList(&diskList);
    }

    *bytesWrittenOut =
        KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE + (size_t)response->bytesRead;
    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL backend: Physical write.
// ============================================================

NTSTATUS
kswordArkDriverDdmaWritePhysical(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write a segment of physical memory via disk DMA. Note: DMA transfer granularity is a full page. When the
    request is not 'page-aligned and exactly one page', the operation must first DMA-read the entire page, replace
    the target sub-segment in a working buffer, and then DMA-write the entire page back (read-modify-write).

    RMW has a 4KB granularity lost-update window: if other bytes on the same page are modified by
    others between the read-back and write-back, they will be overwritten with stale values. This fact
    is explicitly reported via the READ_MODIFY_WRITE_USED bit in the response, without silent handling.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Total length of the response buffer.
    Request - Write request, with bytes to write immediately following the header.
    RequestBufferLength - The actual length of the input buffer.
    BytesWrittenOut - Fixed number of response bytes received.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; details are in response->writeStatus.

--*/
{
    KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE* response = NULL;
    KswordArkDdmaDiskList diskList;
    KswordArkDdmaSession session;
    PHYSICAL_ADDRESS pageBase;
    PVOID transferBuffer = NULL;
    PVOID backupBuffer = NULL;
    PVOID mapping = NULL;
    PDEVICE_OBJECT device = NULL;
    size_t requiredInputBytes = 0U;
    ULONG pageOffset = 0UL;
    ULONG bytesToWrite = 0UL;
    BOOLEAN diskListAcquired = FALSE;
    BOOLEAN namePresent = FALSE;
    BOOLEAN needReadModifyWrite = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS stageOutStatus = STATUS_NOT_SUPPORTED;
    NTSTATUS stageInStatus = STATUS_NOT_SUPPORTED;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (requestBufferLength < KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((request->flags & ~KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED) != 0UL ||
        request->reserved0 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToWrite == 0UL ||
        request->bytesToWrite > KSWORD_ARK_DDMA_WRITE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    bytesToWrite = request->bytesToWrite;
    requiredInputBytes = KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE + (size_t)bytesToWrite;
    if (requestBufferLength < requiredInputBytes) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_DDMA_PROTOCOL_VERSION;
    response->size = (ULONG)sizeof(*response);
    response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_UNAVAILABLE;
    response->mapStatus = STATUS_NOT_SUPPORTED;
    response->backupStatus = STATUS_NOT_SUPPORTED;
    response->stageOutStatus = STATUS_NOT_SUPPORTED;
    response->stageInStatus = STATUS_NOT_SUPPORTED;
    response->restoreStatus = STATUS_NOT_SUPPORTED;
    response->readbackStatus = STATUS_NOT_SUPPORTED;
    response->requestedBytes = bytesToWrite;
    response->maxBytesPerRequest = KSWORD_ARK_DDMA_WRITE_MAX_BYTES;
    response->requestedPhysicalAddress = request->physicalAddress;
    response->scratchLba = request->scratchLba;
    response->diskIndex = request->diskIndex;

    // The three checks represent distinct user errors. Keep their status codes separate; do not merge
    // them into a generic "confirmation required" result, or the UI cannot suggest the correct next step.
    if ((request->flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) == 0UL ||
        request->scratchLba >= KSWORD_ARK_DDMA_LBA48_LIMIT) {

        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_LBA_REQUIRED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if ((request->flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) == 0UL) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_NOT_ACKNOWLEDGED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    if ((request->flags & KSWORD_ARK_DDMA_FLAG_FORCE) == 0UL) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_FORCE_USED;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_IRQL_REJECTED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    if (!kswordArkDdmaIsPhysicalRangeValid(request->physicalAddress, bytesToWrite)) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_RANGE_REJECTED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = kswordArkDdmaAcquireDiskList(&diskList);
    if (!NT_SUCCESS(status)) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_DISK_NOT_FOUND;
        response->mapStatus = status;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    diskListAcquired = TRUE;

    if (request->diskIndex >= diskList.deviceCount) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_DISK_NOT_FOUND;
        response->mapStatus = STATUS_NO_SUCH_DEVICE;
        kswordArkDdmaReleaseDiskList(&diskList);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    device = diskList.devices[request->diskIndex];

    kswordArkDdmaQueryDeviceName(
        device,
        response->deviceName,
        KSWORD_ARK_DDMA_DEVICE_NAME_CHARS,
        &namePresent);
    if (namePresent) {
        response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_DEVICE_NAME_PRESENT;
    }

    transferBuffer = kswordArkDdmaAllocateTransferBuffer();
    backupBuffer = kswordArkDdmaAllocateTransferBuffer();
    if (transferBuffer == NULL || backupBuffer == NULL) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_MAP_FAILED;
        response->mapStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    pageOffset = (ULONG)(request->physicalAddress & ((ULONG64)PAGE_SIZE - 1ULL));
    pageBase.QuadPart =
        (LONGLONG)(request->physicalAddress & ~((ULONG64)PAGE_SIZE - 1ULL));
    needReadModifyWrite =
        (pageOffset != 0UL) || (bytesToWrite != KSWORD_ARK_DDMA_TRANSFER_BYTES);

    mapping = MmMapIoSpace(pageBase, PAGE_SIZE, MmNonCached);
    if (mapping == NULL) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_MAP_FAILED;
        response->mapStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    response->mapStatus = STATUS_SUCCESS;

    {
        // Same logic as the read path: determine the transport first; if it cannot be determined, do not proceed.
        const ULONG kSectorSize = kswordArkDdmaQuerySectorSize(device);
        const ULONG kTransport = kswordArkDdmaSelectTransport(
            device, request->scratchLba, kSectorSize, transferBuffer);
        if (kTransport == KSWORD_ARK_DDMA_TRANSPORT_NONE) {
            response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_DISK_NOT_FOUND;
            response->backupStatus = STATUS_NOT_SUPPORTED;
            goto Cleanup;
        }
        status = kswordArkDdmaSessionBegin(
            &session, device, request->scratchLba, backupBuffer, kTransport, kSectorSize);
    }
    response->backupStatus = status;
    if (!NT_SUCCESS(status)) {
        response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_BACKUP_FAILED;
        goto Cleanup;
    }

    if (needReadModifyWrite) {
        // First pass: DMA read the entire target page into the working buffer as the baseline for write-back.
        response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_READ_MODIFY_WRITE_USED;
        status = kswordArkDdmaCopyPage(
            &session,
            transferBuffer,
            mapping,
            &stageOutStatus,
            &stageInStatus);
        response->readbackStatus = status;
        if (!NT_SUCCESS(status)) {
            response->stageOutStatus = stageOutStatus;
            response->stageInStatus = stageInStatus;
            response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_READBACK_FAILED;
            goto Restore;
        }
    }

    // Replace the bytes carried in the request into the corresponding sub-interval of the draft.
    RtlCopyMemory((PUCHAR)transferBuffer + pageOffset, request->data, bytesToWrite);

    // Second pass: Write back the draft full page via DMA to the target physical page.
    status = kswordArkDdmaCopyPage(
        &session,
        mapping,
        transferBuffer,
        &stageOutStatus,
        &stageInStatus);
    response->stageOutStatus = stageOutStatus;
    response->stageInStatus = stageInStatus;

Restore:

    // Consistent with the read path: the scratch sector must be restored regardless of prior success or failure.
    response->restoreStatus = kswordArkDdmaSessionEnd(&session);
    if (NT_SUCCESS(response->restoreStatus)) {
        response->fieldFlags |= KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED;
    }

    if (response->writeStatus == KSWORD_ARK_DDMA_WRITE_STATUS_UNAVAILABLE) {
        if (NT_SUCCESS(status)) {
            response->bytesWritten = bytesToWrite;
            response->writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_OK;
        }
        else {
            response->writeStatus = NT_SUCCESS(stageOutStatus)
                ? KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_IN_FAILED
                : KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_OUT_FAILED;
        }
    }

Cleanup:

    if (mapping != NULL) {
        MmUnmapIoSpace(mapping, PAGE_SIZE);
        mapping = NULL;
    }
    if (transferBuffer != NULL) {
        MmFreeContiguousMemory(transferBuffer);
        transferBuffer = NULL;
    }
    if (backupBuffer != NULL) {
        MmFreeContiguousMemory(backupBuffer);
        backupBuffer = NULL;
    }
    if (diskListAcquired) {
        kswordArkDdmaReleaseDiskList(&diskList);
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
