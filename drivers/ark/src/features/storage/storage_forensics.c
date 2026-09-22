/*++

Module Name:

    storage_forensics.c

Abstract:

    Implements bounded physical-disk discovery and raw I/O backends.  The
    normal backend uses the named disk stack, the storage-port backend skips
    the upper disk object, and the controller backend targets the deepest
    reachable device object only for an offline disk.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntstrsafe.h>

#define KSW_STORAGE_FORENSICS_POOL_TAG 'frSK'
#define KSW_STORAGE_FORENSICS_DESCRIPTOR_BYTES 1024UL
#define KSW_STORAGE_FORENSICS_MAX_STACK_DEPTH 32UL

typedef struct KswStorageDiskContext
{
    HANDLE handle;
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT namedDevice;
    PDEVICE_OBJECT topDevice;
    PDEVICE_OBJECT portDevice;
    PDEVICE_OBJECT controllerDevice;
    ULONG logicalSectorSize;
    ULONG physicalSectorSize;
    ULONGLONG diskSizeBytes;
    ULONG busType;
    ULONG capabilityFlags;
    SCSI_ADDRESS scsiAddress;
    WCHAR path[KSWORD_ARK_RAW_DISK_PATH_CHARS];
    WCHAR model[KSWORD_ARK_RAW_DISK_MODEL_CHARS];
    WCHAR serial[KSWORD_ARK_RAW_DISK_SERIAL_CHARS];
} KswStorageDiskContext, *PkswStorageDiskContext;

/*
 * These documented kernel exports are declared by ntifs.h rather than the
 * ntddk surface used by the rest of this driver.  Declare only the two exact
 * contracts needed here to avoid mixing the two umbrella headers.
 */
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject(
    _In_ HANDLE handle,
    _In_ BOOLEAN alertable,
    _In_opt_ PLARGE_INTEGER timeout
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCancelIoFileEx(
    _In_ HANDLE fileHandle,
    _In_ PIO_STATUS_BLOCK ioRequestToCancel,
    _Out_ PIO_STATUS_BLOCK ioStatusBlock
    );

NTKERNELAPI
PDEVICE_OBJECT
IoGetLowerDeviceObject(
    _In_ PDEVICE_OBJECT deviceObject
    );

/* Raw storage requests must not leave an IOCTL worker blocked forever. */
#define KSW_STORAGE_IO_TIMEOUT_SECONDS 30LL
#define KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS \
    (-(KSW_STORAGE_IO_TIMEOUT_SECONDS * 10LL * 1000LL * 1000LL))

static VOID
kswordStorageReleaseContext(
    _Inout_ KswStorageDiskContext* context
    )
/*++

Routine Description:

    Releases every referenced object and handle owned by a disk context.

--*/
{
    /* A referenced controller object is released independently. */
    if (context->controllerDevice != NULL) {
        /* Drop the controller device reference acquired while walking down. */
        ObDereferenceObject(context->controllerDevice);
        /* Clear the field so repeated cleanup remains safe. */
        context->controllerDevice = NULL;
    }

    /* A referenced port object is released independently. */
    if (context->portDevice != NULL) {
        /* Drop the port device reference acquired while walking down. */
        ObDereferenceObject(context->portDevice);
        /* Clear the field so repeated cleanup remains safe. */
        context->portDevice = NULL;
    }

    /* The top-of-stack reference was acquired explicitly. */
    if (context->topDevice != NULL) {
        /* Release the top-of-stack device object. */
        ObDereferenceObject(context->topDevice);
        /* Clear the field so repeated cleanup remains safe. */
        context->topDevice = NULL;
    }

    /* IoGetDeviceObjectPointer returned a referenced file object. */
    if (context->fileObject != NULL) {
        /* Releasing the file object also releases its named device reference. */
        ObDereferenceObject(context->fileObject);
        /* Clear both borrowed fields after the reference is gone. */
        context->fileObject = NULL;
        /* NamedDevice is borrowed from FileObject and must not be dereferenced. */
        context->namedDevice = NULL;
    }

    /* ZwCreateFile returned a kernel handle for metadata and stack I/O. */
    if (context->handle != NULL) {
        /* Close the disk handle in the caller process context. */
        ZwClose(context->handle);
        /* Clear the field so repeated cleanup remains safe. */
        context->handle = NULL;
    }
}

static NTSTATUS
kswordStorageSendHandleIoctl(
    _In_ HANDLE handle,
    _In_ ULONG ioctlCode,
    _In_reads_bytes_opt_(inputLength) PVOID inputBuffer,
    _In_ ULONG inputLength,
    _Out_writes_bytes_opt_(outputLength) PVOID outputBuffer,
    _In_ ULONG outputLength,
    _Out_opt_ PULONG_PTR informationOut
    )
/*++

Routine Description:

    Sends one synchronous buffered device-control request to a disk handle.

--*/
{
    /* The synchronous handle still requires a caller-owned I/O status block. */
    IO_STATUS_BLOCK ioStatus = { 0 };
    /* Submit the device control request to the opened physical disk. */
    NTSTATUS status = ZwDeviceIoControlFile(
        handle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        ioctlCode,
        inputBuffer,
        inputLength,
        outputBuffer,
        outputLength);

    /* A pending request must be waited before reading its status or output. */
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;

        /* Bound the first wait so a wedged storage stack cannot pin this worker forever. */
        timeout.QuadPart = KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS;
        waitStatus = ZwWaitForSingleObject(handle, FALSE, &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            IO_STATUS_BLOCK cancelStatus = { 0 };

            /* Cancel this exact request rather than every operation issued on the handle. */
            (VOID)ZwCancelIoFileEx(handle, &ioStatus, &cancelStatus);
            /* ioStatus is stack-owned; do not return until the cancelled request is final. */
            waitStatus = ZwWaitForSingleObject(handle, FALSE, NULL);
            status = NT_SUCCESS(waitStatus) ? STATUS_IO_TIMEOUT : waitStatus;
        }
        else if (NT_SUCCESS(waitStatus)) {
            /* Replace the wait status with the actual I/O completion status. */
            status = ioStatus.Status;
        }
        else {
            IO_STATUS_BLOCK cancelStatus = { 0 };

            /* Preserve lifetime safety even for an unexpected non-alertable wait failure. */
            (VOID)ZwCancelIoFileEx(handle, &ioStatus, &cancelStatus);
            (VOID)ZwWaitForSingleObject(handle, FALSE, NULL);
            status = waitStatus;
        }
    }

    /* Return the completed byte count when the caller requested it. */
    if (informationOut != NULL) {
        /* Only completed bytes reported by the target are exposed. */
        *informationOut = NT_SUCCESS(status) ? ioStatus.Information : 0U;
    }

    /* Propagate the target stack result without translating it. */
    return status;
}

static BOOLEAN
kswordStorageGuidEquals(
    _In_ const GUID* left,
    _In_ const GUID* right
    )
/*++

Routine Description:

    Compares two disk identifiers without relying on a user-mode helper.

--*/
{
    /* A bytewise comparison is valid because GUID has no ignored fields. */
    return RtlCompareMemory(left, right, sizeof(GUID)) == sizeof(GUID);
}

static BOOLEAN
kswordStorageIsSystemDisk(
    _In_ HANDLE handle
    )
/*++

Routine Description:

    Matches the physical disk layout identifier against loader-reported boot
    and system disk identifiers.

--*/
{
    /* The extended loader record covers both MBR signatures and GPT GUIDs. */
    BOOTDISK_INFORMATION_EX bootInfo = { 0 };
    /* Reserve enough space for the fixed layout header used by this check. */
    UCHAR layoutBuffer[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (sizeof(PARTITION_INFORMATION_EX) * 4U)] = { 0 };
    /* Interpret the local byte buffer as the documented layout structure. */
    PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX)layoutBuffer;
    /* Track the bytes returned only for defensive validation. */
    ULONG_PTR information = 0U;
    /* Query the loader-owned boot and system disk identities. */
    NTSTATUS status = IoGetBootDiskInformation(
        (PBOOTDISK_INFORMATION)&bootInfo,
        sizeof(bootInfo));

    /* A failed loader query is treated conservatively by the write path. */
    if (!NT_SUCCESS(status)) {
        /* Unknown identity is classified as system-sensitive. */
        return TRUE;
    }

    /* Query the candidate disk layout and its stable identifier. */
    status = kswordStorageSendHandleIoctl(
        handle,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL,
        0U,
        layoutBuffer,
        sizeof(layoutBuffer),
        &information);

    /* Missing layout identity is also treated conservatively. */
    if (!NT_SUCCESS(status) || information < FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) {
        /* Unknown identity is classified as system-sensitive. */
        return TRUE;
    }

    /* Compare MBR signatures when the target disk uses an MBR layout. */
    if (layout->PartitionStyle == PARTITION_STYLE_MBR) {
        /* Either the boot or system signature makes this a protected disk. */
        return layout->Mbr.Signature == bootInfo.BootDeviceSignature
            || layout->Mbr.Signature == bootInfo.SystemDeviceSignature;
    }

    /* Compare GPT disk identifiers when the target disk uses GPT. */
    if (layout->PartitionStyle == PARTITION_STYLE_GPT) {
        /* A GPT boot identifier is valid only when the loader says it is GPT. */
        if (bootInfo.BootDeviceIsGpt
            && kswordStorageGuidEquals(&layout->Gpt.DiskId, &bootInfo.BootDeviceGuid)) {
            /* The candidate disk contains the boot partition. */
            return TRUE;
        }

        /* A GPT system identifier is valid only when the loader says it is GPT. */
        if (bootInfo.SystemDeviceIsGpt
            && kswordStorageGuidEquals(&layout->Gpt.DiskId, &bootInfo.SystemDeviceGuid)) {
            /* The candidate disk contains the system partition. */
            return TRUE;
        }
    }

    /* No loader identity matched the candidate disk. */
    return FALSE;
}

static VOID
kswordStorageCopyDescriptorText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ size_t destinationChars,
    _In_reads_bytes_(descriptorBytes) const UCHAR* descriptor,
    _In_ ULONG descriptorBytes,
    _In_ ULONG textOffset
    )
/*++

Routine Description:

    Converts one bounded ANSI storage descriptor string to a wide string.

--*/
{
    /* Start with a valid empty destination for every failure path. */
    destination[0] = L'\0';

    /* A zero or out-of-range descriptor offset contains no usable text. */
    if (textOffset == 0U || textOffset >= descriptorBytes) {
        /* Leave the destination empty. */
        return;
    }

    /* Point at the descriptor string after validating its first byte. */
    const CHAR* source = (const CHAR*)(descriptor + textOffset);
    /* Bound the scan by the remaining descriptor bytes. */
    const ULONG kRemaining = descriptorBytes - textOffset;
    /* Count only bytes before the first terminator. */
    ULONG sourceChars = 0U;

    /* Scan the descriptor string without crossing the returned buffer. */
    while (sourceChars < kRemaining && source[sourceChars] != '\0') {
        /* Advance over one bounded ANSI character. */
        sourceChars += 1U;
    }

    /* Convert no more characters than the destination can hold. */
    const ULONG kCopyChars = (ULONG)min((size_t)sourceChars, destinationChars - 1U);

    /* Storage descriptors use printable ASCII for these identity fields. */
    for (ULONG index = 0U; index < kCopyChars; ++index) {
        /* Widen the unsigned byte without applying a locale transform. */
        destination[index] = (WCHAR)(UCHAR)source[index];
    }

    /* Terminate the wide destination explicitly. */
    destination[kCopyChars] = L'\0';
}

static VOID
kswordStorageCaptureLowerDevices(
    _Inout_ KswStorageDiskContext* context
    )
/*++

Routine Description:

    Captures independently referenced lower targets for the two bypass modes.

--*/
{
    /* Start at the top object returned by IoGetAttachedDeviceReference. */
    PDEVICE_OBJECT current = context->topDevice;
    /* Track how many lower objects were followed to bound malformed stacks. */
    ULONG depth = 0U;

    /* A missing top object leaves both bypass backends unavailable. */
    if (current == NULL) {
        /* No stack can be walked. */
        return;
    }

    /* The first lower object is the storage-port bypass target. */
    PDEVICE_OBJECT lower = IoGetLowerDeviceObject(current);

    /* Save the first lower target with its reference already held. */
    if (lower != NULL) {
        /* The context now owns the reference returned for this device. */
        context->portDevice = lower;
        /* Continue the walk from the first lower device. */
        current = lower;
        /* Record the first successful descent. */
        depth = 1U;
    }

    /* Walk to the deepest reachable target with a strict depth bound. */
    while (lower != NULL && depth < KSW_STORAGE_FORENSICS_MAX_STACK_DEPTH) {
        /* Acquire a reference to the next lower device. */
        PDEVICE_OBJECT next = IoGetLowerDeviceObject(current);

        /* Reaching the bottom finishes the controller-target search. */
        if (next == NULL) {
            /* Exit without acquiring another reference. */
            break;
        }

        /* Release the previous candidate controller reference, if any. */
        if (context->controllerDevice != NULL) {
            /* The final context retains only the deepest candidate. */
            ObDereferenceObject(context->controllerDevice);
        }

        /* Store the newly referenced deeper device as the current candidate. */
        context->controllerDevice = next;
        /* Continue walking from the new candidate. */
        current = next;
        /* Advance the strict stack-depth budget. */
        depth += 1U;
        /* Keep the loop condition synchronized with the current candidate. */
        lower = next;
    }

    /* A one-layer stack can use the same lower target for controller mode. */
    if (context->controllerDevice == NULL && context->portDevice != NULL) {
        /* Take a second independent reference for the controller field. */
        ObReferenceObject(context->portDevice);
        /* Both fields now own a separate reference to the same bottom object. */
        context->controllerDevice = context->portDevice;
    }
}

static NTSTATUS
kswordStorageOpenContext(
    _In_ ULONG diskNumber,
    _In_ ACCESS_MASK desiredAccess,
    _Out_ KswStorageDiskContext* context
    )
/*++

Routine Description:

    Opens one physical disk and collects size, geometry, identity and stack
    targets required by every raw-I/O backend.

--*/
{
    /* Zero every owned field before any operation that can fail. */
    RtlZeroMemory(context, sizeof(*context));
    /* Build the Win32 physical-disk kernel path used by ZwCreateFile. */
    NTSTATUS status = RtlStringCchPrintfW(
        context->path,
        RTL_NUMBER_OF(context->path),
        L"\\??\\PhysicalDrive%lu",
        diskNumber);

    /* Reject a path formatting failure before constructing object attributes. */
    if (!NT_SUCCESS(status)) {
        /* Propagate the bounded string helper error. */
        return status;
    }

    /* Wrap the physical-disk path for native object-manager APIs. */
    UNICODE_STRING diskPath = { 0 };
    /* initialize the counted string from the context-owned buffer. */
    RtlInitUnicodeString(&diskPath, context->path);
    /* Kernel handles prevent accidental reuse by the requesting process. */
    OBJECT_ATTRIBUTES attributes;
    /* Configure a case-insensitive kernel-handle open. */
    InitializeObjectAttributes(
        &attributes,
        &diskPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    /* The synchronous handle reports all completion through this local block. */
    IO_STATUS_BLOCK ioStatus = { 0 };

    /* Open the whole-disk object without requesting destructive share exclusion. */
    status = ZwCreateFile(
        &context->handle,
        desiredAccess | SYNCHRONIZE,
        &attributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0U);

    /* A missing or inaccessible disk ends context initialization. */
    if (!NT_SUCCESS(status)) {
        /* normalize the unused handle field for cleanup. */
        context->handle = NULL;
        /* Return the disk-open result. */
        return status;
    }

    /* Get the named disk device and a referenced file object for stack walking. */
    status = IoGetDeviceObjectPointer(
        &diskPath,
        FILE_READ_ATTRIBUTES,
        &context->fileObject,
        &context->namedDevice);

    /* Stack bypass modes require a named device object. */
    if (!NT_SUCCESS(status)) {
        /* Release the already opened handle before returning. */
        kswordStorageReleaseContext(context);
        /* Propagate the object lookup result. */
        return status;
    }

    /* Acquire an independent reference to the current top of the disk stack. */
    context->topDevice = IoGetAttachedDeviceReference(context->namedDevice);
    /* Capture lower objects for explicitly selected bypass backends. */
    kswordStorageCaptureLowerDevices(context);

    /* Use the documented default until geometry provides a better value. */
    context->logicalSectorSize = KSWORD_ARK_RAW_DISK_DEFAULT_SECTOR_SIZE;
    /* Physical sector size defaults to the logical size. */
    context->physicalSectorSize = context->logicalSectorSize;
    /* Query the disk byte length through the named stack. */
    GET_LENGTH_INFORMATION lengthInfo = { 0 };
    /* Ignore the returned-byte count because the structure is fixed size. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        NULL,
        0U,
        &lengthInfo,
        sizeof(lengthInfo),
        NULL);

    /* Preserve the valid non-negative disk length. */
    if (NT_SUCCESS(status) && lengthInfo.Length.QuadPart > 0) {
        /* Convert the signed documented field to the unsigned protocol field. */
        context->diskSizeBytes = (ULONGLONG)lengthInfo.Length.QuadPart;
    }

    /* Query the logical sector geometry. */
    DISK_GEOMETRY geometry = { 0 };
    /* The legacy geometry structure is sufficient for BytesPerSector. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        NULL,
        0U,
        &geometry,
        sizeof(geometry),
        NULL);

    /* Replace the default only with a nonzero device value. */
    if (NT_SUCCESS(status) && geometry.BytesPerSector != 0U) {
        /* Save the device-reported logical sector size. */
        context->logicalSectorSize = geometry.BytesPerSector;
        /* Keep the physical fallback synchronized with the logical sector. */
        context->physicalSectorSize = geometry.BytesPerSector;
    }

    /* Ask for the device descriptor that carries bus and identity metadata. */
    STORAGE_PROPERTY_QUERY propertyQuery = { 0 };
    /* Select the standard storage-device descriptor. */
    propertyQuery.PropertyId = StorageDeviceProperty;
    /* Request the current descriptor without an additional query payload. */
    propertyQuery.QueryType = PropertyStandardQuery;
    /* Keep descriptor storage bounded and stack-local. */
    UCHAR descriptorBuffer[KSW_STORAGE_FORENSICS_DESCRIPTOR_BYTES] = { 0 };
    /* Receive the actual descriptor byte count for offset validation. */
    ULONG_PTR descriptorBytes = 0U;
    /* Query the descriptor through the regular disk stack. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &propertyQuery,
        sizeof(propertyQuery),
        descriptorBuffer,
        sizeof(descriptorBuffer),
        &descriptorBytes);

    /* Parse only a complete fixed descriptor header. */
    if (NT_SUCCESS(status) && descriptorBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        /* Interpret the documented fixed header at the front of the buffer. */
        PSTORAGE_DEVICE_DESCRIPTOR descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)descriptorBuffer;
        /* Preserve the bus type for backend capability decisions. */
        context->busType = (ULONG)descriptor->BusType;
        /* Convert the bounded product identifier to protocol text. */
        kswordStorageCopyDescriptorText(
            context->model,
            RTL_NUMBER_OF(context->model),
            descriptorBuffer,
            (ULONG)descriptorBytes,
            descriptor->ProductIdOffset);
        /* Convert the bounded serial identifier to protocol text. */
        kswordStorageCopyDescriptorText(
            context->serial,
            RTL_NUMBER_OF(context->serial),
            descriptorBuffer,
            (ULONG)descriptorBytes,
            descriptor->SerialNumberOffset);
    }

    /* Query the physical-sector alignment descriptor when supported. */
    RtlZeroMemory(&propertyQuery, sizeof(propertyQuery));
    /* Select the access-alignment property. */
    propertyQuery.PropertyId = StorageAccessAlignmentProperty;
    /* Request the current descriptor. */
    propertyQuery.QueryType = PropertyStandardQuery;
    /* Receive the fixed alignment descriptor. */
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignment = { 0 };
    /* Submit the alignment property query. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &propertyQuery,
        sizeof(propertyQuery),
        &alignment,
        sizeof(alignment),
        NULL);

    /* Accept only a nonzero physical-sector result. */
    if (NT_SUCCESS(status) && alignment.BytesPerPhysicalSector != 0U) {
        /* Save the physical-sector granularity for user warnings. */
        context->physicalSectorSize = alignment.BytesPerPhysicalSector;
    }

    /* Query the port path/target/lun tuple when the disk exposes SCSI addressing. */
    RtlZeroMemory(&context->scsiAddress, sizeof(context->scsiAddress));
    /* Submit the fixed SCSI address query. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_SCSI_GET_ADDRESS,
        NULL,
        0U,
        &context->scsiAddress,
        sizeof(context->scsiAddress),
        NULL);

    /* Record the availability of the address tuple. */
    if (NT_SUCCESS(status)) {
        /* Advertise a valid SCSI address in the response capabilities. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_SCSI_ADDRESS;
    }

    /* Every successfully opened disk supports the named-stack read backend. */
    context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_WINDOWS_STACK;
    /* Every backend in this module is bounded to explicit read requests. */
    context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_READ;

    /* A captured first-lower target enables storage-port bypass reads. */
    if (context->portDevice != NULL) {
        /* Advertise the storage-port target. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_STORAGE_PORT;
    }

    /* Determine whether the disk is offline using documented disk attributes. */
    GET_DISK_ATTRIBUTES diskAttributes = { 0 };
    /* Seed the version field required by the disk class driver. */
    diskAttributes.Version = sizeof(diskAttributes);
    /* Query attributes through the named disk stack. */
    status = kswordStorageSendHandleIoctl(
        context->handle,
        IOCTL_DISK_GET_DISK_ATTRIBUTES,
        NULL,
        0U,
        &diskAttributes,
        sizeof(diskAttributes),
        NULL);

    /* Advertise offline state only when the class driver returned it. */
    if (NT_SUCCESS(status)
        && (diskAttributes.Attributes & DISK_ATTRIBUTE_OFFLINE) != 0ULL) {
        /* Offline disks are eligible for the deepest backend. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_OFFLINE;
    }

    /* Protect loader-identified boot and system disks. */
    if (kswordStorageIsSystemDisk(context->handle)) {
        /* Mark the disk so both R0 policy and R3 UI can enforce the boundary. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK;
    }

    /* Identify NVMe transports for accurate UI backend descriptions. */
    if (context->busType == BusTypeNvme) {
        /* Advertise native NVMe transport metadata. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_NVME;
    }

    /* Identify common ATA/AHCI transport families. */
    if (context->busType == BusTypeAta
        || context->busType == BusTypeSata
        || context->busType == BusTypeAtapi) {
        /* Advertise ATA-family transport metadata. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_ATA;
    }

    /* The deepest target is enabled only for a confirmed offline disk. */
    if (context->controllerDevice != NULL
        && (context->capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) != 0U) {
        /* Advertise the controller-target backend. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_CONTROLLER;
    }

    /* Writes are available only when the caller obtained a writable handle. */
    if ((desiredAccess & FILE_WRITE_DATA) != 0U) {
        /* Advertise write support after the access check succeeded. */
        context->capabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_WRITE;
    }

    /* Context initialization succeeded even when optional metadata was absent. */
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordStorageAllocateAlignedBuffer(
    _In_ ULONG length,
    _In_ ULONG alignment,
    _Outptr_ PVOID* allocationOut,
    _Outptr_ PVOID* alignedBufferOut
    )
/*++

Routine Description:

    Allocates a nonpaged transfer buffer aligned to the logical-sector size.

--*/
{
    /* Reject missing output pointers before allocating pool. */
    if (allocationOut == NULL || alignedBufferOut == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear both outputs before a possible allocation failure. */
    *allocationOut = NULL;
    /* Clear the aligned view independently. */
    *alignedBufferOut = NULL;
    /* normalize unsupported alignment values to the protocol default. */
    ULONG effectiveAlignment = alignment;

    /* A zero or non-power-of-two value cannot be used by ALIGN_UP_BY. */
    if (effectiveAlignment == 0U
        || (effectiveAlignment & (effectiveAlignment - 1U)) != 0U) {
        /* Use the protocol default sector alignment. */
        effectiveAlignment = KSWORD_ARK_RAW_DISK_DEFAULT_SECTOR_SIZE;
    }

    /* Reject arithmetic overflow before adding alignment padding. */
    if (length > MAXULONG - effectiveAlignment) {
        /* The allocation length cannot be represented. */
        return STATUS_INTEGER_OVERFLOW;
    }

    /* Allocate padding so the returned view can be aligned inside the block. */
    PVOID allocation = kswordArkAllocateNonPagedPool(
        (SIZE_T)length + effectiveAlignment,
        KSW_STORAGE_FORENSICS_POOL_TAG);

    /* Propagate pool exhaustion without exposing a partial output. */
    if (allocation == NULL) {
        /* No transfer buffer is available. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Round the first usable address up to the requested alignment. */
    PVOID aligned = (PVOID)ALIGN_UP_BY((ULONG_PTR)allocation, effectiveAlignment);
    /* Return the allocation base for ExFreePool. */
    *allocationOut = allocation;
    /* Return the aligned transfer view for I/O. */
    *alignedBufferOut = aligned;
    /* The allocation and alignment operation completed. */
    return STATUS_SUCCESS;
}

static PDEVICE_OBJECT
kswordStorageSelectBackendDevice(
    _In_ const KswStorageDiskContext* context,
    _In_ ULONG backend
    )
/*++

Routine Description:

    Maps a bypass backend identifier to an already referenced device object.

--*/
{
    /* The first-lower object implements the storage-port bypass mode. */
    if (backend == KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT) {
        /* Return the captured first-lower target. */
        return context->portDevice;
    }

    /* The deepest object implements the offline controller-target mode. */
    if (backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER) {
        /* Return the captured deepest target. */
        return context->controllerDevice;
    }

    /* The named-stack backend is handled through ZwReadFile or ZwWriteFile. */
    return NULL;
}

static NTSTATUS
kswordStorageSendDeviceReadWrite(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ UCHAR majorFunction,
    _In_ ULONGLONG offset,
    _Inout_updates_bytes_(length) PVOID buffer,
    _In_ ULONG length,
    _In_ BOOLEAN forceUnitAccess,
    _Out_ PULONG bytesTransferredOut
    )
/*++

Routine Description:

    Builds one synchronous read or write IRP directly for a selected lower
    device object.

--*/
{
    /* Reject a missing target before allocating an IRP. */
    if (deviceObject == NULL || bytesTransferredOut == NULL) {
        /* The backend target is unavailable. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the byte count before the request is submitted. */
    *bytesTransferredOut = 0U;
    /* A kernel event owns completion synchronization for the built IRP. */
    KEVENT completionEvent;
    /* initialize the event in the non-signaled state. */
    KeInitializeEvent(&completionEvent, NotificationEvent, FALSE);
    /* The completion routine writes the final I/O status here. */
    IO_STATUS_BLOCK ioStatus = { 0 };
    /* Convert the protocol offset to the signed LARGE_INTEGER API type. */
    LARGE_INTEGER byteOffset;
    /* Preserve the full 64-bit byte offset. */
    byteOffset.QuadPart = (LONGLONG)offset;
    /* Build an IRP that reflects the target device buffering flags. */
    PIRP irp = IoBuildSynchronousFsdRequest(
        majorFunction,
        deviceObject,
        buffer,
        length,
        &byteOffset,
        &completionEvent,
        &ioStatus);

    /* IRP allocation failure is reported before touching the target. */
    if (irp == NULL) {
        /* The I/O manager could not allocate the request. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Access the next stack location owned by the target driver. */
    PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(irp);
    /* Permit removable media reads after an operator-selected disk refresh. */
    stack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    /* A write can request hardware-level unit access where the stack honors it. */
    if (majorFunction == IRP_MJ_WRITE && forceUnitAccess) {
        /* Set the documented write-through stack flag. */
        stack->Flags |= SL_WRITE_THROUGH;
    }

    /* Send the fully built request to the explicitly selected target. */
    NTSTATUS status = IoCallDriver(deviceObject, irp);

    /* Wait only when the target retained the request asynchronously. */
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;

        /* Bound the normal wait so a lower storage driver cannot hold the worker forever. */
        timeout.QuadPart = KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS;
        waitStatus = KeWaitForSingleObject(
            &completionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            /* Request cancellation while the caller-owned event/IOSB/buffer are still alive. */
            (VOID)IoCancelIrp(irp);
            /* A final drain is mandatory before returning stack storage to the caller. */
            waitStatus = KeWaitForSingleObject(
                &completionEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            status = NT_SUCCESS(waitStatus) ? STATUS_IO_TIMEOUT : waitStatus;
        }
        else if (NT_SUCCESS(waitStatus)) {
            /* Read the final completion status after the event is signaled. */
            status = ioStatus.Status;
        }
        else {
            /* Unexpected wait failures still require cancellation and completion drainage. */
            (VOID)IoCancelIrp(irp);
            (VOID)KeWaitForSingleObject(
                &completionEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            status = waitStatus;
        }
    }

    /* Preserve the completed transfer size within the protocol ULONG limit. */
    if (NT_SUCCESS(status)) {
        /* The request length is already bounded to ULONG. */
        *bytesTransferredOut = (ULONG)min(ioStatus.Information, (ULONG_PTR)length);
    }

    /* Propagate the selected device object's completion status. */
    return status;
}

static NTSTATUS
kswordStorageValidateTransfer(
    _In_ const KswStorageDiskContext* context,
    _In_ ULONGLONG offset,
    _In_ ULONG length
    )
/*++

Routine Description:

    Enforces bounded, sector-aligned raw disk I/O ranges.

--*/
{
    /* Transfers must be non-empty and remain under the protocol budget. */
    if (length == 0U || length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) {
        /* Reject invalid or unbounded transfer lengths. */
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /* Both offset and length must align to the logical sector. */
    if ((offset % context->logicalSectorSize) != 0ULL
        || (length % context->logicalSectorSize) != 0U) {
        /* Raw disk requests cannot be silently widened. */
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    /* An unknown disk length cannot safely authorize raw transfer ranges. */
    if (context->diskSizeBytes == 0ULL) {
        /* Treat missing capacity metadata as an unavailable backend. */
        return STATUS_DEVICE_NOT_READY;
    }

    /* Check addition overflow before comparing the transfer end. */
    if (offset > MAXULONGLONG - length) {
        /* The requested range cannot be represented. */
        return STATUS_INTEGER_OVERFLOW;
    }

    /* Reject any range extending beyond the physical disk. */
    if (offset + length > context->diskSizeBytes) {
        /* The requested range crosses the disk boundary. */
        return STATUS_END_OF_FILE;
    }

    /* Every range check succeeded. */
    return STATUS_SUCCESS;
}

static ULONG
kswordStorageMapStatus(
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Maps kernel status values to stable protocol status identifiers.

--*/
{
    /* Successful requests have the stable OK identifier. */
    if (NT_SUCCESS(status)) {
        /* Return the protocol success status. */
        return KSWORD_ARK_RAW_DISK_STATUS_OK;
    }

    /* Translate common validation and availability failures. */
    switch (status) {
    case STATUS_INVALID_PARAMETER:
    case STATUS_INVALID_BUFFER_SIZE:
    case STATUS_INFO_LENGTH_MISMATCH:
        return KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
    case STATUS_NO_SUCH_DEVICE:
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
        return KSWORD_ARK_RAW_DISK_STATUS_DISK_NOT_FOUND;
    case STATUS_NOT_SUPPORTED:
    case STATUS_DEVICE_NOT_READY:
        return KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
    case STATUS_END_OF_FILE:
    case STATUS_INTEGER_OVERFLOW:
        return KSWORD_ARK_RAW_DISK_STATUS_RANGE_INVALID;
    case STATUS_DATATYPE_MISALIGNMENT:
        return KSWORD_ARK_RAW_DISK_STATUS_ALIGNMENT_REQUIRED;
    case STATUS_ACCESS_DENIED:
    case STATUS_PRIVILEGE_NOT_HELD:
        return KSWORD_ARK_RAW_DISK_STATUS_ACCESS_DENIED;
    case STATUS_BUFFER_TOO_SMALL:
    case STATUS_BUFFER_OVERFLOW:
        return KSWORD_ARK_RAW_DISK_STATUS_BUFFER_TOO_SMALL;
    default:
        return KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
    }
}

NTSTATUS
kswordArkStorageQueryRawDiskBackend(
    _In_ const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST* request,
    _Out_ KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE* response
    )
/*++

Routine Description:

    Returns one disk's bounded raw-I/O backend capabilities and identity.

--*/
{
    /* Reject missing protocol pointers before writing a response. */
    if (request == NULL || response == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* initialize the fixed response before validating caller-controlled fields. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the response protocol version. */
    response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the complete response size. */
    response->size = sizeof(*response);
    /* Echo the requested disk number for UI correlation. */
    response->diskNumber = request->diskNumber;
    /* Echo the requested backend without silently changing it. */
    response->requestedBackend = request->requestedBackend;

    /* Enforce the exact version and minimum request size. */
    if (request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
        || request->size < sizeof(*request)) {
        /* Report stable protocol validation status. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the kernel validation detail. */
        response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return a protocol-level error to the IOCTL handler. */
        return STATUS_REVISION_MISMATCH;
    }

    /* Collect read-only disk metadata and stack targets. */
    KswStorageDiskContext context;
    /* Open the candidate disk with read-only data and attribute access. */
    NTSTATUS status = kswordStorageOpenContext(
        request->diskNumber,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &context);

    /* Return a fully initialized failure response when the disk cannot open. */
    if (!NT_SUCCESS(status)) {
        /* Map the kernel failure to a stable protocol status. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the raw kernel status for diagnostics. */
        response->lastStatus = status;
        /* Copy a bounded diagnostic string. */
        (void)RtlStringCchPrintfW(
            response->detail,
            RTL_NUMBER_OF(response->detail),
            L"Physical disk %lu could not be opened (0x%08X).",
            request->diskNumber,
            (ULONG)status);
        /* Propagate the disk open failure. */
        return status;
    }

    /* Publish the collected capability flags. */
    response->capabilityFlags = context.capabilityFlags;
    /* Build the compact mask used by backend selectors. */
    response->availableBackendMask = 0U;

    /* Add the regular stack backend bit. */
    if ((context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_WINDOWS_STACK) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK - 1U);
    }

    /* Add the storage-port backend bit. */
    if ((context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_STORAGE_PORT) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT - 1U);
    }

    /* Add the deepest offline backend bit. */
    if ((context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER - 1U);
    }

    /* Publish all stable geometry and transport fields. */
    response->logicalSectorSize = context.logicalSectorSize;
    /* Publish the physical-sector warning granularity. */
    response->physicalSectorSize = context.physicalSectorSize;
    /* Publish the documented storage bus type. */
    response->busType = context.busType;
    /* Publish the SCSI path field when available. */
    response->pathId = context.scsiAddress.PathId;
    /* Publish the SCSI target field when available. */
    response->targetId = context.scsiAddress.TargetId;
    /* Publish the SCSI logical-unit field when available. */
    response->lun = context.scsiAddress.Lun;
    /* Publish the physical disk size. */
    response->diskSizeBytes = context.diskSizeBytes;
    /* Copy the bounded physical-disk path. */
    (void)RtlStringCchCopyW(
        response->devicePath,
        RTL_NUMBER_OF(response->devicePath),
        context.path);
    /* Copy the bounded model identifier. */
    (void)RtlStringCchCopyW(
        response->model,
        RTL_NUMBER_OF(response->model),
        context.model);
    /* Copy the bounded serial identifier. */
    (void)RtlStringCchCopyW(
        response->serial,
        RTL_NUMBER_OF(response->serial),
        context.serial);

    /* Validate an explicitly requested backend against the capability mask. */
    if (request->requestedBackend != 0U
        && (request->requestedBackend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
            || (response->availableBackendMask
                & (1UL << (request->requestedBackend - 1U))) == 0U)) {
        /* Report that the selected backend cannot serve this disk. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Use a stable kernel status for unsupported selection. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Explain the exact selection failure. */
        (void)RtlStringCchPrintfW(
            response->detail,
            RTL_NUMBER_OF(response->detail),
            L"Backend %lu is unavailable for physical disk %lu.",
            request->requestedBackend,
            request->diskNumber);
        /* Release every context-owned reference before returning. */
        kswordStorageReleaseContext(&context);
        /* Return a transport-neutral unsupported status. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Report a successful capability query. */
    response->status = KSWORD_ARK_RAW_DISK_STATUS_OK;
    /* Preserve an explicit successful NTSTATUS. */
    response->lastStatus = STATUS_SUCCESS;
    /* Summarize the enforced boundary for the UI. */
    (void)RtlStringCchPrintfW(
        response->detail,
        RTL_NUMBER_OF(response->detail),
        L"Backends=0x%X, sector=%lu/%lu, offline=%s, system=%s.",
        response->availableBackendMask,
        response->logicalSectorSize,
        response->physicalSectorSize,
        (context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) != 0U ? L"yes" : L"no",
        (context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U ? L"yes" : L"no");
    /* Release every context-owned reference after copying metadata. */
    kswordStorageReleaseContext(&context);
    /* The capability query completed successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkStorageReadRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_READ_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Reads one aligned, bounded disk range through the explicitly selected
    backend.

--*/
{
    /* Reject missing pointers before accessing caller buffers. */
    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the completion count for every failure path. */
    *bytesWrittenOut = 0U;
    /* Interpret the caller output as the variable protocol response. */
    PKSWORD_ARK_RAW_DISK_READ_RESPONSE response =
        (PKSWORD_ARK_RAW_DISK_READ_RESPONSE)outputBuffer;

    /* The fixed response header must always fit. */
    if (outputBufferLength < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE) {
        /* No protocol response can be returned. */
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* initialize only the fixed response header before validation. */
    RtlZeroMemory(response, KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE);
    /* Publish the current protocol version. */
    response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the fixed response header size initially. */
    response->size = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
    /* Echo the selected backend. */
    response->backendUsed = request->backend;

    /* Validate the fixed request and backend identifier. */
    if (request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
        || request->size < sizeof(*request)
        || request->backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        || request->backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER) {
        /* Report stable validation status. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the validation status. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the initialized header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Reject the malformed request. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Ensure the variable response data fits the WDF output buffer. */
    if (request->length > outputBufferLength - KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE) {
        /* Report the stable buffer-size failure. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BUFFER_TOO_SMALL;
        /* Preserve the kernel buffer status. */
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        /* Return the initialized header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Reject the undersized caller buffer. */
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Open the disk through its regular stack and capture bypass targets. */
    KswStorageDiskContext context;
    /* Reads require data and attribute access only. */
    NTSTATUS status = kswordStorageOpenContext(
        request->diskNumber,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &context);

    /* Stop before allocating transfer memory when the disk cannot open. */
    if (!NT_SUCCESS(status)) {
        /* Report the stable disk-open failure. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the kernel status. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Propagate the disk-open failure. */
        return status;
    }

    /* Publish the actual sector granularity before transfer validation. */
    response->logicalSectorSize = context.logicalSectorSize;
    /* Enforce the system-disk read confirmation for bypass backends. */
    if ((context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U
        && request->backend != KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        && (request->flags & KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_READ) == 0U) {
        /* Report the protected-system-disk boundary. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED;
        /* Preserve the access decision as a kernel status. */
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Deny the bypass read without explicit caller confirmation. */
        return STATUS_ACCESS_DENIED;
    }

    /* The controller-target backend is restricted to offline media. */
    if (request->backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        && (context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) == 0U) {
        /* Report backend unavailability. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Preserve the unsupported status. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Reject the unsupported backend. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Validate length, alignment and disk boundary before I/O. */
    status = kswordStorageValidateTransfer(
        &context,
        request->offset,
        request->length);

    /* Return the exact range validation failure. */
    if (!NT_SUCCESS(status)) {
        /* Map the failure to the stable protocol status. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the kernel status. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Propagate the range failure. */
        return status;
    }

    /* Allocate an aligned nonpaged buffer for every disk backend. */
    PVOID allocation = NULL;
    /* The aligned view is copied into the buffered IOCTL response after I/O. */
    PVOID transferBuffer = NULL;
    /* Request alignment matching the logical disk sector. */
    status = kswordStorageAllocateAlignedBuffer(
        request->length,
        context.logicalSectorSize,
        &allocation,
        &transferBuffer);

    /* Stop cleanly on pool exhaustion. */
    if (!NT_SUCCESS(status)) {
        /* Report the stable I/O failure. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the allocation failure. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Propagate the allocation failure. */
        return status;
    }

    /* Start with no transferred bytes. */
    ULONG transferred = 0U;

    /* Use the named physical-disk stack for backend one. */
    if (request->backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
        /* Convert the absolute byte offset to the ZwReadFile type. */
        LARGE_INTEGER byteOffset;
        /* Preserve the caller's full 64-bit offset. */
        byteOffset.QuadPart = (LONGLONG)request->offset;
        /* Receive synchronous completion metadata. */
        IO_STATUS_BLOCK ioStatus = { 0 };
        /* Read through the named disk stack. */
        status = ZwReadFile(
            context.handle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            transferBuffer,
            request->length,
            &byteOffset,
            NULL);

        /* Preserve the completed byte count when the request succeeded. */
        if (NT_SUCCESS(status)) {
            /* The requested length bounds the completion count. */
            transferred = (ULONG)min(ioStatus.Information, (ULONG_PTR)request->length);
        }
    } else {
        /* Select the independently referenced lower target. */
        PDEVICE_OBJECT target = kswordStorageSelectBackendDevice(
            &context,
            request->backend);
        /* Submit a direct read IRP to the selected lower device. */
        status = kswordStorageSendDeviceReadWrite(
            target,
            IRP_MJ_READ,
            request->offset,
            transferBuffer,
            request->length,
            FALSE,
            &transferred);
    }

    /* Copy completed bytes into the METHOD_BUFFERED output only on success. */
    if (NT_SUCCESS(status)) {
        /* Preserve exactly the bytes reported by the selected backend. */
        RtlCopyMemory(response->data, transferBuffer, transferred);
        /* Publish the transferred byte count. */
        response->bytesTransferred = transferred;
        /* Publish the full variable response size. */
        response->size = (ULONG)(KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE + transferred);
        /* Report stable protocol success. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_OK;
        /* Preserve successful kernel completion. */
        response->lastStatus = STATUS_SUCCESS;
        /* Return the full variable response. */
        *bytesWrittenOut = response->size;
    } else {
        /* Map the backend failure to a stable protocol status. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the raw backend failure. */
        response->lastStatus = status;
        /* Return only the initialized response header. */
        *bytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
    }

    /* Release the transfer allocation base. */
    ExFreePoolWithTag(allocation, KSW_STORAGE_FORENSICS_POOL_TAG);
    /* Release the disk handle and referenced stack objects. */
    kswordStorageReleaseContext(&context);
    /* Propagate the selected backend completion status. */
    return status;
}

NTSTATUS
kswordArkStorageWriteRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_WRITE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ KSWORD_ARK_RAW_DISK_WRITE_RESPONSE* response
    )
/*++

Routine Description:

    Writes one aligned disk range after protocol, safety-policy, system-disk
    and offline-backend checks.

--*/
{
    /* Reject missing protocol pointers before writing a response. */
    if (request == NULL || response == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* initialize the complete fixed response. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the current protocol version. */
    response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the fixed response size. */
    response->size = sizeof(*response);
    /* Echo the selected backend. */
    response->backendUsed = request->backend;

    /* Validate fixed fields and the variable input length. */
    if (request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
        || request->size < KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE
        || request->backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        || request->backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        || request->confirmationToken != KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN
        || (request->flags & KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE) == 0U
        || request->length > inputBufferLength - min(
            inputBufferLength,
            (size_t)KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE)) {
        /* Report stable protocol validation status. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the kernel validation status. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Reject the malformed or unconfirmed request. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Open the disk with explicit write data access. */
    KswStorageDiskContext context;
    /* Request both data directions because some stacks require read access for metadata. */
    NTSTATUS status = kswordStorageOpenContext(
        request->diskNumber,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
        &context);

    /* Return a stable failure when write access cannot be obtained. */
    if (!NT_SUCCESS(status)) {
        /* Map the disk-open failure. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the raw kernel status. */
        response->lastStatus = status;
        /* Propagate the disk-open failure. */
        return status;
    }

    /* Publish the actual logical-sector size. */
    response->logicalSectorSize = context.logicalSectorSize;

    /* System disks require the stronger explicit confirmation flag. */
    if ((context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U
        && (request->flags & KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE) == 0U) {
        /* Report the protected system-disk boundary. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED;
        /* Preserve the access decision. */
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Deny the write before safety-policy evaluation. */
        return STATUS_ACCESS_DENIED;
    }

    /* The deepest backend is enabled only for offline media. */
    if (request->backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        && (context.capabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) == 0U) {
        /* Report backend unavailability. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Preserve the unsupported status. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Reject the unsafe backend selection. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Validate length, alignment and disk boundary before policy evaluation. */
    status = kswordStorageValidateTransfer(
        &context,
        request->offset,
        request->length);

    /* Stop on an invalid raw disk range. */
    if (!NT_SUCCESS(status)) {
        /* Map the range failure. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the raw kernel status. */
        response->lastStatus = status;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Propagate the range failure. */
        return status;
    }

    /* Allocate an aligned nonpaged transfer buffer. */
    PVOID allocation = NULL;
    /* This aligned view is supplied to the disk stack. */
    PVOID transferBuffer = NULL;
    /* Align the buffer to the disk's logical sector. */
    status = kswordStorageAllocateAlignedBuffer(
        request->length,
        context.logicalSectorSize,
        &allocation,
        &transferBuffer);

    /* Stop cleanly on pool exhaustion. */
    if (!NT_SUCCESS(status)) {
        /* Map the allocation failure. */
        response->status = kswordStorageMapStatus(status);
        /* Preserve the allocation status. */
        response->lastStatus = status;
        /* Release the opened disk and referenced stack objects. */
        kswordStorageReleaseContext(&context);
        /* Propagate the allocation failure. */
        return status;
    }

    /* Copy caller bytes out of the METHOD_BUFFERED system buffer. */
    RtlCopyMemory(transferBuffer, request->data, request->length);
    /* Start with no transferred bytes. */
    ULONG transferred = 0U;

    /* Use the named physical-disk stack for backend one. */
    if (request->backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
        /* Convert the absolute byte offset to the ZwWriteFile type. */
        LARGE_INTEGER byteOffset;
        /* Preserve the caller's full 64-bit offset. */
        byteOffset.QuadPart = (LONGLONG)request->offset;
        /* Receive synchronous completion metadata. */
        IO_STATUS_BLOCK ioStatus = { 0 };
        /* Write through the named disk stack. */
        status = ZwWriteFile(
            context.handle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            transferBuffer,
            request->length,
            &byteOffset,
            NULL);

        /* Preserve the completed byte count when the write succeeded. */
        if (NT_SUCCESS(status)) {
            /* The requested length bounds the completion count. */
            transferred = (ULONG)min(ioStatus.Information, (ULONG_PTR)request->length);
        }
    } else {
        /* Select the independently referenced lower target. */
        PDEVICE_OBJECT target = kswordStorageSelectBackendDevice(
            &context,
            request->backend);
        /* Submit a direct write IRP to the selected lower device. */
        status = kswordStorageSendDeviceReadWrite(
            target,
            IRP_MJ_WRITE,
            request->offset,
            transferBuffer,
            request->length,
            (request->flags & KSWORD_ARK_RAW_DISK_FLAG_FUA) != 0U,
            &transferred);
    }

    /* Publish the completed write result. */
    response->status = kswordStorageMapStatus(status);
    /* Publish the exact backend transfer size. */
    response->bytesTransferred = transferred;
    /* Preserve the selected backend's raw completion status. */
    response->lastStatus = status;
    /* Release the aligned transfer allocation. */
    ExFreePoolWithTag(allocation, KSW_STORAGE_FORENSICS_POOL_TAG);
    /* Release the disk handle and referenced stack objects. */
    kswordStorageReleaseContext(&context);
    /* Propagate the selected backend completion status. */
    return status;
}
