/*++

Module Name:

    file_irp_request.c

Abstract:

    Create a custom IRP and dispatch it directly to a specific layer of the file system device stack. This contrasts with the Zw* path
    in file_directory_query.c: Zw* requests enter from the top of the stack, inevitably passing through FltMgr and all legacy filters.
    This module allows dispatching the same semantic request to either IoGetBaseFileSystemDeviceObject or
    VPB->DeviceObject, allowing R3 to use set difference to determine 'which entries are visible only when bypassing the filter layer'.

    This module rejects raw kernel pointers from R3. It derives every target DEVICE_OBJECT from a
    FILE_OBJECT it resolves from a path. User mode can choose the layer, not an arbitrary address.

Environment:

    Kernel-mode Driver Framework: all entry points require PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "ark/ark_file_irp.h"

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000UL
#endif

#ifndef IRP_MJ_MAXIMUM_FUNCTION
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b
#endif

#define KSWORD_ARK_FILE_IRP_POOL_TAG 'iFsK'

// Native buffer for a single QUERY_DIRECTORY call; kept consistent with file_directory_query.c
// to ensure both paths observe no difference in "how many entries can be retrieved at once".
#define KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES (64UL * 1024UL)

/*
 * ObCreateObject is not publicly declared in the WDK but is exported by ntoskrnl.exe. Manually
 * constructing a FILE_OBJECT is the only way to let IRP_MJ_CREATE itself bypass the filter layer:
 * the IoCreateFile series always enters from the top of the stack and cannot dispatch CREATE to the
 * base file system device. This path is only reached when targetLayer explicitly requires bypassing.
 */
NTKERNELAPI
NTSTATUS
NTAPI
ObCreateObject(
    _In_ KPROCESSOR_MODE probeMode,
    _In_ POBJECT_TYPE objectType,
    _In_ POBJECT_ATTRIBUTES objectAttributes,
    _In_ KPROCESSOR_MODE ownershipMode,
    _Inout_opt_ PVOID parseContext,
    _In_ ULONG objectBodySize,
    _In_ ULONG pagedPoolCharge,
    _In_ ULONG nonPagedPoolCharge,
    _Out_ PVOID* object
    );

// KswordArkFileIrpSync: synchronization block for completing a single synchronous IRP.
// The completion routine returns STATUS_MORE_PROCESSING_REQUIRED, so the I/O manager will not
// write to UserIosb; the final status must be copied here by the completion routine itself.
typedef struct KswordArkFileIrpSync
{
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
} KswordArkFileIrpSync, *PkswordArkFileIrpSync;

// KswordArkFileIrpTarget: A complete device stack view parsed from a single request.
// All three candidate layers are retained simultaneously; the response returns them together to R3 so the UI can explain 'why this layer is unavailable'.
typedef struct KswordArkFileIrpTarget
{
    PFILE_OBJECT fileObject;        // Target file object.
    PDEVICE_OBJECT targetDevice;    // The device to which this IRP was actually dispatched.
    PDEVICE_OBJECT relatedDevice;   // Result of IoGetRelatedDeviceObject.
    PDEVICE_OBJECT baseFsDevice;    // Result of IoGetBaseFileSystemDeviceObject.
    PDEVICE_OBJECT vpbDevice;       // VPB->DeviceObject。
    PDEVICE_OBJECT fileDevice;      // FileObject->DeviceObject。
    PDEVICE_OBJECT createDevice;    // The device that actually receives IRP_MJ_CREATE in the manual path.
    HANDLE fileHandle;              // Holds the kernel handle for the opened path.
    PWCHAR manualNameBuffer;        // Manual FILE_OBJECT name buffer.
    BOOLEAN manual;                 // TRUE indicates the FILE_OBJECT was constructed by this module.
    BOOLEAN vpbReferenced;          // Whether VPB reference was added after CREATE success.
    ULONG resolvedLayer;            // Actual effective stack layer.
    NTSTATUS createStatus;          // Result during CREATE phase.
} KswordArkFileIrpTarget, *PkswordArkFileIrpTarget;

static PVOID
kswordArkFileIrpAllocate(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate a non-paged buffer for the IRP data segment. The IRP may be asynchronously held by lower-level drivers, so the
    buffer cannot come from the call stack or from METHOD_BUFFERED system buffers that could be overwritten by the response.

Arguments:

    BufferBytes: request byte count; return NULL directly if 0.

Return Value:

    Returns the address on success, NULL on failure.

--*/
{
    PVOID buffer = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    buffer = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        bufferBytes,
        KSWORD_ARK_FILE_IRP_POOL_TAG);
#pragma warning(pop)

    if (buffer != NULL) {
        RtlZeroMemory(buffer, bufferBytes);
    }
    return buffer;
}

static VOID
kswordArkFileIrpFree(
    _In_opt_ PVOID buffer
    )
/*++

Routine Description:

    Free the buffer returned by kswordArkFileIrpAllocate; NULL input allows immediate return.

Arguments:

    Buffer - Address to be freed.

Return Value:

    None.

--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, KSWORD_ARK_FILE_IRP_POOL_TAG);
    }
}

static VOID
kswordArkFileIrpReleaseManualName(
    _Inout_ PkswordArkFileIrpTarget target,
    _In_opt_ PFILE_OBJECT fileObject
    )
/*++

Routine Description:

    Detach and free the name buffer used for manual CREATE from the FILE_OBJECT.

    After this buffer is attached to FILE_OBJECT->FileName.Buffer, it gains a second potential release point:
    When the reference count drops to zero, nt!IopDeleteFile checks FileName.Length; if non-zero, it frees
    FileName.Buffer using tag 0 (at nt!IopDeleteFile+0x195). If this module also frees the same pointer
    using its own tag, it results in a deterministic double-free — occurring on every open/close cycle.

    This error may not crash immediately: after the pool header is corrupted, a subsequent unrelated pool operation might trigger a 0x13A
    KERNEL_MODE_HEAP_CORRUPTION during consistency checks. The stack points to the discoverer, not the culprit (in practice, the
    discoverer is ndis/NETIO, while the corrupted block's ownership tag belongs to this module's KsFi). When the Driver Verifier's special
    pool is enabled, pages containing freed blocks are unmapped, causing a second free to read the pool header and crash immediately.
    0x50 PAGE_FAULT_IN_NONPAGED_AREA。

    Therefore, "detach" and "reattach" must be performed in pairs and before ObDereferenceObject: first clear
    FileName so IopDeleteFile has nothing to do, then release using this module's own tag. In another scenario
    where the file system replaces FileName.Buffer during reparse (reparse points / mount points / symbolic
    links / DFS), Target->ManualNameBuffer becomes a dangling pointer; do not touch it in such cases.

Arguments:

    Target - Target view; ManualNameBuffer is always cleared upon return.
    FileObject: The associated file object; NULL indicates it has not yet been handed to the file system.

Return Value:

    None.

--*/
{
    PWCHAR attached = (fileObject != NULL) ? fileObject->FileName.Buffer : NULL;

    if (fileObject != NULL) {
        //
        // Detach the buffer from FILE_OBJECT first. IopDeleteFile checks FileName.Length:
        // If non-zero, it will release FileName.Buffer again using tag 0 (nt!IopDeleteFile+0x195).
        // The acquire action and the release action must be paired; missing half results in a double-free or a leak.
        //
        fileObject->FileName.Buffer = NULL;
        fileObject->FileName.Length = 0U;
        fileObject->FileName.MaximumLength = 0U;
    }

    if (fileObject == NULL || attached == target->manualNameBuffer) {
        //
        // Buffer remains owned by this module (both being NULL also takes this path; the free operation is a no-op).
        // Note that 'the pointer remains unchanged' does not mean 'the file system was not modified': nt!IoReplaceFileObjectName performs
        // an in-place memset+memcpy (at the +0x2e branch) when the new name does not exceed MaximumLength, preserving the original pointer.
        // The remaining 32 WCHARs above exactly direct the reparse to this in-place rewrite branch.
        // However, regardless of content changes, ownership of this block remains with this module, so freeing it using this module's tag is correct.
        //
        kswordArkFileIrpFree(target->manualNameBuffer);
    }
    else if (attached != NULL) {
        //
        // The pointer has been replaced. The re-allocation branch of nt!IoReplaceFileObjectName (+0x7f)
        // uses ExAllocatePool2(POOL_FLAG_PAGED, ..., 'IoNm') to obtain a new block and directly frees
        // this module's block at +0xa3 using ExFreePoolWithTag(old_block, 0). Since the tag is 0 (no
        // validation), this module's pool block can indeed be freed by an unrelated component.
        // Therefore, Target->ManualNameBuffer is now a dangling pointer; no byte can be accessed.
        //
        // This block, now attached, must be freed by the party responsible for discarding the FILE_OBJECT per I/O Manager
        // conventions, always using tag 0 (as done in IopDeleteFile+0x195 and IopParseDevice+0x16f0). Since cleanup authority
        // has been assumed by this module, it must also release this block following the same rules; otherwise, a leak occurs.
        //
        ExFreePoolWithTag(attached, 0);
    }

    target->manualNameBuffer = NULL;
}

static VOID
kswordArkFileIrpDisposeManualFileObject(
    _Inout_ PkswordArkFileIrpTarget target,
    _In_ PFILE_OBJECT fileObject
    )
/*++

Routine Description:

    Discard the manually constructed FILE_OBJECT and prevent the I/O manager from performing cleanup again.

    Zeroing the reference triggers nt!IopDeleteFile, which finalizes according to the 'standard FILE_OBJECT' convention by performing four actions at once:
    IopCloseFile issues IRP_MJ_CLEANUP, we issue IRP_MJ_CLOSE, decrement the VPB reference
    count, and release FileName.Buffer with tag 0. The criteria are FO_HANDLE_CREATED and
    FO_FILE_OPEN_CANCELLED in Flags; since manually constructed objects never entered the
    handle table, these two flags are always 0, so all four actions execute.

    This module performs all four actions itself, using the actual device received during CREATE (Target->CreateDevice). The I/O
    Manager only sends requests to the topmost device returned by IoGetRelatedDeviceObject, which is precisely the layer this module
    intends to bypass. Therefore, the cleanup authority must remain within this module, and the redundant portion must be eliminated.

    This check is the first gate in IopDeleteFile: when FileObject->DeviceObject is NULL, it only calls
    IopDeleteFileObjectExtension and returns. Both Vpb and FileName are cleared together, so even if the check is moved later,
    the two operations of decrementing the VPB reference and releasing the name buffer each retain an independent safeguard.

    This is not a hack to bypass the kernel: when nt!IopParseDevice discards its own FILE_OBJECT, it
    performs "release name buffer → zero FileName.Length → set DeviceObject to NULL → dereference".

Arguments:

    Target - target view; ManualNameBuffer is set to NULL upon return.
    FileObject - Manual file object to be discarded.

Return Value:

    None.

--*/
{
    kswordArkFileIrpReleaseManualName(target, fileObject);
    fileObject->DeviceObject = NULL;
    fileObject->Vpb = NULL;
    ObDereferenceObject(fileObject);
}

static VOID
kswordArkFileIrpCloseVolumeAnchor(
    _In_opt_ PFILE_OBJECT volumeFileObject,
    _In_opt_ HANDLE volumeHandle
    )
/*++

Routine Description:

    Release the "volume anchor"—the handle and file object used to open the volume during manual CREATE.

    The manual path borrows three raw pointers from the volume file object: the mounted file system device, the real volume device,
    and the volume's VPB. Their lifetimes are entirely guaranteed by the single reference on the volume file object: the VPB and
    the FS device mounted on it are kept alive by VPB->ReferenceCount. Once the last FILE_OBJECT on the volume disappears, a forced
    unload, media ejection, or BitLocker volume lock can trigger VPB reclamation and FS device deletion through IoDeleteDevice.
    IoGetBaseFileSystemDeviceObject and Vpb->DeviceObject both return borrowed pointers;
    the documentation does not guarantee validity after the source FILE_OBJECT is released.

    Therefore, the anchor must be held until the manual CREATE succeeds and this module adds its own device and VPB references;
    it is released only on any exit path prior to that. Releasing it early means sending IRPs with a released device object.

Arguments:

    VolumeFileObject: Volume file object; may be NULL.
    VolumeHandle - The volume handle; may be NULL.

Return Value:

    None.

--*/
{
    if (volumeFileObject != NULL) {
        ObDereferenceObject(volumeFileObject);
    }
    if (volumeHandle != NULL) {
        ZwClose(volumeHandle);
    }
}

static NTSTATUS
kswordArkFileIrpCompletion(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp,
    _In_opt_ PVOID context
    )
/*++

Routine Description:

    Unified completion routine. After copying the final IO_STATUS_BLOCK, return STATUS_MORE_PROCESSING_REQUIRED to
    keep the IRP at this layer, with the initiator responsible for releasing the MDL and the IRP itself. Note: The
    reference implementation's 'IoFreeIrp then read Irp->UserEvent' pattern is use-after-free; this module reclaims
    all release responsibility to the initiator, with the completion routine solely handling state transfer.

Arguments:

    DeviceObject - Device object at completion; unused by this module.
    Irp: Completed request.
    Context - points to the KswordArkFileIrpSync on the caller's stack.

Return Value:

    Always return STATUS_MORE_PROCESSING_REQUIRED.

--*/
{
    PkswordArkFileIrpSync sync = (PkswordArkFileIrpSync)context;

    UNREFERENCED_PARAMETER(deviceObject);

    if (sync != NULL) {
        sync->ioStatus = irp->IoStatus;
        KeSetEvent(&sync->event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
kswordArkFileIrpCallAndWait(
    _In_ PDEVICE_OBJECT targetDevice,
    _In_ PIRP irp,
    _Inout_ PkswordArkFileIrpSync sync,
    _In_ ULONG timeoutMs,
    _In_ BOOLEAN powerIrp,
    _Out_ PBOOLEAN cancelledOut
    )
/*++

Routine Description:

    Submit a pre-filled IRP and wait synchronously for completion. On timeout, cancel first, then wait indefinitely for draining:
    since the Sync object resides on the call stack, it must never be returned to as long as the lower layers might still access it.

Arguments:

    TargetDevice - The dispatch target.
    Irp: Request with completion routine set.
    Sync - Complete the synchronization block; must remain valid before this function returns.
    TimeoutMs - Normal wait timeout limit.
    PowerIrp - Use PoCallDriver semantics when TRUE.
    CancelledOut - TRUE indicates this request was cancelled due to timeout.

Return Value:

    The final NTSTATUS written by the target driver.

--*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    LARGE_INTEGER timeout;

    *cancelledOut = FALSE;

    if (powerIrp) {
        status = PoCallDriver(targetDevice, irp);
    }
    else {
        status = IoCallDriver(targetDevice, irp);
    }

    if (status == STATUS_PENDING) {
        timeout.QuadPart = -((LONGLONG)timeoutMs * 10000LL);
        waitStatus = KeWaitForSingleObject(
            &sync->event,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            *cancelledOut = TRUE;
            (VOID)IoCancelIrp(irp);
            // Draining is mandatory: the completion routine still writes to Sync; returning early would corrupt the call stack.
            (VOID)KeWaitForSingleObject(
                &sync->event,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
    }

    return sync->ioStatus.Status;
}

static VOID
kswordArkFileIrpCopyObjectName(
    _In_opt_ PVOID object,
    _Out_writes_(maxChars) PWCHAR nameBuffer,
    _In_ ULONG maxChars,
    _Out_ PULONG nameLengthCharsOut
    )
/*++

Routine Description:

    Read the object name and write it to a fixed-width character field. On failure, leave an empty string without affecting the IRP result.

Arguments:

    Object: Driver object or device object.
    NameBuffer: Target fixed buffer.
    MaxChars - Buffer capacity (including trailing NUL).
    NameLengthCharsOut: Actual number of characters written.

Return Value:

    None.

--*/
{
    POBJECT_NAME_INFORMATION nameInformation = NULL;
    ULONG returnedLength = 0UL;
    ULONG copyChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    *nameLengthCharsOut = 0UL;
    if (maxChars == 0U) {
        return;
    }
    nameBuffer[0] = L'\0';
    if (object == NULL) {
        return;
    }

    nameInformation = (POBJECT_NAME_INFORMATION)kswordArkFileIrpAllocate(
        sizeof(OBJECT_NAME_INFORMATION) + (512U * sizeof(WCHAR)));
    if (nameInformation == NULL) {
        return;
    }

    status = ObQueryNameString(
        object,
        nameInformation,
        sizeof(OBJECT_NAME_INFORMATION) + (512U * sizeof(WCHAR)),
        &returnedLength);
    if (NT_SUCCESS(status) &&
        nameInformation->Name.Buffer != NULL &&
        nameInformation->Name.Length != 0U) {
        copyChars = (ULONG)(nameInformation->Name.Length / sizeof(WCHAR));
        if (copyChars >= maxChars) {
            copyChars = maxChars - 1U;
        }
        RtlCopyMemory(
            nameBuffer,
            nameInformation->Name.Buffer,
            copyChars * sizeof(WCHAR));
        nameBuffer[copyChars] = L'\0';
        *nameLengthCharsOut = copyChars;
    }

    kswordArkFileIrpFree(nameInformation);
}

static BOOLEAN
kswordArkFileIrpSplitVolumePath(
    _In_reads_(pathChars) PCWSTR path,
    _In_ USHORT pathChars,
    _Out_writes_(volumeBufferChars) PWCHAR volumeBuffer,
    _In_ USHORT volumeBufferChars,
    _Out_ PUSHORT volumeCharsOut,
    _Out_ PCWSTR* relativeNameOut,
    _Out_ PUSHORT relativeCharsOut
    )
/*++

Routine Description:

    Split the NT path into "volume root" and "relative path within the volume". When manually constructing a FILE_OBJECT, this split is required:
    When IRP_MJ_CREATE is passed to a file system device, FileObject->FileName must be a relative
    path within the volume; names with volume prefixes are rejected by the file system as invalid.

Arguments:

    Path/PathChars - Full NT path, e.g., \??\C:\Windows or
        \Device\HarddiskVolume3\Windows。
    VolumeBuffer/VolumeBufferChars: Receives the volume root path (including the trailing NUL).
    VolumeCharsOut: number of characters in the volume root.
    RelativeNameOut: Points to the start of the relative name within Path (begins with a backslash).
    RelativeCharsOut - number of characters in the relative name; the volume root itself returns 0.

Return Value:

    TRUE indicates successful recognition; FALSE indicates the volume path format is not supported.

--*/
{
    USHORT index = 0U;
    USHORT volumeChars = 0U;

    *volumeCharsOut = 0U;
    *relativeNameOut = NULL;
    *relativeCharsOut = 0U;
    if (path == NULL || pathChars < 4U || volumeBufferChars < 8U) {
        return FALSE;
    }

    if (pathChars >= 6U &&
        path[0] == L'\\' &&
        path[1] == L'?' &&
        path[2] == L'?' &&
        path[3] == L'\\' &&
        path[5] == L':') {
        // \??\C: format: volume root is fixed to the first 6 characters.
        volumeChars = 6U;
    }
    else if (pathChars > 8U &&
        (path[0] == L'\\') &&
        (path[1] == L'D' || path[1] == L'd')) {
        // Format \Device\XXX: from the volume root up to the fourth backslash (\Device\HarddiskVolumeN).
        USHORT separatorCount = 0U;
        for (index = 0U; index < pathChars; ++index) {
            if (path[index] != L'\\') {
                continue;
            }
            ++separatorCount;
            if (separatorCount == 3U) {
                break;
            }
        }
        if (separatorCount < 2U) {
            return FALSE;
        }
        volumeChars = (separatorCount == 3U) ? index : pathChars;
    }
    else {
        return FALSE;
    }

    if (volumeChars == 0U || volumeChars >= volumeBufferChars) {
        return FALSE;
    }

    RtlCopyMemory(volumeBuffer, path, volumeChars * sizeof(WCHAR));
    volumeBuffer[volumeChars] = L'\0';
    *volumeCharsOut = volumeChars;

    if (pathChars > volumeChars && path[volumeChars] == L'\\') {
        *relativeNameOut = path + volumeChars;
        *relativeCharsOut = (USHORT)(pathChars - volumeChars);
    }
    return TRUE;
}

static VOID
kswordArkFileIrpCaptureLayers(
    _In_ PFILE_OBJECT fileObject,
    _Inout_ PkswordArkFileIrpTarget target
    )
/*++

Routine Description:

    Record all optional target layers on a file object. All three layers must be retained so the UI can display whether the stack top
    and the base file system device are the same object; if they are the same, it indicates no filter layers are attached to this path.

Arguments:

    FileObject - The opened file object.
    Target - receives addresses from each layer.

Return Value:

    None.

--*/
{
    target->relatedDevice = IoGetRelatedDeviceObject(fileObject);
    target->baseFsDevice = IoGetBaseFileSystemDeviceObject(fileObject);
    target->fileDevice = fileObject->DeviceObject;
    target->vpbDevice = NULL;
    if (fileObject->Vpb != NULL) {
        target->vpbDevice = fileObject->Vpb->DeviceObject;
    }
    else if (fileObject->DeviceObject != NULL &&
        fileObject->DeviceObject->Vpb != NULL) {
        target->vpbDevice = fileObject->DeviceObject->Vpb->DeviceObject;
    }
}

static PDEVICE_OBJECT
kswordArkFileIrpSelectLayer(
    _In_ const KswordArkFileIrpTarget* target,
    _In_ ULONG requestedLayer,
    _Out_ PULONG resolvedLayerOut
    )
/*++

Routine Description:

    Select the dispatch layer based on the request. If the requested layer is unavailable, fall back to the stack top instead
    of failing, and report the actual effective layer to prevent R3 from mistaking the fallback result for a successful bypass.

Arguments:

    Target: The target view with the captured three-layer address.
    RequestedLayer - R3 requested layer.
    ResolvedLayerOut - The actual effective layer.

Return Value:

    Selected device object; returns NULL if all are unavailable.

--*/
{
    PDEVICE_OBJECT selected = NULL;

    *resolvedLayerOut = requestedLayer;
    switch (requestedLayer) {
    case KSWORD_ARK_FILE_IRP_LAYER_BASE_FS:
        selected = target->baseFsDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_VPB_FS:
        selected = target->vpbDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_DEVICE:
        selected = target->fileDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_RELATED:
    default:
        selected = target->relatedDevice;
        *resolvedLayerOut = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
        break;
    }

    if (selected == NULL) {
        selected = target->relatedDevice;
        *resolvedLayerOut = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
    }
    return selected;
}

static NTSTATUS
kswordArkFileIrpOpenManaged(
    _In_reads_(pathChars) PCWSTR path,
    _In_ USHORT pathChars,
    _In_ ACCESS_MASK desiredAccess,
    _In_ ULONG shareAccess,
    _In_ ULONG createDisposition,
    _In_ ULONG createOptions,
    _In_ ULONG fileAttributes,
    _Inout_ PkswordArkFileIrpTarget target
    )
/*++

Routine Description:

    Obtain the FILE_OBJECT via the normal I/O Manager open path. This path traverses all filter layers and
    serves as the 'stack top baseline'; subsequent major functions can still be dispatched to deeper layers.

Arguments:

    Path/PathChars - NT path.
    DesiredAccess/ShareAccess/CreateDisposition/CreateOptions/FileAttributes -
        CREATE parameters.
    Target - receives handle, file object, and addresses at each layer.

Return Value:

    NTSTATUS for ZwCreateFile and ObReferenceObjectByHandle.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)path;
    targetPath.Length = (USHORT)(pathChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &target->fileHandle,
        desiredAccess,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        fileAttributes,
        shareAccess,
        createDisposition,
        createOptions,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        target->fileHandle = NULL;
        return status;
    }

    status = ObReferenceObjectByHandle(
        target->fileHandle,
        0U,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&target->fileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(target->fileHandle);
        target->fileHandle = NULL;
        target->fileObject = NULL;
        return status;
    }

    target->manual = FALSE;
    kswordArkFileIrpCaptureLayers(target->fileObject, target);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkFileIrpOpenManual(
    _In_reads_(pathChars) PCWSTR path,
    _In_ USHORT pathChars,
    _In_ ACCESS_MASK desiredAccess,
    _In_ ULONG shareAccess,
    _In_ ULONG createDisposition,
    _In_ ULONG createOptions,
    _In_ ULONG fileAttributes,
    _In_ ULONG requestedLayer,
    _In_ ULONG timeoutMs,
    _Inout_ PkswordArkFileIrpTarget target
    )
/*++

Routine Description:

    Construct a FILE_OBJECT and directly dispatch IRP_MJ_CREATE to the file system device. This bypasses the
    filter layer even for the "open" step, revealing paths that are only hidden during the CREATE phase.

    The volume root is still obtained via a normal open because its VPB is needed to identify the currently mounted file
    system device versus the real volume device; the subsequent target file CREATE is entirely constructed by this function.

Arguments:

    Path/PathChars - Full NT path.
    DesiredAccess/ShareAccess/CreateDisposition/CreateOptions/FileAttributes -
        CREATE parameters.
    RequestedLayer - The layer to which the request is dispatched.
    TimeoutMs - The maximum wait time for CREATE.
    Target - Receives the constructed file object and addresses at each layer.

Return Value:

    NTSTATUS from path resolution, object construction, or the CREATE phase.

--*/
{
    WCHAR volumeBuffer[64] = { 0 };
    USHORT volumeChars = 0U;
    PCWSTR relativeName = NULL;
    USHORT relativeChars = 0U;
    UNICODE_STRING volumePath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE volumeHandle = NULL;
    PFILE_OBJECT volumeFileObject = NULL;
    PDEVICE_OBJECT fileSystemDevice = NULL;
    PDEVICE_OBJECT realDevice = NULL;
    PFILE_OBJECT manualFileObject = NULL;
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KswordArkFileIrpSync sync;
    ACCESS_STATE accessState;
    PVOID auxAccessData = NULL;
    IO_SECURITY_CONTEXT securityContext;
    BOOLEAN subjectContextCaptured = FALSE;
    BOOLEAN cancelled = FALSE;
    ULONG nameBufferBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!kswordArkFileIrpSplitVolumePath(
            path,
            pathChars,
            volumeBuffer,
            (USHORT)RTL_NUMBER_OF(volumeBuffer),
            &volumeChars,
            &relativeName,
            &relativeChars)) {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    RtlInitUnicodeString(&volumePath, volumeBuffer);
    InitializeObjectAttributes(
        &objectAttributes,
        &volumePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwOpenFile(
        &volumeHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(
        volumeHandle,
        0U,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&volumeFileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(volumeHandle);
        return status;
    }

    // Parse the current mounted file system device and the real volume device on the volume.
    if (requestedLayer == KSWORD_ARK_FILE_IRP_LAYER_BASE_FS) {
        fileSystemDevice = IoGetBaseFileSystemDeviceObject(volumeFileObject);
    }
    if (fileSystemDevice == NULL && volumeFileObject->Vpb != NULL) {
        fileSystemDevice = volumeFileObject->Vpb->DeviceObject;
        realDevice = volumeFileObject->Vpb->RealDevice;
    }
    if (realDevice == NULL) {
        realDevice = volumeFileObject->DeviceObject;
    }
    if (fileSystemDevice == NULL) {
        fileSystemDevice = IoGetRelatedDeviceObject(volumeFileObject);
    }

    //
    // The volume anchor is held until CREATE succeeds: the device pointers above and the realDevice->Vpb to be read
    // below are borrowed from the volume file object; once the anchor is released, they may become invalid at any time.
    //
    if (fileSystemDevice == NULL || realDevice == NULL) {
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Construct a raw FILE_OBJECT. ObCreateObject returns an object with a reference count of 1 that
    // is not inserted into the handle table; release it using ObDereferenceObject during cleanup.
    InitializeObjectAttributes(
        &objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    status = ObCreateObject(
        KernelMode,
        *IoFileObjectType,
        &objectAttributes,
        KernelMode,
        NULL,
        (ULONG)sizeof(FILE_OBJECT),
        0U,
        0U,
        (PVOID*)&manualFileObject);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return status;
    }

    RtlZeroMemory(manualFileObject, sizeof(FILE_OBJECT));
    manualFileObject->Type = IO_TYPE_FILE;
    manualFileObject->Size = sizeof(FILE_OBJECT);
    manualFileObject->DeviceObject = realDevice;
    manualFileObject->Vpb = realDevice->Vpb;
    manualFileObject->Flags = FO_SYNCHRONOUS_IO;
    KeInitializeEvent(&manualFileObject->Lock, SynchronizationEvent, FALSE);
    KeInitializeEvent(&manualFileObject->Event, NotificationEvent, FALSE);

    // Reserve extra space in the name buffer: the file system may rewrite FileName in reparse scenarios.
    nameBufferBytes = (ULONG)((relativeChars + 32U) * sizeof(WCHAR));
    target->manualNameBuffer = (PWCHAR)kswordArkFileIrpAllocate(nameBufferBytes);
    if (target->manualNameBuffer == NULL) {
        kswordArkFileIrpDisposeManualFileObject(target, manualFileObject);
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    manualFileObject->FileName.Buffer = target->manualNameBuffer;
    manualFileObject->FileName.MaximumLength = (USHORT)nameBufferBytes;
    if (relativeName != NULL && relativeChars != 0U) {
        RtlCopyMemory(
            manualFileObject->FileName.Buffer,
            relativeName,
            relativeChars * sizeof(WCHAR));
        manualFileObject->FileName.Length = (USHORT)(relativeChars * sizeof(WCHAR));
    }
    else {
        manualFileObject->FileName.Buffer[0] = L'\\';
        manualFileObject->FileName.Length = sizeof(WCHAR);
    }

    /*
     * Construct the security context for CREATE. We do not use SeCreateAccessState: the current WDK no longer exposes
     * this function or the layout of AUX_ACCESS_DATA. Passing a stack variable with a guessed structure size would
     * corrupt the stack if the layout changes. Instead, we manually populate ACCESS_STATE—the file system reads
     * RemainingDesiredAccess / PreviouslyGrantedAccess / SubjectSecurityContext，
     * All three can be correctly constructed using documented APIs.
     *
     * AuxData uses a single zero-initialized page: some file systems may dereference it; passing NULL would cause a
     * crash, and since its actual layout is not public, we can only guarantee it is 'large enough and all zeros'.
     */
    auxAccessData = kswordArkFileIrpAllocate(PAGE_SIZE);
    if (auxAccessData == NULL) {
        kswordArkFileIrpDisposeManualFileObject(target, manualFileObject);
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&accessState, sizeof(accessState));
    SeCaptureSubjectContext(&accessState.SubjectSecurityContext);
    subjectContextCaptured = TRUE;
    // Access checks have already been performed by this driver's IOCTL gate; declare here as "all granted, none remaining to check."
    accessState.OriginalDesiredAccess = desiredAccess;
    accessState.PreviouslyGrantedAccess = desiredAccess;
    accessState.RemainingDesiredAccess = 0UL;
    accessState.SecurityEvaluated = TRUE;
    accessState.SecurityDescriptor = NULL;
    accessState.AuxData = auxAccessData;

    RtlZeroMemory(&securityContext, sizeof(securityContext));
    securityContext.SecurityQos = NULL;
    securityContext.AccessState = &accessState;
    securityContext.DesiredAccess = desiredAccess;
    securityContext.FullCreateOptions = 0UL;

    irp = IoAllocateIrp(fileSystemDevice->StackSize, FALSE);
    if (irp == NULL) {
        if (subjectContextCaptured) {
            SeReleaseSubjectContext(&accessState.SubjectSecurityContext);
        }
        kswordArkFileIrpFree(auxAccessData);
        kswordArkFileIrpDisposeManualFileObject(target, manualFileObject);
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.event, NotificationEvent, FALSE);
    sync.ioStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.ioStatus;
    irp->UserEvent = NULL;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.AuxiliaryBuffer = NULL;
    irp->Tail.Overlay.OriginalFileObject = manualFileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = IRP_MJ_CREATE;
    stackLocation->MinorFunction = 0U;
    stackLocation->DeviceObject = fileSystemDevice;
    stackLocation->FileObject = manualFileObject;
    stackLocation->Parameters.Create.SecurityContext = &securityContext;
    // CreateDisposition occupies the high 8 bits of Options; this is the fixed encoding for IRP_MJ_CREATE.
    stackLocation->Parameters.Create.Options =
        ((createDisposition & 0xFFUL) << 24) | (createOptions & 0x00FFFFFFUL);
    stackLocation->Parameters.Create.FileAttributes = (USHORT)fileAttributes;
    stackLocation->Parameters.Create.ShareAccess = (USHORT)shareAccess;
    stackLocation->Parameters.Create.EaLength = 0UL;

    IoSetCompletionRoutine(
        irp,
        kswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = kswordArkFileIrpCallAndWait(
        fileSystemDevice,
        irp,
        &sync,
        timeoutMs,
        FALSE,
        &cancelled);

    IoFreeIrp(irp);
    if (subjectContextCaptured) {
        SeReleaseSubjectContext(&accessState.SubjectSecurityContext);
    }
    kswordArkFileIrpFree(auxAccessData);

    if (!NT_SUCCESS(status)) {
        //
        // Even if CREATE fails, the disarm entry must be taken: since the file system did not open successfully, it should
        // not receive a CLEANUP/CLOSE. IopDeleteFile does not check the CREATE result, only the shape of the FILE_OBJECT.
        // Additionally, the file system may have already performed a reparse and replaced FileName.Buffer before the failure.
        //
        kswordArkFileIrpDisposeManualFileObject(target, manualFileObject);
        kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return status;
    }

    // After CREATE succeeds, the file system has already registered this FILE_OBJECT in its internal structure. We
    // must increment the references for the device and VPB so that the CLEANUP/CLOSE phase at the end pairs correctly.
    InterlockedIncrement(&manualFileObject->DeviceObject->ReferenceCount);
    if (manualFileObject->Vpb != NULL) {
        KIRQL vpbIrql = 0;

        //
        // VPB->ReferenceCount must be modified under the VPB spinlock. On the kernel side
        // (nt!IopDecrementVpbRefCount), the operation is a plain dec [Vpb+0x1C], not an atomic instruction;
        // mutual exclusion is guaranteed by the queue spinlock. IoAcquireVpbSpinLock internally calls
        // KeAcquireQueuedSpinLock(9), which is the same lock (verified via disassembly on both sides).
        // Using Interlocked for concurrency is equivalent to locking and not locking simultaneously; updates will
        // be lost. If this count is lost, the volume may be unloaded while this module still holds the file object.
        //
        IoAcquireVpbSpinLock(&vpbIrql);
        manualFileObject->Vpb->ReferenceCount += 1;
        IoReleaseVpbSpinLock(vpbIrql);
        target->vpbReferenced = TRUE;
    }

    //
    // At this point, this module holds its own reference to both the device and the VPB; the borrowed
    // pointer no longer relies on the volume anchor for guarantee, so the anchor can be released.
    //
    kswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);

    target->fileObject = manualFileObject;
    target->manual = TRUE;
    // Remember the actual recipient of CREATE: CLEANUP/CLOSE must return to the same device. Sending to
    // another layer causes the file system to receive a cleanup request for a FILE_OBJECT it has never seen.
    target->createDevice = fileSystemDevice;
    kswordArkFileIrpCaptureLayers(manualFileObject, target);
    // The manual path already knows which device the CREATE request was dispatched to; record it directly as one of the optional layers.
    if (target->baseFsDevice == NULL) {
        target->baseFsDevice = fileSystemDevice;
    }
    if (target->vpbDevice == NULL) {
        target->vpbDevice = fileSystemDevice;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkFileIrpSendSimple(
    _In_ PDEVICE_OBJECT targetDevice,
    _In_ PFILE_OBJECT fileObject,
    _In_ UCHAR majorFunction,
    _In_ ULONG irpFlags,
    _In_ ULONG timeoutMs
    )
/*++

Routine Description:

    Send an IRP without a data buffer (CLEANUP/CLOSE/FLUSH_BUFFERS/SHUTDOWN).

Arguments:

    TargetDevice - The dispatch target.
    FileObject - Associated file object.
    MajorFunction - IRP_MJ_* value.
    IrpFlags - Initial value of IRP->Flags.
    TimeoutMs - Wait upper limit.

Return Value:

    NTSTATUS returned by the target driver.

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KswordArkFileIrpSync sync;
    BOOLEAN cancelled = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (targetDevice == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    irp = IoAllocateIrp(targetDevice->StackSize, FALSE);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.event, NotificationEvent, FALSE);
    sync.ioStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = irpFlags;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.ioStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = fileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = majorFunction;
    stackLocation->MinorFunction = 0U;
    stackLocation->DeviceObject = targetDevice;
    stackLocation->FileObject = fileObject;

    IoSetCompletionRoutine(
        irp,
        kswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = kswordArkFileIrpCallAndWait(
        targetDevice,
        irp,
        &sync,
        timeoutMs,
        FALSE,
        &cancelled);
    IoFreeIrp(irp);
    return status;
}

static VOID
kswordArkFileIrpCloseTarget(
    _Inout_ PkswordArkFileIrpTarget target,
    _In_ ULONG timeoutMs,
    _Out_ PNTSTATUS cleanupStatusOut,
    _Out_ PNTSTATUS closeStatusOut,
    _Out_ PULONG stageFlagsOut
    )
/*++

Routine Description:

    Finalize an opened target. The managed handle is returned to the I/O manager; manual objects must complete the
    CLEANUP → CLOSE sequence themselves, otherwise the file system will permanently hold a reference to the stream.

Arguments:

    Target - Target view to be finalized.
    TimeoutMs - maximum wait time for each cleanup IRP.
    CleanupStatusOut/CloseStatusOut: Two-stage results under the manual path.
    StageFlagsOut - Append the flags of executed stages.

Return Value:

    None.

--*/
{
    PDEVICE_OBJECT closeDevice = NULL;

    *cleanupStatusOut = STATUS_SUCCESS;
    *closeStatusOut = STATUS_SUCCESS;

    if (target->manual && target->fileObject != NULL) {
        /*
         * Cleanup must be returned to the original CREATE recipient. The manual path can dispatch CREATE to the
         * base file system device, but IoGetRelatedDeviceObject returns the stack top: once cleanup is performed
         * on the stack top, the file system receives a CLEANUP/CLOSE for a FILE_OBJECT it has never seen.
         */
        closeDevice = target->createDevice;
        if (closeDevice == NULL) {
            closeDevice = (target->relatedDevice != NULL)
                ? target->relatedDevice
                : target->targetDevice;
        }
        if (closeDevice != NULL) {
            *cleanupStatusOut = kswordArkFileIrpSendSimple(
                closeDevice,
                target->fileObject,
                IRP_MJ_CLEANUP,
                IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
                timeoutMs);
            *stageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLEANUP;

            if (target->vpbReferenced && target->fileObject->Vpb != NULL) {
                KIRQL vpbIrql = 0;

                // Paired with the increment after a successful CREATE; must also be performed under the VPB spinlock.
                IoAcquireVpbSpinLock(&vpbIrql);
                target->fileObject->Vpb->ReferenceCount -= 1;
                IoReleaseVpbSpinLock(vpbIrql);
                target->vpbReferenced = FALSE;
            }

            *closeStatusOut = kswordArkFileIrpSendSimple(
                closeDevice,
                target->fileObject,
                IRP_MJ_CLOSE,
                IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
                timeoutMs);
            *stageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLOSE;
        }
        if (target->fileObject->DeviceObject != NULL) {
            InterlockedDecrement(&target->fileObject->DeviceObject->ReferenceCount);
        }
        //
        // The entire block above (CLEANUP, VPB dereference, CLOSE, device dereference) is exactly what IopDeleteFile does again when the
        // reference count reaches zero. Dropping the entry first disarms the FILE_OBJECT and then dereferences it; the order cannot be reversed:
        // disarming requires reading DeviceObject/Vpb, and dereferencing also requires reading them, so both must precede the dereference.
        //
        kswordArkFileIrpDisposeManualFileObject(target, target->fileObject);
        target->fileObject = NULL;
        return;
    }

    if (target->fileObject != NULL) {
        ObDereferenceObject(target->fileObject);
        target->fileObject = NULL;
    }
    if (target->fileHandle != NULL) {
        *closeStatusOut = ZwClose(target->fileHandle);
        target->fileHandle = NULL;
        *stageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLOSE;
    }
}

static NTSTATUS
kswordArkFileIrpOpenTarget(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request,
    _In_ ULONG timeoutMs,
    _Inout_ PkswordArkFileIrpTarget target
    )
/*++

Routine Description:

    Select the open mode based on the request stack level: use managed open at the top stack level, and manual CREATE dispatch for other levels.
    This way, the UI option 'which layer to select' simultaneously determines whether CREATE bypasses the filter layer.

Arguments:

    Request - A request snapshot with boundary checks completed.
    TimeoutMs - CREATE wait timeout limit.
    Target - receives the open result.

Return Value:

    NTSTATUS from the CREATE phase.

--*/
{
    ULONG createOptions = request->createOptions;
    ULONG createDisposition = request->createDisposition;
    ACCESS_MASK desiredAccess = (ACCESS_MASK)request->desiredAccess;
    ULONG shareAccess = request->shareAccess;

    if (desiredAccess == 0UL) {
        desiredAccess = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    }
    if (shareAccess == 0UL) {
        shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    }
    if (createDisposition == 0UL) {
        createDisposition = FILE_OPEN;
    }
    if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT) != 0UL) {
        createOptions |= FILE_OPEN_REPARSE_POINT;
    }
    if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT) != 0UL) {
        createOptions |= FILE_DIRECTORY_FILE;
    }
    createOptions |= FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT;

    if (request->targetLayer == KSWORD_ARK_FILE_IRP_LAYER_RELATED) {
        return kswordArkFileIrpOpenManaged(
            request->path,
            request->pathLengthChars,
            desiredAccess,
            shareAccess,
            createDisposition,
            createOptions,
            request->fileAttributes != 0UL
                ? request->fileAttributes
                : FILE_ATTRIBUTE_NORMAL,
            target);
    }

    return kswordArkFileIrpOpenManual(
        request->path,
        request->pathLengthChars,
        desiredAccess,
        shareAccess,
        createDisposition,
        createOptions,
        request->fileAttributes != 0UL
            ? request->fileAttributes
            : FILE_ATTRIBUTE_NORMAL,
        request->targetLayer,
        timeoutMs,
        target);
}

// KswordArkFileIrpBufferMode: the data transfer convention used by the target major function.
typedef enum KswordArkFileIrpBufferMode
{
    kKswordArkFileIrpBufferNone = 0,      // No data segment.
    kKswordArkFileIrpBufferSystem,        // AssociatedIrp.SystemBuffer。
    kKswordArkFileIrpBufferUser,          // UserBuffer (with MDL if necessary).
    kKswordArkFileIrpBufferDeviceFlags,   // Based on target device DO_BUFFERED_IO/DO_DIRECT_IO.
    kKswordArkFileIrpBufferControlCode    // Determined by the METHOD_* of the control code.
} KswordArkFileIrpBufferMode;

static KswordArkFileIrpBufferMode
kswordArkFileIrpBufferModeForMajor(
    _In_ ULONG majorFunction
    )
/*++

Routine Description:

    Return the data transfer convention for a major function. These conventions are fixed definitions from IRP major function codes
    and do not change with specific file systems; only READ/WRITE and two types of control codes require runtime information.

Arguments:

    MajorFunction - IRP_MJ_* value.

Return Value:

    Corresponding buffer mode.

--*/
{
    switch (majorFunction) {
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        return kKswordArkFileIrpBufferDeviceFlags;

    case IRP_MJ_QUERY_INFORMATION:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_QUERY_EA:
    case IRP_MJ_SET_EA:
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_QUERY_QUOTA:
    case IRP_MJ_SET_QUOTA:
        return kKswordArkFileIrpBufferSystem;

    case IRP_MJ_DIRECTORY_CONTROL:
    case IRP_MJ_QUERY_SECURITY:
    case IRP_MJ_SET_SECURITY:
        return kKswordArkFileIrpBufferUser;

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return kKswordArkFileIrpBufferControlCode;

    default:
        return kKswordArkFileIrpBufferNone;
    }
}

static BOOLEAN
kswordArkFileIrpMajorIsWriteLike(
    _In_ ULONG majorFunction
    )
/*++

Routine Description:

    Determine if a major function code might alter disk or device state. Write semantics must require UI confirmation
    of a token to prevent a no-gate entry point from being shared between 'viewing a directory' and 'rewriting a file'.

Arguments:

    MajorFunction - IRP_MJ_* value.

Return Value:

    TRUE indicates write semantics.

--*/
{
    switch (majorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_SET_SECURITY:
    case IRP_MJ_SET_QUOTA:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_LOCK_CONTROL:
    case IRP_MJ_CREATE_NAMED_PIPE:
    case IRP_MJ_CREATE_MAILSLOT:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
kswordArkFileIrpRequestHasWriteSemantics(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request
    )
/*++

Routine Description:

    Audit the CREATE phase disposition/options in addition to the major function check. Query-type major functions
    also require opening the target first; if the caller changes the open mode to FILE_CREATE/OPEN_IF/OVERWRITE or
    FILE_DELETE_ON_CLOSE, it will still modify the file system, so token confirmation is required.

--*/
{
    if (kswordArkFileIrpMajorIsWriteLike(request->majorFunction)) {
        return TRUE;
    }
    if (request->createDisposition >= FILE_CREATE &&
        request->createDisposition <= FILE_OVERWRITE_IF) {
        return TRUE;
    }
    return ((request->createOptions & FILE_DELETE_ON_CLOSE) != 0UL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkFileIrpMajorIsDangerous(
    _In_ ULONG majorFunction
    )
/*++

Routine Description:

    Determine if a major function belongs to the category of 'operations that are inherently contrary to the design intent when sent to the file system stack'.
    The PnP/power manager issues these requests through a strict state machine. Constructing them
    manually can easily put the target driver into an invalid state, so ALLOW_DANGEROUS is also required.

Arguments:

    MajorFunction - IRP_MJ_* value.

Return Value:

    TRUE indicates additional confirmation is required.

--*/
{
    switch (majorFunction) {
    case IRP_MJ_POWER:
    case IRP_MJ_PNP:
    case IRP_MJ_SYSTEM_CONTROL:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_DEVICE_CHANGE:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID
kswordArkFileIrpFillStackLocation(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request,
    _In_ PIO_STACK_LOCATION stackLocation,
    _In_opt_ PVOID dataBuffer,
    _In_ ULONG dataBytes,
    _In_opt_ PUNICODE_STRING pattern,
    _In_ PLARGE_INTEGER lockLength
    )
/*++

Routine Description:

    Populate the IO_STACK_LOCATION parameter union according to the major function. Each branch writes only the fields defined
    for that major; leave undefined fields zero to avoid propagating residual values from the previous layer as valid parameters.

Arguments:

    Request - Snapshot request.
    StackLocation: The stack location the target driver will read.
    DataBuffer/DataBytes: Prepared data buffer.
    Pattern - Wildcard for file names in DIRECTORY_CONTROL.
    LockLength - LOCK_CONTROL length value. Since the IRP only stores a pointer, this storage must be
        held by the caller until the request completes and cannot be a local variable of this function.

Return Value:

    None.

--*/
{
    LARGE_INTEGER byteOffset;

    byteOffset.QuadPart = (LONGLONG)request->byteOffset;

    switch (request->majorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CREATE_NAMED_PIPE:
    case IRP_MJ_CREATE_MAILSLOT:
        // CREATE is already completed during the open phase; here, only R3 requesting
        // 'CREATE only' is possible, so parameters do not need to be filled again.
        break;

    case IRP_MJ_READ:
        stackLocation->Parameters.Read.Length = dataBytes;
        stackLocation->Parameters.Read.ByteOffset = byteOffset;
        stackLocation->Parameters.Read.Key = request->lockKey;
        break;

    case IRP_MJ_WRITE:
        stackLocation->Parameters.Write.Length = dataBytes;
        stackLocation->Parameters.Write.ByteOffset = byteOffset;
        stackLocation->Parameters.Write.Key = request->lockKey;
        break;

    case IRP_MJ_QUERY_INFORMATION:
        stackLocation->Parameters.QueryFile.Length = dataBytes;
        stackLocation->Parameters.QueryFile.FileInformationClass =
            (FILE_INFORMATION_CLASS)request->informationClass;
        break;

    case IRP_MJ_SET_INFORMATION:
        stackLocation->Parameters.SetFile.Length = dataBytes;
        stackLocation->Parameters.SetFile.FileInformationClass =
            (FILE_INFORMATION_CLASS)request->informationClass;
        break;

    case IRP_MJ_QUERY_EA:
        stackLocation->Parameters.QueryEa.Length = dataBytes;
        break;

    case IRP_MJ_SET_EA:
        stackLocation->Parameters.SetEa.Length = dataBytes;
        break;

    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        stackLocation->Parameters.QueryVolume.Length = dataBytes;
        stackLocation->Parameters.QueryVolume.FsInformationClass =
            (FS_INFORMATION_CLASS)request->informationClass;
        break;

    case IRP_MJ_SET_VOLUME_INFORMATION:
        stackLocation->Parameters.SetVolume.Length = dataBytes;
        stackLocation->Parameters.SetVolume.FsInformationClass =
            (FS_INFORMATION_CLASS)request->informationClass;
        break;

    case IRP_MJ_DIRECTORY_CONTROL:
        if (request->minorFunction == IRP_MN_QUERY_DIRECTORY) {
            stackLocation->Parameters.QueryDirectory.Length = dataBytes;
            stackLocation->Parameters.QueryDirectory.FileName = pattern;
            stackLocation->Parameters.QueryDirectory.FileInformationClass =
                (FILE_INFORMATION_CLASS)request->informationClass;
        }
        else {
            stackLocation->Parameters.NotifyDirectory.Length = dataBytes;
            stackLocation->Parameters.NotifyDirectory.CompletionFilter =
                request->informationClass;
        }
        break;

    // The following three control code branches must, like other branches, derive the length solely from DataBytes.
    // Request->inputBytes and outputBytes are self-reported values from R3, while the actual buffer passed to the
    // target driver is only DataBytes bytes (= max(actual input length, min(response capacity, output length))).
    // Once the self-reported value exceeds DataBytes, the target driver writes to this pool memory based on the self-reported
    // length, directly overflowing the allocation boundary—this is the cause of 0x13A KERNEL_MODE_HEAP_CORRUPTION.
    // Taking the minimum does not alter the normal path: under normal conditions, the two values are already equal.
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        stackLocation->Parameters.FileSystemControl.FsControlCode =
            request->controlCode;
        stackLocation->Parameters.FileSystemControl.InputBufferLength =
            (request->inputBytes < dataBytes) ? request->inputBytes : dataBytes;
        stackLocation->Parameters.FileSystemControl.OutputBufferLength =
            (request->outputBytes < dataBytes) ? request->outputBytes : dataBytes;
        break;

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        stackLocation->Parameters.DeviceIoControl.IoControlCode =
            request->controlCode;
        stackLocation->Parameters.DeviceIoControl.InputBufferLength =
            (request->inputBytes < dataBytes) ? request->inputBytes : dataBytes;
        stackLocation->Parameters.DeviceIoControl.OutputBufferLength =
            (request->outputBytes < dataBytes) ? request->outputBytes : dataBytes;
        break;

    case IRP_MJ_LOCK_CONTROL:
        stackLocation->Parameters.LockControl.Key = request->lockKey;
        stackLocation->Parameters.LockControl.ByteOffset = byteOffset;
        stackLocation->Parameters.LockControl.Length = lockLength;
        break;

    case IRP_MJ_QUERY_SECURITY:
        stackLocation->Parameters.QuerySecurity.SecurityInformation =
            request->securityInformation;
        stackLocation->Parameters.QuerySecurity.Length = dataBytes;
        break;

    case IRP_MJ_SET_SECURITY:
        stackLocation->Parameters.SetSecurity.SecurityInformation =
            request->securityInformation;
        stackLocation->Parameters.SetSecurity.SecurityDescriptor = dataBuffer;
        break;

    case IRP_MJ_QUERY_QUOTA:
        stackLocation->Parameters.QueryQuota.Length = dataBytes;
        break;

    case IRP_MJ_SET_QUOTA:
        stackLocation->Parameters.SetQuota.Length = dataBytes;
        break;

    case IRP_MJ_POWER:
        // The power request parameter union is determined by the minor. Here, only the system power
        // state is filled; informationClass reuses the target SYSTEM_POWER_STATE; other fields remain
        // zero to let the target driver handle it as unsupported rather than reading dirty values.
        stackLocation->Parameters.Power.SystemContext = 0UL;
        stackLocation->Parameters.Power.Type = SystemPowerState;
        stackLocation->Parameters.Power.State.SystemState =
            (SYSTEM_POWER_STATE)request->informationClass;
        break;

    default:
        // SHUTDOWN/CLEANUP/CLOSE/FLUSH/PNP/SYSTEM_CONTROL/DEVICE_CHANGE do not require generic parameters;
        // PNP-specific minor parameters are interpreted by the target driver according to the minor type.
        break;
    }
}

static NTSTATUS
kswordArkFileIrpExecuteOperation(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request,
    _In_ PkswordArkFileIrpTarget target,
    _In_reads_bytes_opt_(inputBytes) const void* inputData,
    _In_ ULONG inputBytes,
    _In_ ULONG timeoutMs,
    _Out_writes_bytes_to_(outputCapacity, *outputBytesOut) PVOID outputBuffer,
    _In_ ULONG outputCapacity,
    _Out_ PULONG outputBytesOut,
    _Out_ PULONGLONG informationOut,
    _Out_ PBOOLEAN cancelledOut
    )
/*++

Routine Description:

    Construct and dispatch the IRP for the target major function, then copy the result data back to the response buffer.

Arguments:

    Request - Snapshot request.
    Target - Opened target view.
    InputData/InputBytes - Inline input data provided by R3.
    TimeoutMs - Wait upper limit.
    OutputBuffer/OutputCapacity - Writable data region in the response.
    OutputBytesOut - Actual number of bytes written back.
    InformationOut - IoStatus.Information。
    CancelledOut - TRUE indicates timeout cancellation.

Return Value:

    NTSTATUS for the target major.

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KswordArkFileIrpSync sync;
    KswordArkFileIrpBufferMode bufferMode = kKswordArkFileIrpBufferNone;
    PVOID dataBuffer = NULL;
    PMDL dataMdl = NULL;
    ULONG dataBytes = 0UL;
    ULONG requestedOutputBytes = 0UL;
    ULONG transferMethod = 0UL;
    UNICODE_STRING pattern;
    PUNICODE_STRING patternPointer = NULL;
    LARGE_INTEGER lockLength;
    BOOLEAN powerIrp = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    *outputBytesOut = 0UL;
    *informationOut = 0ULL;
    *cancelledOut = FALSE;

    if (target->targetDevice == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    lockLength.QuadPart = (LONGLONG)request->lockLength;

    // Take the larger of "input length" and "writable output length" for the data segment capacity: under METHOD_BUFFERED semantics, both
    // share a single buffer; separate allocations would cause the target driver to see an inconsistent view. The request's output length is
    // first capped against the actual bytes the response can hold to prevent the driver from filling an R3 buffer that cannot be consumed.
    requestedOutputBytes = (request->outputBytes < outputCapacity)
        ? request->outputBytes
        : outputCapacity;
    dataBytes = (inputBytes > requestedOutputBytes)
        ? inputBytes
        : requestedOutputBytes;

    bufferMode = kswordArkFileIrpBufferModeForMajor(request->majorFunction);
    if (bufferMode != kKswordArkFileIrpBufferNone && dataBytes != 0UL) {
        dataBuffer = kswordArkFileIrpAllocate(dataBytes);
        if (dataBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (inputData != NULL && inputBytes != 0UL) {
            RtlCopyMemory(dataBuffer, inputData, inputBytes);
        }
    }

    irp = IoAllocateIrp(target->targetDevice->StackSize, FALSE);
    if (irp == NULL) {
        kswordArkFileIrpFree(dataBuffer);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.event, NotificationEvent, FALSE);
    sync.ioStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.ioStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = target->fileObject;
    // PnP requests default to STATUS_NOT_SUPPORTED so the intermediate layer can correctly determine if the request has been handled.
    irp->IoStatus.Status = (request->majorFunction == IRP_MJ_PNP)
        ? STATUS_NOT_SUPPORTED
        : STATUS_SUCCESS;
    irp->IoStatus.Information = 0ULL;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = (UCHAR)request->majorFunction;
    stackLocation->MinorFunction = (UCHAR)request->minorFunction;
    stackLocation->DeviceObject = target->targetDevice;
    stackLocation->FileObject = target->fileObject;
    stackLocation->Flags = 0U;
    if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN) != 0UL) {
        stackLocation->Flags |= SL_RESTART_SCAN;
    }
    if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY) != 0UL) {
        stackLocation->Flags |= SL_RETURN_SINGLE_ENTRY;
    }

    // Bind data buffer.
    switch (bufferMode) {
    case kKswordArkFileIrpBufferSystem:
        // Set only IRP_BUFFERED_IO, not IRP_DEALLOCATE_BUFFER: the buffer is allocated by this module, so the deallocation
        // responsibility must also remain within this module; handing it to the I/O Manager would cause a double-free.
        irp->AssociatedIrp.SystemBuffer = dataBuffer;
        irp->Flags |= IRP_BUFFERED_IO;
        break;

    case kKswordArkFileIrpBufferUser:
        irp->UserBuffer = dataBuffer;
        if (dataBuffer != NULL &&
            (target->targetDevice->Flags & DO_DIRECT_IO) != 0UL) {
            dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
            if (dataMdl == NULL) {
                IoFreeIrp(irp);
                kswordArkFileIrpFree(dataBuffer);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            MmBuildMdlForNonPagedPool(dataMdl);
            irp->MdlAddress = dataMdl;
        }
        break;

    case kKswordArkFileIrpBufferDeviceFlags:
        if (dataBuffer != NULL) {
            if ((target->targetDevice->Flags & DO_BUFFERED_IO) != 0UL) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
            else if ((target->targetDevice->Flags & DO_DIRECT_IO) != 0UL) {
                dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
                if (dataMdl == NULL) {
                    IoFreeIrp(irp);
                    kswordArkFileIrpFree(dataBuffer);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                MmBuildMdlForNonPagedPool(dataMdl);
                irp->MdlAddress = dataMdl;
            }
            else {
                irp->UserBuffer = dataBuffer;
            }
        }
        irp->Flags |= (request->majorFunction == IRP_MJ_READ)
            ? IRP_READ_OPERATION
            : IRP_WRITE_OPERATION;
        irp->Flags |= IRP_NOCACHE;
        break;

    case kKswordArkFileIrpBufferControlCode:
        transferMethod = request->controlCode & 3UL;
        if (dataBuffer != NULL) {
            if (transferMethod == METHOD_BUFFERED) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
            else if (transferMethod == METHOD_IN_DIRECT ||
                     transferMethod == METHOD_OUT_DIRECT) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
                if (dataMdl == NULL) {
                    IoFreeIrp(irp);
                    kswordArkFileIrpFree(dataBuffer);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                MmBuildMdlForNonPagedPool(dataMdl);
                irp->MdlAddress = dataMdl;
            }
            else {
                stackLocation->Parameters.DeviceIoControl.Type3InputBuffer =
                    dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
        }
        break;

    case kKswordArkFileIrpBufferNone:
    default:
        break;
    }

    if (request->majorFunction == IRP_MJ_DIRECTORY_CONTROL &&
        request->patternLengthChars != 0U) {
        RtlZeroMemory(&pattern, sizeof(pattern));
        pattern.Buffer = (PWCH)request->pattern;
        pattern.Length = (USHORT)(request->patternLengthChars * sizeof(WCHAR));
        pattern.MaximumLength = (USHORT)(pattern.Length + sizeof(WCHAR));
        patternPointer = &pattern;
    }

    kswordArkFileIrpFillStackLocation(
        request,
        stackLocation,
        dataBuffer,
        dataBytes,
        patternPointer,
        &lockLength);

    IoSetCompletionRoutine(
        irp,
        kswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    powerIrp = (request->majorFunction == IRP_MJ_POWER) ? TRUE : FALSE;
    status = kswordArkFileIrpCallAndWait(
        target->targetDevice,
        irp,
        &sync,
        timeoutMs,
        powerIrp,
        cancelledOut);

    if (powerIrp) {
        // Power request convention: The next power IRP in the queue must always be released regardless of the result.
        PoStartNextPowerIrp(irp);
    }

    *informationOut = (ULONGLONG)sync.ioStatus.Information;

    // Fill back output data. Information is the target driver's self-reported value and cannot be directly treated as a trusted length:
    // Only accept if within (0, dataBytes]; otherwise, revert to the 'R3 request output window' so the caller can
    // still see the original buffer content and judge independently. Finally, always cap at the actual capacity.
    if (dataBuffer != NULL && outputBuffer != NULL && outputCapacity != 0UL) {
        ULONG copyBytes = (ULONG)sync.ioStatus.Information;
        if (copyBytes == 0UL || copyBytes > dataBytes) {
            copyBytes = requestedOutputBytes;
        }
        if (copyBytes > dataBytes) {
            copyBytes = dataBytes;
        }
        if (copyBytes > outputCapacity) {
            copyBytes = outputCapacity;
        }
        if (copyBytes != 0UL) {
            RtlCopyMemory(outputBuffer, dataBuffer, copyBytes);
        }
        *outputBytesOut = copyBytes;
    }

    if (dataMdl != NULL) {
        irp->MdlAddress = NULL;
        IoFreeMdl(dataMdl);
    }
    IoFreeIrp(irp);
    kswordArkFileIrpFree(dataBuffer);
    return status;
}

NTSTATUS
kswordArkDriverSubmitFileIrp(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request,
    _In_reads_bytes_opt_(inputBytes) const void* inputData,
    _In_ ULONG inputBytes,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE* response = NULL;
    KswordArkFileIrpTarget target;
    ULONG outputCapacity = 0UL;
    ULONG outputBytes = 0UL;
    ULONG stageFlags = 0UL;
    ULONG timeoutMs = 0UL;
    ULONGLONG information = 0ULL;
    BOOLEAN cancelled = FALSE;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    outputCapacity = (ULONG)(
        outputBufferLength - KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE);

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
    response->size = KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;
    response->status = KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST;
    response->majorFunction = request->majorFunction;
    response->minorFunction = request->minorFunction;
    response->targetLayer = request->targetLayer;
    response->createStatus = STATUS_UNSUCCESSFUL;
    response->operationStatus = STATUS_UNSUCCESSFUL;
    response->cleanupStatus = STATUS_UNSUCCESSFUL;
    response->closeStatus = STATUS_UNSUCCESSFUL;
    *bytesWrittenOut = KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST;
        response->operationStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (request->majorFunction > IRP_MJ_MAXIMUM_FUNCTION ||
        request->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX) {
        response->operationStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    // Dual gate for write semantics and dangerous major functions: check the token first, then the specific flag.
    if (kswordArkFileIrpRequestHasWriteSemantics(request) ||
        kswordArkFileIrpMajorIsDangerous(request->majorFunction)) {
        if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED) == 0UL ||
            request->confirmationToken != KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN) {
            response->status = KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED;
            response->operationStatus = STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }
    }
    if (kswordArkFileIrpMajorIsDangerous(request->majorFunction) &&
        (request->flags & KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS) == 0UL) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED;
        response->operationStatus = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }

    timeoutMs = request->timeoutMs;
    if (timeoutMs == 0UL || timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS) {
        timeoutMs = KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS;
    }

    RtlZeroMemory(&target, sizeof(target));
    status = kswordArkFileIrpOpenTarget(request, timeoutMs, &target);
    response->createStatus = status;
    stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_CREATE;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED;
        response->stageFlags = stageFlags;
        return STATUS_SUCCESS;
    }

    target.targetDevice = kswordArkFileIrpSelectLayer(
        &target,
        request->targetLayer,
        &target.resolvedLayer);
    response->targetLayer = target.resolvedLayer;
    response->fileObjectAddress = (ULONGLONG)(ULONG_PTR)target.fileObject;
    response->relatedDeviceAddress = (ULONGLONG)(ULONG_PTR)target.relatedDevice;
    response->baseFsDeviceAddress = (ULONGLONG)(ULONG_PTR)target.baseFsDevice;
    response->vpbDeviceAddress = (ULONGLONG)(ULONG_PTR)target.vpbDevice;
    response->targetDeviceAddress = (ULONGLONG)(ULONG_PTR)target.targetDevice;

    if (target.targetDevice != NULL) {
        response->targetStackSize = (ULONG)target.targetDevice->StackSize;
        response->targetDeviceFlags = target.targetDevice->Flags;
        response->targetDriverAddress =
            (ULONGLONG)(ULONG_PTR)target.targetDevice->DriverObject;
        if (target.targetDevice->DriverObject != NULL &&
            request->majorFunction <= IRP_MJ_MAXIMUM_FUNCTION) {
            response->dispatchAddress = (ULONGLONG)(ULONG_PTR)
                target.targetDevice->DriverObject->MajorFunction[
                    request->majorFunction];
        }
        kswordArkFileIrpCopyObjectName(
            target.targetDevice->DriverObject,
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->driverNameLengthChars);
        kswordArkFileIrpCopyObjectName(
            target.targetDevice,
            response->deviceName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->deviceNameLengthChars);
    }

    // CREATE_ONLY validates only during the open phase and sends no further requests.
    if ((request->flags & KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY) != 0UL ||
        request->majorFunction == IRP_MJ_CREATE) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        response->operationStatus = status;
    }
    else {
        NTSTATUS operationStatus = kswordArkFileIrpExecuteOperation(
            request,
            &target,
            inputData,
            inputBytes,
            timeoutMs,
            response->outputData,
            outputCapacity,
            &outputBytes,
            &information,
            &cancelled);
        stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OPERATION;
        response->operationStatus = operationStatus;
        response->information = information;
        response->outputBytes = outputBytes;
        if (cancelled) {
            stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_CANCELLED;
            response->status = KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT;
        }
        else if (information > (ULONGLONG)outputBytes) {
            stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED;
            response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        }
        else {
            response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        }
    }

    // Cleanup is unconditionally executed. SKIP_CLEANUP_CLOSE only indicates that the caller intends to pair CLEANUP/CLOSE
    // themselves, but once an IOCTL completes, R3 can no longer reference this kernel file object. Skipping cleanup here would
    // permanently leak a file object and a volume reference, so this flag does not alter the release behavior at this location.
    kswordArkFileIrpCloseTarget(
        &target,
        timeoutMs,
        &cleanupStatus,
        &closeStatus,
        &stageFlags);
    response->cleanupStatus = cleanupStatus;
    response->closeStatus = closeStatus;

    response->stageFlags = stageFlags;
    response->size =
        KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE + response->outputBytes;
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkFileIrpConsumeDirectoryBuffer(
    _In_reads_bytes_(nativeBytes) const UCHAR* nativeBuffer,
    _In_ ULONG nativeBytes,
    _In_ ULONG startIndex,
    _In_ ULONG maximumRows,
    _Inout_ PULONG visibleIndex,
    _Inout_ KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* response,
    _Out_ PBOOLEAN pageCompleteOut
    )
/*++

Routine Description:

    Convert a FILE_ID_BOTH_DIR_INFORMATION chain to a fixed-protocol line. Perform per-field boundary checks consistent
    with file_directory_query.c so that the line contents of both paths can be directly compared for set difference.

Arguments:

    NativeBuffer/NativeBytes - Native buffer written back by the target driver.
    StartIndex: Index of the first visible entry on the current page.
    MaximumRows: Maximum number of rows per page.
    VisibleIndex - Cumulative visible index across buffers.
    Response: Received line response.
    PageCompleteOut - TRUE indicates this page is full.

Return Value:

    STATUS_SUCCESS or STATUS_DATA_ERROR.

--*/
{
    ULONG nativeOffset = 0UL;
    const ULONG kNativeHeaderBytes =
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);

    *pageCompleteOut = FALSE;

    while (nativeOffset < nativeBytes) {
        const FILE_ID_BOTH_DIR_INFORMATION* nativeEntry = NULL;
        KSWORD_ARK_DIRECTORY_ENTRY* outputEntry = NULL;
        ULONG remainingBytes = nativeBytes - nativeOffset;
        ULONG nameChars = 0UL;
        ULONG copyNameChars = 0UL;
        ULONG minimumEntryBytes = 0UL;
        BOOLEAN dotEntry = FALSE;

        if (remainingBytes < kNativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        nativeEntry = (const FILE_ID_BOTH_DIR_INFORMATION*)(
            nativeBuffer + nativeOffset);
        if ((nativeEntry->FileNameLength % sizeof(WCHAR)) != 0U) {
            return STATUS_DATA_ERROR;
        }
        if (nativeEntry->FileNameLength > remainingBytes - kNativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        minimumEntryBytes = kNativeHeaderBytes + nativeEntry->FileNameLength;
        if (nativeEntry->NextEntryOffset != 0UL &&
            (nativeEntry->NextEntryOffset < minimumEntryBytes ||
                nativeEntry->NextEntryOffset > remainingBytes)) {
            return STATUS_DATA_ERROR;
        }

        dotEntry = (nativeEntry->FileNameLength == sizeof(WCHAR) &&
                nativeEntry->FileName[0] == L'.') ||
            (nativeEntry->FileNameLength == (2U * sizeof(WCHAR)) &&
                nativeEntry->FileName[0] == L'.' &&
                nativeEntry->FileName[1] == L'.');

        if (!dotEntry) {
            if (*visibleIndex < startIndex) {
                *visibleIndex += 1UL;
            }
            else if (response->rowCount >= maximumRows) {
                response->responseFlags |=
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE;
                *pageCompleteOut = TRUE;
                return STATUS_SUCCESS;
            }
            else {
                outputEntry = &response->rows[response->rowCount];
                RtlZeroMemory(outputEntry, sizeof(*outputEntry));
                outputEntry->fileAttributes = nativeEntry->FileAttributes;
                outputEntry->fileId = (ULONGLONG)nativeEntry->FileId.QuadPart;
                outputEntry->allocationSize = nativeEntry->AllocationSize.QuadPart;
                outputEntry->endOfFile = nativeEntry->EndOfFile.QuadPart;
                outputEntry->creationTime = nativeEntry->CreationTime.QuadPart;
                outputEntry->lastAccessTime = nativeEntry->LastAccessTime.QuadPart;
                outputEntry->lastWriteTime = nativeEntry->LastWriteTime.QuadPart;
                outputEntry->changeTime = nativeEntry->ChangeTime.QuadPart;

                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY;
                }
                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_REPARSE_POINT;
                }

                nameChars = (ULONG)(nativeEntry->FileNameLength / sizeof(WCHAR));
                copyNameChars = nameChars;
                if (copyNameChars >= KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS) {
                    copyNameChars = KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS - 1UL;
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_NAME_TRUNCATED;
                }
                if (copyNameChars != 0UL) {
                    RtlCopyMemory(
                        outputEntry->name,
                        nativeEntry->FileName,
                        copyNameChars * sizeof(WCHAR));
                }
                outputEntry->name[copyNameChars] = L'\0';
                outputEntry->nameLengthChars = copyNameChars;
                response->rowCount += 1UL;
                *visibleIndex += 1UL;
            }
        }

        if (nativeEntry->NextEntryOffset == 0UL) {
            break;
        }
        nativeOffset += nativeEntry->NextEntryOffset;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkFileIrpQueryDirectoryOnce(
    _In_ PkswordArkFileIrpTarget target,
    _Out_writes_bytes_(bufferBytes) PVOID buffer,
    _In_ ULONG bufferBytes,
    _In_ BOOLEAN restartScan,
    _In_ ULONG timeoutMs,
    _Out_ PULONG returnedBytesOut
    )
/*++

Routine Description:

    Send one IRP_MJ_DIRECTORY_CONTROL/IRP_MN_QUERY_DIRECTORY to the target layer.

Arguments:

    Target - Opened directory target.
    Buffer/BufferBytes - Non-paged receive buffer.
    RestartScan - TRUE indicates starting from the beginning.
    TimeoutMs - Wait upper limit.
    ReturnedBytesOut - Valid number of bytes written back by the target driver.

Return Value:

    NTSTATUS returned by the target driver.

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KswordArkFileIrpSync sync;
    BOOLEAN cancelled = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    *returnedBytesOut = 0UL;
    if (target->targetDevice == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    irp = IoAllocateIrp(target->targetDevice->StackSize, FALSE);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.event, NotificationEvent, FALSE);
    sync.ioStatus.Status = STATUS_UNSUCCESSFUL;

    /*
     * Directory queries attach only to UserBuffer, not MDL. File systems retrieve buffers using...
     * FsRtlGetUserBuffer: If MdlAddress is set, use MDL mapping; otherwise, use UserBuffer. Both paths are valid. However,
     * skipping the MDL layer reduces potential failure points (mapping failure, incomplete flags). Since the buffer here is
     * already contiguous non-paged pool memory, passing the virtual address directly is the most straightforward approach.
     */
    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = buffer;
    irp->Flags = IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.ioStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = target->fileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    stackLocation->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    stackLocation->DeviceObject = target->targetDevice;
    stackLocation->FileObject = target->fileObject;
    stackLocation->Flags = restartScan ? SL_RESTART_SCAN : 0U;
    stackLocation->Parameters.QueryDirectory.Length = bufferBytes;
    stackLocation->Parameters.QueryDirectory.FileName = NULL;
    stackLocation->Parameters.QueryDirectory.FileInformationClass =
        FileIdBothDirectoryInformation;

    IoSetCompletionRoutine(
        irp,
        kswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = kswordArkFileIrpCallAndWait(
        target->targetDevice,
        irp,
        &sync,
        timeoutMs,
        FALSE,
        &cancelled);

    if (NT_SUCCESS(status)) {
        *returnedBytesOut = (ULONG)sync.ioStatus.Information;
    }

    IoFreeIrp(irp);
    return status;
}

NTSTATUS
kswordArkDriverEnumerateDirectoryByIrp(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* response = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST openRequest;
    KswordArkFileIrpTarget target;
    PVOID nativeBuffer = NULL;
    ULONG maximumRowsByBuffer = 0UL;
    ULONG maximumRows = 0UL;
    ULONG visibleIndex = 0UL;
    ULONG returnedBytes = 0UL;
    ULONG stageFlags = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN pageComplete = FALSE;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength <
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maximumRowsByBuffer = (ULONG)(
        (outputBufferLength -
            KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    maximumRows = request->maxEntries;
    if (maximumRows > maximumRowsByBuffer) {
        maximumRows = maximumRowsByBuffer;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
    response->size = KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;
    response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE;
    response->rowSize = (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
    response->startIndex = request->startIndex;
    response->nextIndex = request->startIndex;
    response->targetLayer = request->targetLayer;
    response->openStatus = STATUS_UNSUCCESSFUL;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *bytesWrittenOut = KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        maximumRows == 0UL ||
        request->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST;
        response->lastStatus = (KeGetCurrentIrql() != PASSIVE_LEVEL)
            ? STATUS_INVALID_DEVICE_STATE
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    /*
     * Directory enumeration always uses the managed path to open, rather than manually constructing a FILE_OBJECT based on the request layer.
     *
     * Reason: A FILE_OBJECT obtained through a manual CREATE can make NTFS return STATUS_SUCCESS, but
     * lacks the complete associations established by the normal I/O manager path (RelatedFileObject,
     * fields populated by IopParseDevice, and others). NTFS later uses NtfsDecodeFileObject in
     * IRP_MJ_DIRECTORY_CONTROL to identify the open type. If it cannot identify UserDirectoryOpen, it
     * immediately returns STATUS_INVALID_PARAMETER(0xC000000D), which was consistently reproduced on C:\.
     *
     * Therefore, step back here: open via the I/O manager to ensure the file object state remains complete.
     * IRP_MJ_DIRECTORY_CONTROL requests that truly need to bypass the filter layer are still sent directly according to targetLayer.
     * This precisely covers the most common interception point for hidden files—rewriting the FILE_*_DIRECTORY_INFORMATION
     * list upon completion of directory queries. The trade-off is that interception cannot bypass the CREATE phase; this
     * boundary must be truthfully communicated to the caller, without claiming "even opening is bypassed."
     */
    RtlZeroMemory(&openRequest, sizeof(openRequest));
    openRequest.targetLayer = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
    openRequest.desiredAccess = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    openRequest.shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    openRequest.createDisposition = FILE_OPEN;
    openRequest.fileAttributes = FILE_ATTRIBUTE_NORMAL;
    openRequest.flags = KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT;
    openRequest.pathLengthChars = request->pathLengthChars;
    RtlCopyMemory(
        openRequest.path,
        request->path,
        (SIZE_T)request->pathLengthChars * sizeof(WCHAR));

    RtlZeroMemory(&target, sizeof(target));
    status = kswordArkFileIrpOpenTarget(
        &openRequest,
        KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
        &target);
    response->openStatus = status;
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED;
        return STATUS_SUCCESS;
    }

    target.targetDevice = kswordArkFileIrpSelectLayer(
        &target,
        request->targetLayer,
        &target.resolvedLayer);
    response->targetLayer = target.resolvedLayer;
    response->targetDeviceAddress = (ULONGLONG)(ULONG_PTR)target.targetDevice;
    if (target.targetDevice != NULL) {
        response->targetDriverAddress =
            (ULONGLONG)(ULONG_PTR)target.targetDevice->DriverObject;
        kswordArkFileIrpCopyObjectName(
            target.targetDevice->DriverObject,
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->driverNameLengthChars);
    }

    nativeBuffer = kswordArkFileIrpAllocate(
        KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES);
    if (nativeBuffer == NULL) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        kswordArkFileIrpCloseTarget(
            &target,
            KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
            &cleanupStatus,
            &closeStatus,
            &stageFlags);
        return STATUS_SUCCESS;
    }

    for (;;) {
        RtlZeroMemory(nativeBuffer, KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES);
        returnedBytes = 0UL;
        status = kswordArkFileIrpQueryDirectoryOnce(
            &target,
            nativeBuffer,
            KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES,
            restartScan,
            KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
            &returnedBytes);
        restartScan = FALSE;

        if (status == STATUS_NO_MORE_FILES) {
            response->lastStatus = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            response->lastStatus = status;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }
        if (returnedBytes == 0UL ||
            returnedBytes > KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES) {
            response->lastStatus = STATUS_DATA_ERROR;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }

        status = kswordArkFileIrpConsumeDirectoryBuffer(
            (const UCHAR*)nativeBuffer,
            returnedBytes,
            request->startIndex,
            maximumRows,
            &visibleIndex,
            response,
            &pageComplete);
        if (!NT_SUCCESS(status)) {
            response->lastStatus = status;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }
        if (pageComplete) {
            response->lastStatus = STATUS_SUCCESS;
            break;
        }
    }

    if (response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK;
    }
    response->nextIndex = request->startIndex + response->rowCount;
    response->size =
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
        (response->rowCount * (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    *bytesWrittenOut = response->size;

    kswordArkFileIrpFree(nativeBuffer);
    kswordArkFileIrpCloseTarget(
        &target,
        KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
        &cleanupStatus,
        &closeStatus,
        &stageFlags);
    return STATUS_SUCCESS;
}
