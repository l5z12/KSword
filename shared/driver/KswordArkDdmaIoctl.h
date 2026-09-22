#pragma once

#include "KswordArkMemoryIoctl.h"

// ============================================================
// KswordArkDdmaIoctl.h
// Purpose:
// - Define the R3/R0 shared protocol for the DDMA (Disk Direct Memory Access) backend.
// - DDMA uses bus mastering DMA via the disk controller to read/write arbitrary physical
//   addresses; the data path bypasses the CPU page tables and SLAT/EPT, allowing visibility
//   into physical pages that have been redirected or hidden by upper-layer virtualization.
// - Reference implementation: https://github.com/btbd/ddma (Disks for DMA).
//
// Mechanism description (read thoroughly before modifying this file):
// - R0 obtains the kernel virtual address via MmMapIoSpace for the target physical address,
//   then passes it as ATA_PASS_THROUGH_DIRECT.DataBuffer to the \Driver\Disk device object.
//   The storage port driver creates an MDL for this buffer and populates the HBA's hash table
//   with the physical pages, enabling the HBA to perform DMA on that physical address.
// - Read: first write the target physical page to a temporary disk sector, then read it
//   back into the caller's buffer. Write: perform the same pair of operations in reverse.
//   Therefore, DDMA structurally requires reserving a small disk sector as a transit buffer.
//
// Security boundary (protocol-enforced, not voluntarily adhered to by the UI):
// - The sector LBA for temporary storage must be explicitly provided by the caller; the protocol does not supply a default value.
//   Any request that does not set SCRATCH_LBA_VALID will return
//   SCRATCH_LBA_REQUIRED; it will not degrade to 'defaulting to LBA 0'.
//   Note: LBA 0 is a valid value, so 0 cannot serve as a "not filled" sentinel; an
//   independent flag bit must distinguish between "filled with 0" and "not filled."
// - Each read/write operation is completed within the same function as a closed loop: 'backup temporary
//   sector → use → restore temporary sector', ensuring no dirty sectors are retained across IOCTLs.
// - Writing requires the FORCE bit; if FORCE is missing, return FORCE_REQUIRED.
//   This is a distinct state from SCRATCH_LBA_REQUIRED and must not be conflated.
// ============================================================

#define KSWORD_ARK_DDMA_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_DDMA_QUERY_CAPABILITY 0x917UL
#define KSWORD_ARK_IOCTL_FUNCTION_DDMA_READ_PHYSICAL 0x918UL
#define KSWORD_ARK_IOCTL_FUNCTION_DDMA_WRITE_PHYSICAL 0x919UL

// All three IOCTLs use FILE_WRITE_ACCESS: capability probing issues real ATA commands to the disk,
// and read/write operations directly manipulate physical memory; all are destructive interfaces.
#define IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DDMA_QUERY_CAPABILITY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DDMA_READ_PHYSICAL, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DDMA_WRITE_PHYSICAL, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// ------------------------------------------------------------
// Size constants
// ------------------------------------------------------------

// The scratch area is fixed to occupy one page = 8 sectors of 512 bytes each. Fixing it as a constant rather
// than letting it float with the request length ensures that the statement 'we will overwrite sectors
// [scratchLba, +8)' remains valid for the user, allowing the UI to clearly explain the scope of impact.
#define KSWORD_ARK_DDMA_SECTOR_SIZE 512UL
#define KSWORD_ARK_DDMA_TRANSFER_BYTES 4096UL
#define KSWORD_ARK_DDMA_SCRATCH_SECTOR_COUNT \
    (KSWORD_ARK_DDMA_TRANSFER_BYTES / KSWORD_ARK_DDMA_SECTOR_SIZE)

// The maximum read/write limit per IOCTL equals one DMA transfer length; ranges crossing pages or
// exceeding this limit are sliced by R3 into multiple calls, ensuring each disk window is minimized.
#define KSWORD_ARK_DDMA_READ_MAX_BYTES KSWORD_ARK_DDMA_TRANSFER_BYTES
#define KSWORD_ARK_DDMA_WRITE_MAX_BYTES KSWORD_ARK_DDMA_TRANSFER_BYTES

// Maximum number of disks returned in a single capability query.
#define KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT 8UL
#define KSWORD_ARK_DDMA_DISK_LIMIT_HARD 32UL

// Fixed-length upper limit for device name and disk description (character count, including trailing NUL).
#define KSWORD_ARK_DDMA_DEVICE_NAME_CHARS 128U

// ------------------------------------------------------------
// Request flags
// ------------------------------------------------------------

// UI_CONFIRMED: R3 has already displayed the impact of this operation to the user on the interface.
#define KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED 0x00000001UL
// FORCE: The mandatory bit in the write path. If missing, the driver writes no bytes.
#define KSWORD_ARK_DDMA_FLAG_FORCE 0x00000002UL
// SCRATCH_LBA_VALID: The scratchLba in the request is explicitly provided by the caller.
// If missing, the driver rejects the request and does not select any default sector for the caller.
#define KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID 0x00000004UL
// SCRATCH_ACKNOWLEDGED: The caller confirms data in this scratch sector can be temporarily
// overwritten. It is separated from SCRATCH_LBA_VALID because 'providing an address' and 'knowing
// this address will be written' are distinct concepts, reflected in separate UI controls.
#define KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED 0x00000008UL

#define KSWORD_ARK_DDMA_READ_FLAG_ALLOWED \
    (KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED | \
     KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID | \
     KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED)

#define KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED \
    (KSWORD_ARK_DDMA_READ_FLAG_ALLOWED | KSWORD_ARK_DDMA_FLAG_FORCE)

// Flags dedicated to capability queries. Placed above 0x00010000 to separate
// from the above set of generic flags into two non-overlapping bit fields.
//
// Why segmentation is required: These two bit groups are squeezed into the **same** request->flags field.
// Initially, PROBE_TRANSFER was set to 0x1, colliding with the same bit as UI_CONFIRMED—"User Confirmed"
// and "Perform Transfer Probe" became the same event, and neither side reported an error. On the target
// machine, this manifested as win32=87, where the error code provided no indication of a bit collision.
//
// PROBE_TRANSFER issues an actual ATA DMA read command for each disk to determine availability.
// Without this bit, only enumerate devices without sending commands.
#define KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER 0x00010000UL

// The allowed bitmask **must be a superset of the bits the caller will actually set**.
// The backend checks both PROBE_TRANSFER and SCRATCH_LBA_VALID when probeRequested is true, so the
// latter must also be allowed here; omitting it would make the transfer probe an unreachable dead end.
// The request is rejected during the handler's flags validation, so the backend check is never executed.
#define KSWORD_ARK_DDMA_QUERY_FLAG_ALLOWED \
    (KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER | \
     KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED | \
     KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID)

// ------------------------------------------------------------
// Status code
// ------------------------------------------------------------

#define KSWORD_ARK_DDMA_QUERY_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_OK 1UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_TRUNCATED 2UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_DISK_DRIVER_MISSING 3UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_ENUM_FAILED 4UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_NO_SUPPORTED_DISK 5UL
#define KSWORD_ARK_DDMA_QUERY_STATUS_IRQL_REJECTED 6UL

#define KSWORD_ARK_DDMA_READ_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_DDMA_READ_STATUS_OK 1UL
#define KSWORD_ARK_DDMA_READ_STATUS_RANGE_REJECTED 2UL
#define KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED 3UL
#define KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED 4UL
#define KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND 5UL
#define KSWORD_ARK_DDMA_READ_STATUS_MAP_FAILED 6UL
#define KSWORD_ARK_DDMA_READ_STATUS_BACKUP_FAILED 7UL
#define KSWORD_ARK_DDMA_READ_STATUS_STAGE_OUT_FAILED 8UL
#define KSWORD_ARK_DDMA_READ_STATUS_STAGE_IN_FAILED 9UL
#define KSWORD_ARK_DDMA_READ_STATUS_BUFFER_TOO_SMALL 10UL
#define KSWORD_ARK_DDMA_READ_STATUS_IRQL_REJECTED 11UL

#define KSWORD_ARK_DDMA_WRITE_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_OK 1UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_RANGE_REJECTED 2UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_LBA_REQUIRED 3UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_NOT_ACKNOWLEDGED 4UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_DISK_NOT_FOUND 5UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_MAP_FAILED 6UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_BACKUP_FAILED 7UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_OUT_FAILED 8UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_IN_FAILED 9UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED 10UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_ACCESS_DENIED 11UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_READBACK_FAILED 12UL
#define KSWORD_ARK_DDMA_WRITE_STATUS_IRQL_REJECTED 13UL

// ------------------------------------------------------------
// Response fieldFlags
// ------------------------------------------------------------

// SCRATCH_RESTORED: The scratch sector has been written back to its original content. If this bit is not set,
// the restore step itself failed, leaving dirty sectors on the disk; this must trigger a significant alert.
#define KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED 0x00000001UL
// READ_MODIFY_WRITE_USED: The write is not a full-page overwrite; the driver first DMA-reads
// the entire page, replaces the requested sub-interval, and then DMA-writes the entire page
// back. This creates a 4KB-granularity lost-update window that the caller must be aware of.
#define KSWORD_ARK_DDMA_FIELD_READ_MODIFY_WRITE_USED 0x00000002UL
// DEVICE_NAME_PRESENT: The deviceName in the response is valid. R3 can compare it with
// the name recorded during capability query to confirm the same disk is being used.
#define KSWORD_ARK_DDMA_FIELD_DEVICE_NAME_PRESENT 0x00000004UL
// FORCE_USED: The write operation explicitly included the FORCE bit.
#define KSWORD_ARK_DDMA_FIELD_FORCE_USED 0x00000008UL

// ------------------------------------------------------------
// Capability response capabilityFlags
// ------------------------------------------------------------

// KERNEL_DEBUGGER_ENABLED: Kernel debugging is enabled on this machine.
// This is not an optional note: DDMA uses MmMapIoSpace to map regular RAM; enabling
// kernel debugging triggers MiShowBadMapper and causes a BSOD (the upstream ddma
// README also documents this). UI must disable DDMA by default on such machines.
// The workaround is to use a custom MDL to map physical pages and bypass MmMapIoSpace's
// RAM checks. This version does not implement it and only reports the status truthfully.
#define KSWORD_ARK_DDMA_CAP_FLAG_KERNEL_DEBUGGER_ENABLED 0x00000001UL
// DISK_DRIVER_PRESENT: Successfully obtained the \Driver\Disk driver object.
#define KSWORD_ARK_DDMA_CAP_FLAG_DISK_DRIVER_PRESENT 0x00000002UL
// PROBE_PERFORMED: An ATA DMA read command was actually issued for probing during this query.
#define KSWORD_ARK_DDMA_CAP_FLAG_PROBE_PERFORMED 0x00000004UL
// LBA48_SUPPORTED: The driver automatically switches to 48-bit commands when LBA >= 2^28.
#define KSWORD_ARK_DDMA_CAP_FLAG_LBA48_SUPPORTED 0x00000008UL

// ------------------------------------------------------------
// Disk entry diskFlags
// ------------------------------------------------------------

// ATA_DMA_READY: The temporary sector was successfully read via ATA passthrough during the probe phase.
#define KSWORD_ARK_DDMA_DISK_FLAG_ATA_DMA_READY 0x00000001UL
// PROBE_SKIPPED: The request did not include PROBE_TRANSFER; this entry performed only device enumeration.
#define KSWORD_ARK_DDMA_DISK_FLAG_PROBE_SKIPPED 0x00000002UL
// NAME_PRESENT: The deviceName field is valid.
#define KSWORD_ARK_DDMA_DISK_FLAG_NAME_PRESENT 0x00000004UL
// SCSI_DMA_READY: Indicates that a SCSI passthrough read successfully retrieved the temporary sector during the probe phase.
//
// Reason for this bit: DDMA requires a 'direct channel that treats a specified physical page as a
// DMA target', not 'ATA'. Modern machines are mostly NVMe; ATA passthrough returns
// STATUS_NOT_SUPPORTED. Relying solely on ATA would render this path meaningless on most machines.
// IOCTL_SCSI_PASS_THROUGH_DIRECT also uses MDL for direct DMA. Since stornvme translates
// SCSI READ/WRITE into NVMe commands, this covers NVMe, SAS/SATA, and synthetic SCSI.
#define KSWORD_ARK_DDMA_DISK_FLAG_SCSI_DMA_READY 0x00000008UL

// Any single available transfer suffices to establish a DDMA channel.
#define KSWORD_ARK_DDMA_DISK_FLAG_ANY_DMA_READY \
    (KSWORD_ARK_DDMA_DISK_FLAG_ATA_DMA_READY | \
     KSWORD_ARK_DDMA_DISK_FLAG_SCSI_DMA_READY)

// Transport channel identifier, used in the response to indicate which path was actually taken.
#define KSWORD_ARK_DDMA_TRANSPORT_NONE 0UL
#define KSWORD_ARK_DDMA_TRANSPORT_ATA 1UL
#define KSWORD_ARK_DDMA_TRANSPORT_SCSI 2UL

// ------------------------------------------------------------
// Structure
// ------------------------------------------------------------

typedef struct _KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST
{
    unsigned long flags;
    unsigned long maxDisks;
    // During the probe phase, a read command must be sent to the disk, requiring an explicit scratch LBA.
    // Without SCRATCH_LBA_VALID, the driver only enumerates devices and performs no transfer probing.
    unsigned long long scratchLba;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST;

typedef struct _KSWORD_ARK_DDMA_DISK_ENTRY
{
    unsigned long entrySize;
    unsigned long deviceIndex;
    unsigned long diskFlags;
    long probeStatus;       // NTSTATUS for ATA passthrough probe.
    unsigned long sectorSize; // The actual logical sector size of the disk; the number of blocks in the SCSI CDB is converted based on it.
    long scsiProbeStatus;   // SCSI passthrough probe NTSTATUS, recorded separately from the ATA entry.
    wchar_t deviceName[KSWORD_ARK_DDMA_DEVICE_NAME_CHARS];
} KSWORD_ARK_DDMA_DISK_ENTRY;

typedef struct _KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE
{
    unsigned long version;
    unsigned long headerSize;
    unsigned long status;
    unsigned long entrySize;
    unsigned long totalDisks;
    unsigned long returnedDisks;
    unsigned long readyDisks;
    unsigned long transferBytes;
    unsigned long scratchSectorCount;
    unsigned long capabilityFlags;
    long lastStatus;
    unsigned long reserved0;
    KSWORD_ARK_DDMA_DISK_ENTRY entries[1];
} KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE;

typedef struct _KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST
{
    unsigned long flags;
    unsigned long diskIndex;
    unsigned long long physicalAddress;
    unsigned long long scratchLba;
    unsigned long bytesToRead;
    unsigned long reserved0;
} KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST;

typedef struct _KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE
{
    unsigned long version;
    unsigned long headerSize;
    unsigned long fieldFlags;
    unsigned long readStatus;
    long mapStatus;
    long backupStatus;
    long stageOutStatus;
    long stageInStatus;
    long restoreStatus;
    unsigned long requestedBytes;
    unsigned long bytesRead;
    unsigned long maxBytesPerRequest;
    unsigned long long requestedPhysicalAddress;
    unsigned long long scratchLba;
    unsigned long diskIndex;
    unsigned long reserved0;
    wchar_t deviceName[KSWORD_ARK_DDMA_DEVICE_NAME_CHARS];
    unsigned char data[1];
} KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE;

typedef struct _KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST
{
    unsigned long flags;
    unsigned long diskIndex;
    unsigned long long physicalAddress;
    unsigned long long scratchLba;
    unsigned long bytesToWrite;
    unsigned long reserved0;
    unsigned char data[1];
} KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST;

typedef struct _KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long fieldFlags;
    unsigned long writeStatus;
    long mapStatus;
    long backupStatus;
    long stageOutStatus;
    long stageInStatus;
    long restoreStatus;
    long readbackStatus;
    unsigned long requestedBytes;
    unsigned long bytesWritten;
    unsigned long maxBytesPerRequest;
    unsigned long reserved0;
    unsigned long long requestedPhysicalAddress;
    unsigned long long scratchLba;
    unsigned long diskIndex;
    unsigned long reserved1;
    wchar_t deviceName[KSWORD_ARK_DDMA_DEVICE_NAME_CHARS];
} KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE;
