#pragma once

#include "KswordArkDdmaIoctl.h"

// ============================================================
// KswordArkDdmaPlan.h
// Purpose:
// - Extract the three 'pure arithmetic, most severe consequences if wrong' logic blocks in DDMA into static inline functions
//   usable by both C and C++: ATA task file register encoding, physical range validation, and page-sliced length calculation.
// - R0 driver, R3 client, and unit tests all reference the same
//   implementation to avoid "testing code different from running code".
//
// Why extract this separately:
// - The mapping from LBA to ATA registers has a completely different layout in 28-bit versus 48-bit modes;
//   writing a single bit incorrectly causes reads/writes to another location on the disk. This is the only pure
//   calculation in this feature where an error destroys user data, so it must be covered by exhaustive testing.
// - Interval validation and slice length determine whether adjacent physical pages are accessed across page boundaries.
//
// This file performs only arithmetic operations and does not touch any kernel objects, handles, or global state.
// ============================================================

// ATA task file register indices. Order taken from IDE register definitions; shared by both modes:
// [0]=Features [1]=SectorCount [2]=LBA Low [3]=LBA Mid [4]=LBA High
// [5]=Device/Head [6]=Command [7]=Reserved
#define KSWORD_ARK_ATA_TASKFILE_FEATURES 0
#define KSWORD_ARK_ATA_TASKFILE_SECTOR_COUNT 1
#define KSWORD_ARK_ATA_TASKFILE_LBA_LOW 2
#define KSWORD_ARK_ATA_TASKFILE_LBA_MID 3
#define KSWORD_ARK_ATA_TASKFILE_LBA_HIGH 4
#define KSWORD_ARK_ATA_TASKFILE_DEVICE 5
#define KSWORD_ARK_ATA_TASKFILE_COMMAND 6
#define KSWORD_ARK_ATA_TASKFILE_RESERVED 7

#define KSWORD_ARK_ATA_TASKFILE_BYTES 8

// ATA command codes. 28-bit and 48-bit commands are two separate sets with different register layouts.
#define KSWORD_ARK_ATA_CMD_READ_SECTORS 0x20
#define KSWORD_ARK_ATA_CMD_WRITE_SECTORS 0x30
#define KSWORD_ARK_ATA_CMD_READ_SECTORS_EXT 0x24
#define KSWORD_ARK_ATA_CMD_WRITE_SECTORS_EXT 0x34

// Device/Head register LBA mode bit.
#define KSWORD_ARK_ATA_DEVICE_LBA 0x40

// ATA_FLAGS_48BIT_COMMAND comes from ntddscsi.h. This header file must be referenceable by unit
// tests that cannot conveniently include ntddscsi.h. Therefore, if missing, a definition with
// the same value is provided. When both exist, the values are consistent and do not conflict.
#ifndef ATA_FLAGS_48BIT_COMMAND
#define ATA_FLAGS_48BIT_COMMAND (1 << 3)
#endif

// 28-bit LBA limit; a 48-bit command must be used when reaching or exceeding this limit.
#define KSWORD_ARK_DDMA_LBA28_LIMIT 0x10000000ULL
// Upper limit for 48-bit LBA.
#define KSWORD_ARK_DDMA_LBA48_LIMIT 0x0001000000000000ULL

// x64 current page table format supports up to 52 physical address bits, matching the same limit in memory_physical.c.
#define KSWORD_ARK_DDMA_PHYSICAL_ADDRESS_MAX 0x000FFFFFFFFFFFFFULL

// Access control gate result. The three rejection reasons must be kept separate: they correspond to three entirely different
// user actions. Merging them into a generic "needs confirmation" would prevent the UI from presenting the correct next step.
#define KSWORD_ARK_DDMA_GATE_ALLOWED 0
#define KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED 1
#define KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER 2
#define KSWORD_ARK_DDMA_GATE_SCRATCH_LBA_MISSING 3
#define KSWORD_ARK_DDMA_GATE_SCRATCH_NOT_ACKNOWLEDGED 4

// KSWORD_ARK_DDMA_TASKFILE: A complete register snapshot for one ATA command.
typedef struct _KSWORD_ARK_DDMA_TASKFILE
{
    unsigned char currentTaskFile[KSWORD_ARK_ATA_TASKFILE_BYTES];
    unsigned char previousTaskFile[KSWORD_ARK_ATA_TASKFILE_BYTES];
    unsigned short extraAtaFlags;  // Additional AtaFlags bits to be ORed (48-bit command flags).
    unsigned char usesLba48;       // 1 indicates using a 48-bit command for this operation.
    unsigned char valid;           // 0 indicates the parameter was rejected; other fields are meaningless.
} KSWORD_ARK_DDMA_TASKFILE;

/*
 * KswordArkDdmaEncodeTaskFile: encode LBA, sector count, and read/write direction into an ATA task file.
 *
 * Input: Lba is the starting sector number; SectorCount is the number of sectors for this transfer
 * (1..65536; in 28-bit mode, must not exceed 256); IsWrite non-zero indicates a write operation.
 *
 * Handling: When LBA < 2^28, use a 28-bit command with the top 4 bits of LBA squeezed into the low nibble of the Device
 * register, and represent 256 sectors as 0; otherwise, switch to a 48-bit command where the top 3 bytes and the high
 * byte of the sector count are carried by previousTaskFile, and the Device register no longer carries any LBA bits.
 *
 * Returns: Filled register snapshot; valid is 0 if parameters are out of bounds.
 */
static __inline KSWORD_ARK_DDMA_TASKFILE
KswordArkDdmaEncodeTaskFile(
    unsigned long long Lba,
    unsigned long SectorCount,
    int IsWrite
    )
{
    KSWORD_ARK_DDMA_TASKFILE taskFile;
    int index = 0;
    int useLba48 = 0;

    for (index = 0; index < KSWORD_ARK_ATA_TASKFILE_BYTES; ++index) {
        taskFile.currentTaskFile[index] = 0;
        taskFile.previousTaskFile[index] = 0;
    }
    taskFile.extraAtaFlags = 0;
    taskFile.usesLba48 = 0;
    taskFile.valid = 0;

    if (SectorCount == 0UL || SectorCount > 65536UL) {
        return taskFile;
    }
    if (Lba >= KSWORD_ARK_DDMA_LBA48_LIMIT) {
        return taskFile;
    }
    /* The range must not cross the 48-bit limit. */
    if ((KSWORD_ARK_DDMA_LBA48_LIMIT - Lba) < (unsigned long long)SectorCount) {
        return taskFile;
    }

    useLba48 = (Lba >= KSWORD_ARK_DDMA_LBA28_LIMIT) || (SectorCount > 256UL);
    taskFile.usesLba48 = (unsigned char)(useLba48 ? 1 : 0);

    taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_LOW] =
        (unsigned char)(Lba & 0xFFULL);
    taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_MID] =
        (unsigned char)((Lba >> 8) & 0xFFULL);
    taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_HIGH] =
        (unsigned char)((Lba >> 16) & 0xFFULL);

    if (useLba48) {
        taskFile.extraAtaFlags = (unsigned short)ATA_FLAGS_48BIT_COMMAND;
        /* In 48-bit mode, the Device register retains only the LBA mode bit. */
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_DEVICE] =
            (unsigned char)KSWORD_ARK_ATA_DEVICE_LBA;
        taskFile.previousTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_LOW] =
            (unsigned char)((Lba >> 24) & 0xFFULL);
        taskFile.previousTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_MID] =
            (unsigned char)((Lba >> 32) & 0xFFULL);
        taskFile.previousTaskFile[KSWORD_ARK_ATA_TASKFILE_LBA_HIGH] =
            (unsigned char)((Lba >> 40) & 0xFFULL);
        /* 48-bit mode sector count is 16 bits: low byte in current, high byte in previous. */
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_SECTOR_COUNT] =
            (unsigned char)(SectorCount & 0xFFUL);
        taskFile.previousTaskFile[KSWORD_ARK_ATA_TASKFILE_SECTOR_COUNT] =
            (unsigned char)((SectorCount >> 8) & 0xFFUL);
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_COMMAND] = (unsigned char)(IsWrite
            ? KSWORD_ARK_ATA_CMD_WRITE_SECTORS_EXT
            : KSWORD_ARK_ATA_CMD_READ_SECTORS_EXT);
    }
    else {
        /* 28-bit mode: the top 4 bits of LBA are squeezed into the lower nibble of the Device register. */
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_DEVICE] =
            (unsigned char)(KSWORD_ARK_ATA_DEVICE_LBA |
                            (unsigned char)((Lba >> 24) & 0x0FULL));
        /* In 28-bit mode, the sector count is 8 bits, where 256 is represented as 0. */
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_SECTOR_COUNT] =
            (unsigned char)(SectorCount & 0xFFUL);
        taskFile.currentTaskFile[KSWORD_ARK_ATA_TASKFILE_COMMAND] = (unsigned char)(IsWrite
            ? KSWORD_ARK_ATA_CMD_WRITE_SECTORS
            : KSWORD_ARK_ATA_CMD_READ_SECTORS);
    }

    taskFile.valid = 1;
    return taskFile;
}

// ------------------------------------------------------------
// SCSI passthrough (overrides NVMe / SAS / SATA / synthetic SCSI).
// ------------------------------------------------------------
//
// Why a second transfer is mandatory: DDMA doesn't actually need "ATA"; it needs a passthrough channel that
// can designate our specified physical pages as DMA targets. IOCTL_ATA_PASS_THROUGH_DIRECT is just one such
// channel, but modern machines are mostly NVMe, and that path directly returns STATUS_NOT_SUPPORTED.
//
// IOCTL_SCSI_PASS_THROUGH_DIRECT also uses _DIRECT (using MDL for direct DMA from the controller
// to the physical pages provided by us), and Windows' stornvme.sys translates SCSI READ/WRITE
// commands into NVMe commands. It covers NVMe, SAS/SATA, and Hyper-V synthetic SCSI disks.
//
// Note: The transfer length unit in the CDB is **blocks** (logical sectors), not bytes. Filling it with a byte count would cause the
// controller to read/write a range hundreds of times larger. Therefore, the encoding function must obtain the actual sector size.

#define KSWORD_ARK_SCSI_CMD_READ_10 0x28
#define KSWORD_ARK_SCSI_CMD_WRITE_10 0x2A
#define KSWORD_ARK_SCSI_CMD_READ_16 0x88
#define KSWORD_ARK_SCSI_CMD_WRITE_16 0x8A

#define KSWORD_ARK_SCSI_CDB_BYTES 16

// READ(10)/WRITE(10) LBA is 32-bit and block count is 16-bit; exceeding this requires switching to a 16-byte CDB.
#define KSWORD_ARK_DDMA_LBA32_LIMIT 0x100000000ULL

// KSWORD_ARK_DDMA_CDB: A SCSI command descriptor block.
typedef struct _KSWORD_ARK_DDMA_CDB
{
    unsigned char cdb[KSWORD_ARK_SCSI_CDB_BYTES];
    unsigned char cdbLength;    // Actual valid length: 10 or 16.
    unsigned char valid;        // 0 indicates the parameter was rejected; other fields are meaningless.
} KSWORD_ARK_DDMA_CDB;

/*
 * KswordArkDdmaEncodeCdb: Encodes LBA, transfer byte count, and read/write direction into a SCSI CDB.
 *
 * Inputs: Lba is the starting logical block address; TransferBytes is the number of bytes to transfer;
 * SectorSize is the logical sector size of the disk; IsWrite is non-zero for write operations.
 *
 * Handling: TransferBytes must be an integer multiple of SectorSize—the CDB stores block counts, so if it's not
 * divisible, the caller mistakenly used bytes as blocks. If LBA and block count fit in 32/16 bits, use a 10-byte CDB;
 * otherwise, use a 16-byte CDB. Multi-byte fields in both CDB types are **big-endian**, as per SCSI specification,
 * which is opposite to x86; writing them incorrectly will cause reads/writes to a completely different sector.
 *
 * Returns: Filled CDB; valid is 0 if parameters are out of bounds or division is not exact.
 */
static __inline KSWORD_ARK_DDMA_CDB
KswordArkDdmaEncodeCdb(
    unsigned long long Lba,
    unsigned long TransferBytes,
    unsigned long SectorSize,
    int IsWrite
    )
{
    KSWORD_ARK_DDMA_CDB command;
    unsigned long long blocks = 0ULL;
    int index = 0;

    for (index = 0; index < KSWORD_ARK_SCSI_CDB_BYTES; ++index) {
        command.cdb[index] = 0;
    }
    command.cdbLength = 0;
    command.valid = 0;

    if (SectorSize == 0UL || TransferBytes == 0UL) {
        return command;
    }
    if ((TransferBytes % SectorSize) != 0UL) {
        /* A non-divisible result indicates the caller passed bytes as block count; reject rather than round. */
        return command;
    }
    blocks = (unsigned long long)(TransferBytes / SectorSize);
    if (blocks == 0ULL || blocks > 0xFFFFFFFFULL) {
        return command;
    }
    /* The range must not cross the 64-bit block number limit. */
    if ((0xFFFFFFFFFFFFFFFFULL - Lba) < blocks) {
        return command;
    }

    if (Lba < KSWORD_ARK_DDMA_LBA32_LIMIT && blocks <= 0xFFFFULL) {
        /* READ(10)/WRITE(10): LBA is in [2..5], block count is in [7..8], both in big-endian. */
        command.cdb[0] = (unsigned char)(IsWrite
            ? KSWORD_ARK_SCSI_CMD_WRITE_10
            : KSWORD_ARK_SCSI_CMD_READ_10);
        command.cdb[2] = (unsigned char)((Lba >> 24) & 0xFFULL);
        command.cdb[3] = (unsigned char)((Lba >> 16) & 0xFFULL);
        command.cdb[4] = (unsigned char)((Lba >> 8) & 0xFFULL);
        command.cdb[5] = (unsigned char)(Lba & 0xFFULL);
        command.cdb[7] = (unsigned char)((blocks >> 8) & 0xFFULL);
        command.cdb[8] = (unsigned char)(blocks & 0xFFULL);
        command.cdbLength = 10U;
    }
    else {
        /* READ(16)/WRITE(16): LBA is in [2..9], block count is in [10..13], both in big-endian. */
        command.cdb[0] = (unsigned char)(IsWrite
            ? KSWORD_ARK_SCSI_CMD_WRITE_16
            : KSWORD_ARK_SCSI_CMD_READ_16);
        command.cdb[2] = (unsigned char)((Lba >> 56) & 0xFFULL);
        command.cdb[3] = (unsigned char)((Lba >> 48) & 0xFFULL);
        command.cdb[4] = (unsigned char)((Lba >> 40) & 0xFFULL);
        command.cdb[5] = (unsigned char)((Lba >> 32) & 0xFFULL);
        command.cdb[6] = (unsigned char)((Lba >> 24) & 0xFFULL);
        command.cdb[7] = (unsigned char)((Lba >> 16) & 0xFFULL);
        command.cdb[8] = (unsigned char)((Lba >> 8) & 0xFFULL);
        command.cdb[9] = (unsigned char)(Lba & 0xFFULL);
        command.cdb[10] = (unsigned char)((blocks >> 24) & 0xFFULL);
        command.cdb[11] = (unsigned char)((blocks >> 16) & 0xFFULL);
        command.cdb[12] = (unsigned char)((blocks >> 8) & 0xFFULL);
        command.cdb[13] = (unsigned char)(blocks & 0xFFULL);
        command.cdbLength = 16U;
    }

    command.valid = 1;
    return command;
}

/*
 * KswordArkDdmaIsPhysicalRangeValid: Validates a physical range for a DDMA transfer.
 *
 * In addition to the 52-bit limit and wraparound, DDMA requires the entire range to reside within a single transfer page. Since DMA
 * granularity is one page, the caller must slice any cross-page ranges; otherwise, adjacent physical pages may be silently modified.
 *
 * Return: Non-zero indicates acceptance.
 */
static __inline int
KswordArkDdmaIsPhysicalRangeValid(
    unsigned long long PhysicalAddress,
    unsigned long Length
    )
{
    unsigned long long endAddress = 0ULL;
    unsigned long long pageBase = 0ULL;

    if (Length == 0UL || Length > KSWORD_ARK_DDMA_TRANSFER_BYTES) {
        return 0;
    }
    if (PhysicalAddress > KSWORD_ARK_DDMA_PHYSICAL_ADDRESS_MAX) {
        return 0;
    }
    if ((unsigned long long)Length >
        (KSWORD_ARK_DDMA_PHYSICAL_ADDRESS_MAX - PhysicalAddress + 1ULL)) {
        return 0;
    }

    endAddress = PhysicalAddress + (unsigned long long)Length - 1ULL;
    if (endAddress < PhysicalAddress) {
        return 0;
    }

    pageBase = PhysicalAddress & ~((unsigned long long)KSWORD_ARK_DDMA_TRANSFER_BYTES - 1ULL);
    return (endAddress < (pageBase + (unsigned long long)KSWORD_ARK_DDMA_TRANSFER_BYTES)) ? 1 : 0;
}

/*
 * KswordArkDdmaChunkLength: Calculate how many bytes can be processed in this step starting from
 * Address without crossing a page boundary. The caller uses this to slice and loop forward.
 *
 * Returns: The number of bytes that can be processed in this iteration; returns 0 if Remaining is 0.
 */
static __inline unsigned long
KswordArkDdmaChunkLength(
    unsigned long long Address,
    unsigned long long Remaining
    )
{
    unsigned long long pageBase = 0ULL;
    unsigned long long pageEnd = 0ULL;
    unsigned long long available = 0ULL;

    if (Remaining == 0ULL) {
        return 0UL;
    }

    pageBase = Address & ~((unsigned long long)KSWORD_ARK_DDMA_TRANSFER_BYTES - 1ULL);
    pageEnd = pageBase + (unsigned long long)KSWORD_ARK_DDMA_TRANSFER_BYTES;
    available = pageEnd - Address;
    return (unsigned long)((Remaining < available) ? Remaining : available);
}

/*
 * KswordArkDdmaEvaluateGate: Determines DDMA session availability in a fixed order.
 *
 * Order is part of the criterion: kernel debugging must be listed before reasons like "not configured yet" because
 * it is not "unusable" but "will cause a BSOD" and cannot be obscured by a message like "Please fill in LBA first."
 *
 * Input: Four boolean status bits; non-zero indicates true.
 * Return: One of KSWORD_ARK_DDMA_GATE_*.
 */
static __inline int
KswordArkDdmaEvaluateGate(
    int Configured,
    int KernelDebuggerEnabled,
    int ScratchLbaValid,
    int ScratchAcknowledged
    )
{
    if (!Configured) {
        return KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED;
    }
    if (KernelDebuggerEnabled) {
        return KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER;
    }
    if (!ScratchLbaValid) {
        return KSWORD_ARK_DDMA_GATE_SCRATCH_LBA_MISSING;
    }
    if (!ScratchAcknowledged) {
        return KSWORD_ARK_DDMA_GATE_SCRATCH_NOT_ACKNOWLEDGED;
    }
    return KSWORD_ARK_DDMA_GATE_ALLOWED;
}
