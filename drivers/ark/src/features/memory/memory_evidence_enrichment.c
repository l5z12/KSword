/*++

Module Name:

    memory_evidence_enrichment.c

Abstract:

    Small read-only enrichment helpers for kernel memory evidence rows.

Environment:

    Kernel-mode Driver Framework

--*/

#include "memory_evidence_enrichment.h"

static BOOLEAN
kswordArkMemoryEvidenceBytesLookImageLike(
    _In_reads_bytes_(sampleSize) const UCHAR* sample,
    _In_ ULONG sampleSize
    )
/*++

Routine Description:

    Check if the current limited bytes resemble the start of a PE image. Note: This check uses only a small number of bytes already
    copied to local memory by the caller to identify the MZ signature and the verifiable PE\0\0 signature within the sample.

Arguments:

    Sample: local sample bytes.
    SampleSize - Local sample length.

Return Value:

    TRUE indicates the sample has MZ or PE-like header features; FALSE indicates none were observed.

--*/
{
    ULONG peOffset = 0UL;

    if (sample == NULL || sampleSize < 2UL) {
        return FALSE;
    }
    if (sample[0] != 'M' || sample[1] != 'Z') {
        return FALSE;
    }
    if (sampleSize < 0x40UL) {
        return TRUE;
    }

    peOffset =
        (ULONG)sample[0x3CUL] |
        ((ULONG)sample[0x3DUL] << 8) |
        ((ULONG)sample[0x3EUL] << 16) |
        ((ULONG)sample[0x3FUL] << 24);
    if (peOffset <= sampleSize - 4UL &&
        sample[peOffset] == 'P' &&
        sample[peOffset + 1UL] == 'E' &&
        sample[peOffset + 2UL] == 0U &&
        sample[peOffset + 3UL] == 0U) {
        return TRUE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkMemoryEvidenceAddressLooksImageLike(
    _In_ ULONG64 virtualAddress
    )
/*++

Routine Description:

    Read-only copy a fixed short prefix from the target address and check if it is image-like. Note: this function
    does not write to the protocol sample field; read failures return FALSE and do not affect the main scan result.

Arguments:

    VirtualAddress - The kernel virtual address to be read.

Return Value:

    TRUE indicates a short prefix resembling a PE image; FALSE indicates it is unreadable or this feature was not observed.

--*/
{
    UCHAR localSample[KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES];
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (virtualAddress == 0ULL) {
        return FALSE;
    }

    RtlZeroMemory(localSample, sizeof(localSample));
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)virtualAddress;
    __try {
        status = MmCopyMemory(
            localSample,
            copyAddress,
            sizeof(localSample),
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copiedBytes = 0U;
    }

    if (!NT_SUCCESS(status) || copiedBytes < 2U) {
        RtlZeroMemory(localSample, sizeof(localSample));
        return FALSE;
    }
    if (copiedBytes > sizeof(localSample)) {
        copiedBytes = sizeof(localSample);
    }

    status = kswordArkMemoryEvidenceBytesLookImageLike(localSample, (ULONG)copiedBytes) ?
        STATUS_SUCCESS :
        STATUS_NOT_FOUND;
    RtlZeroMemory(localSample, sizeof(localSample));
    return NT_SUCCESS(status);
}

VOID
kswordArkMemoryEvidenceApplyImageLikeHint(
    _Inout_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row
    )
/*++

Routine Description:

    Mark image-like memory based on the read sample. Note: This is a read-only heuristic
    that, by default, only elevates the risk of private/non-module/BigPool rows; it does
    not attempt to parse or dump a full PE, nor does it access disk files.

Arguments:

    Row - evidence row to be updated.

Return Value:

    None. The function only writes to Row.

--*/
{
    if (row == NULL) {
        return;
    }
    if ((row->sampleSize != 0UL &&
            kswordArkMemoryEvidenceBytesLookImageLike(row->sample, row->sampleSize)) ||
        (row->sampleSize == 0UL &&
            kswordArkMemoryEvidenceAddressLooksImageLike(row->virtualAddress))) {
        row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_IMAGE_LIKE_MEMORY;
        if (row->backingKind != KSWORD_ARK_MEMORY_EVIDENCE_BACKING_LOADED_MODULE) {
            row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_IMAGE_LIKE_MEMORY;
        }
        if (row->confidence < KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_MEDIUM) {
            row->confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_MEDIUM;
        }
    }
}
