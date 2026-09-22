/*++

Module Name:

    ci_hash_fallback.c

Abstract:

    Runtime-signature fallback for the CI kernel hash cache.  Stable exported
    CI entry points seed a bounded direct-call scan.  Candidate list globals,
    entry layouts, and ERESOURCE objects are accepted only after unique live
    chain/name validation and a non-blocking locked revalidation.

    A candidate lock must be proven to sit on the global resource list before
    it reaches ExAcquireResourceSharedLite.  Field-shape checks cannot settle
    that question, and this module's candidate pool is wider than the anchored
    scan alone: it falls back to a whole-image data-reference sweep.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query path.

--*/

#include "ci_hash_fallback.h"
#include "hook_scan_support.h"
#include "../../platform/kernel_object_probe.h"
#include "../../platform/runtime_signature_scan.h"
#include "../../platform/pool_compat.h"

#define KSW_CI_HASH_FALLBACK_TAG 'hCsK'
#define KSW_CI_HASH_MAX_REFERENCES 768UL
#define KSW_CI_HASH_ROUTINE_SCAN_BYTES 0x0800UL
#define KSW_CI_HASH_FULL_SCAN_BUDGET 0x00400000UL
#define KSW_CI_HASH_MAX_ENTRY_BYTES 0x0100UL
#define KSW_CI_HASH_MAX_CHAIN 64UL
#define KSW_CI_HASH_MAX_SAMPLES 16UL
#define KSW_CI_HASH_MAX_NAME_BYTES 520U

typedef struct KswCiHashCandidate
{
    ULONG_PTR listGlobal;
    ULONG_PTR referenceRoutine;
    ULONG_PTR referenceInstruction;
    ULONG nextOffset;
    ULONG nameOffset;
    ULONG chainLength;
    PVOID samples[KSW_CI_HASH_MAX_SAMPLES];
    ULONG sampleCount;
} KswCiHashCandidate, *PkswCiHashCandidate;

static BOOLEAN
kswordArkCiHashIsKernelAddress(
    _In_ ULONG_PTR address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkCiHashNameIsDriver(
    _In_ const UCHAR* entry,
    _In_ ULONG offset
    )
{
    UNICODE_STRING name;
    UNICODE_STRING expected;
    UNICODE_STRING tailString;
    WCHAR tail[5];
    SIZE_T suffixBytes = 0U;
    BOOLEAN matched = FALSE;

    if (entry == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&name, sizeof(name));
    RtlZeroMemory(tail, sizeof(tail));
    if (!kswordArkRuntimeReadMemory(
            entry + offset,
            &name,
            sizeof(name)) ||
        name.Buffer == NULL ||
        !kswordArkCiHashIsKernelAddress((ULONG_PTR)name.Buffer) ||
        name.Length == 0U || name.Length > KSW_CI_HASH_MAX_NAME_BYTES ||
        name.Length > name.MaximumLength ||
        (name.Length & (sizeof(WCHAR) - 1U)) != 0U) {
        return FALSE;
    }

    RtlInitUnicodeString(&expected, L".sys");
    suffixBytes = expected.Length;
    if (name.Length >= suffixBytes &&
        kswordArkRuntimeReadMemory(
            (const UCHAR*)name.Buffer + name.Length - suffixBytes,
            tail,
            suffixBytes)) {
        tailString.Buffer = tail;
        tailString.Length = (USHORT)suffixBytes;
        tailString.MaximumLength = (USHORT)suffixBytes;
        matched = RtlEqualUnicodeString(&tailString, &expected, TRUE);
    }
    if (matched) {
        return TRUE;
    }

    RtlZeroMemory(tail, sizeof(tail));
    RtlInitUnicodeString(&expected, L".dll");
    suffixBytes = expected.Length;
    if (name.Length < suffixBytes ||
        !kswordArkRuntimeReadMemory(
            (const UCHAR*)name.Buffer + name.Length - suffixBytes,
            tail,
            suffixBytes)) {
        return FALSE;
    }
    tailString.Buffer = tail;
    tailString.Length = (USHORT)suffixBytes;
    tailString.MaximumLength = (USHORT)suffixBytes;
    return RtlEqualUnicodeString(&tailString, &expected, TRUE);
}

static BOOLEAN
kswordArkCiHashWalkCandidate(
    _In_ ULONG_PTR listGlobal,
    _In_ ULONG nextOffset,
    _In_ ULONG nameOffset,
    _Out_opt_ KswCiHashCandidate* candidateOut
    )
{
    ULONG_PTR current = 0U;
    ULONG_PTR seen[KSW_CI_HASH_MAX_CHAIN];
    ULONG count = 0UL;
    KswCiHashCandidate candidate;

    RtlZeroMemory(seen, sizeof(seen));
    RtlZeroMemory(&candidate, sizeof(candidate));
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)listGlobal,
            &current,
            sizeof(current)) ||
        !kswordArkCiHashIsKernelAddress(current)) {
        return FALSE;
    }
    while (current != 0U && count < KSW_CI_HASH_MAX_CHAIN) {
        ULONG_PTR next = 0U;
        ULONG seenIndex = 0UL;

        for (seenIndex = 0UL; seenIndex < count; ++seenIndex) {
            if (seen[seenIndex] == current) {
                return FALSE;
            }
        }
        if (!kswordArkCiHashNameIsDriver(
                (const UCHAR*)current,
                nameOffset) ||
            !kswordArkRuntimeReadMemory(
                (const UCHAR*)current + nextOffset,
                &next,
                sizeof(next)) ||
            (next != 0U && !kswordArkCiHashIsKernelAddress(next))) {
            return FALSE;
        }
        seen[count] = current;
        if (count < KSW_CI_HASH_MAX_SAMPLES) {
            candidate.samples[count] = (PVOID)current;
            candidate.sampleCount += 1UL;
        }
        count += 1UL;
        current = next;
    }
    if (count < 2UL || current != 0U) {
        return FALSE;
    }
    candidate.listGlobal = listGlobal;
    candidate.nextOffset = nextOffset;
    candidate.nameOffset = nameOffset;
    candidate.chainLength = count;
    if (candidateOut != NULL) {
        *candidateOut = candidate;
    }
    return TRUE;
}

static BOOLEAN
kswordArkCiHashInferListCandidate(
    _In_ const KswRuntimeImageView* view,
    _In_ const KswRuntimeDataReference* reference,
    _Out_ KswCiHashCandidate* candidateOut
    )
{
    KswCiHashCandidate best;
    ULONG bestLength = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG nextOffset = 0UL;

    if (view == NULL || reference == NULL || candidateOut == NULL ||
        !kswordArkRuntimeAddressIsWritableData(
            view,
            reference->address,
            sizeof(PVOID))) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (nextOffset = 0UL;
         nextOffset + sizeof(PVOID) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
         nextOffset += sizeof(PVOID)) {
        ULONG nameOffset = 0UL;

        for (nameOffset = 0UL;
             nameOffset + sizeof(UNICODE_STRING) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
             nameOffset += sizeof(PVOID)) {
            KswCiHashCandidate candidate;

            if (nameOffset == nextOffset) {
                continue;
            }
            RtlZeroMemory(&candidate, sizeof(candidate));
            if (!kswordArkCiHashWalkCandidate(
                    reference->address,
                    nextOffset,
                    nameOffset,
                    &candidate) ||
                candidate.chainLength < bestLength) {
                continue;
            }
            if (candidate.chainLength == bestLength && bestLength != 0UL) {
                ambiguous = TRUE;
                continue;
            }
            best = candidate;
            bestLength = candidate.chainLength;
            ambiguous = FALSE;
        }
    }
    if (bestLength < 2UL || ambiguous) {
        return FALSE;
    }
    best.referenceRoutine = reference->routineAddress;
    best.referenceInstruction = reference->instructionAddress;
    *candidateOut = best;
    return TRUE;
}

static BOOLEAN
kswordArkCiHashOptionalPointerIsSane(
    _In_opt_ const VOID* pointer
    )
{
    return pointer == NULL ||
        kswordArkCiHashIsKernelAddress((ULONG_PTR)pointer);
}

static BOOLEAN
kswordArkCiHashResourceIsPlausible(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Cheap shape filter used while pairing candidates.  It narrows the search
    space only; it can never establish that the address is a real ERESOURCE,
    because every self-consistent LIST_ENTRY in a writable image section
    satisfies these conditions.  Identity is settled by
    kswordArkKernelProbeResourceIsSystemResource before the lock is acquired.

Return Value:

    TRUE when the candidate is shaped like a resource.

--*/
{
    ERESOURCE resource;
    LIST_ENTRY forward;
    LIST_ENTRY backward;

    RtlZeroMemory(&resource, sizeof(resource));
    RtlZeroMemory(&forward, sizeof(forward));
    RtlZeroMemory(&backward, sizeof(backward));
    if ((address & (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkRuntimeAddressIsWritableData(view, address, sizeof(resource)) ||
        !kswordArkRuntimeReadMemory((const VOID*)address, &resource, sizeof(resource)) ||
        !kswordArkCiHashIsKernelAddress(
            (ULONG_PTR)resource.SystemResourcesList.Flink) ||
        !kswordArkCiHashIsKernelAddress(
            (ULONG_PTR)resource.SystemResourcesList.Blink) ||
        (((ULONG_PTR)resource.SystemResourcesList.Flink |
          (ULONG_PTR)resource.SystemResourcesList.Blink) &
         (sizeof(PVOID) - 1U)) != 0U ||
        resource.ActiveCount < 0 ||
        !kswordArkCiHashOptionalPointerIsSane(resource.OwnerTable) ||
        !kswordArkCiHashOptionalPointerIsSane(resource.SharedWaiters) ||
        !kswordArkCiHashOptionalPointerIsSane(resource.ExclusiveWaiters) ||
        !kswordArkRuntimeReadMemory(
            resource.SystemResourcesList.Flink,
            &forward,
            sizeof(forward)) ||
        !kswordArkRuntimeReadMemory(
            resource.SystemResourcesList.Blink,
            &backward,
            sizeof(backward)) ||
        forward.Blink != (PLIST_ENTRY)address ||
        backward.Flink != (PLIST_ENTRY)address) {
        return FALSE;
    }
    return TRUE;
}

static ULONG
kswordArkCiHashPairScore(
    _In_ const KswCiHashCandidate* listCandidate,
    _In_ const KswRuntimeDataReference* lockReference
    )
{
    ULONG_PTR distance = listCandidate->referenceInstruction >
            lockReference->instructionAddress
        ? listCandidate->referenceInstruction - lockReference->instructionAddress
        : lockReference->instructionAddress - listCandidate->referenceInstruction;
    ULONG score = 0UL;

    if (listCandidate->referenceRoutine == lockReference->routineAddress) {
        score += 8UL;
    }
    if (distance <= 0x100UL) {
        score += 4UL;
    }
    else if (distance <= 0x800UL) {
        score += 2UL;
    }
    else if (distance <= 0x2000UL) {
        score += 1UL;
    }
    return score;
}

static BOOLEAN
kswordArkCiHashFindModule(
    _In_ const KswHookSystemModuleInformation* modules,
    _Out_ const KswHookSystemModuleEntry** moduleOut
    )
{
    ULONG index = 0UL;

    if (modules == NULL || moduleOut == NULL) {
        return FALSE;
    }
    *moduleOut = NULL;
    for (index = 0UL; index < modules->numberOfModules; ++index) {
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;

        kswordArkHookGetModuleFileName(
            &modules->modules[index],
            &fileName,
            &fileNameBytes);
        if (kswordArkHookBoundedAnsiEqualsInsensitive(
                fileName,
                fileNameBytes,
                "ci.dll") ||
            kswordArkHookBoundedAnsiEqualsInsensitive(
                fileName,
                fileNameBytes,
                "ci.sys")) {
            *moduleOut = &modules->modules[index];
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
kswordArkCiHashInferOptionalFields(
    _In_ const KswCiHashCandidate* candidate,
    _Inout_ KswDynV4CiKernelHashLayout* layout
    )
{
    ULONG pairOffset = 0UL;
    ULONG bestPairMatches = 0UL;
    LONG bestPairOffset = -1;
    BOOLEAN pairTied = FALSE;
    ULONG imageOffset = 0UL;
    ULONG bestImageMatches = 0UL;
    LONG bestImageOffset = -1;
    BOOLEAN imageTied = FALSE;

    for (pairOffset = 0UL;
         pairOffset + (2UL * sizeof(ULONG)) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
         pairOffset += sizeof(ULONG)) {
        ULONG sampleIndex = 0UL;
        ULONG matches = 0UL;

        if (pairOffset == candidate->nextOffset ||
            pairOffset == candidate->nameOffset) {
            continue;
        }
        for (sampleIndex = 0UL;
             sampleIndex < candidate->sampleCount;
             ++sampleIndex) {
            ULONG timestamp = 0UL;
            NTSTATUS loadStatus = STATUS_SUCCESS;

            if (kswordArkRuntimeReadMemory(
                    (const UCHAR*)candidate->samples[sampleIndex] + pairOffset,
                    &timestamp,
                    sizeof(timestamp)) &&
                kswordArkRuntimeReadMemory(
                    (const UCHAR*)candidate->samples[sampleIndex] + pairOffset +
                        sizeof(ULONG),
                    &loadStatus,
                    sizeof(loadStatus)) &&
                timestamp >= 0x20000000UL &&
                (loadStatus == STATUS_SUCCESS ||
                 (((ULONG)loadStatus & 0xC0000000UL) == 0xC0000000UL) ||
                 (((ULONG)loadStatus & 0xC0000000UL) == 0x80000000UL))) {
                matches += 1UL;
            }
        }
        if (matches < 2UL || matches < bestPairMatches) {
            continue;
        }
        if (matches == bestPairMatches && bestPairMatches != 0UL) {
            pairTied = TRUE;
            continue;
        }
        bestPairMatches = matches;
        bestPairOffset = (LONG)pairOffset;
        pairTied = FALSE;
    }
    if (bestPairOffset >= 0 && !pairTied) {
        layout->entryTimeDateStamp = (ULONG)bestPairOffset;
        layout->entryLoadStatus = (ULONG)bestPairOffset + sizeof(ULONG);
    }

    for (imageOffset = 0UL;
         imageOffset + sizeof(PVOID) + sizeof(ULONG) <=
             KSW_CI_HASH_MAX_ENTRY_BYTES;
         imageOffset += sizeof(PVOID)) {
        ULONG sampleIndex = 0UL;
        ULONG matches = 0UL;

        for (sampleIndex = 0UL;
             sampleIndex < candidate->sampleCount;
             ++sampleIndex) {
            ULONG_PTR imageBase = 0U;
            ULONG imageSize = 0UL;

            if (kswordArkRuntimeReadMemory(
                    (const UCHAR*)candidate->samples[sampleIndex] + imageOffset,
                    &imageBase,
                    sizeof(imageBase)) &&
                kswordArkRuntimeReadMemory(
                    (const UCHAR*)candidate->samples[sampleIndex] + imageOffset +
                        sizeof(PVOID),
                    &imageSize,
                    sizeof(imageSize)) &&
                kswordArkCiHashIsKernelAddress(imageBase) &&
                imageSize >= PAGE_SIZE && imageSize <= 0x40000000UL) {
                matches += 1UL;
            }
        }
        if (matches < 2UL || matches < bestImageMatches) {
            continue;
        }
        if (matches == bestImageMatches && bestImageMatches != 0UL) {
            imageTied = TRUE;
            continue;
        }
        bestImageMatches = matches;
        bestImageOffset = (LONG)imageOffset;
        imageTied = FALSE;
    }
    if (bestImageOffset >= 0 && !imageTied) {
        layout->entryImageBase = (ULONG)bestImageOffset;
        layout->entryImageSize = (ULONG)bestImageOffset + sizeof(PVOID);
    }
}

NTSTATUS
kswordArkCiHashResolveRuntimeLayout(
    _Out_ KswDynV4CiKernelHashLayout* layoutOut
    )
{
    static PCSTR const kAnchors[] = {
        "CiInitialize",
        "CiValidateFileObject",
        "CiCheckSignedFile",
        "CiVerifyHashInCatalog"
    };
    KswHookSystemModuleInformation* modules = NULL;
    const KswHookSystemModuleEntry* ciModule = NULL;
    ULONG moduleBytes = 0UL;
    KswRuntimeImageView view;
    KswRuntimeDataReference* references = NULL;
    ULONG referenceCount = 0UL;
    KswCiHashCandidate bestList;
    const KswRuntimeDataReference* bestLock = NULL;
    ULONG bestChainLength = 0UL;
    ULONG bestPairScore = 0UL;
    BOOLEAN listAmbiguous = FALSE;
    BOOLEAN pairAmbiguous = FALSE;
    ULONG referenceIndex = 0UL;
    BOOLEAN lockAcquired = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    layoutOut->entryTimeDateStamp = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryLoadStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryImageBase = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryImageSize = KSW_DYN_OFFSET_UNAVAILABLE;
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&bestList, sizeof(bestList));
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = kswordArkHookBuildModuleSnapshot(&modules, &moduleBytes);
    if (!NT_SUCCESS(status) || !kswordArkCiHashFindModule(modules, &ciModule) ||
        !kswordArkRuntimeInitializeImageView(
            ciModule->imageBase,
            ciModule->imageSize,
            &view)) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    references = (KswRuntimeDataReference*)kswordArkAllocateNonPagedPool(
        KSW_CI_HASH_MAX_REFERENCES * sizeof(*references),
        KSW_CI_HASH_FALLBACK_TAG);
    if (references == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        &view,
        kAnchors,
        RTL_NUMBER_OF(kAnchors),
        4UL,
        KSW_CI_HASH_ROUTINE_SCAN_BYTES,
        references,
        KSW_CI_HASH_MAX_REFERENCES);
    if (referenceCount == 0UL) {
        referenceCount = kswordArkRuntimeCollectExecutableDataReferences(
            &view,
            min(view.size, KSW_CI_HASH_FULL_SCAN_BUDGET),
            references,
            KSW_CI_HASH_MAX_REFERENCES);
    }

    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        KswCiHashCandidate candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!kswordArkCiHashInferListCandidate(
                &view,
                &references[referenceIndex],
                &candidate) ||
            candidate.chainLength < bestChainLength) {
            continue;
        }
        if (candidate.chainLength == bestChainLength &&
            bestChainLength != 0UL &&
            (candidate.listGlobal != bestList.listGlobal ||
             candidate.nextOffset != bestList.nextOffset ||
             candidate.nameOffset != bestList.nameOffset)) {
            listAmbiguous = TRUE;
            continue;
        }
        bestList = candidate;
        bestChainLength = candidate.chainLength;
        listAmbiguous = FALSE;
    }
    if (bestChainLength < 2UL || listAmbiguous) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        ULONG pairScore = 0UL;

        if (references[referenceIndex].address == bestList.listGlobal ||
            !kswordArkCiHashResourceIsPlausible(
                &view,
                references[referenceIndex].address)) {
            continue;
        }
        pairScore = kswordArkCiHashPairScore(
            &bestList,
            &references[referenceIndex]);
        if (pairScore == 0UL || pairScore < bestPairScore) {
            continue;
        }
        if (pairScore == bestPairScore && bestPairScore != 0UL &&
            bestLock != NULL &&
            bestLock->address != references[referenceIndex].address) {
            pairAmbiguous = TRUE;
            continue;
        }
        bestLock = &references[referenceIndex];
        bestPairScore = pairScore;
        pairAmbiguous = FALSE;
    }
    if (bestLock == NULL || bestPairScore < 2UL || pairAmbiguous) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    /*
     * Shape checks got us a candidate; only global-resource-list membership
     * proves it is a resource.  Handing a non-resource to the Ex API faults
     * inside the kernel's lock path, so this gate precedes the acquire.
     */
    if (!kswordArkKernelProbeResourceIsSystemResource(bestLock->address)) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    KeEnterCriticalRegion();
    lockAcquired = ExAcquireResourceSharedLite(
        (PERESOURCE)bestLock->address,
        FALSE);
    if (lockAcquired) {
        KswCiHashCandidate lockedCandidate;

        RtlZeroMemory(&lockedCandidate, sizeof(lockedCandidate));
        if (kswordArkCiHashWalkCandidate(
                bestList.listGlobal,
                bestList.nextOffset,
                bestList.nameOffset,
                &lockedCandidate) &&
            lockedCandidate.chainLength == bestList.chainLength &&
            bestList.listGlobal >= view.base &&
            bestLock->address >= view.base &&
            bestList.listGlobal - view.base <= MAXULONG &&
            bestLock->address - view.base <= MAXULONG) {
            layoutOut->moduleBase = view.base;
            layoutOut->moduleSize = view.size;
            layoutOut->kernelHashBucketListRva =
                (ULONG)(bestList.listGlobal - view.base);
            layoutOut->hashCacheLockRva =
                (ULONG)(bestLock->address - view.base);
            layoutOut->entryNext = bestList.nextOffset;
            layoutOut->entryDriverName = bestList.nameOffset;
            kswordArkCiHashInferOptionalFields(&lockedCandidate, layoutOut);
            layoutOut->entryTypeSize = max(
                layoutOut->entryNext + (ULONG)sizeof(PVOID),
                layoutOut->entryDriverName + (ULONG)sizeof(UNICODE_STRING));
            if (layoutOut->entryTimeDateStamp != KSW_DYN_OFFSET_UNAVAILABLE) {
                layoutOut->entryTypeSize = max(
                    layoutOut->entryTypeSize,
                    layoutOut->entryLoadStatus + (ULONG)sizeof(NTSTATUS));
            }
            if (layoutOut->entryImageBase != KSW_DYN_OFFSET_UNAVAILABLE) {
                layoutOut->entryTypeSize = max(
                    layoutOut->entryTypeSize,
                    layoutOut->entryImageSize + (ULONG)sizeof(ULONG));
            }
            layoutOut->entryTypeSize =
                (layoutOut->entryTypeSize + (sizeof(PVOID) - 1UL)) &
                ~(sizeof(PVOID) - 1UL);
            status = STATUS_SUCCESS;
        }
        ExReleaseResourceLite((PERESOURCE)bestLock->address);
    }
    KeLeaveCriticalRegion();

Exit:
    if (references != NULL) {
        ExFreePoolWithTag(references, KSW_CI_HASH_FALLBACK_TAG);
    }
    if (modules != NULL) {
        ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
    }
    UNREFERENCED_PARAMETER(moduleBytes);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    }
    return status;
}
