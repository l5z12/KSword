/*++

Module Name:

    hvm_ept_domain.c

Abstract:

    Implements EPT execution domains and the EPTP list that publishes them to
    VMFUNC.  A domain is a fork of the default identity view whose permissions
    may only be narrower, never wider.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_ept_domain.h"
#include "hvm_ept.h"
#include "driver/KswordArkHvmControls.h"

/* Mark a private-table record as being the PDPT rather than a page directory. */
#define KSW_HVM_DOMAIN_PDPT_MARKER MAXULONG

/* Compose one EPT pointer from a root physical address. */
static ULONGLONG
kswordArkHvmEptDomainComposePointer(
    _In_ const KswHvmRuntime* runtime,
    _In_ PHYSICAL_ADDRESS rootPhysical
    )
{
    /* Encode write-back memory and the architectural four-level walk. */
    ULONGLONG pointer =
        ((ULONGLONG)rootPhysical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        6ULL |
        (3ULL << 3);

    /* Match the default view's accessed-and-dirty choice exactly. */
    if ((runtime->featureFlags & KSWORD_ARK_HVM_FEATURE_EPT_AD) != 0ULL) {
        /* Set the architecturally defined EPTP accessed/dirty enable bit. */
        pointer |= (1ULL << 6);
    }
    /* Return the complete pointer for an EPTP list slot. */
    return pointer;
}

/* Find one domain's private table, or NULL when it has not forked yet. */
static KswHvmDomainPrivateTable*
kswordArkHvmEptDomainFindPrivate(
    _Inout_ KswHvmEptDomain* domain,
    _In_ ULONG pml4Index,
    _In_ ULONG pdptIndex
    )
{
    ULONG index = 0UL;

    /* Scan the bounded fork ledger for an exact position match. */
    for (index = 0UL; index < domain->privateTableCount; ++index) {
        /* Compare both coordinates so a PDPT never matches a page directory. */
        if (domain->privateTables[index].pml4Index == pml4Index &&
            domain->privateTables[index].pdptIndex == pdptIndex) {
            /* Return the existing private table for in-place editing. */
            return &domain->privateTables[index];
        }
    }
    /* Report that this position is still shared with the default view. */
    return NULL;
}

/* Fork one paging structure so this domain can diverge at that position. */
static NTSTATUS
kswordArkHvmEptDomainForkTable(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptDomain* domain,
    _In_ ULONG pml4Index,
    _In_ ULONG pdptIndex,
    _In_ const VOID* sourceTable
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KswHvmDomainPrivateTable* record = NULL;
    PVOID page = NULL;

    /* Reject a fork the bounded per-domain ledger cannot record. */
    if (domain->privateTableCount >= KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Allocate one ledgered page; the allocator primes suppress-#VE. */
    page = kswordArkHvmAllocateEptPageLocked(runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the shared table wholesale.  The fork starts identical to the
     * default view by construction, which is what makes "narrower only" an
     * invariant rather than a hope: every later edit is a removal.
     */
    RtlCopyMemory(page, sourceTable, (SIZE_T)KSW_HVM_PAGE_BYTES);
    /* Record the fork so cleanup and later lookups can find it. */
    record = &domain->privateTables[domain->privateTableCount];
    record->pml4Index = pml4Index;
    record->pdptIndex = pdptIndex;
    record->virtual = page;
    record->physical = physicalAddress;
    domain->privateTableCount += 1UL;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

/* Ensure this domain owns a private page directory for one GiB window. */
static NTSTATUS
kswordArkHvmEptDomainEnsurePrivatePd(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptDomain* domain,
    _In_ ULONG pml4Index,
    _In_ ULONG pdptIndex,
    _Outptr_ ULONGLONG** pdEntries
    )
{
    KswHvmDomainPrivateTable* record = NULL;
    ULONGLONG* pdptEntries = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse positions the default view never mapped. */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        pdptIndex >= 512UL ||
        runtime->eptPdpt[pml4Index] == NULL ||
        runtime->eptPd[pml4Index][pdptIndex] == NULL ||
        domain->pml4Virtual == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reuse an existing private page directory when one already exists. */
    record = kswordArkHvmEptDomainFindPrivate(domain, pml4Index, pdptIndex);
    if (record != NULL) {
        /* Return the previously forked page directory. */
        *pdEntries = (ULONGLONG*)record->virtual;
        /* Complete without allocating a second copy. */
        return STATUS_SUCCESS;
    }
    /*
     * A private page directory needs a private PDPT to point at it, otherwise
     * publishing it would edit the table every other domain shares.
     */
    record = kswordArkHvmEptDomainFindPrivate(
        domain,
        pml4Index,
        KSW_HVM_DOMAIN_PDPT_MARKER);
    if (record == NULL) {
        /* Fork the PDPT before anything can point at a private directory. */
        status = kswordArkHvmEptDomainForkTable(
            runtime,
            domain,
            pml4Index,
            KSW_HVM_DOMAIN_PDPT_MARKER,
            runtime->eptPdpt[pml4Index]);
        if (!NT_SUCCESS(status)) {
            /* Return before touching any published table. */
            return status;
        }
        record = kswordArkHvmEptDomainFindPrivate(
            domain,
            pml4Index,
            KSW_HVM_DOMAIN_PDPT_MARKER);
        if (record == NULL) {
            /* Return the exact internal-consistency failure. */
            return STATUS_INTERNAL_ERROR;
        }
        /* Point this domain's own root slot at the forked PDPT. */
        ((ULONGLONG*)domain->pml4Virtual)[pml4Index] =
            ((ULONGLONG)record->physical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ |
            KSW_EPT_WRITE |
            KSW_EPT_EXECUTE;
    }
    /* Bind the private PDPT that will own the forked page directory. */
    pdptEntries = (ULONGLONG*)record->virtual;
    /* Fork the page directory that actually holds the target leaves. */
    status = kswordArkHvmEptDomainForkTable(
        runtime,
        domain,
        pml4Index,
        pdptIndex,
        runtime->eptPd[pml4Index][pdptIndex]);
    if (!NT_SUCCESS(status)) {
        /* Return with the private PDPT retained for a later attempt. */
        return status;
    }
    record = kswordArkHvmEptDomainFindPrivate(domain, pml4Index, pdptIndex);
    if (record == NULL) {
        /* Return the exact internal-consistency failure. */
        return STATUS_INTERNAL_ERROR;
    }
    /* Publish the forked page directory inside this domain's PDPT only. */
    pdptEntries[pdptIndex] =
        ((ULONGLONG)record->physical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Return the writable page directory for leaf edits. */
    *pdEntries = (ULONGLONG*)record->virtual;
    /* Complete the copy-on-write path successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptDomainPrepareLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    ULONGLONG* entries = NULL;
    PVOID page = NULL;

    /* Report success when the list already exists for this runtime. */
    if (runtime->eptpListVirtual != NULL) {
        /* Complete without allocating a second list. */
        return STATUS_SUCCESS;
    }
    /* Refuse to build a list before the default view exists. */
    if (runtime->eptPointer == 0ULL ||
        runtime->eptPml4 == NULL) {
        /* Return the exact ordering failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Allocate one ledgered page to hold 512 EPT pointers. */
    page = kswordArkHvmAllocateEptPageLocked(runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Zero every slot.  A zero EPT pointer is architecturally invalid, so an
     * unused slot makes VMFUNC fail and exit rather than switch somewhere
     * unintended.  The page allocator primes EPT tables with suppress-#VE,
     * which is meaningless for a pointer list, so this zeroing is not
     * redundant with it.
     */
    RtlZeroMemory(page, (SIZE_T)KSW_HVM_PAGE_BYTES);
    entries = (ULONGLONG*)page;
    /* Publish the default view as entry zero so VMFUNC 0 always returns. */
    entries[0] = runtime->eptPointer;
    runtime->eptDomains[0].active = TRUE;
    runtime->eptDomains[0].eptPointer = runtime->eptPointer;
    runtime->eptDomains[0].pml4Virtual = runtime->eptPml4;
    runtime->eptpListVirtual = page;
    runtime->eptpListPhysical = physicalAddress;
    /* Publish list readiness for callers deciding whether to arm VMFUNC. */
    runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY;
    /* Complete the list preparation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptDomainCreateLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Out_ ULONG* domainIndex
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KswHvmEptDomain* domain = NULL;
    PVOID page = NULL;
    ULONG index = 0UL;
    ULONG selected = 0UL;

    /* Reject a request that cannot report which domain was created. */
    if (domainIndex == NULL) {
        /* Return the exact contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *domainIndex = 0UL;
    /* Refuse to fork before the list and the default view both exist. */
    if (runtime->eptpListVirtual == NULL ||
        runtime->eptPml4 == NULL) {
        /* Return the exact ordering failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Select the first free slot, never slot zero which is the default. */
    for (index = 1UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        if (!runtime->eptDomains[index].active) {
            /* Bind the free slot for this fork. */
            domain = &runtime->eptDomains[index];
            selected = index;
            break;
        }
    }
    if (domain == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Allocate this domain's own root table. */
    page = kswordArkHvmAllocateEptPageLocked(runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the default root.  Every slot still points at the shared PDPTs, so
     * the new domain is byte-for-byte equivalent to the default view until a
     * restriction forks something.  An equivalent domain is the only safe
     * starting point, because it cannot grant anything the guest lacks.
     */
    RtlCopyMemory(page, runtime->eptPml4, (SIZE_T)KSW_HVM_PAGE_BYTES);
    domain->pml4Virtual = page;
    domain->pml4Physical = physicalAddress;
    domain->privateTableCount = 0UL;
    domain->eptPointer =
        kswordArkHvmEptDomainComposePointer(runtime, physicalAddress);
    domain->active = TRUE;
    /* Publish the domain so guest VMFUNC can select it by index. */
    ((ULONGLONG*)runtime->eptpListVirtual)[selected] = domain->eptPointer;
    *domainIndex = selected;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptDomainRestrictRangeLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG domainIndex,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount,
    _In_ ULONG deniedAccess
    )
{
    KswHvmEptDomain* domain = NULL;
    ULONGLONG removedBits = 0ULL;
    ULONGLONG cursor = 0ULL;
    ULONGLONG end = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse the default view: narrowing it would affect every domain. */
    if (domainIndex == 0UL ||
        domainIndex >= KSW_HVM_MAX_EPT_DOMAINS ||
        !runtime->eptDomains[domainIndex].active) {
        /* Return the exact target-selection failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse an empty or wrapping range before touching any table. */
    if (byteCount == 0ULL ||
        physicalAddress > (MAXULONGLONG - byteCount)) {
        /* Return the exact range-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse ranges outside the window the default view actually maps. */
    if ((physicalAddress + byteCount) >
            runtime->highestMappedPhysicalAddress) {
        /* Return the exact coverage failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Translate protocol access bits into the EPT permission bits to clear. */
    if ((deniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        removedBits |= KSW_EPT_READ;
    }
    if ((deniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        removedBits |= KSW_EPT_WRITE;
    }
    if ((deniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
        removedBits |= KSW_EPT_EXECUTE;
    }
    /* Refuse a request that would remove nothing. */
    if (removedBits == 0ULL) {
        /* Return the exact empty-policy failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A leaf that denies read while keeping write or execute is
     * architecturally invalid unless the processor supports execute-only
     * translation, and an invalid leaf fails VM entry rather than the access.
     * Refuse the request instead of publishing a table that cannot launch.
     */
    if ((removedBits & KSW_EPT_READ) != 0ULL &&
        (runtime->vmxEptVpidCapabilities &
            KSW_EPT_CAP_EXECUTE_ONLY) == 0ULL) {
        /* Return the exact unsupported-permission failure. */
        return STATUS_NOT_SUPPORTED;
    }
    domain = &runtime->eptDomains[domainIndex];
    /*
     * Walk whole two-MiB leaves so no partial leaf is ever left edited.  The
     * index arithmetic lives in KswordArkHvmControls.h so the host unit tests
     * exercise the same code the driver runs: getting it wrong does not fault,
     * it silently narrows an unrelated region.
     */
    cursor = KswordArkHvmEptLeafBase(physicalAddress);
    end = physicalAddress + byteCount;
    while (cursor < end) {
        const ULONG kPml4Index = KswordArkHvmEptPml4Index(cursor);
        const ULONG kPdptIndex = KswordArkHvmEptPdptIndex(cursor);
        const ULONG kPdIndex = KswordArkHvmEptPdIndex(cursor);
        ULONGLONG* pdEntries = NULL;

        /* Fork whatever this position still shares with the default view. */
        status = kswordArkHvmEptDomainEnsurePrivatePd(
            runtime,
            domain,
            kPml4Index,
            kPdptIndex,
            &pdEntries);
        if (!NT_SUCCESS(status)) {
            /* Return with earlier leaves narrowed; the caller resets. */
            return status;
        }
        /*
         * Remove permissions only; this is what keeps a domain a subset.  The
         * helper cannot express "grant", so it cannot be called wrongly.
         */
        pdEntries[kPdIndex] = KswordArkHvmEptApplyRestriction(
            pdEntries[kPdIndex],
            removedBits);
        /* Advance to the next whole two-MiB leaf. */
        cursor += KSW_HVM_LARGE_PAGE_BYTES;
    }
    /* Complete the narrowing successfully. */
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmEptDomainResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /*
     * Unpublish before forgetting.  Every list slot is reachable by one guest
     * instruction, so a slot must stop naming a domain before that domain's
     * pages can be reused for anything else.
     */
    if (runtime->eptpListVirtual != NULL) {
        RtlZeroMemory(
            runtime->eptpListVirtual,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    }
    /*
     * Forget every domain.  The pages themselves belong to the shared EPT
     * allocation ledger and are freed with it, so this clears references
     * rather than memory; releasing them here would double-free.
     */
    for (index = 0UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        RtlZeroMemory(
            &runtime->eptDomains[index],
            sizeof(runtime->eptDomains[index]));
    }
    runtime->eptpListVirtual = NULL;
    runtime->eptpListPhysical.QuadPart = 0LL;
    /* Withdraw the readiness claim along with the list. */
    runtime->featureFlags &= ~KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY;
}

/* Publish one domain slot as a protocol row. */
static VOID
kswordArkHvmEptDomainFillRow(
    _In_ const KswHvmEptDomain* domain,
    _In_ ULONG domainIndex,
    _Out_ KSWORD_ARK_HVM_DOMAIN_ROW* row
    )
{
    /* Start from a deterministic row for every field. */
    RtlZeroMemory(row, sizeof(*row));
    /* Publish the index guest code would name in a VMFUNC. */
    row->domainIndex = domainIndex;
    /* Publish whether this slot currently holds a live domain. */
    row->active = domain->active ? 1UL : 0UL;
    /* Publish how far this domain diverged from the shared hierarchy. */
    row->privateTableCount = domain->privateTableCount;
    /* Publish the pointer actually written into the list slot. */
    row->eptPointer = domain->eptPointer;
}

/* Execute one validated domain request with the runtime lock already held. */
static NTSTATUS
kswordArkHvmEptDomainControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* response
    )
{
    ULONG domainIndex = 0UL;
    ULONG index = 0UL;
    ULONG rows = 0UL;
    ULONG active = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before touching any state. */
    if (runtime == NULL || request == NULL || response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->generation = runtime->generation;
    response->featureFlags = runtime->featureFlags;
    response->stateFlags = runtime->stateFlags;
    /* Validate the complete versioned request. */
    if (request->version != KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION ||
        request->size != sizeof(*request)) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Count live domains once for every operation that reports them. */
    for (index = 0UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        if (runtime->eptDomains[index].active) {
            /* Account one live domain. */
            active += 1UL;
        }
    }
    /* Answer read-only queries before any confirmation requirement. */
    if (request->operation == KSWORD_ARK_HVM_DOMAIN_OP_QUERY) {
        /* Publish every slot, live or not, so gaps stay visible. */
        for (index = 0UL;
             index < KSW_HVM_MAX_EPT_DOMAINS &&
                rows < KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
             ++index) {
            /* Publish one complete row. */
            kswordArkHvmEptDomainFillRow(
                &runtime->eptDomains[index],
                index,
                &response->rows[rows]);
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        response->returnedRows = rows;
        /* Publish the live domain count. */
        response->domainCount = active;
        /* Publish the successful query. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
        /* Return the complete query answer. */
        return STATUS_SUCCESS;
    }
    /*
     * Every mutating operation edits tables that guest code can reach with a
     * single instruction, so all of them require the confirmation token.
     */
    if (request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (request->flags &
            KSWORD_ARK_HVM_DOMAIN_FLAG_UI_CONFIRMED) == 0UL) {
        /* Publish the stable confirmation-required protocol status. */
        response->status =
            KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Honor a generation-bound request exactly as the control path does. */
    if (request->expectedGeneration != 0UL &&
        request->expectedGeneration != runtime->generation) {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse every mutation on a processor that cannot switch pointers. */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING) == 0ULL) {
        /* Publish the stable unsupported protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse mutation before the list that publishes domains exists. */
    if (runtime->eptpListVirtual == NULL) {
        /* Publish the stable not-prepared protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Dispatch the exact requested mutation. */
    if (request->operation == KSWORD_ARK_HVM_DOMAIN_OP_CREATE) {
        /* Fork one domain equivalent to the default view. */
        status = kswordArkHvmEptDomainCreateLocked(
            runtime,
            &domainIndex);
        /* Publish the created index for the caller to restrict later. */
        response->domainIndex = domainIndex;
        /* Translate the exact backend failure into a protocol status. */
        response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_DOMAIN_STATUS_OK
            : (status == STATUS_INSUFFICIENT_RESOURCES
                ? KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL
                : KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED);
    } else if (request->operation == KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT) {
        /* Remove the requested permissions from the named domain. */
        status = kswordArkHvmEptDomainRestrictRangeLocked(
            runtime,
            request->domainIndex,
            request->physicalAddress,
            request->byteCount,
            request->deniedAccess);
        /* Echo the target so a caller can correlate the answer. */
        response->domainIndex = request->domainIndex;
        /* Translate the exact backend failure into a protocol status. */
        if (NT_SUCCESS(status)) {
            response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
        } else if (status == STATUS_NOT_SUPPORTED) {
            response->status =
                KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED;
        } else if (status == STATUS_INVALID_PARAMETER) {
            response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND;
        } else if (status == STATUS_INSUFFICIENT_RESOURCES) {
            response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL;
        } else {
            response->status =
                KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
        }
    } else if (request->operation == KSWORD_ARK_HVM_DOMAIN_OP_RESET) {
        /*
         * Reset drops the list too, so rebuild it immediately.  A runtime
         * holding a default view but no list would report EPTP_LIST_READY as
         * false and refuse a later start that asked for VMFUNC.
         */
        kswordArkHvmEptDomainResetLocked(runtime);
        status = kswordArkHvmEptDomainPrepareLocked(runtime);
        response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_DOMAIN_STATUS_OK
            : KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
    } else {
        /* Publish the stable invalid-request protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
    }
    /* Publish the authoritative backend result alongside the status. */
    response->lastStatus = status;
    /* Recount and republish so the caller sees the post-operation shape. */
    active = 0UL;
    rows = 0UL;
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_DOMAINS &&
            rows < KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
         ++index) {
        if (runtime->eptDomains[index].active) {
            /* Account one live domain. */
            active += 1UL;
        }
        /* Publish one complete row. */
        kswordArkHvmEptDomainFillRow(
            &runtime->eptDomains[index],
            index,
            &response->rows[rows]);
        /* Account the published row. */
        rows += 1UL;
    }
    response->returnedRows = rows;
    response->domainCount = active;
    response->featureFlags = runtime->featureFlags;
    /* Report protocol-level success; the detail lives in the response. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptDomainControl(
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* response
    )
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (request == NULL || response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = request->operation != KSWORD_ARK_HVM_DOMAIN_OP_QUERY;
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->lock);
    if (!runtime->initialized) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Publish the stable not-prepared protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating && runtime->busy) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Reuse the resource status for a transient lifecycle conflict. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No domain, table or list slot was changed. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * A resident processor may be executing inside one of these tables
         * right now, and guest code can switch between them without exiting.
         * Editing a live domain would change translations under a running
         * VCPU with no coherent way to invalidate, so refuse instead.
         */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /* Publish the stable resident-active protocol status. */
        response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No domain, table or list slot was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded domain operation under lifecycle ownership. */
        status = kswordArkHvmEptDomainControlLocked(
            runtime,
            request,
            response);
    }
    ExReleasePushLockExclusive(&runtime->lock);
    KeLeaveCriticalRegion();
    /* Return the complete domain operation result. */
    return status;
}
