/* AMD NPT composition. Hardware publication/ASID invalidation is a separate owner. */
#include "hvm_svm_nested_mmu.h"

/* Keep the walk adapter on the caller's nonpaged exit stack. */
typedef struct KswNmmuContext {
    /* Immutable roots, capability limits and PAT layouts. */
    const KswNmmuConfig* config;
    /* Host-physical accesses supplied by the per-CPU window. */
    const KswNmmuIo* io;
    /* Preserve failure provenance across boolean callback interfaces. */
    KswNmmuResult* result;
    /* Callback failures have more precise status than a generic unreadable slot. */
    unsigned int callbackStatus;
} KswNmmuContext;

/* Count actual reads; never infer success from an initialized output value. */
static int kswNmmuReadHost(void* opaque, KswSvmU64 address, KswSvmU64* value)
{
    /* The context is processor-local and never shared with another exit handler. */
    KswNmmuContext* context = (KswNmmuContext*)opaque;
    /* Operand words must be aligned, wholly within an admitted RAM page. */
    if ((address & 7ULL) || !context->io->read(context->io->context, address, value)) {
        /* An inaccessible hardware operand is a host-side failure. */
        context->result->faultOwner = KSW_NMMU_PHYSICAL;
        /* Preserve the exact physical address that the adapter refused. */
        context->result->faultAddress = address;
        /* A physical read failure cannot synthesize a not-present entry. */
        context->callbackStatus = KSW_NNPT_UNREADABLE;
        /* Stop this walk immediately. */
        return 0;
    }
    /* Count only initialized source words. */
    ++context->result->reads;
    /* Return the caller-supplied word unchanged. */
    return 1;
}

/* Forward atomic updates without replacing guest-owned frame or permission bits. */
static int kswNmmuUpdateHost(void* opaque, KswSvmU64 address,
    KswSvmU64 expected, KswSvmU64 bits)
{
    /* This callback shares the same window owner as the read callback. */
    KswNmmuContext* context = (KswNmmuContext*)opaque;
    /* A refused physical write and a compare mismatch both require a new resolution. */
    return context->io->compareOr(context->io->context, address, expected, bits);
}

/* Translate an NPT12 slot through NPT01; table fetches require nested-level writes. */
static unsigned int kswNmmuTableAddress(KswNmmuContext* context,
    KswSvmU64 address, KswSvmU64* physical)
{
    /* Retain the outer path long enough to commit its table-access A/D bits. */
    KswNnptWalk path;
    /* Alias the immutable owner configuration. */
    const KswNmmuConfig* config = context->config;
    /* Never read a guest-physical table as if it were host physical. */
    unsigned int status = kswSvmNestedNptWalk(config->outerRoot, address,
        config->outerBits, config->outerPage1Gb, config->outerNx, KSW_NNPT_WRITE,
        kswNmmuReadHost, context, &path);
    /* Even an inner-table read is an outer user write (APM 15.25.5). */
    if (status == KSW_NNPT_OK) {
        /* Hardware would set outer A/D while resolving the inner page-table access. */
        status = kswSvmNestedNptCommitAd(&path, 1, kswNmmuReadHost, kswNmmuUpdateHost, context);
    }
    /* Preserve which translation failed rather than reflecting every NPF inward. */
    if (status != KSW_NNPT_OK) {
        /* Physical callback failures already record their actual failing address. */
        if (context->result->faultOwner != KSW_NMMU_PHYSICAL) {
            /* This failure belongs to the outer mapping of an inner table. */
            context->result->faultOwner = KSW_NMMU_OUTER_TABLE;
            /* Record the L1 physical table slot that was being resolved. */
            context->result->faultAddress = address;
            /* Record architectural fault bits only when a real walk fault occurred. */
            context->result->faultInfo = status == KSW_NNPT_FAULT ? path.fault | KSW_NMMU_TABLE : 0;
        }
        /* Carry the precise outcome through the read/compare callback contract. */
        context->callbackStatus = status;
        /* Do not return an address from an incomplete walk. */
        return status;
    }
    /* This slot is writable RAM only if the host callback subsequently admits it. */
    *physical = path.address;
    /* Let the caller perform exactly one word operation. */
    return KSW_NNPT_OK;
}

/* Adapter used by the NPT12 walker and its full-path A/D revalidation. */
static int kswNmmuReadInner(void* opaque, KswSvmU64 address, KswSvmU64* value)
{
    /* Preserve a single window mapping at a time. */
    KswNmmuContext* context = (KswNmmuContext*)opaque;
    /* A physical address is only usable after both mappings succeeded. */
    KswSvmU64 physical = 0;
    /* Complete the outer walk before opening the final table slot. */
    if (kswNmmuTableAddress(context, address, &physical) != KSW_NNPT_OK) { return 0; }
    /* Host RAM admission remains mandatory even for a valid guest PTE. */
    return kswNmmuReadHost(context, physical, value);
}

/* Re-translate each source slot before atomic A/D modification. */
static int kswNmmuUpdateInner(void* opaque, KswSvmU64 address,
    KswSvmU64 expected, KswSvmU64 bits)
{
    /* The same outer epoch must remain held by the caller throughout resolution. */
    KswNmmuContext* context = (KswNmmuContext*)opaque;
    /* Never retain a physical-window pointer across another window operation. */
    KswSvmU64 physical = 0;
    /* This also verifies that the table is still writable through NPT01. */
    if (kswNmmuTableAddress(context, address, &physical) != KSW_NNPT_OK) { return 0; }
    /* CAS detects source mutation without overwriting a concurrent remap. */
    return kswNmmuUpdateHost(context, physical, expected, bits);
}

/* Resolve and commit one source translation; hardware installation is deliberately separate. */
unsigned int kswSvmNestedMmuResolve(const KswNmmuConfig* config,
    const KswNmmuIo* io, KswSvmU64 gpa, unsigned int access,
    KswSvmU64 faultContext, KswNmmuResult* result)
{
    /* Deterministic output, including failure paths before any memory access. */
    const KswNmmuResult kEmpty = {0};
    /* Bound all state to this one synchronous resolution. */
    KswNmmuContext context;
    /* A leaf remains private until both A/D paths commit. */
    KswSvmU64 leaf = 0;
    /* Preserve the first failing stage. */
    unsigned int status;
    /* No caller may omit the evidence/output buffer. */
    if (!result) { return KSW_NNPT_UNSUPPORTED; }
    /* Never leave a stale valid leaf on argument failure. */
    *result = kEmpty;
    /* initialize status before any early return. */
    result->status = KSW_NNPT_UNSUPPORTED;
    /* Require one architectural NPF origin and an explicit invalidation epoch. */
    if (!config || !io || !io->read || !io->compareOr || !config->epoch ||
        (access & ~(KSW_NNPT_WRITE | KSW_NNPT_EXECUTE)) ||
        (faultContext != KSW_NMMU_FINAL && faultContext != KSW_NMMU_TABLE)) { return result->status; }
    /* A page-table fetch is a nested user write, even for an instruction fetch. */
    if (faultContext == KSW_NMMU_TABLE) { access = KSW_NNPT_WRITE; }
    /* Bind the candidate leaf to its source address. */
    result->gpa = gpa;
    /* This is a stamp, not a substitute for the caller holding the epoch stable. */
    result->epoch = config->epoch;
    /* Install immutable configuration for the callback adapters. */
    context.config = config;
    /* Preserve the actual physical-memory implementation. */
    context.io = io;
    /* Callbacks publish their fault ownership directly. */
    context.result = result;
    /* Zero means no callback has yet failed. */
    context.callbackStatus = KSW_NNPT_OK;
    /* The first walk resolves L2 GPA to L1 GPA through translated table accesses. */
    status = kswSvmNestedNptWalk(config->innerRoot, gpa, config->innerBits,
        config->innerPage1Gb, config->innerNx, access, kswNmmuReadInner, &context, &result->inner);
    /* Only a genuine NPT12 fault is reflected to the inner hypervisor. */
    if (status == KSW_NNPT_FAULT) {
        /* Preserve the original L2 physical address, not an intermediate table PA. */
        result->faultAddress = gpa;
        /* Retain the final/page-table context from the hardware fault. */
        result->faultInfo = result->inner.fault | faultContext;
        /* Name the owner explicitly. */
        result->faultOwner = KSW_NMMU_INNER;
    }
    /* Translate final L1 GPA through the real outer NPT. */
    if (status == KSW_NNPT_OK) {
        /* Use the same access permissions at both levels. */
        status = kswSvmNestedNptWalk(config->outerRoot, result->inner.address,
            config->outerBits, config->outerPage1Gb, config->outerNx,
            access, kswNmmuReadHost, &context, &result->outer);
        /* Preserve an outer failure separately from a guest-controlled NPT fault. */
        if (status != KSW_NNPT_OK && result->faultOwner != KSW_NMMU_PHYSICAL) {
            /* This address is the translated L1 GPA. */
            result->faultAddress = result->inner.address;
            /* Only faults, not unsupported/read failures, have architectural error bits. */
            result->faultInfo = status == KSW_NNPT_FAULT ? result->outer.fault | faultContext : 0;
            /* The host must handle this instead of telling L1 its own map failed. */
            result->faultOwner = KSW_NMMU_OUTER_DATA;
        }
    }
    /* Cache policy validation precedes final source dirty-bit updates. */
    if (status == KSW_NNPT_OK) {
        /* WB/UC subset only; arbitrary three-stage PAT composition is not advertised. */
        status = kswSvmNestedNptCompose4k(&result->inner, &result->outer,
            config->innerPat, config->outerPat, config->hardwarePat, &leaf);
    }
    /* Commit the final outer page, preserving concurrent table mutations via CAS. */
    if (status == KSW_NNPT_OK) {
        /* A writable hardware leaf requires source dirty accounting first. */
        status = kswSvmNestedNptCommitAd(&result->outer, access & KSW_NNPT_WRITE,
            kswNmmuReadHost, kswNmmuUpdateHost, &context);
    }
    /* Commit the inner source path through the translated slot adapter. */
    if (status == KSW_NNPT_OK) {
        /* Failed commits never publish the private composed leaf. */
        status = kswSvmNestedNptCommitAd(&result->inner, access & KSW_NNPT_WRITE,
            kswNmmuReadInner, kswNmmuUpdateInner, &context);
    }
    /* Recover a precise fault/retry that a boolean callback could not express. */
    if (context.callbackStatus != KSW_NNPT_OK) { status = context.callbackStatus; }
    /* A leaf installed for reads must fault on its first write to maintain source D bits. */
    if (status == KSW_NNPT_OK) {
        /* The source A bits are already committed; D only follows a write resolution. */
        result->leaf = (leaf & ((access & KSW_NNPT_WRITE) ? ~0ULL : ~2ULL)) |
            0x20ULL | ((access & KSW_NNPT_WRITE) ? 0x40ULL : 0ULL);
    }
    /* Never equate a usable candidate leaf with hardware entry success. */
    result->status = status;
    /* Return exactly the diagnostic result recorded above. */
    return status;
}
