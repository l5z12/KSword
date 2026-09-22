/* PASSIVE_LEVEL ownership plus VMEXIT-safe, RAM-only physical operand access. */
#include "hvm_svm_nested_runtime.h"
#include "../../platform/pool_compat.h"

/* Validate full operands against the retained, immutable RAM inventory. */
static BOOLEAN kswNsvmRam(const KswSvmNested* nested, ULONGLONG address)
{
    /* Walk the trusted Windows inventory, never guest-supplied intervals. */
    ULONG index;
    /* Reads/atomic updates are exactly one aligned word. */
    if ((address & 7ULL) || address > nested->outer->limit - 8ULL || !nested->outer->ranges) { return FALSE; }
    /* The inventory was validated before any CPU entered SVM. */
    for (index = 0; nested->outer->ranges[index].NumberOfBytes.QuadPart; ++index) {
        /* Decode a validated nonnegative interval. */
        ULONGLONG low = (ULONGLONG)nested->outer->ranges[index].BaseAddress.QuadPart;
        /* The builder already checked addition against the physical-address limit. */
        ULONGLONG high = low + (ULONGLONG)nested->outer->ranges[index].NumberOfBytes.QuadPart;
        /* No MMIO/unknown hole is mapped with the window's RAM cache attributes. */
        if (address >= low && address <= high - 8ULL) { return TRUE; }
    }
    /* Unclassified physical memory is not an admissible table operand. */
    return FALSE;
}

/* Each physical mapping is opened and closed within one callback. */
int kswordSvmNestedRead(void* context, KswSvmU64 address, KswSvmU64* value)
{
    /* CPU ownership is held by the current SVM host loop. */
    KswSvmNested* nested = (KswSvmNested*)context;
    /* Never return or retain the transient mapping pointer. */
    volatile VOID* mapped = NULL;
    /* RAM validation precedes window mapping. */
    if (!kswNsvmRam(nested, address) ||
        kswordArkHvmPhysWindowMap(nested->window, address, 8, &mapped) != KSW_HVM_PHYS_WINDOW_OK) { return 0; }
    /* Aligned x64 word access does not fabricate a value on mapping failure. */
    *value = *(volatile ULONGLONG*)mapped;
    /* Every successful map has exactly one unmap before another callback. */
    kswordArkHvmPhysWindowUnmap(nested->window);
    /* The caller receives one complete source word. */
    return 1;
}

/* Publish A/D without overwriting a concurrent frame/permission change. */
int kswordSvmNestedCompareOr(void* context, KswSvmU64 address,
    KswSvmU64 expected, KswSvmU64 bits)
{
    /* This is the same per-CPU window used by reads. */
    KswSvmNested* nested = (KswSvmNested*)context;
    /* The mapping exists only during this atomic operation. */
    volatile VOID* mapped = NULL;
    /* Preserve the actual compare-exchange observation. */
    LONG64 observed;
    /* This callback may alter only the architectural Accessed/Dirty bits. */
    if ((bits & ~0x60ULL) || !kswNsvmRam(nested, address) ||
        kswordArkHvmPhysWindowMap(nested->window, address, 8, &mapped) != KSW_HVM_PHYS_WINDOW_OK) { return 0; }
    /* LOCK CMPXCHG is nonblocking and does not acquire a kernel spinlock. */
    observed = InterlockedCompareExchange64((volatile LONG64*)mapped, (LONG64)(expected | bits), (LONG64)expected);
    /* Drop the mapping even when a competing writer changed the slot. */
    kswordArkHvmPhysWindowUnmap(nested->window);
    /* A mismatch forces a new walk; the competing value is never overwritten. */
    return (ULONGLONG)observed == expected;
}

/* Release only after the backend has proved complete native return on every CPU. */
VOID kswordSvmNestedRelease(KswSvmCpu* cpu)
{
    /* Partial preparation is cleaned through the same allocation ledger. */
    KswSvmNested* nested = cpu->nested;
    /* Every descriptor starts zero. */
    ULONG index;
    /* No allocation was acquired for an ordinary baseline prepare. */
    if (!nested) { return; }
    /* Retain everything if the owner could still issue a nested VMRUN. */
    if (cpu->active || nested->runningL2) { return; }
    /* Reverse the complete allocation set, including unused shadow pages. */
    for (index = KSW_NSVM_PROBE_PAGES; index != 0;) {
        /* Descend through the allocation ledger, not hardware pointers. */
        --index;
        /* Free every successfully allocated page exactly once. */
        if (nested->pages[index].words) { MmFreeContiguousMemory(nested->pages[index].words); }
    }
    /* The private inner stack is ordinary nonpaged NX memory. */
    if (nested->stack) { ExFreePoolWithTag(nested->stack, 'pSvK'); }
    /* Hardware permission maps remain owned until the inner CPU is native. */
    if (nested->mergedMaps) { MmFreeContiguousMemory(nested->mergedMaps); }
    /* One contiguous allocation owns both operand and virtual HSAVE pages. */
    if (nested->operand) { MmFreeContiguousMemory(nested->operand); }
    /* Drop CPU-local snapshots last. */
    ExFreePoolWithTag(nested, 'pSvK');
    /* Prevent reuse after teardown. */
    cpu->nested = NULL;
}

/* Called after the shared NPT has a complete physical range inventory. */
NTSTATUS kswordSvmNestedPrepare(KswSvmCpu* cpu, ULONG index)
{
    /* Keep cleanup ownership visible before allocating child resources. */
    KswSvmNested* nested;
    /* Bound hardware pages to the same address width as the outer backend. */
    PHYSICAL_ADDRESS highest;
    /* Validate both subranges without trusting allocator alignment implicitly. */
    ULONGLONG mapBase;
    /* Populate the fixed-capacity pool without runtime allocation. */
    ULONG page;
    /* Current backend lifetime holds the shared NPT throughout this preparation. */
    KswSvmState* state = cpu->runtime->backendContext;
    /* Do not replace an existing owner. */
    if (cpu->nested) { return STATUS_ALREADY_REGISTERED; }
    /* Allocate snapshots/ledger from nonpaged memory. */
    nested = kswordArkAllocateNonPagedPool(sizeof(*nested), 'pSvK');
    /* No ownership can be published on allocation failure. */
    if (!nested) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Null pointers make all partial failure paths releasable. */
    RtlZeroMemory(nested, sizeof(*nested));
    /* Publish allocation ownership, not executable readiness. */
    cpu->nested = nested;
    /* Borrow the verified CPU-local window for the driver's lifetime. */
    nested->window = kswordArkHvmPhysWindowForProcessor(index);
    /* Borrow the backend lifetime's immutable outer map. */
    nested->outer = &state->npt;
    /* Refuse to execute without the physical access/cache admission mechanism. */
    if (!nested->window || !state->npt.ranges) { return STATUS_NOT_SUPPORTED; }
    /* Highest representable host physical byte. */
    highest.QuadPart = (LONGLONG)(state->npt.limit - 1);
    /* VMCB12 and virtual HSAVE are adjacent only for the bounded assembly probe. */
    nested->operand = MmAllocateContiguousMemory(8192, highest);
    /* Independent merged maps ensure L1 cannot weaken or overwrite L0's maps. */
    nested->mergedMaps = MmAllocateContiguousMemory(KSW_NSVM_MSRPM_BYTES + KSW_NSVM_IOPM_BYTES, highest);
    /* The inner test has a full private kernel-sized stack. */
    nested->stack = kswordArkAllocateNonPagedPool(KSW_SVM_STACK_BYTES, 'pSvK');
    /* Leave acquired pointers in the release ledger. */
    if (!nested->operand || !nested->mergedMaps || !nested->stack) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Resolve the entire combined allocation before entering the exit loop. */
    nested->mergedMapsPa = (ULONGLONG)MmGetPhysicalAddress(nested->mergedMaps).QuadPart;
    /* Hardware requires page alignment even though guest permission bases ignore low bits. */
    if ((nested->mergedMapsPa & 4095ULL) ||
        !kswSvmNestedMapAddress(nested->mergedMapsPa, KSW_NSVM_MSRPM_BYTES, cpu->caps.physicalBits, &mapBase) ||
        !kswSvmNestedMapAddress(nested->mergedMapsPa + KSW_NSVM_MSRPM_BYTES,
            KSW_NSVM_IOPM_BYTES, cpu->caps.physicalBits, &mapBase)) { return STATUS_DATA_ERROR; }
    /* Resolve the operand identity only at PASSIVE_LEVEL. */
    nested->operandPa = (ULONGLONG)MmGetPhysicalAddress(nested->operand).QuadPart;
    /* Every shadow table must be independently aligned/physically contiguous. */
    for (page = 0; page < KSW_NSVM_PROBE_PAGES; ++page) {
        /* Keep each allocation in the ledger before deriving its address. */
        nested->pages[page].words = MmAllocateContiguousMemory(4096, highest);
        /* A partial pool cannot admit nested execution. */
        if (!nested->pages[page].words) { return STATUS_INSUFFICIENT_RESOURCES; }
        /* Pre-resolve every hardware pointer used by the exit handler. */
        nested->pages[page].physical = (ULONGLONG)MmGetPhysicalAddress(nested->pages[page].words).QuadPart;
    }
    /* The portable builder validates alignment, duplicate ownership and address width. */
    if (kswSvmNestedShadowInitialize(&nested->shadow, nested->pages, KSW_NSVM_PROBE_PAGES,
        cpu->caps.physicalBits) != KSW_NSHADOW_OK) { return STATUS_DATA_ERROR; }
    /* No SVM instruction has executed yet. */
    return STATUS_SUCCESS;
}
