/*++

Module Name:

    hvm_internal.h

Abstract:

    Defines the private HVM runtime shared by lifecycle, EPT, resident VMX,
    nested-VMX, eVMCS, and event modules.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_runtime.h"
/* KswHvmActiveControls is embedded in the runtime below. */
#include "hvm_vmcs.h"
/* Immutable translation identity shared by page admission and root readers. */
#include "hvm_nested_lease_walk.h"
#include "hvm_nested_leaf_plan.h"

/* Define the architectural page size used by VMX and EPT structures. */
#define KSW_HVM_PAGE_BYTES 0x1000ULL
/* Define the large EPT leaf size used by the baseline identity map. */
#define KSW_HVM_LARGE_PAGE_BYTES 0x200000ULL
/* Define the byte span covered by one EPT page-directory. */
#define KSW_HVM_ONE_GIB 0x40000000ULL
/* Define the byte span covered by one EPT PML4 entry. */
#define KSW_HVM_ONE_512_GIB 0x8000000000ULL
/*
 * Bound the identity map to a thirty-two-TiB guest-physical window.
 *
 * The number is not a preference, it is CPUID.80000008H:EAX[7:0] on real
 * hardware.  This used to be 16 (eight TiB), chosen when every machine in
 * reach reported 39 or 42 physical-address bits.  An Intel Core Ultra 270K
 * reports **45** - thirty-two TiB - and the builder clipped the map, set
 * EPT_TRUNCATED, and residency refused. The user was told "Processor does not support",
 * by a processor that supports every single thing this backend needs.
 * (Issue #195 is a separate matter; this one corresponds to issue #198.)
 *
 * Sixty-four entries covers MAXPHYADDR <= 45 exactly.  It is deliberately not
 * larger: a machine reporting 46 bits will now say precisely what it needs
 * (see KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL) instead of blaming
 * the processor, and raising this number for a machine nobody has measured is
 * how the previous value came to be wrong in the first place.
 */
#define KSW_HVM_MAX_PML4_ENTRIES 64UL
/*
 * Bound the page directories the identity map may own.
 *
 * A page directory is only needed where a one-GiB window must be described at
 * two-MiB granularity, which is exactly where installed RAM lives: RAM leaves
 * carry an MTRR-resolved cache type, and EPT rules/views/watches split a leaf
 * down to 4 KiB, which starts from a PDE.  Windows with no installed RAM are
 * MMIO or reserved, are uniformly UC, and are published as a single one-GiB
 * leaf in the PDPT - no page directory at all.
 *
 * Kept at 8192 (the value implied by the old sixteen-entry window) rather than
 * at KSW_HVM_MAX_PML4_ENTRIES * 512: a directory per GiB across the new window
 * would be 32768 pages, 128 MiB of nonpaged pool, allocated at prepare on
 * every machine.  Eight TiB of *installed RAM* is the real bound here, and no
 * machine that has that much is short of the 32 MiB this costs.
 *
 * Exhausting it is reported, not silently clipped - see the builder.
 */
#define KSW_HVM_MAX_EPT_PD_PAGES 8192UL
/* Bound the number of simultaneously split two-MiB EPT leaves. */
#define KSW_HVM_MAX_EPT_SPLITS 256UL

/*
 * Bound the EPT execution domains reachable through the EPTP list.
 *
 * The architectural list holds 512 entries, but every entry is an interface
 * published to unprivileged guest code - VMFUNC performs no CPL check - so
 * the useful bound is "as few as the feature needs", not "as many as fit".
 */
#define KSW_HVM_MAX_EPT_DOMAINS 8UL
/* Bound the private paging structures one domain may fork copy-on-write. */
#define KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES 16UL
/* Reserve ledger space for every domain root plus its private tables. */
#define KSW_HVM_MAX_DOMAIN_PAGES \
    (KSW_HVM_MAX_EPT_DOMAINS * (1UL + KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES))
/*
 * Reserve enough allocation-ledger entries for sparse tables and splits.
 *
 * The page-directory term is KSW_HVM_MAX_EPT_PD_PAGES, not
 * KSW_HVM_MAX_PML4_ENTRIES * 512: directories are allocated only where a GiB
 * needs two-MiB granularity, and the ledger must bound what is actually
 * allocated rather than what the address space could theoretically hold.
 */
#define KSW_HVM_MAX_EPT_PAGES \
    (1UL + KSW_HVM_MAX_PML4_ENTRIES + \
        KSW_HVM_MAX_EPT_PD_PAGES + \
        KSW_HVM_MAX_EPT_SPLITS + \
        KSW_HVM_MAX_DOMAIN_PAGES)
/* Bound every physical address accepted by the EPT backend. */
#define KSW_HVM_MAX_MAPPED_PHYSICAL \
    (KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES)
/* Bound one per-processor resident VM-exit stack. */
#define KSW_HVM_RESIDENT_HOST_STACK_BYTES 0x8000UL
/* Sample soak residency often enough to catch a short-lived collapse. */
#define KSW_HVM_SOAK_SLICE_MILLISECONDS 50UL

/* Name the VMX feature-control model-specific register. */
#define KSW_IA32_FEATURE_CONTROL 0x3AUL
/* Name the VMX basic capability model-specific register. */
#define KSW_IA32_VMX_BASIC 0x480UL
/* Name the VMX CR0 required-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED0 0x486UL
/* Name the VMX CR0 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED1 0x487UL
/* Name the VMX CR4 required-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED0 0x488UL
/* Name the VMX CR4 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED1 0x489UL
/* Name the secondary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
/* Name the legacy primary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS 0x482UL
/* Name the true primary processor-control capability register. */
#define KSW_IA32_VMX_TRUE_PROCBASED_CTLS 0x48EUL
/* Name the EPT and VPID capability model-specific register. */
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL
/* Name the VM-function capability model-specific register. */
#define KSW_IA32_VMX_VMFUNC 0x491UL
/* Name the Hyper-V VP-assist-page model-specific register. */
#define KSW_HV_X64_MSR_VP_ASSIST_PAGE 0x40000073UL

/* Identify the CR4 bit that enables VMX instructions. */
#define KSW_CR4_VMXE (1ULL << 13)

/* Define the EPT read permission bit. */
#define KSW_EPT_READ 0x1ULL
/* Define the EPT write permission bit. */
#define KSW_EPT_WRITE 0x2ULL
/* Define the EPT execute permission bit. */
#define KSW_EPT_EXECUTE 0x4ULL
/* Define the EPT memory-type field shift. */
#define KSW_EPT_MEMORY_TYPE_SHIFT 3UL
/* Define the EPT large-page marker. */
#define KSW_EPT_LARGE_PAGE (1ULL << 7)

/*
 * Suppress-#VE.  The architectural default is inverted: a leaf with this bit
 * CLEAR is convertible, so once "EPT-violation #VE" is enabled every such page
 * reflects its EPT violations into the guest.  The guest here is the running
 * Windows, whose IDT[20] is not prepared for a #VE we invented, and the result
 * is #GP -> #DF -> triple fault.
 *
 * Every leaf this driver installs therefore carries the bit, whether or not
 * #VE is enabled - when the control is off the processor ignores it, so the
 * safe default costs nothing.  Only intermediate entries omit it, because the
 * architecture ignores bit 63 on entries that point at another EPT structure.
 */
#define KSW_EPT_SUPPRESS_VE (1ULL << 63)
/* Define the physical-address portion of an EPT entry. */
#define KSW_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL

/*
 * Virtualization-exception information area.  When the processor converts an
 * EPT violation into a #VE it writes this structure, and it reads the busy
 * field FIRST to decide whether to convert at all: a non-zero busy field means
 * the guest has not consumed the previous exception, so the processor delivers
 * an ordinary EPT-violation VM exit instead of a second #VE.
 *
 * That is the second safety layer here.  The first is suppress-#VE on every
 * leaf; this one latches busy at allocation and never clears it, so even a
 * page that somehow became convertible degrades to the exit path this driver
 * already handles rather than to a fault Windows has no IDT[20] for.  A guest
 * that genuinely wants #VE has to clear busy itself, from inside its own
 * handler - which is exactly the handshake the architecture intends.
 */
#define KSW_VE_INFO_OFFSET_REASON 0UL
#define KSW_VE_INFO_OFFSET_BUSY 4UL
#define KSW_VE_INFO_OFFSET_QUALIFICATION 8UL
#define KSW_VE_INFO_OFFSET_GUEST_LINEAR 16UL
#define KSW_VE_INFO_OFFSET_GUEST_PHYSICAL 24UL
#define KSW_VE_INFO_OFFSET_EPTP_INDEX 32UL
/* Define the architectural "not consumed yet" value for the busy field. */
#define KSW_VE_INFO_BUSY 0xFFFFFFFFUL

/* Identify four-level EPT page-walk capability. */
#define KSW_EPT_CAP_PAGE_WALK_4 (1ULL << 6)
/* Identify EPT execute-only leaf translation capability. */
#define KSW_EPT_CAP_EXECUTE_ONLY (1ULL << 0)
/* Identify write-back EPT memory-type capability. */
#define KSW_EPT_CAP_WB (1ULL << 14)
/* Identify two-MiB EPT leaf capability. */
#define KSW_EPT_CAP_2MB (1ULL << 16)
/* Identify one-GiB EPT leaf capability. */
#define KSW_EPT_CAP_1GB (1ULL << 17)
/* Identify INVEPT instruction capability. */
#define KSW_EPT_CAP_INVEPT (1ULL << 20)
/* Identify EPT accessed-and-dirty capability. */
#define KSW_EPT_CAP_AD (1ULL << 21)
/* Identify single-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_SINGLE (1ULL << 25)
/* Identify all-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_ALL (1ULL << 26)
/* Identify VPID capability. */
#define KSW_EPT_CAP_VPID (1ULL << 32)

/* Bound the variable-MTRR snapshot to the architectural low-byte count. */
#define KSW_HVM_MAX_VARIABLE_MTRRS 32UL

/* Describe one processor-owned VMXON and VMCS allocation pair. */
typedef struct KswHvmCpuResource
{
    /* Preserve the protocol-visible processor state. */
    KSWORD_ARK_HVM_CPU_ROW row;
    /* Retain the processor-owned VMXON virtual address. */
    PVOID vmxonVirtual;
    /* Retain the processor-owned VMXON physical address. */
    PHYSICAL_ADDRESS vmxonPhysical;
    /* Retain the processor-owned VMCS virtual address. */
    PVOID vmcsVirtual;
    /* Retain the processor-owned VMCS physical address. */
    PHYSICAL_ADDRESS vmcsPhysical;
    /*
     * Retain the processor-owned vmcs02 - the hardware VMCS that runs L2.
     *
     * A second real VMCS, not a copy of vmcs12.  vmcs12 is L1's idea of a VMCS
     * and lives in L1's memory in whatever format L1 chose; this is the one the
     * processor actually loads, holding our host state, L1's guest state, and
     * controls merged from both.  Allocated per processor beside the others
     * because it has exactly the same lifetime and the same page requirements.
     */
    PVOID vmcs02Virtual;
    /* Retain the processor-owned vmcs02 physical address. */
    PHYSICAL_ADDRESS vmcs02Physical;
    /*
     * Retain the three bitmap pages vmcs02 points at while L2 runs.
     *
     * These exist because a control bit and its companion address are separate
     * VMCS fields, and vmcs02's controls are the union of L1's and ours.  Our
     * own USE_MSR_BITMAPS therefore survives into vmcs02 whether or not L1 set
     * it - and without an address to go with it the processor consults
     * whatever the field already held, which on a fresh vmcs02 is physical
     * page zero.  Measured on the 2 vCPU target: primary 0xB40065F2 with bit
     * 28 set and MSR_BITMAP 0x0.  Nothing else in any readout changes, because
     * VM entry succeeds and L2 runs; only which MSRs exit becomes whatever
     * bits happen to live in the BIOS area.
     *
     * The MSR page is a merge - L1's bitmap ORed with ours - because an MSR
     * has to exit if either side wants it.  The two I/O pages are copies of
     * L1's, since we request no I/O exiting of our own and so have nothing to
     * contribute to a union.
     */
    PVOID l2MsrBitmapVirtual;
    /* Retain the merged MSR-bitmap physical address for vmcs02. */
    PHYSICAL_ADDRESS l2MsrBitmapPhysical;
    /* Retain L2's I/O bitmap A (ports 0x0000-0x7FFF) virtual address. */
    PVOID l2IoBitmapAVirtual;
    /* Retain L2's I/O bitmap A physical address for vmcs02. */
    PHYSICAL_ADDRESS l2IoBitmapAPhysical;
    /* Retain L2's I/O bitmap B (ports 0x8000-0xFFFF) virtual address. */
    PVOID l2IoBitmapBVirtual;
    /* Retain L2's I/O bitmap B physical address for vmcs02. */
    PHYSICAL_ADDRESS l2IoBitmapBPhysical;
    /*
     * Retain an unmerged copy of L1's MSR bitmap.
     *
     * Kept separately because the merged page cannot answer the question the
     * exit path asks.  A set bit in the union means "somebody wanted this
     * MSR"; routing needs "did *L1* want it", and once ORed the two are
     * indistinguishable.  Never handed to hardware, so ordinary pool memory
     * is enough.
     */
    PVOID l2MsrBitmapL1Copy;
    /* Retain the processor-owned #VE information-area virtual address. */
    PVOID veInfoVirtual;
    /* Retain the processor-owned #VE information-area physical address. */
    PHYSICAL_ADDRESS veInfoPhysical;
    /*
     * How many exits this processor took, per Intel basic exit reason.
     *
     * The driver already reports a total exit count and the *last* reason, and
     * neither answers the question that actually comes up while diagnosing:
     * where do the exits go.  Reading "lastExitReason 18" a hundred times does
     * not distinguish VMCALL being 99% of the traffic from VMCALL being rare
     * and merely last.
     *
     * The event ring cannot answer it either.  One ring is shared by every
     * processor, so at exit rates in the tens of thousands per second its
     * writers collide and it discards - measured on 2 vCPU: 1024 slots,
     * 17071 dropped publications in a single run.  A ring that discards most of
     * what it is handed is evidence of nothing.  A ring records the last N
     * exits; this records the shape of all of them, which is what the ring was
     * being asked for and could not deliver.
     *
     * This array cannot drop.  It belongs to one processor, so it has exactly
     * one writer and needs no interlocked access, no slot ownership and no
     * failure path.
     *
     * Held here, on the resource, rather than on the resident VCPU context:
     * the VCPU contexts are released and zeroed when residency stops, which
     * would discard the histogram at exactly the moment someone goes looking
     * for it.  The resource outlives residency, so a soak's exit shape is still
     * readable after the soak ends.
     *
     * Indexed by basic exit reason, sized past every reason Intel currently
     * defines; a reason at or beyond the bound is counted nowhere rather than
     * folded into a neighbour.  ULONG, so a processor sustaining ten thousand
     * exits a second wraps after about five days - acceptable for a diagnostic
     * counter, and the protocol widens to 64 bits before summing.
     */
    /* Long nested runs can exceed 32-bit counts; match the protocol width. */
    ULONGLONG exitReasonCount[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
    /* Vendor-private resources; never interpreted as a VMX allocation. */
    PVOID backendContext;
    /* Populated on this CPU by the native VMCS self-test, never guessed. */
    ULONG nativeVmcsFields[64];
    ULONG nativeVmcsFieldCount;
} KswHvmCpuResource;

/* Track one contiguous page allocated for an EPT hierarchy. */
typedef struct KswHvmEptPage
{
    /* Retain the kernel virtual address used for cleanup. */
    PVOID virtualAddress;
    /* Retain the physical address encoded into a parent EPT entry. */
    PHYSICAL_ADDRESS physicalAddress;
} KswHvmEptPage;

/* Describe one variable MTRR range after mask decoding. */
typedef struct KswHvmMtrrRange
{
    /* Retain the inclusive physical base of the MTRR range. */
    ULONGLONG base;
    /* Retain the exclusive physical end of the MTRR range. */
    ULONGLONG end;
    /* Retain the Intel memory-type encoding. */
    UCHAR type;
    /* Record whether the architectural valid bit was present. */
    UCHAR valid;
    /* Keep the structure naturally aligned without undefined padding data. */
    USHORT reserved;
} KswHvmMtrrRange;

/* Preserve an immutable MTRR snapshot used while building EPT leaves. */
typedef struct KswHvmMtrrState
{
    /* Record whether MTRRs are globally enabled. */
    BOOLEAN enabled;
    /* Record whether fixed-range MTRRs are enabled. */
    BOOLEAN fixedEnabled;
    /* Retain the default Intel memory-type encoding. */
    UCHAR defaultType;
    /* Retain the number of valid variable-range records. */
    UCHAR variableCount;
    /* Retain all architecturally discoverable fixed-range type bytes. */
    UCHAR fixedTypes[88];
    /* Retain the decoded variable MTRR records. */
    KswHvmMtrrRange variable[KSW_HVM_MAX_VARIABLE_MTRRS];
} KswHvmMtrrState;

/*
 * Track one paging structure a domain forked from the shared hierarchy.
 *
 * Domains share the default view's tables until they need to differ, so the
 * common case costs one page: the domain's own PML4.  A restriction touching
 * one two-MiB leaf costs two more, the PDPT and PD on the path to it.
 */
typedef struct KswHvmDomainPrivateTable
{
    /* Retain the PML4 slot this table sits under. */
    ULONG pml4Index;
    /* Retain the PDPT slot, or MAXULONG when this table IS the PDPT. */
    ULONG pdptIndex;
    /* Retain the writable mapping used to edit and free the table. */
    PVOID virtual;
    /* Retain the physical address published into the parent entry. */
    PHYSICAL_ADDRESS physical;
} KswHvmDomainPrivateTable;

/* Describe one EPT execution domain reachable through the EPTP list. */
typedef struct KswHvmEptDomain
{
    /* Record whether the slot holds a live domain. */
    BOOLEAN active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[3];
    /* Retain the number of forked private tables. */
    ULONG privateTableCount;
    /* Retain this domain's own root table. */
    PVOID pml4Virtual;
    /* Retain the root physical address encoded into the EPT pointer. */
    PHYSICAL_ADDRESS pml4Physical;
    /* Retain the EPT pointer published into the EPTP list. */
    ULONGLONG eptPointer;
    /* Own every copy-on-write paging structure this domain forked. */
    KswHvmDomainPrivateTable
        privateTables[KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES];
} KswHvmEptDomain;

/* Describe one active protocol-visible EPT rule. */
typedef struct KswHvmEptRuleSlot
{
    /* Record whether the slot contains an active rule. */
    BOOLEAN active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[3];
    /* Retain the stable protocol-visible rule identifier. */
    ULONG ruleId;
    /* Retain the permissions removed from each target page. */
    ULONG deniedAccess;
    /* Retain the rule behavior flags. */
    ULONG flags;
    /* Retain the first page-aligned guest physical address. */
    ULONGLONG physicalAddress;
    /* Retain the number of covered four-KiB pages. */
    ULONGLONG pageCount;
    /*
     * —— Fields below are only meaningful for rules with WATCH_ONCE —
     *
     * Watch shares this table with the other three handling modes because they share the same mechanism: 4
     * KiB leaf entries, the same permission recalculation function, and the same EPT violation path. Building
     * a parallel page-rule subsystem would mean two code paths writing to the same leaf entry — the last one
     * wins, and the winner would silently overwrite the other's functionality without the other's knowledge.
     *
     * WatchState is a volatile LONG, not a BOOLEAN: multi-core first-hit resolution relies on
     * InterlockedCompareExchange to determine a unique owner, which requires an aligned 32-bit lockable quantity.
     * Using a boolean bit for the same purpose would cause two CPUs to both believe they are the first.
     */
    volatile LONG watchState;
    /* Access type selected by the user, not architecture-normalized, for reporting only. */
    ULONG watchRequestedAccess;
    /*
     * The access type actually installed in EPT.
     *
     * After a hit, DeniedAccess is cleared (this is the notation for 'no longer intercepting'), so both the
     * recalculation function and violation scan rely on it. Therefore, the original mask must be saved separately;
     * otherwise, after a hit, the interface can no longer answer 'what this watch was originally monitoring'.
     */
    ULONG watchEffectiveAccess;
    /* See KSWORD_ARK_HVM_WATCH_ADDRESS_* in the protocol. */
    ULONG watchAddressKind;
    /* Cumulative hit count; continues accumulating after REARM. */
    ULONG watchHitCount;
    /* See KSWORD_ARK_HVM_EPT_WATCH_HIT_* in the protocol. */
    ULONG watchLastHitStatus;
    /* Generation when this watch was armed, used to determine if this watch has crossed a gap. */
    ULONG watchArmedGeneration;
    /* The address and length requested by the user, preserved as-is. */
    ULONGLONG watchRequestedAddress;
    ULONGLONG watchRequestedLength;
    /* Context of the most recent hit, filled in during VM-exit. */
    ULONGLONG watchLastHitSequence;
    ULONGLONG watchLastHitRip;
    ULONGLONG watchLastHitGuestLinearAddress;
    ULONGLONG watchLastHitGuestPhysicalAddress;
    ULONGLONG watchLastHitCr3;
    ULONGLONG watchLastHitRsp;
    ULONGLONG watchLastHitTimestamp;
    USHORT watchLastHitProcessorGroup;
    UCHAR watchLastHitProcessorNumber;
    UCHAR watchLastHitGuestLinearValid;
    ULONG watchLastHitRangeMatch;
} KswHvmEptRuleSlot;

/* Track one two-MiB EPT leaf that was split into four-KiB entries. */
typedef struct KswHvmEptSplit
{
    /* Record whether the split ledger slot is active. */
    BOOLEAN active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[7];
    /* Retain the aligned guest physical base represented by the page table. */
    ULONGLONG physicalBase;
    /* Retain the writable virtual address of the page table. */
    PVOID pageTable;
    /* Retain the page-table physical address encoded into the parent PDE. */
    PHYSICAL_ADDRESS pageTablePhysical;
    /* Retain the writable parent PDE address for merge and invalidation. */
    volatile ULONGLONG* parentEntry;
    /* Retain the original two-MiB identity leaf. */
    ULONGLONG originalEntry;
} KswHvmEptSplit;

/*
 * Describe one installed EPT split view.  The leaf alternates between two
 * values: the primary one the view keeps installed, and the secondary one that
 * services the access the primary deliberately forbids.  Restoration reuses the
 * allow-once transient machinery, so a view flip is a monitor-trap step.
 */
typedef struct KswHvmEptViewSlot
{
    /* Record whether the slot holds an installed view. */
    BOOLEAN active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[3];
    /* Retain the stable protocol-visible view identifier. */
    ULONG viewId;
    /* Retain the kind that decides which access is served by the shadow. */
    ULONG kind;
    /* Retain the view behavior flags. */
    ULONG flags;
    /* Retain the page-aligned guest physical address the view covers. */
    ULONGLONG physicalAddress;
    /* Own the shadow page that backs the redirected access. */
    PVOID shadowVirtual;
    /* Retain the shadow physical address encoded into the secondary value. */
    PHYSICAL_ADDRESS shadowPhysical;
    /* Reference the writable four-KiB leaf entry this view flips. */
    volatile ULONGLONG* entry;
    /* Preserve the leaf value that existed before installation. */
    ULONGLONG originalEntry;
    /* Preserve the steady-state value the view keeps installed. */
    ULONGLONG primaryEntry;
    /* Preserve the value used while the redirected access is serviced. */
    ULONGLONG secondaryEntry;
    /* Count how often the leaf flipped to the secondary value. */
    volatile LONG64 flipCount;
    /*
     * Which secondary EPT hierarchy backs this view, or 0 when none does.
     *
     * Zero is the base index, which is exactly the right encoding for "this
     * view is served by the write-leaf + monitor-trap backend": that backend
     * never leaves the base hierarchy, so "no hierarchy of its own" and "runs
     * on the base" are the same statement rather than two that could disagree.
     */
    ULONG eptSwitchIndex;
    /* Keep the structure's tail explicitly initialized. */
    ULONG reserved1;
} KswHvmEptViewSlot;

/* A complete driver-side state for an R-1 process disposition. */
typedef struct KswHvmProcessSlot
{
    /* Non-zero indicates this slot is in use. */
    BOOLEAN inUse;
    /* Maintain natural alignment for subsequent members. */
    UCHAR reserved0[3];
    /* PID at dispatch time, used only for reporting; the criterion is DirectoryBase. */
    ULONG processId;
    /* OP_FREEZE or OP_TERMINATE. */
    ULONG disposition;
    /*
     * Restricted hierarchy index occupied by this entry (1..LeafCapacity); 0 is the base and will never appear here.
     *
     * The leaf of the hierarchy writes the target page as non-executable while sharing the rest
     * with the base; thus, this hierarchy differs only in that 'one page is non-executable'.
     */
    ULONG hierarchyIndex;
    /* Target address space; the lower bits of PCID and flags are masked. */
    ULONGLONG directoryBase;
    /* Guest physical address of a page that was denied execution, already page-aligned. */
    ULONGLONG guestPhysicalAddress;
    /* Guest linear address provided during dispatch to trace how this page was selected. */
    ULONGLONG guestLinearAddress;
    /* Number of times this interception occurred. If frozen, it will continue to grow, which is evidence of a spin loop. */
    volatile LONG64 interceptCount;
} KswHvmProcessSlot;

/*
 * Root-to-leaf pages one secondary EPT hierarchy copies.
 *
 * Written as a literal here rather than pulled from the shared arithmetic
 * header, which is nearly two thousand lines of static __inline helpers that
 * every translation unit including this file would then carry.  The literal
 * is not a second source of truth: hvm_ept_switch.c asserts at compile time
 * that it equals KSWORD_ARK_HVM_EPTSW_PATH_PAGES, so a change on either side
 * breaks the build instead of silently disagreeing.
 */
#define KSW_HVM_EPTSW_PATH_PAGES 4UL

/* Own one secondary EPT hierarchy: the copied path plus its bookkeeping. */
typedef struct KswHvmEptswHierarchy
{
    /* Record whether this record describes a built hierarchy. */
    BOOLEAN active;
    /* Keep the 64-bit members naturally aligned. */
    UCHAR reserved0[7];
    /*
     * Retain the EPT pointer this hierarchy is loaded with.  Derived from the
     * base pointer by replacing only the root address, never composed from
     * constants: composing would give the memory type, the walk length and
     * the accessed/dirty bit a second source of truth, and a derived pointer
     * is accepted by VM entry exactly when the base one is.
     */
    ULONGLONG eptPointer;
    /* Retain the guest-physical page this hierarchy relaxes. */
    ULONGLONG leafPhysical;
    /* Retain the value that leaf carries inside this hierarchy. */
    ULONGLONG secondaryEntry;
    /* Retain the base value, so a return to base can be verified. */
    ULONGLONG primaryEntry;
    /* Retain the copied pages, indexed by level (0 = PML4 ... 3 = PT). */
    PVOID level[KSW_HVM_EPTSW_PATH_PAGES];
} KswHvmEptswHierarchy;

/*
 * Own every secondary hierarchy this runtime may switch to.
 *
 * Index 0 is the base - every leaf at its primary value, byte for byte the
 * steady state that exists today - and index k means leaf k-1, and only leaf
 * k-1, is relaxed.  "Is any leaf relaxed" is therefore exactly "is the index
 * non-zero", with deliberately no second boolean to keep in step.
 */
typedef struct KswHvmEptsw
{
    /* Record whether the page pool exists and the ledger is consistent. */
    BOOLEAN active;
    /* Keep the 32-bit members naturally aligned. */
    UCHAR reserved0[3];
    /* Ledger length: the base plus one per leaf, i.e. LeafCapacity + 1. */
    ULONG hierarchyCount;
    /* Bound the flippable leaves this runtime admits. */
    ULONG leafCapacity;
    /* Count the hierarchies actually built, never above LeafCapacity. */
    ULONG builtCount;
    /*
     * Record i owns pool pages [i*PATH_PAGES, (i+1)*PATH_PAGES) - a fixed
     * slice, not a bump allocation.  A cursor would make releasing one
     * hierarchy either leak its pages or fragment the pool, and a view can be
     * removed and re-added in any order.  Fixed slices make release exact and
     * reuse free, at the cost of reserving the whole pool up front - which is
     * 512 KiB total and independent of the processor count.
     */
    ULONG reserved2;
    /*
     * One allocation backs every hierarchy.  A per-table allocator would make
     * a fragmented machine fail a start half-way through, and would put a
     * PASSIVE_LEVEL-only free on a teardown path a power callback can reach.
     */
    PUCHAR pageBlock;
    /* Count the pages in the pool: LeafCapacity * KSW_HVM_EPTSW_PATH_PAGES. */
    ULONG pageCount;
    /* Keep the trailing pointer array naturally aligned. */
    ULONG reserved1;
    /* One record per leaf; array index k-1 is hierarchy index k. */
    KswHvmEptswHierarchy hierarchies[KSWORD_ARK_HVM_MAX_VIEWS];
    /*
     * Flat pointer ledger indexed by hierarchy index: slot 0 is the base and
     * slot k is leaf k-1's hierarchy, zero while unbuilt.
     *
     * Kept alongside the records rather than derived from them on each exit
     * because the switch planner takes a contiguous table and its own length,
     * and refuses a length that is not exactly "base plus one per leaf".  A
     * short table would be indexed past its end and would read whatever sits
     * after it - quite possibly a stale pointer that still looks valid, which
     * the processor would then be loaded with.
     */
    ULONGLONG eptp[KSWORD_ARK_HVM_MAX_VIEWS + 1UL];
} KswHvmEptsw;

/* Describe one installed MSR policy and the bitmap hole it owns. */
typedef struct KswHvmMsrPolicySlot
{
    /* Record whether the slot holds an installed policy. */
    BOOLEAN active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[3];
    /* Retain the stable protocol-visible policy identifier. */
    ULONG policyId;
    /* Retain the intercepted architectural MSR index. */
    ULONG msrIndex;
    /* Retain which of read and write this policy intercepts. */
    ULONG access;
    /* Retain the action applied to an intercepted access. */
    ULONG action;
    /* Keep the following value naturally aligned. */
    ULONG reserved1;
    /* Retain the value returned by a faked read. */
    ULONGLONG fakeValue;
    /* Count how often the dispatcher applied this policy. */
    volatile LONG64 hitCount;
} KswHvmMsrPolicySlot;

/* Own the serialized HVM capability, lifecycle, EPT, and telemetry state. */
/* Immutable while published; counters are written atomically from VMX root. */
typedef struct KswHvmNestedPage {
    PVOID shadowVirtual;
    ULONGLONG ept12Pointer, guestPhysicalPage, shadowPhysicalPage;
    volatile LONG64 originalPhysicalPage, composedCount;
    /* A referenced process object binds the rule beyond numeric PID reuse. */
    PEPROCESS ownerProcess;
    /* Preserve the identity checked when the mapping was admitted. */
    ULONGLONG ownerCreationTime;
    /* Publication never automatically rebinds this path to a recycled GPA. */
    KswHvmPageTranslation translation;
    /*
     * Region this override owns, appended rather than inserted.
     *
     * Appended deliberately: this structure is read from VMX root by the
     * composition path, and inserting a field mid-structure produces two
     * different layouts across an incremental build, which shows up as a
     * bugcheck rather than a compile error.
     *
     * Plan.LeafShift is 12 for the original single-page behaviour, so every
     * field below is meaningful for a 4-KiB override too and the composition
     * path needs no special case for it.
     */
    KswHvmLeafPlan plan;
    /* Bytes actually allocated for the replacement; freed as one block. */
    ULONGLONG backingBytes;
    /* Count of staged page writes applied since publication, for evidence. */
    volatile LONG64 stagedPageCount;
    /*
     * What the admitting scan proved, kept so it can be rechecked.
     *
     * Admission by scanning reads every source leaf under the region once. That
     * is a statement about one instant, and the intermediate VMM keeps changing
     * its per-page permissions while the guest runs - measured: a region that
     * scanned uniform disagreed on a later run, and one that disagreed scanned
     * uniform. Without these the region would keep serving on a condition
     * nobody ever looked at again.
     */
    ULONGLONG scanSharedBits;
    /* Next page of the region for the sampler to recheck; wraps. */
    volatile LONG scanCursor;
    /* Set only for regions the scanning rule admitted. */
    BOOLEAN scanAdmitted;
} KswHvmNestedPage;

typedef struct KswHvmRuntime
{
    /* Serialize PASSIVE_LEVEL lifecycle and protocol operations. */
    EX_PUSH_LOCK lock;
    /* Publish whether runtime initialization completed. */
    BOOLEAN initialized;
    /* Publish whether one serialized control operation is executing. */
    BOOLEAN busy;
    /* Keep explicit padding initialized for stable crash-dump inspection. */
    USHORT reserved0;
    /*
     * Publish protocol-visible lifecycle flags.
     *
     * Mutate this ONLY through kswordArkHvmStateSet / kswordArkHvmStateClear
     * below.  Two writers reach it and they cannot share a lock: every
     * lifecycle path holds the runtime push lock, while the power callback
     * deliberately does not take it - blocking there would let a VMX window
     * cross the S0 boundary, which is the one thing that callback exists to
     * prevent, and it bugchecks rather than wait (see its DEVICE_BUSY branch).
     * So the synchronization has to live in the word itself.  A single plain
     * read-modify-write anywhere can drop the FAULTED and ROLLBACK_REQUIRED
     * the callback just set, and those are fail-closed markers.
     */
    volatile LONG stateFlags;
    /* Publish the generation used for compare-before control requests. */
    ULONG generation;
    /* Publish the stable query status. */
    ULONG queryStatus;
    /* Preserve the last authoritative NTSTATUS. */
    NTSTATUS lastStatus;
    /* Preserve the number of enumerated processors. */
    ULONG processorCount;
    /* Preserve the number of allocated processor resource pairs. */
    ULONG preparedProcessorCount;
    /* Preserve the number of successful VMXON/VMXOFF tests. */
    ULONG selfTestPassedProcessorCount;
    /* Publish the number of processors currently in VMX non-root mode. */
    volatile LONG residentProcessorCount;
    /* Publish resident-lifecycle implementation maturity. */
    ULONG residentImplementation;
    /* Publish EPT-rule implementation maturity. */
    ULONG eptImplementation;
    /* Publish nested-VMX implementation maturity. */
    ULONG nestedImplementation;
    /* Publish eVMCS implementation maturity. */
    ULONG evmcsImplementation;
    /* Publish the current nested-VMX state. */
    ULONG nestedState;
    /*
     * Count refused L2 launches.  NestedState alone cannot carry this: it is
     * reset to DISPATCH_READY on the next VMXOFF, so the evidence that another
     * hypervisor tried to start a VM under us disappears before any poll can
     * see it.  Monotonic, never reset while the driver is loaded.
     */
    volatile LONG nestedL2LaunchRefusedCount;
    /*
     * Which of the entry path's refusals produced the most recent one, 1..7.
     *
     * The count beside it says a launch was refused; every one of those seven
     * conditions reports the same architectural error to L1, so without this
     * the count is the whole story and it does not name anything actionable.
     */
    volatile LONG nestedLastRefusalSite;
    /*
     * Count vmcs12 dropped because the per-processor pool was full.
     *
     * The only honest readout for "this L1 keeps more VMCSs than we hold".  An
     * evicted vmcs12 comes back zeroed at its next VMPTRLD, which looks to L1
     * exactly like the single-vmcs12 defect the pool exists to fix - so when a
     * hypervisor misbehaves under us this is the first number to read.
     *
     * Kept here rather than per processor for the same reason as the count
     * above: the per-processor pools are released at devirtualization, and a
     * counter that dies with the thing it measures answers "is it happening
     * right now" when the question is "did it ever happen".
     *
     * The nested probe's depth test overflows the pool deliberately and takes
     * its own evictions back out of this total when it finishes.  Without that
     * this would raise its alarm on a healthy machine every time the probe
     * ran, which is the fastest way to make a real warning unbelievable.
     */
    volatile LONG nestedVmcs12EvictionCount;
    /*
     * Times the no-progress fuse stopped an L2, machine-wide and durable.
     *
     * Same reason as the two counts above: the per-processor record dies with
     * the residency, and the thing worth knowing afterwards is that it ever
     * happened.  A real L1 does not run our probe, so without this a tripped
     * fuse is invisible in exactly the situation it exists for.
     */
    volatile LONG nestedFuseTripCount;
    /*
     * How many bits our own MSR bitmap holds.
     *
     * The nested merge points vmcs02 straight at L1's bitmap page when our
     * half adds nothing, which is worth 15-20% of an L2 entry.  That decision
     * needs to test the bitmap, not a proxy for it: it used to ask whether any
     * MSR policy existed, which stopped meaning "our page is empty" the moment
     * the VMX capability interception started setting bits of its own.
     */
    ULONG msrBitmapInterceptCount;
    /* Publish the current eVMCS state. */
    ULONG evmcsState;
    /* Publish the TLFS eVMCS version discovered from CPUID. */
    USHORT evmcsVersion;
    /* Keep explicit padding initialized for deterministic snapshots. */
    USHORT reserved1;
    /* Publish TLFS partition and VP-assist ownership evidence. */
    ULONG evmcsFlags;
    /* Preserve the current VP-assist-page MSR value when readable. */
    ULONGLONG evmcsVpAssistMsr;
    /* Preserve the number of active EPT rules. */
    ULONG eptRuleCount;
    /* Preserve the number of allocated EPT table pages. */
    ULONG eptPageCount;
    /* Preserve the number of populated EPT PML4 entries. */
    ULONG eptPml4Entries;
    /* Preserve the number of populated EPT PDPT entries. */
    ULONG eptPdptEntries;
    /*
     * Preserve the number of populated two-MiB EPT leaves.
     *
     * This is **not** the whole identity window: one-GiB windows with no
     * installed RAM are published as single PDPT leaves and counted in
     * EptPdptEntries instead.  The authoritative coverage is
     * HighestMappedPhysicalAddress; summing leaves will not reach it.
     */
    ULONG eptLargePageEntries;
    /* Preserve decoded protocol capability flags. */
    ULONGLONG featureFlags;
    /* Preserve IA32_VMX_BASIC evidence. */
    ULONGLONG vmxBasic;
    /*
     * IA32_VMX_MISC.  Cached because the HLT exit path needs bit 6 - whether
     * the halt activity state is supported - and reading the MSR there would
     * mean an MSR access per idle tick, which the hypervisor beneath us is
     * free to intercept.
     */
    ULONGLONG vmxMisc;
    /*
     * Page-directory base the VM-exit handler runs on, captured from the
     * System process.
     *
     * HOST_CR3 cannot be the CR3 that happens to be live while the VMCS is
     * configured: residency is armed through KeIpiGenericCall from the thread
     * that issued the IOCTL, so that CR3 belongs to the requesting user-mode
     * process.  Once residency outlives that process - which it now does, since
     * HLT no longer devirtualizes - its top-level page table is freed and
     * zeroed, and the next VM exit loads a CR3 that cannot translate HOST_RIP.
     * The resulting #PF cannot read the IDT either, so it escalates to #DF and
     * then to a triple fault: the virtual machine simply resets, with no
     * bugcheck and no dump.  That fingerprint is indistinguishable from the
     * silent hang this whole investigation started from.
     *
     * The System process never exits while the driver is loaded, so its
     * top-level page table is the only base that stays valid for the entire
     * life of residency.
     */
    ULONGLONG hostCr3;
    /* Preserve IA32_VMX_EPT_VPID_CAP evidence. */
    ULONGLONG vmxEptVpidCapabilities;
    /*
     * What was actually written into the VMCS execution-control fields, and the
     * capability MSR each one was adjusted against.
     *
     * Recorded because "which exits does this machine take" and "which of them
     * did we ask for" are different questions, and until now the second one
     * could only be answered by reading the source and reasoning about it.
     * The exit histogram made the gap concrete: HLT is the single largest exit
     * reason on the nested target, while resident mode requests no HLT exiting
     * at all - so either the outer hypervisor forces the bit through the
     * allowed-0 half of the capability MSR, or the control is being computed
     * wrongly, and reasoning cannot tell those apart.
     *
     * Kept as the adjusted result rather than the request: the request is a
     * compile-time constant anyone can read, whereas the value the processor
     * actually enforces is the one that explains the exits.  A bit set here
     * that the request did not ask for is, by construction, one the capability
     * MSR made mandatory.
     *
     * Written once per residency start, from the processor that configures the
     * VMCS; every processor computes the same values from the same MSRs.
     */
    KswHvmActiveControls activeControls;
    /*
     * Nonzero while the exit path should execute a batch of throwaway VMREADs
     * on every exit.
     *
     * Measurement only.  Published on the runtime rather than kept in the
     * resident module's own flags because the exit dispatcher cannot see those,
     * and reading it costs one load on a path that is about to do far more work
     * than that by construction.
     */
    volatile LONG vmreadBenchArmed;
    /*
     * Number of iterations per exit when armed. Provided by request, already clamped within the upper limit.
     *
     * Separate from VmreadBenchArmed into two fields instead of using "0 to disable": disabling
     * and iteration count are distinct concepts; combining them into a single value cannot express
     * "armed but the request provides 0 (use default)", which is the most common call pattern.
     */
    volatile LONG vmreadBenchIterations;
    /*
     * When non-zero, log every normal exit to the event ring; default is zero, recording only the four types of evidence events.
     *
     * Like the two fields above, this is placed on the runtime: the exit dispatcher cannot see
     * the flags of resident modules, and this one must be read at **every** exit dispatch point.
     */
    volatile LONG traceRoutineExits;
    /*
     * Non-zero hides the hypervisor identity from the guest user-mode CPUID; defaults to zero.
     *
     * Like the previous fields, this is attached to runtime for the same reason: the exit dispatcher can read it, and this bit must be read
     * on **every** CPUID exit. Each time a resident instance is reset, it must not inherit state—there is no requirement for the hidden
     * state from the previous round to persist. Otherwise, the statement 'behavior remains unchanged when hidden is off' would be invalid.
     */
    volatile LONG hideHypervisorCpuid;
    /* Diagnostic reference mode changes field-read cost, not emulated CPU state. */
    volatile LONG fullExitSnapshot;
    /* Preserve IA32_VMX_VMFUNC evidence; bit 0 is EPTP switching. */
    ULONGLONG vmFunctionCapabilities;
    /* Retain the 512-entry EPTP list published to VMFUNC. */
    PVOID eptpListVirtual;
    /* Retain the EPTP list physical address written into the VMCS. */
    PHYSICAL_ADDRESS eptpListPhysical;
    /* Own every EPT execution domain; slot zero is the default view. */
    KswHvmEptDomain eptDomains[KSW_HVM_MAX_EPT_DOMAINS];
    /* Preserve IA32_FEATURE_CONTROL evidence. */
    ULONGLONG featureControl;
    /* Preserve IA32_VMX_CR0_FIXED0 evidence. */
    ULONGLONG cr0Fixed0;
    /* Preserve IA32_VMX_CR0_FIXED1 evidence. */
    ULONGLONG cr0Fixed1;
    /* Preserve IA32_VMX_CR4_FIXED0 evidence. */
    ULONGLONG cr4Fixed0;
    /* Preserve IA32_VMX_CR4_FIXED1 evidence. */
    ULONGLONG cr4Fixed1;
    /* Preserve the active EPT pointer. */
    ULONGLONG eptPointer;
    /* Preserve the number of identity-mapped RAM bytes. */
    ULONGLONG mappedRamBytes;
    /* Preserve the exclusive upper physical mapping boundary. */
    ULONGLONG highestMappedPhysicalAddress;
    /* Preserve a monotonic VM-exit count. */
    volatile LONG64 vmExitCount;
    /* Preserve the last VM-exit qualification. */
    volatile LONG64 lastExitQualification;
    /* Preserve the last guest instruction pointer. */
    volatile LONG64 lastGuestRip;
    /* Preserve the last guest stack pointer. */
    volatile LONG64 lastGuestRsp;
    /* Preserve the last basic VM-exit reason. */
    volatile LONG lastExitReason;
    /* Preserve the last VM-exit instruction length. */
    volatile LONG lastExitInstructionLength;
    /* Preserve the last VM-instruction error. */
    volatile LONG lastVmInstructionError;
    /*
     * The interrupt-controller mask L2 currently has in force.
     *
     * Shared rather than per-processor, and that is the entire point: the PIC
     * is one device, while L1's virtual processor thread migrates between
     * physical ones.  Recording the mask per-processor produced two records
     * that disagreed - one said the timer was masked, the other said it was
     * open - with no way to tell which write came last, because each half had
     * only seen the writes that happened to land on its own processor.
     *
     * One location, last writer wins, which is exactly what a device register
     * is.  Bit 8 marks it written so a mask of zero is not read as absence.
     */
    volatile LONG l2PicMaskMaster;
    volatile LONG l2PicMaskSlave;
    /* Preserve the group of the last one-shot launch. */
    USHORT lastLaunchProcessorGroup;
    /* Preserve the group-relative CPU of the last one-shot launch. */
    UCHAR lastLaunchProcessorNumber;
    /* Preserve whether the last one-shot launch was nested. */
    UCHAR lastLaunchWasNested;
    /* Preserve the processor vendor string. */
    CHAR cpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    /* Preserve the hypervisor vendor string. */
    CHAR hypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    /* Own every per-processor VMX resource pair. */
    KswHvmCpuResource processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Track every EPT allocation exactly once. */
    KswHvmEptPage eptPages[KSW_HVM_MAX_EPT_PAGES];
    /* Own the shared MSR-bitmap page that keeps resident MSR access native. */
    PVOID msrBitmapVirtual;
    /* Retain the MSR-bitmap physical address written into every VMCS. */
    PHYSICAL_ADDRESS msrBitmapPhysical;
    /* Retain the EPT PML4 virtual address. */
    PVOID eptPml4;
    /* Retain each sparse EPT PDPT virtual address. */
    PVOID eptPdpt[KSW_HVM_MAX_PML4_ENTRIES];
    /* Retain each sparse EPT page-directory virtual address. */
    PVOID eptPd[KSW_HVM_MAX_PML4_ENTRIES][512];
    /* Retain the immutable MTRR snapshot used to type EPT leaves. */
    KswHvmMtrrState mtrr;
    /* Retain every protocol-visible EPT rule. */
    KswHvmEptRuleSlot eptRules[KSWORD_ARK_HVM_MAX_EPT_RULES];
    /* Retain every split two-MiB EPT leaf. */
    KswHvmEptSplit eptSplits[KSW_HVM_MAX_EPT_SPLITS];
    /* Retain every installed EPT split view. */
    KswHvmEptViewSlot eptViews[KSWORD_ARK_HVM_MAX_VIEWS];
    /*
     * Secondary EPT hierarchies for the EPTP-switching split-view backend.
     *
     * Reserved at prepare only when EptpSwitchArmed is TRUE, and zeroed
     * otherwise, so an unarmed runtime carries the storage but never a page.
     */
    KswHvmEptsw eptSwitch;
    KswHvmNestedPage* volatile nestedPage;
    /* Failed unpublication retains its backing until invalidation is retried. */
    KswHvmNestedPage* nestedPageRetired;
    /* Owner publication is serialized with the exit notification by the lease lock. */
    PEPROCESS nestedPageOwner;
    /* VMX root reads only this resident flag, never an OS process API. */
    volatile LONG nestedPageOwnerExited;
    /* First revocation reason wins and cannot be cleared while backing is live. */
    volatile LONG nestedPageRevocationReason;
    ULONG nestedPageGeneration;
    /* Each R-1 process disposition. Modify the table only while the resident hypervisor is stopped; the exit path reads it without a lock. */
    KswHvmProcessSlot processDispositions[KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS];
    /* Number of entries currently in the table. */
    ULONG processDispositionCount;
    /* Preserve the number of installed EPT split views. */
    ULONG eptViewCount;
    /* Preserve the next view identifier handed out by the view backend. */
    ULONG eptViewNextId;
    /* Retain every installed MSR policy. */
    KswHvmMsrPolicySlot msrPolicies[KSWORD_ARK_HVM_MAX_MSR_POLICIES];
    /* Preserve the number of installed MSR policies. */
    ULONG msrPolicyCount;
    /* Preserve the next policy identifier handed out by the MSR backend. */
    ULONG msrPolicyNextId;
    /* Publish the control-register policy flags currently configured. */
    ULONG crPolicyFlags;
    /* Retain the CR0 bits the guest must not change. */
    ULONGLONG crPolicyCr0PinnedMask;
    /* Retain the CR4 bits the guest must not change. */
    ULONGLONG crPolicyCr4PinnedMask;
    /* Preserve the CR0 value captured when the policy was installed. */
    ULONGLONG crPolicyCr0PinnedValue;
    /* Preserve the CR4 value captured when the policy was installed. */
    ULONGLONG crPolicyCr4PinnedValue;
    /* Count refused guest writes to pinned control-register bits. */
    volatile LONG64 crPolicyRefusedWriteCount;
    /* Count observed address-space switches. */
    volatile LONG64 crPolicyCr3SwitchCount;
    /* Count intercepted debug-register accesses. */
    volatile LONG64 crPolicyDebugAccessCount;
    /* Protect only the resident-transition phase and idle-event state. */
    KSPIN_LOCK residentTransitionStateLock;
    /* Wake wait-capable transition contenders after the current owner exits. */
    KEVENT residentTransitionIdleEvent;
    /* Publish whether one VMX transition phase currently owns the runtime. */
    volatile LONG residentTransitionActive;
    /* Reference this image's driver object for the unload interlock. */
    PDRIVER_OBJECT driverObject;
    /* Preserve the exact KMDF-installed unload entry while residency is active. */
    PDRIVER_UNLOAD originalDriverUnload;
    /* Reference the system-defined power-state callback object. */
    PCALLBACK_OBJECT powerStateCallbackObject;
    /* Own the power-state callback registration. */
    PVOID powerStateCallbackRegistration;
    /* Own the processor-add veto callback registration. */
    PVOID processorChangeRegistration;
    /* Publish host-stack construction so a power callback never frees it. */
    volatile LONG residentContextPreparing;
    /* Publish 0=idle, 1=leaving S0, 2=resumed while context prep drains. */
    volatile LONG powerTransitionPending;
    /* Increment once whenever the power manager begins leaving S0. */
    volatile LONG powerTransitionGeneration;
    /* Publish whether DriverUnload is currently removed from DriverObject. */
    volatile LONG unloadGuardArmed;
    /*
     * Ask every still-resident processor to leave VMX after one of them failed
     * closed.
     *
     * kswordArkHvmResidentDeactivateCurrent devirtualizes **one current**
     * processor, and the IPI rendezvous that could reach the others cannot be
     * issued from a VM-exit handler: that code runs in VMX root at an
     * indeterminate IRQL.  So a fail-closed exit used to leave the box half
     * devirtualized - one processor back on bare metal while the others kept
     * running in VMX non-root on a hierarchy whose leaves the fault had just
     * been about.  On one processor "devirtualize the current one" and "stop
     * everything" are indistinguishable, which is why this survived until the
     * target was given a second virtual processor.
     *
     * Measured 2026-09-07 (2 vCPU, probe-xonly): one strict EPT rule hit,
     * residentProcessorCount went 2 -> 1 and stayed there.
     *
     * Deliberately NOT the per-VCPU stopRequested flag.  That one is consumed
     * by the private stop hypercall (hvm_exit.c:641-652) and its exit advances
     * RIP past the VMCALL; honouring it at the top of the dispatcher would make
     * that same VMCALL re-execute natively and #UD.  The two mechanisms need
     * different instruction-length semantics, so they get different flags.
     *
     * Set by the failing processor before it leaves VMX, consumed by every
     * other processor at the top of its next VM exit, cleared when residency
     * starts.  Exits are frequent enough that convergence is immediate in
     * practice (a short resident window measured 91082 of them).
     */
    volatile LONG residentFaultStopRequested;
    /* Fail-closed resident lifecycle gate, enabled only after all guards bind. */
    BOOLEAN residentStartAllowed;
    /*
     * Record whether this runtime may hand out per-processor EPT hierarchies.
     * Capability-derived, so it is evidence and must be destroyed alongside
     * the other pre-suspend evidence on an S0 transition.
     */
    BOOLEAN localEptArmed;
    /*
     * Record whether this runtime uses the EPTP-switching split-view backend
     * instead of the write-leaf + monitor-trap one.  Capability-derived like
     * LocalEptArmed, so it is evidence and must be destroyed alongside the
     * other pre-suspend evidence on an S0 transition.
     *
     * FALSE is the existing behaviour in full: every run-time path keeps
     * asking the MTF backend, and the only cost of the feature being off is
     * this one BOOLEAN load.
     */
    BOOLEAN eptpSwitchArmed;
    /*
     * Record whether the hypervisor underneath us identifies itself with the
     * TLFS Hv#1 interface signature (CPUID 0x40000001 EAX == 'Hv#1').
     *
     * HYPERVISOR_PRESENT alone is the generic CPUID.1:ECX[31] bit and says
     * nothing about whose ABI is in force, but the hypercall forwarding stub
     * hard-codes the Hv#1 register contract - it passes RCX/RDX/R8/XMM0-5 and
     * destroys RAX with its unserviced sentinel.  Under an outer hypervisor
     * with a different contract RAX is a live input, so forwarding there would
     * corrupt the call rather than relay it.  Gating on this keeps that from
     * happening, and it cannot cost a legitimate call: Windows only builds a
     * hypercall page after it sees this same signature, so a guest that does
     * not present Hv#1 never issues the hypercalls this gate refuses.
     */
    BOOLEAN hypervisorInterfaceIsHv1;
    /* Keep the tail deterministic for crash-dump inspection. */
    UCHAR reserved2[5];
    /* Selected architecture, using the shared protocol backend namespace. */
    ULONG backendId;
    /* Preserve AMD probe validity even when prepare is unavailable. */
    KSWORD_ARK_HVM_SVM_CAPABILITIES svmCapabilities;
    /* Vendor-private lifetime-owned resources. */
    PVOID backendContext;
} KswHvmRuntime;

/*
 * The only two ways StateFlags may be mutated.  See the field's own comment for
 * why a plain read-modify-write is not safe anywhere, including under the lock.
 */
static __forceinline VOID
kswordArkHvmStateSet(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG bits
    )
{
    /* Publish the requested lifecycle bits without losing a concurrent set. */
    (VOID)InterlockedOr(&runtime->stateFlags, (LONG)bits);
}

static __forceinline VOID
kswordArkHvmStateClear(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG bits
    )
{
    /* Retire the requested lifecycle bits without losing a concurrent set. */
    (VOID)InterlockedAnd(&runtime->stateFlags, (LONG)~bits);
}

EXTERN_C_START

/*
 * Serialize VMX transition phases without holding a spin lock across VMX or
 * all-processor rendezvous work.  At IRQL <= APC_LEVEL contenders wait on the
 * preallocated event.  A DISPATCH_LEVEL callback never spins behind an owner;
 * it receives STATUS_DEVICE_BUSY so the power path can fail closed.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS
kswordArkHvmAcquireResidentTransition(
    _Inout_ KswHvmRuntime* runtime
    );

/* Release one transition phase and wake every wait-capable contender. */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
kswordArkHvmReleaseResidentTransition(
    _Inout_ KswHvmRuntime* runtime
    );

/* Allocate one zeroed EPT page and record it in the runtime ledger. */
PVOID
kswordArkHvmAllocateEptPageLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Out_ PHYSICAL_ADDRESS* physicalAddress
    );

/* Return the process-wide HVM runtime for nonblocking VM-exit telemetry. */
KswHvmRuntime*
kswordArkHvmGetRuntime(
    VOID
    );

/* Remove the exact captured KMDF unload entry before resident VMX entry. */
NTSTATUS
kswordArkHvmArmUnloadGuard(
    _Inout_ KswHvmRuntime* runtime
    );

/* Restore the captured unload entry after every resident CPU completed VMXOFF. */
NTSTATUS
kswordArkHvmDisarmUnloadGuard(
    _Inout_ KswHvmRuntime* runtime
    );

/* Invalidate pre-sleep VMX evidence before reopening resident start. */
VOID
kswordArkHvmInvalidatePowerResumeEvidence(
    _Inout_ KswHvmRuntime* runtime
    );

EXTERN_C_END
