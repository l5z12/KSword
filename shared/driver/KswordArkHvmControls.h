/*
 * KswordArkHvmControls.h
 *
 * Pure arithmetic in HVM that 'fails silently' (calculates incorrectly without raising errors) is centralized here.
 *
 * Why separate this logic: These checks were originally buried in .c files depending on the WDK, requiring a driver
 * load to verify. Loading a driver needs a signature and a machine without HVCI enabled; failure results in a BSOD.
 * After converting these to inline functions that depend on no kernel headers, the driver and host unit tests reference the same
 * implementation (not a copy, so no drift occurs), allowing correctness of this part to be verified directly on the build machine.
 *
 * The only inclusion criterion is: pure input-to-output with no side effects, where errors are hard to detect immediately.
 * For example, if the four-segment offset calculation for the MSR bitmap is incorrect, the policy will be applied to a different MSR; if the
 * self-mapping formula is incorrect, an unrelated page table entry will be modified. Neither of these cases will immediately report an error.
 *
 * This header is included by both kernel-mode C and user-mode C++, so it uses only
 * fixed-width primitive types and does not reference WDK, CRT, or Windows headers.
 */

#pragma once

/* ------------------------------------------------------------------ */
/* VMX control field clamping                                                       */
/* ------------------------------------------------------------------ */

/*
 * Extract a set of control bits via capability MSRs.
 *
 * The lower 32 bits of the capability MSR are allowed-0 (these bits must be 1), and the upper 32 bits
 * are allowed-1 (only these bits are allowed to be 1). Therefore, the correct approach is always "OR
 * with required bits first, then AND with allowed bits," rather than directly writing the desired value.
 *
 * This is critical in nested virtualization: the outer hypervisor exposes a narrower capability surface than bare metal.
 * Any control bits forced hard will cause VM entry to fail directly, with only a single error code as the failure message.
 */
static __inline unsigned long
KswordArkHvmAdjustControls(
    unsigned long Desired,
    unsigned long long Capability
    )
{
    /* Lower 32 bits: bits that must be set to 1. */
    const unsigned long mustBeOne =
        (unsigned long)(Capability & 0xFFFFFFFFULL);
    /* Upper 32 bits: bits allowed to be set to 1. */
    const unsigned long mayBeOne =
        (unsigned long)(Capability >> 32);

    /* Preserve required bits and discard bits requested by unsupported hardware. */
    return (Desired | mustBeOne) & mayBeOne;
}

/* ------------------------------------------------------------------ */
/* MSR bitmap addressing                                                         */
/* ------------------------------------------------------------------ */

/* Last index of the low segment covered by the bitmap page. */
#define KSWORD_ARK_HVM_MSR_LOW_LIMIT 0x00001FFFUL
/* Starting index of the high segment covered by the bitmap page. */
#define KSWORD_ARK_HVM_MSR_HIGH_BASE 0xC0000000UL
/* Last index of the high segment covered by the bitmap page. */
#define KSWORD_ARK_HVM_MSR_HIGH_LIMIT 0xC0001FFFUL

/* Byte offsets of the four 1KiB regions within the page. */
#define KSWORD_ARK_HVM_MSR_READ_LOW_OFFSET   0x000U
#define KSWORD_ARK_HVM_MSR_READ_HIGH_OFFSET  0x400U
#define KSWORD_ARK_HVM_MSR_WRITE_LOW_OFFSET  0x800U
#define KSWORD_ARK_HVM_MSR_WRITE_HIGH_OFFSET 0xC00U

/* Bitmap page size, used for out-of-bounds assertions. */
#define KSWORD_ARK_HVM_MSR_BITMAP_BYTES 0x1000U

/*
 * Check if a given MSR index falls within the two ranges described by the bitmap.
 * Indices out of range unconditionally exit, are not controlled by the bitmap, and thus cannot have a policy set for them.
 */
static __inline int
KswordArkHvmMsrIndexIsCovered(
    unsigned long MsrIndex
    )
{
    if (MsrIndex <= KSWORD_ARK_HVM_MSR_LOW_LIMIT) {
        return 1;
    }
    return (MsrIndex >= KSWORD_ARK_HVM_MSR_HIGH_BASE &&
            MsrIndex <= KSWORD_ARK_HVM_MSR_HIGH_LIMIT) ? 1 : 0;
}

/*
 * Calculate the byte offset and bit mask for a given MSR in the bitmap.
 *
 * The bitmap page is divided into four 1KiB regions in the following order: low-range read, high-range read, low-range write, high-range write.
 * High-range indices must be offset by subtracting 0xC0000000 before locating; omitting this step causes writes to
 * IA32_LSTAR (0xC0000082) to target the 0x82nd MSR in the low range instead. Since both MSRs exist, no error is raised.
 *
 * Returns 0 if the index is out of the covered range, in which case neither output is written.
 */
static __inline int
KswordArkHvmMsrBitmapLocate(
    unsigned long MsrIndex,
    int IsWrite,
    unsigned long* ByteOffset,
    unsigned char* BitMask
    )
{
    unsigned long base = 0UL;
    unsigned long relative = 0UL;

    if (!KswordArkHvmMsrIndexIsCovered(MsrIndex)) {
        return 0;
    }
    if (MsrIndex <= KSWORD_ARK_HVM_MSR_LOW_LIMIT) {
        base = IsWrite
            ? KSWORD_ARK_HVM_MSR_WRITE_LOW_OFFSET
            : KSWORD_ARK_HVM_MSR_READ_LOW_OFFSET;
        relative = MsrIndex;
    } else {
        base = IsWrite
            ? KSWORD_ARK_HVM_MSR_WRITE_HIGH_OFFSET
            : KSWORD_ARK_HVM_MSR_READ_HIGH_OFFSET;
        relative = MsrIndex - KSWORD_ARK_HVM_MSR_HIGH_BASE;
    }
    *ByteOffset = base + (relative >> 3);
    *BitMask = (unsigned char)(1U << (relative & 7U));
    return 1;
}

/* ------------------------------------------------------------------ */
/* Page table self-mapping addressing                                                       */
/* ------------------------------------------------------------------ */

/* The lower 48 bits of the canonical address that actually participate in indexing. */
#define KSWORD_ARK_HVM_VA_INDEX_MASK 0x0000FFFFFFFFFFFFULL

/*
 * Derive the leaf page table entry address for a virtual address from the self-mapping base.
 *
 * Must mask off the sign-extended upper 16 bits before shifting: kernel addresses have all 1s in the high bits.
 * Directly computing (va >> 12) << 3 would shift the result out of the self-mapping region into an unrelated address.
 * Since that address is often still readable, the error manifests as 'page table changes appear ineffective'.
 */
static __inline unsigned long long
KswordArkHvmSelfMapEntryAddress(
    unsigned long long SelfMapBase,
    unsigned long long VirtualAddress
    )
{
    const unsigned long long offset =
        ((VirtualAddress & KSWORD_ARK_HVM_VA_INDEX_MASK) >> 12) << 3;

    return SelfMapBase + offset;
}

/* Construct self-mapping base address from the PML4 slot number. */
static __inline unsigned long long
KswordArkHvmSelfMapBaseFromIndex(
    unsigned long Pml4Index
    )
{
    return 0xFFFF000000000000ULL |
        ((unsigned long long)(Pml4Index & 0x1FFUL) << 39);
}

/* ------------------------------------------------------------------ */
/* EPTP validation.                                                            */
/* ------------------------------------------------------------------ */

/* Bits in IA32_VMX_EPT_VPID_CAP related to EPTP field validity. */
#define KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4   (1ULL << 6)
#define KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC (1ULL << 8)
#define KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB (1ULL << 14)
#define KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY (1ULL << 21)

/* EPTP field layout. */
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK 0x7ULL
#define KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT 3
#define KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK 0x7ULL
#define KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY (1ULL << 6)
/* Bits 11:7 are reserved (bit 7 is used for supervisor shadow stack in newer SDM versions). */
#define KSWORD_ARK_HVM_EPTP_RESERVED_LOW 0x0F80ULL

/* Two memory types defined by the architecture. */
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC 0ULL
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB 6ULL

/*
 * Validate an EPTP value according to SDM criteria.
 *
 * This validation criterion serves two purposes: self-checking the EPT pointer field before VM entry, and validating
 * each item in the EPTP list. When VMFUNC switches using an invalid item, it only receives exit reason 59 with no
 * additional information about which item failed or why; therefore, validation must occur before writing to the list.
 *
 * Special note: a value of all zeros is always invalid (page traversal level is 0), so unused slots in
 * the list must not be left empty; they must be filled with a valid value identical to the current EPTP.
 *
 * MaxPhysicalAddressBits comes from CPUID.80000008H:EAX[7:0].
 * Returns non-zero if the value is acceptable by the hardware.
 */
static __inline int
KswordArkHvmEptpIsValid(
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    unsigned long MaxPhysicalAddressBits
    )
{
    const unsigned long long memoryType =
        Eptp & KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK;
    const unsigned long long walkLength =
        (Eptp >> KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT) &
        KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK;
    unsigned long long physicalMask = 0ULL;

    /* The memory type must be one supported by the hardware report. */
    if (memoryType == KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC) == 0ULL) {
            return 0;
        }
    } else if (memoryType == KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB) == 0ULL) {
            return 0;
        }
    } else {
        /* Undefined on other encoding architectures. */
        return 0;
    }
    /* The page traversal level field stores "level minus one"; thus a four-level walk is 3. */
    if (walkLength != 3ULL) {
        return 0;
    }
    if ((EptVpidCapability &
            KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4) == 0ULL) {
        return 0;
    }
    /* Only allow enabling accessed/dirty if the hardware supports it. */
    if ((Eptp & KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY) != 0ULL &&
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY) == 0ULL) {
        return 0;
    }
    /* Low-order reserved bits must be zero. */
    if ((Eptp & KSWORD_ARK_HVM_EPTP_RESERVED_LOW) != 0ULL) {
        return 0;
    }
    /* High bits exceeding the physical address width must be zero. */
    if (MaxPhysicalAddressBits == 0UL ||
        MaxPhysicalAddressBits >= 64UL) {
        return 0;
    }
    physicalMask =
        ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((Eptp & physicalMask) != 0ULL) {
        return 0;
    }
    return 1;
}

/*
 * EPT hierarchy index decomposition.
 *
 * Shared with the domain backend so the walk it performs can be checked on the
 * host.  A wrong index here does not fault - it silently edits the permissions
 * of an unrelated two-MiB region, which is exactly the class of bug that is
 * invisible until something far away misbehaves.
 */
/* EPT leaf permission bits, mirrored from the driver-private header. */
#define KSWORD_ARK_HVM_EPT_READ 0x1ULL
#define KSWORD_ARK_HVM_EPT_WRITE 0x2ULL
#define KSWORD_ARK_HVM_EPT_EXECUTE 0x4ULL

#define KSWORD_ARK_HVM_ONE_GIB 0x40000000ULL
#define KSWORD_ARK_HVM_ONE_512_GIB 0x8000000000ULL
#define KSWORD_ARK_HVM_LARGE_PAGE_BYTES 0x200000ULL
#define KSWORD_ARK_HVM_PAGE_BYTES 0x1000ULL

/* Select the PML4 slot covering one guest-physical address. */
static __inline unsigned long
KswordArkHvmEptPml4Index(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(PhysicalAddress / KSWORD_ARK_HVM_ONE_512_GIB);
}

/* Select the PDPT slot, that is the one-GiB window inside the PML4 slot. */
static __inline unsigned long
KswordArkHvmEptPdptIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_ONE_512_GIB) /
        KSWORD_ARK_HVM_ONE_GIB);
}

/* Select the page-directory slot, that is the two-MiB leaf. */
static __inline unsigned long
KswordArkHvmEptPdIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_ONE_GIB) /
        KSWORD_ARK_HVM_LARGE_PAGE_BYTES);
}

/* Round one address down to the two-MiB leaf that contains it. */
static __inline unsigned long long
KswordArkHvmEptLeafBase(
    unsigned long long PhysicalAddress)
{
    return PhysicalAddress & ~(KSWORD_ARK_HVM_LARGE_PAGE_BYTES - 1ULL);
}

/*
 * Apply one domain restriction to one leaf.
 *
 * Domains may only lose permissions, and this is where that rule lives.  It is
 * expressed as a mask-and rather than as a validated assignment on purpose: a
 * function that cannot express "grant" cannot be called wrongly to grant.
 */
static __inline unsigned long long
KswordArkHvmEptApplyRestriction(
    unsigned long long LeafEntry,
    unsigned long long RemovedBits)
{
    return LeafEntry & ~RemovedBits;
}

/*
 * Per-processor private EPT hierarchies (P4.1).
 *
 * A private hierarchy is the shared one with a handful of tables replaced by
 * private copies, so that flipping a leaf touches only the processor walking
 * it.  Every table on a private path is byte-for-byte its shared counterpart
 * except for the addresses that had to point somewhere else.  The arithmetic
 * that does the replacing lives here so the host tests can prove it, because
 * a wrong address in a paging structure does not fault - it silently walks to
 * the wrong page.
 */

/* Mask the physical-address field of an EPT entry or pointer. */
#define KSWORD_ARK_HVM_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL
/* Mask the byte offset within one paging structure. */
#define KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK 0xFFFULL

/* Select the page-table slot, that is the four-KiB leaf inside a split. */
static __inline unsigned long
KswordArkHvmEptPtIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_LARGE_PAGE_BYTES) /
        KSWORD_ARK_HVM_PAGE_BYTES);
}

/*
 * Encode one non-leaf entry pointing at a paging structure.
 *
 * Non-leaf entries carry no memory type, no large-page bit and no
 * suppress-#VE: those are leaf-only fields, and the permissions are the
 * permissive union so the leaves below decide the effective access.
 */
static __inline unsigned long long
KswordArkHvmEptTablePointer(
    unsigned long long TablePhysical)
{
    return (TablePhysical & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        KSWORD_ARK_HVM_EPT_READ |
        KSWORD_ARK_HVM_EPT_WRITE |
        KSWORD_ARK_HVM_EPT_EXECUTE;
}

/*
 * Replace the address in an entry or pointer, keeping every other bit.
 *
 * This is the only operation that builds a private path, and it is used for
 * the EPT pointer itself as well as for table entries.  Composing a private
 * EPT pointer from constants instead would be a second source of truth for
 * the memory type, the walk length and the accessed/dirty bit: a private
 * pointer built this way is accepted by VM entry exactly when the shared one
 * is, and INVEPT sees the same descriptor the VMCS carries.
 */
static __inline unsigned long long
KswordArkHvmEptRebaseEntry(
    unsigned long long SharedEntry,
    unsigned long long PrivatePhysical)
{
    return (PrivatePhysical & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        (SharedEntry & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK);
}

/* Recover the paging structure that contains one entry address. */
static __inline unsigned long long
KswordArkHvmEptEntryTableBase(
    unsigned long long EntryAddress)
{
    return EntryAddress & ~KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK;
}

/* Recover the byte offset of one entry inside its paging structure. */
static __inline unsigned long long
KswordArkHvmEptEntryByteOffset(
    unsigned long long EntryAddress)
{
    return EntryAddress & KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK;
}

/*
 * Count the pages one private hierarchy set costs.
 *
 * Per processor: one private root, one private PDPT for each distinct PML4
 * slot the flippable leaves fall under, one private page directory for each
 * distinct one-GiB window, and one private page table per flippable leaf.
 * Everything else stays shared, which is what keeps this affordable.
 */
static __inline unsigned long long
KswordArkHvmEptLocalPageCost(
    unsigned long ProcessorCount,
    unsigned long DistinctPml4Slots,
    unsigned long DistinctGibWindows,
    unsigned long LeafCount)
{
    const unsigned long long perProcessor =
        1ULL +
        (unsigned long long)DistinctPml4Slots +
        (unsigned long long)DistinctGibWindows +
        (unsigned long long)LeafCount;

    return (unsigned long long)ProcessorCount * perProcessor;
}

/* Report whether a computed page cost fits the ledger reserved for it. */
static __inline int
KswordArkHvmEptLocalFitsBudget(
    unsigned long long PageCost,
    unsigned long long Cap)
{
    return PageCost != 0ULL && PageCost <= Cap ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* VMX capability MSR filtering                                                    */
/* ------------------------------------------------------------------ */

/*
 * What we **declare** support must equal what we **implement**.
 *
 * Before L1 enables a VMX feature, it reads only these MSRs. Without filtering, it reads the host's actual
 * capabilities and attempts to enable VPID, unrestricted guest, VMFUNC, and posted interrupts—features whose fields
 * we never copied into vmcs02. It sets the control bits, but we do not write the corresponding fields; the processor
 * then acts based on the stale value in vmcs02 (typically 0). There is no error reporting anywhere along this path.
 *
 * This belongs to the same family as the MSR bitmap defect: **control bits and their corresponding fields are separated**.
 * The difference is that last time we missed copying, while this time we voluntarily agreed to an impossible task.
 *
 * Thus, this is a **whitelist**: only explicitly listed bits are allowed to be advertised;
 * all others must be cleared. New Intel features default to 'not advertised' — the reverse (a
 * blacklist) would mean every new feature is implicitly accepted, and no one would notice.
 */

/* Index range for capability MSRs; all are read-only. */
#define KSWORD_ARK_HVM_VMX_MSR_BASIC            0x480UL
#define KSWORD_ARK_HVM_VMX_MSR_PINBASED         0x481UL
#define KSWORD_ARK_HVM_VMX_MSR_PROCBASED        0x482UL
#define KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS        0x483UL
#define KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS       0x484UL
#define KSWORD_ARK_HVM_VMX_MSR_MISC             0x485UL
#define KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED0       0x486UL
#define KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED1       0x487UL
#define KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED0       0x488UL
#define KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED1       0x489UL
#define KSWORD_ARK_HVM_VMX_MSR_VMCS_ENUM        0x48AUL
#define KSWORD_ARK_HVM_VMX_MSR_PROCBASED2       0x48BUL
#define KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP     0x48CUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_PINBASED    0x48DUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_PROCBASED   0x48EUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_EXIT_CTLS   0x48FUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_ENTRY_CTLS  0x490UL
#define KSWORD_ARK_HVM_VMX_MSR_VMFUNC           0x491UL

/* Check if an index corresponds to a VMX capability MSR. */
static __inline int
KswordArkHvmIsVmxCapabilityMsr(
    unsigned long MsrIndex
    )
{
    return (MsrIndex >= KSWORD_ARK_HVM_VMX_MSR_BASIC &&
            MsrIndex <= KSWORD_ARK_HVM_VMX_MSR_VMFUNC) ? 1 : 0;
}

/*
 * Bits allowed to be declared in pin-based control.
 *
 * bit 0: External interrupt exit / bit 3: NMI exit / bit 5: Virtual NMI: control
 * bit only; merged into vmcs02 during merge, with no associated address field.
 * Clear bit 6 (VMX preemption timer, requires 0x482E and exit control 22) and bit 7 (posted
 * interrupt, requires 0x2016 descriptor address + notification vector); we do not copy either field.
 */
/*
 * 2026-09-14: Bit 6 was temporarily added to this table to see if "declaring a preemptible timer" would
 * cause VMware to configure a real monitoring timer. **That experiment was a no-op; nothing was verified.**
 *
 * This table is a whitelist; the filter below performs `upper_half &= this_table`, which can only narrow the
 * result. The host (Hyper-V) pin allowed-1 is 0x3F, and bit 6 is not included. Therefore, whether 0x29 or 0x69
 * is written here, the same 0x3F is passed to the guest, and the VMware capability dump remains unchanged.
 * `Activate VMX-preemption timer { 0 }`。
 *
 * **Criterion: To make L1 see a new capability, updating the whitelist is insufficient; the filter must synthesize it.** That
 * is no longer filtering but forging, requiring implementation of both the field (0x482E) and the exit semantics (reason 52).
 * Before this point, only bits that we will actually merge into vmcs02 are placed here.
 */
#define KSWORD_ARK_HVM_VMX_PIN_ALLOWED 0x00000029UL

/*
 * Bit allowed to be declared in the primary processor-based controls.
 *
 * The cleared ones are all cases of 'requiring a matching address field that we do not write'.
 *   bit 27 monitor trap flag -> We have not implemented MTF for L2.
 *
 * Bit 21 (use TPR shadow) was previously in this line because the reason was 'we need 0x2012 but we don't write it'. Now we do write it:
 * 0x2012 and 0x401C are included in the copied control field table in hvm_nested_l2.c, with validation that the page
 * address is non-zero and page-aligned before entry. Added because VMware Workstation 17.6 explicitly requires it.
 * （`True Primary Processor-Based VM-Execution Controls: Use TPR shadow`）。
 * Note that this is distinct from secondary virtualize-APIC-accesses (bit 0), which remains unannounced.
 * Retain bit 25 for I/O bitmap and bit 28 for MSR bitmap (both paths
 * have been end-to-end verified), and bit 31 to activate secondary.
 *
 * Bit 3 (TSC offsetting) was erroneously cleared: 0x2010 was always copied into
 * g_KswordL2CopiedControlFields, yet I incorrectly stopped declaring it as copied—a regression I caused
 * myself. To determine whether a bit should be retained, **check the field table in hvm_nested_l2.c**, do not
 * grep macro names: those three tables are applied cyclically, and the fields within them contain no macros.
 */
#define KSWORD_ARK_HVM_VMX_PROC_ALLOWED 0xF3F99E8CUL

/*
 * secondary control: bits allowed to declare are EPT and unrestricted guest.
 *
 * Every other bit requires a field not copied into vmcs02: VPID needs the VPID field and
 * INVVPID handling; VMFUNC needs 0x2018; VMCS shadowing needs 0x2026/0x2028; PML needs
 * 0x200E; #VE needs 0x202A; EPTP switching needs 0x2024; TSC scaling needs 0x2032.
 *
 * Bit 7 (unrestricted guest) requires no new fields; this is its fundamental distinction from the above:
 * It merely relaxes the processor's requirements for guest CR0.PE/PG, allowing L2 to run in real mode or unpaged protected mode.
 * Guest CR0, segment attributes, CR0 mask, and shadow reads are already copied field-by-field from vmcs12, and
 * the entry path performs no CR0.PE validation—meaning all required elements for this bit are already present.
 *
 * Added due to a requirement observed on physical hardware: VMware Workstation 17.6 explicitly references this in its own logs.
 * `The Intel "VMX Unrestricted Guest" feature is necessary to run this virtual
 * machine` — its guest boots in **real mode**, and without this bit it cannot start. This is the only one of the four
 * missing features that cannot be bypassed (the other three are TPR shadow, ack-interrupt-on-exit, and INVVPID).
 *
 * Dependencies must be enforced by code, not L1 compliance: Intel specifies that when unrestricted
 * guest = 1, EPT must also be enabled, otherwise VM entry fails. Merging vmcs02 controls drops the
 * unrestricted guest bit if EPT is disabled—similar to handling 'Virtual NMI requires NMI exit' in pin
 * controls. The rationale is identical: **do not pass an unverified pair of controls into VMLAUNCH**.
 *
 * The consequences must be stated clearly: this capability remains very narrow, and many hypervisors will refuse
 * to start directly. That is the desired outcome—a clean refusal rather than agreeing and then silently failing.
 */
#define KSWORD_ARK_HVM_VMX_PROC2_ALLOWED 0x00000082UL

/*
 * Bits allowed to be declared in VM-exit controls.
 *
 * Each reserved bit can point to the field it depends on in the field table of hvm_nested_l2.c:
 *   bit 2  Save debug controls -> guest IA32_DEBUGCTL(0x2802) and DR7(0x681A) are in the bidirectional table.
 *   bit 9  Host address space -> already mandatory on x64.
 *   bit 18 Save guest PAT -> 0x2804 is in the bidirectional table; write back to vmcs12 on reflection.
 *   bit 19 Load host PAT -> 0x2C00 is in the host table (inherited from vmcs01).
 *   bit 20 Save guest EFER -> 0x2806, handled like guest PAT above.
 *   bit 21 Load host EFER -> 0x2C02, handled like host PAT above.
 * Cleared: 12 PERF_GLOBAL_CTRL (0x2808 is **not in** any table), and 22 preemption timer
 * (0x482E is also absent).
 *
 * Bit 15 (respond to interrupt on exit): When set, the processor itself responds to the interrupt controller and
 * writes the vector to 0x4404. During reflection, 0x4404 and 0x4406 are already written into vmcs12 field-by-field.
 * VMware Workstation 17.6 explicitly requires this (`True VM-Exit Controls: Acknowledge
 * interrupt on exit`); it is the final missing item among its four requirements.
 *
 * The danger of this bit lies not in semantics but in **routing**: the acknowledged interrupt has already been removed from the
 * controller, so no one will re-inject it; thus, this exit **must** reach L1. Three things guarantee this, all of which are indispensable:
 *   1. We never request external interrupt exits, so reason 1 can only occur if L1 requested it;
 *   2. Our own exit control does not have bit 15; this bit in vmcs02 comes only from vmcs12;
 *   3. In the exit ownership, reason 1 is explicitly assigned to L1 (not relying on the default
 *      fallback) — see hvm_nested_l2.c, which explains why this case cannot follow the default.
 * If any of the three is broken by later changes, the symptom is a silent hang caused by lost interrupts.
 *
 * **Confirmed by two practical tests that this bit cannot be cleared and cannot be stripped during merging** (2026-09-14):
 *   - Removing it from this table is a no-op. Filters can only narrow within the
 *     host-provided range, and `high |= low` restores every 'must-be-one' bit, including
 *     bit 15; thus, even after removal, it remains set in the vmcs12 read by the guest.
 *   - Strip this when merging into vmcs02; the VMware monitor crashes immediately.
 *     `MONITOR PANIC: VERIFY vmcore/monitor/common/platform/common/x86/irq.c:111`。
 *     Note: Once L1 requests this bit, it unconditionally reads that vector; if an invalid value is read, it triggers its own assertion.
 * Control bits set by L1 cannot be silently suppressed: either they should never be settable, or they must be honored exactly as set.
 */
#define KSWORD_ARK_HVM_VMX_EXIT_ALLOWED 0x003C8204UL

/*
 * Bits allowed to be declared in the VM-entry control.
 *
 *   bit 2  Load debug controls -> guest IA32_DEBUGCTL(0x2802) and DR7 are in the bidirectional table.
 *   bit 9  IA-32e mode guest -> without this bit, a 64-bit L2 cannot enter.
 *   bit 14 Load guest PAT -> 0x2804 is in the bidirectional table.
 *   bit 15 Load guest EFER -> 0x2806 is in the bidirectional table.
 * Clear 13 (PERF_GLOBAL_CTRL; 0x2808 is not copied) and 16/17/18/20/21/22
 * (BNDCFGS, PT, RTIT, CET, LBR, PKRS; none of these fields are copied).
 *
 * This group originally only reserved bit 9; I wrote it based on the incorrect premise that 'these fields were not copied,' whereas those three
 * batch tables are always copied. **An overly narrow declaration is as harmful as an overly wide one**: being too wide promises what cannot be
 * done, while being too narrow causes a hypervisor that could otherwise run to cleanly refuse startup, and neither case produces an error.
 * Thus, every bit in this table now specifies which field encoding it depends on; check the table before making changes.
 */
#define KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED 0x0000C204UL

/*
 * Bits allowed to declare in EPT/VPID capabilities.
 *
 * The remaining entries reflect the actual path taken by shadow EPT: 4-level page tables, UC/WB memory
 * types, 2 MiB and 1 GiB leaf entries, INVEPT and its two contexts, plus bit 21 (accessed/dirty). A/D is
 * the only capability bit on this line that has been empirically observed to fold back to the L1 table.
 *
 * The VPID family only declares **bit 32 (INVVPID support)** and **bits 40/41/42 (types 0/1/2)**, which
 * exactly match the four bits VMware Workstation 17.6 explicitly requires in its own logs. Note that it
 * requires **instruction capabilities**, not the secondary enable-VPID control bit (which remains
 * undeclared, see KSWORD_ARK_HVM_VMX_PROC2_ALLOWED)—these two concepts are architecturally distinct.
 *
 * We do not enable VPID, so L2 in vmcs02 uses VPID 0000H. The processor invalidates the linear mapping for
 * VPID 0000H on every VM entry and VM exit. This means any translations L1 intends to remove via INVVPID are
 * already gone before the next entry/exit. The correct action for this instruction is to do nothing, not to
 * flush the shadow EPT (which is INVEPT's job, and rebuilding the shadow on every INVVPID would be expensive).
 *
 * Bit 43 (Type 3, single-context reserved global) is not declared: VMware
 * doesn't require it, and we have no reason to commit to a finer granularity.
 *
 * Clear bit 0 (execute-only) as well. It has not been verified whether shadow synthesis
 * preserves execute-only bit-by-bit; do not declare bits that haven't been verified.
 *
 * **This whitelist must be a superset of the bits used by us in the guest.**
 *
 * A common oversight: the driver itself is also a reader of these MSRs. Once resident, the driver runs
 * inside the guest, so we read values filtered by ourselves. There are currently two such readers:
 *   hvm_nested_ept.c: Check bit 21 to decide whether to maintain A/D. hvm_nested_probe.c: Check bit 17 to decide
 *   if EPT12 can use 1 GiB pages. Bit 17 was initially missing from this table, causing the probe's EPT12 setup
 * to FAIL entirely, resulting in a failure status. The observed symptom is identical to "nested virtualization
 * broken," but the root cause is that we inadvertently disabled a capability we ourselves require.
 */
#define KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED 0x0000070106334140ULL

/* Position of the CR3-target field in MISC; we do not copy the CR3-target field, so it must be reported as 0. */
#define KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK 0x01FF0000ULL

/*
 * Narrow a paired-format control capability MSR.
 *
 * The lower 32 bits are allowed-0 (set to 1 means "must be 1"), and the upper 32 bits
 * are allowed-1 (set to 1 means "can be 1"). Narrowing only affects the upper half.
 *
 * The `| low` step is mandatory: bits forced to 1 by hardware must also be allowed to be 1. Clearing them
 * from the high half creates a self-contradictory MSR. L1 would compute a control value based on it that
 * the processor rejects as invalid, but the error would point to L1's own calculation rather than to us.
 * Better to declare an unimplemented bit that is forced on than to provide an inconsistent capability.
 */
static __inline unsigned long long
KswordArkHvmFilterPairedControlMsr(
    unsigned long long HostValue,
    unsigned long AllowedHigh
    )
{
    unsigned long long low = HostValue & 0xFFFFFFFFULL;
    unsigned long long high = (HostValue >> 32) & 0xFFFFFFFFULL;

    high &= (unsigned long long)AllowedHigh;
    high |= low;
    return (high << 32) | low;
}

/*
 * Narrow a capability MSR by index. Return the value to be given to the guest.
 *
 * Return the index unchanged if it is not in the filter range. The caller has already bounded the range using
 * KswordArkHvmIsVmxCapabilityMsr; checking again here ensures this function remains correct when used standalone.
 */
static __inline unsigned long long
KswordArkHvmFilterVmxCapabilityMsr(
    unsigned long MsrIndex,
    unsigned long long HostValue
    )
{
    switch (MsrIndex) {
    case KSWORD_ARK_HVM_VMX_MSR_PINBASED:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_PINBASED:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PIN_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_PROCBASED:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_PROCBASED:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PROC_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_EXIT_CTLS:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_EXIT_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_ENTRY_CTLS:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_PROCBASED2:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PROC2_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP:
        /* Single-value format, not paired: directly AND with the whitelist. */
        return HostValue & KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED;
    case KSWORD_ARK_HVM_VMX_MSR_VMFUNC:
        /*
         * VMFUNC has already cleared the secondary context; clear the feature bits here as well.
         *
         * Clearing both is intentional: if L1 reads only this MSR and uses VMFUNC, it gets
         * 'no functionality at all' rather than 'functionality exists but activation bits
         * are off'. The latter would make it think it's a configuration issue and retry.
         */
        return 0ULL;
    case KSWORD_ARK_HVM_VMX_MSR_MISC:
        /*
         * Clear only the CR3-target count.
         *
         * This field is a **promise**: reporting N means there are N CR3-target values available in the
         * VMCS, and we copy none of them into vmcs02. The remaining bits are descriptive (active state, MSEG
         * version, preemption timer frequency) and do not constitute functional guarantees we must honor.
         */
        return HostValue & ~KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK;
    default:
        /*
         * BASIC / CR0 and CR4 fixed bits / VMCS_ENUM are passed through as-is.
         *
         * BASIC must not be modified: The lower 31 bits represent the VMCS revision ID. Changing it causes
         * guests to build VMCS regions with the new ID, leading to VMXON and VMPTRLD failures due to header
         * mismatches—a failure unrelated to capabilities but mistaken for nested virtualization corruption.
         */
        return HostValue;
    }
}


/* ------------------------------------------------------------------ */
/* Nested EPT: L2 GPA -> L1 GPA -> KSword backing page.                 */
/* Return ownership separately: an outer denial is not an L1 fault.    */
/* ------------------------------------------------------------------ */
#define KSWORD_ARK_HVM_NEPT_COMPOSE_OK 0UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_L1_DENIED 1UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED 2UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID 3UL

static __inline unsigned long
KswordArkHvmNestedEptComposeLeaf(
    unsigned long long L1Physical,
    unsigned long long L1Leaf,
    unsigned long long OuterLeaf,
    unsigned long OuterShift,
    unsigned long Access,
    unsigned long long* Composed)
{
    unsigned long long offsetMask;
    unsigned long long permissions;
    unsigned long innerType;
    unsigned long outerType;
    unsigned long memoryType;

    if (Composed == 0) { return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID; }
    *Composed = 0ULL;
    if (Access == 0UL || (Access & ~7UL) != 0UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    if ((L1Leaf & Access) != Access) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_L1_DENIED;
    }
    if (OuterShift != 12UL && OuterShift != 21UL && OuterShift != 30UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    offsetMask = (1ULL << OuterShift) - 1ULL;
    if ((L1Physical & ~(KSWORD_ARK_HVM_EPT_PHYSICAL_MASK | 0xFFFULL)) != 0ULL ||
        (OuterLeaf & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK & offsetMask) != 0ULL ||
        (((OuterLeaf & 0x80ULL) != 0ULL) != (OuterShift != 12UL)) ||
        ((OuterLeaf & 3ULL) == 2ULL) || ((L1Leaf & 3ULL) == 2ULL)) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    permissions = L1Leaf & OuterLeaf & 7ULL;
    if ((permissions & Access) != Access) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED;
    }
    innerType = (unsigned long)((L1Leaf >> 3) & 7ULL);
    outerType = (unsigned long)((OuterLeaf >> 3) & 7ULL);
    if (innerType == 2UL || innerType == 3UL || innerType == 7UL ||
        outerType == 2UL || outerType == 3UL || outerType == 7UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    /* UC wins; unlike non-WB types use conservative UC, never forced WB. */
    memoryType = innerType == outerType ? innerType :
        (innerType == 6UL ? outerType : (outerType == 6UL ? innerType : 0UL));
    *Composed = (OuterLeaf & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        (L1Physical & offsetMask & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        permissions | ((unsigned long long)memoryType << 3) |
        (L1Leaf & 0x40ULL) | 0x8000000000000000ULL;
    /* A/D starts clear; the shadow's existing accounting owns these bits. */
    return KSWORD_ARK_HVM_NEPT_COMPOSE_OK;
}
