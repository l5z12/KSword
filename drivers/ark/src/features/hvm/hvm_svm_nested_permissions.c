/* Fine-grained ownership must follow the original L1 map, never the merged map. */
#include "hvm_svm_nested_permissions.h"

/* Reject incomplete enabled maps before touching output or making a routing decision. */
static unsigned int kswNsvmPermissionValid(const KswNsvmPermissionView* view)
{
    /* A disabled map's address has no bearing on whether L1 requested an exit. */
    return view && (!(view->flags & KSW_NSVM_MSR_PROT) || view->msr) &&
        (!(view->flags & KSW_NSVM_IOIO_PROT) || view->io);
}

/* normalize architectural bases without truncating unsupported high address bits. */
unsigned int kswSvmNestedMapAddress(KswSvmU64 address, unsigned int bytes,
    unsigned int physicalBits, KswSvmU64* base)
{
    /* The shared four-level implementation currently supports at most 48 bits. */
    KswSvmU64 mask = kswNptAddressMask(physicalBits);
    /* Never leave a stale address in a failed result. */
    if (!base) { return 0; }
    /* Clear before testing either size or address. */
    *base = 0;
    /* Only the two architectural permission-map allocation sizes are admitted. */
    if (!mask || (bytes != KSW_NSVM_MSRPM_BYTES && bytes != KSW_NSVM_IOPM_BYTES) ||
        (address & ~(mask | 0xfffULL))) { return 0; }
    /* VMRUN ignores the low twelve bits, unlike the VMCB operand's alignment check. */
    address &= ~0xfffULL;
    /* Subtraction prevents both wraparound and a final page beyond MAXPHYADDR. */
    if (address > (mask | 0xfffULL) - (bytes - 1U)) { return 0; }
    /* Zero is a representable base; RAM ownership belongs to the read callback. */
    *base = address;
    /* Address validity alone never proves that the memory is readable RAM. */
    return 1;
}

/* Build a private image without publishing partially read maps. */
unsigned int kswSvmNestedCapturePermissions(KswNsvmPermissionImage* image,
    unsigned int flags, KswSvmU64 msrPa, KswSvmU64 ioPa,
    unsigned int physicalBits, KswNsvmPermissionRead read, void* context)
{
    /* Decode both complete ranges before making the first memory access. */
    KswSvmU64 msr = 0, io = 0;
    /* Five bounded page reads are enough for both maps. */
    unsigned int offset;
    /* A missing destination cannot acquire ownership. */
    if (!image) { return 0; }
    /* Any previous snapshot becomes unusable, including on a failed recapture. */
    image->ready = 0;
    /* Preserve only the relevant intercept controls from this VMRUN. */
    image->flags = flags & KSW_NSVM_PERMISSION_FLAGS;
    /* Disabled maps are not read or range-checked by this software snapshotter. */
    if (((image->flags & KSW_NSVM_MSR_PROT) &&
            !kswSvmNestedMapAddress(msrPa, KSW_NSVM_MSRPM_BYTES, physicalBits, &msr)) ||
        ((image->flags & KSW_NSVM_IOIO_PROT) &&
            !kswSvmNestedMapAddress(ioPa, KSW_NSVM_IOPM_BYTES, physicalBits, &io)) ||
        (image->flags && !read)) { return 0; }
    /* No disabled/previous map bytes may leak into a subsequent combined image. */
    for (offset = 0; offset < KSW_NSVM_MSRPM_BYTES; ++offset) { image->msr[offset] = 0; }
    /* Clear the full hardware IOPM allocation, including its tail page. */
    for (offset = 0; offset < KSW_NSVM_IOPM_BYTES; ++offset) { image->io[offset] = 0; }
    /* Each callback must translate L1 physical memory rather than using it as host PA. */
    if (image->flags & KSW_NSVM_MSR_PROT) {
        /* Copy a page into owned memory, never retain the callback's transient mapping. */
        for (offset = 0; offset < KSW_NSVM_MSRPM_BYTES; offset += 4096U) {
            /* A failure invalidates the whole image, including earlier successful pages. */
            if (!read(context, msr + offset, image->msr + offset)) { return 0; }
        }
    }
    /* I/O width can consume the first three bits of the third page at port 0xffff. */
    if (image->flags & KSW_NSVM_IOIO_PROT) {
        /* Keep all three hardware pages under the same lifetime as the MSR snapshot. */
        for (offset = 0; offset < KSW_NSVM_IOPM_BYTES; offset += 4096U) {
            /* The caller must refuse VMRUN if any source page cannot be captured. */
            if (!read(context, io + offset, image->io + offset)) { return 0; }
        }
    }
    /* Only the fully captured CPU-private image is eligible for merge and routing. */
    image->ready = 1;
    /* No hardware or TLB state was changed by this capture. */
    return 1;
}

/* Produce a view only after complete capture, including the all-disabled case. */
unsigned int kswSvmNestedPermissionView(const KswNsvmPermissionImage* image,
    KswNsvmPermissionView* view)
{
    /* No stale view is returned on failure; the caller must check the result. */
    if (!view) { return 0; }
    /* Start with an inert descriptor, not a pointer to a previous generation's image. */
    view->flags = 0; view->msr = 0; view->io = 0;
    /* A partial read is not a valid empty permissions map. */
    if (!image || image->ready != 1U) { return 0; }
    /* Controls and buffers are bound to the same completed snapshot. */
    view->flags = image->flags; view->msr = image->msr; view->io = image->io;
    /* Lifetimes remain the caller's responsibility throughout inner execution. */
    return 1;
}

/* OR only enabled source maps: disabling an intercept must ignore stale map bits. */
unsigned int kswSvmNestedMergePermissions(const KswNsvmPermissionView* outer,
    const KswNsvmPermissionView* inner, unsigned char* msr, unsigned char* io)
{
    /* All inputs are owned snapshots; no guest read takes place in the merge. */
    unsigned int index;
    /* Reject missing active maps before touching either hardware output. */
    if (!msr || !io || !kswNsvmPermissionValid(outer) || !kswNsvmPermissionValid(inner)) { return 0; }
    /* Preserve every L0 protection even if L1 leaves its permission map clear. */
    for (index = 0; index < KSW_NSVM_MSRPM_BYTES; ++index) {
        /* Bits outside the three MSR ranges remain opaque, not routed as extra MSRs. */
        msr[index] = (unsigned char)(((outer->flags & KSW_NSVM_MSR_PROT) ? outer->msr[index] : 0) |
            ((inner->flags & KSW_NSVM_MSR_PROT) ? inner->msr[index] : 0));
    }
    /* The tail bits are significant for multibyte I/O at the last port. */
    for (index = 0; index < KSW_NSVM_IOPM_BYTES; ++index) {
        /* Hardware control bits must separately be the OR of both owners' intercepts. */
        io[index] = (unsigned char)(((outer->flags & KSW_NSVM_IOIO_PROT) ? outer->io[index] : 0) |
            ((inner->flags & KSW_NSVM_IOIO_PROT) ? inner->io[index] : 0));
    }
    /* Caller may now publish these pre-resolved physical pointers into VMCB02. */
    return 1;
}

/* Query one owner independently; never derive ownership from the combined maps. */
static unsigned int kswNsvmPermissionRequested(const KswNsvmPermissionView* view,
    KswSvmU64 code, unsigned int bit, unsigned int width)
{
    /* IOIO can span four permission bits, with no 16-bit wrap at the last port. */
    unsigned int index;
    /* A clear MSR_PROT disables even the implicit out-of-range MSR intercept. */
    if (code == KSW_SVM_EXIT_MSR) {
        /* A missing map was rejected before this helper. */
        if (!(view->flags & KSW_NSVM_MSR_PROT)) { return 0; }
        /* The architecture intercepts all MSRs absent from its three bitmap ranges. */
        return bit == 0xffffffffU || ((view->msr[bit / 8U] >> (bit & 7U)) & 1U);
    }
    /* Disabled I/O interception ignores every IOPM bit, including the tail. */
    if (!(view->flags & KSW_NSVM_IOIO_PROT)) { return 0; }
    /* Port plus byte offset fits within the architectural 65539 meaningful bits. */
    for (index = 0; index < width; ++index) {
        /* Any covered byte forces the entire IN/OUT/INS/OUTS operation to intercept. */
        if ((view->io[(bit + index) / 8U] >> ((bit + index) & 7U)) & 1U) { return 1; }
    }
    /* Neither direction nor REP changes which port bytes are checked. */
    return 0;
}

/* Return ownership evidence; the dispatcher still implements reflection/emulation. */
unsigned int kswSvmNestedPermissionOwners(const KswNsvmPermissionView* outer,
    const KswNsvmPermissionView* inner, KswSvmU64 exitCode,
    KswSvmU64 exitInfo1, unsigned int msrNumber)
{
    /* normalize both exit formats before looking at either owner's map. */
    unsigned int bit, width = 1;
    /* Invalid views cannot silently become a local/native passthrough decision. */
    if (!kswNsvmPermissionValid(outer) || !kswNsvmPermissionValid(inner)) { return KSW_NSVM_OWNER_INVALID; }
    /* MSR EXITINFO1 is exactly zero for read or one for write. */
    if (exitCode == KSW_SVM_EXIT_MSR) {
        /* Ignore neither malformed high bits nor an invalid direction. */
        if (exitInfo1 > 1ULL) { return KSW_NSVM_OWNER_INVALID; }
        /* Keep the architectural out-of-map sentinel for implicit interception. */
        bit = kswSvmMsrpmBit(msrNumber, (unsigned int)exitInfo1);
    } else if (exitCode == 0x7bULL) {
        /* Size is a one-hot 8/16/32-bit operand encoding. */
        width = (unsigned int)((exitInfo1 >> 4) & 7ULL);
        /* Reserved bits must not turn an unknown exit into a guessed port access. */
        if ((exitInfo1 & ~0xffff1ffdULL) || (width != 1U && width != 2U && width != 4U)) {
            /* Caller preserves the raw failure instead of executing I/O on a guessed port. */
            return KSW_NSVM_OWNER_INVALID;
        }
        /* Do not cast port plus width to ushort: trailing permission bits do not wrap. */
        bit = (unsigned int)(exitInfo1 >> 16);
    } else {
        /* Other exit classes require their own intercept/exception ownership rules. */
        return KSW_NSVM_OWNER_INVALID;
    }
    /* When both request an exit, L1 sees its intercept before local side effects. */
    return (kswNsvmPermissionRequested(outer, exitCode, bit, width) ? KSW_NSVM_OWNER_L0 : 0U) |
        (kswNsvmPermissionRequested(inner, exitCode, bit, width) ? KSW_NSVM_OWNER_L1 : 0U);
}
