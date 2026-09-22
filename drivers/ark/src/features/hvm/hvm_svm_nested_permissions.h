/* AMD APM 15.10/15.11: capture, combine and route nested permission maps. */
#pragma once
#include "hvm_svm_arch.h"

#define KSW_NSVM_MSRPM_BYTES 8192U
#define KSW_NSVM_IOPM_BYTES 12288U
#define KSW_NSVM_IOIO_PROT (1U << 27)
#define KSW_NSVM_MSR_PROT (1U << 28)
#define KSW_NSVM_PERMISSION_FLAGS (KSW_NSVM_IOIO_PROT | KSW_NSVM_MSR_PROT)
/* Ownership is a bit mask; BOTH still requires reflection before L0 emulation. */
#define KSW_NSVM_OWNER_NONE 0U
#define KSW_NSVM_OWNER_L0 1U
#define KSW_NSVM_OWNER_L1 2U
#define KSW_NSVM_OWNER_INVALID 4U

/* The caller holds these immutable, nonpageable snapshots until L2 exits. */
typedef struct KswNsvmPermissionView {
    /* Only the IOIO_PROT/MSR_PROT bits affect map semantics. */
    unsigned int flags;
    /* Disabled maps may be NULL and must not be dereferenced. */
    const unsigned char* msr;
    const unsigned char* io;
} KswNsvmPermissionView;

/* Preallocated destination; Ready is cleared before any capture attempt. */
typedef struct KswNsvmPermissionImage {
    /* Publication is CPU-local; external readers must use the runtime sequence. */
    unsigned int ready, flags;
    /* Reserved map bytes are retained, but never interpreted as MSR bits. */
    unsigned char msr[KSW_NSVM_MSRPM_BYTES];
    unsigned char io[KSW_NSVM_IOPM_BYTES];
} KswNsvmPermissionImage;

/* Reads one full page of L1 physical RAM, after NPT01/cache/ownership validation.
   No direct physical cast, MMIO, allocation or blocking is allowed in this callback. */
typedef int (*KswNsvmPermissionRead)(void* context, KswSvmU64 guestPa,
    unsigned char* page);

/* APM ignores low twelve base bits; validate the entire hardware allocation. */
unsigned int kswSvmNestedMapAddress(KswSvmU64 address, unsigned int bytes,
    unsigned int physicalBits, KswSvmU64* base);
/* Capture is not atomic with an unsynchronized L1 writer; entry owns publication. */
unsigned int kswSvmNestedCapturePermissions(KswNsvmPermissionImage* image,
    unsigned int flags, KswSvmU64 msrPa, KswSvmU64 ioPa,
    unsigned int physicalBits, KswNsvmPermissionRead read, void* context);
/* Failed capture images cannot be turned into an executable permission view. */
unsigned int kswSvmNestedPermissionView(const KswNsvmPermissionImage* image,
    KswNsvmPermissionView* view);
/* Destination maps must be distinct preallocated hardware allocations, not sources.
   On failure they remain untouched and must not be published to VMCB02. */
unsigned int kswSvmNestedMergePermissions(const KswNsvmPermissionView* outer,
    const KswNsvmPermissionView* inner, unsigned char* msr, unsigned char* io);
/* Only MSR/IOIO exits are accepted; malformed metadata returns INVALID, never NONE. */
unsigned int kswSvmNestedPermissionOwners(const KswNsvmPermissionView* outer,
    const KswNsvmPermissionView* inner, KswSvmU64 exitCode,
    KswSvmU64 exitInfo1, unsigned int msrNumber);
