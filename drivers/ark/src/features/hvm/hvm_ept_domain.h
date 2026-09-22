/*++

Module Name:

    hvm_ept_domain.h

Abstract:

    Declares EPT execution domains and the EPTP list that publishes them to
    VMFUNC.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Allocate the EPTP list and publish the default view as entry zero. */
NTSTATUS
kswordArkHvmEptDomainPrepareLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Fork one domain from the default view and publish it in the EPTP list. */
NTSTATUS
kswordArkHvmEptDomainCreateLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Out_ ULONG* domainIndex
    );

/*
 * Remove permissions from one physical range inside one domain.
 *
 * Removal is the only direction this interface offers, and that is the whole
 * security argument for VMFUNC: because a domain can never grant more than the
 * default view, unprivileged guest code that switches into it cannot gain
 * anything it did not already have.  See the VMFUNC comment in the protocol
 * header for why that matters.
 */
NTSTATUS
kswordArkHvmEptDomainRestrictRangeLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG domainIndex,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount,
    _In_ ULONG deniedAccess
    );

/* Release every domain and the EPTP list without touching the default view. */
VOID
kswordArkHvmEptDomainResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Execute one versioned domain request under lifecycle ownership. */
NTSTATUS
kswordArkHvmEptDomainControl(
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* response
    );

EXTERN_C_END
