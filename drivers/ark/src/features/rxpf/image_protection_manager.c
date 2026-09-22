/*++

Module Name:

    image_protection_manager.c

Abstract:

    Exact-build MmChangeImageProtection resolver and managed test-page MDLs.

Environment:

    Kernel mode, PASSIVE_LEVEL control path only.

--*/

#include "image_protection_manager.h"
#include <ntimage.h>
#include "src/platform/kernel_module_identity.h"
#include "src/platform/pool_compat.h"

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID pcValue,
    _Outptr_ PVOID* baseOfImage
    );

#define KSW_RXPF_BACKUP_TAG 'bPxR'
#define KSW_RXPF_CONTENT_TAG 'cPxR'
#define KSW_RXPF_EXPECTED_NT_BUILD 26220UL
#define KSW_RXPF_EXPECTED_TIMESTAMP 0xB292FCA9UL
#define KSW_RXPF_EXPECTED_IMAGE_SIZE 0x01450000UL
#define KSW_RXPF_EXPECTED_CHECKSUM 0x00C7D4D4UL
#define KSW_RXPF_MM_CHANGE_RVA 0x00A3B300UL
#define KSW_RXPF_MM_CHANGE_OPERATION_RX 1UL
#define KSW_RXPF_MM_CHANGE_OPERATION_READONLY_NX 2UL
#define KSW_RXPF_RSDS_SIGNATURE 0x53445352UL

typedef NTSTATUS
(NTAPI* KswRxpfMmChangeImageProtection)(
    _In_ PMDL mdl,
    _In_ PVOID baseAddress,
    _In_ ULONG numberOfBytes,
    _In_ ULONG operation
    );

#pragma pack(push, 1)
typedef struct KswRxpfRsdsHeader
{
    ULONG signature;
    GUID guid;
    ULONG age;
} KswRxpfRsdsHeader, *PkswRxpfRsdsHeader;
#pragma pack(pop)

typedef struct KswRxpfBuildProfile
{
    ULONG ntBuildNumber;
    ULONG imageTimeDateStamp;
    ULONG imageSize;
    ULONG imageCheckSum;
    ULONG functionRva;
    ULONG functionParameterCount;
    ULONG operationRx;
    ULONG operationReadOnlyNx;
    ULONG pdbAge;
    const GUID* pdbGuid;
    const UCHAR* signature;
    const UCHAR* signatureMask;
    ULONG signatureLength;
} KswRxpfBuildProfile, *PkswRxpfBuildProfile;

typedef struct KswRxpfImageProtectionState
{
    PDRIVER_OBJECT driverObject;
    PVOID kernelBase;
    ULONG ntBuildNumber;
    ULONG imageTimeDateStamp;
    ULONG imageSize;
    ULONG imageCheckSum;
    ULONG buildStatus;
    GUID pdbGuid;
    ULONG pdbAge;
    KswRxpfMmChangeImageProtection mmChangeImageProtection;
    const KswRxpfBuildProfile* activeProfile;
    volatile LONG initialized;
    volatile LONG buildSupported;
    NTSTATUS lastStatus;
} KswRxpfImageProtectionState;

static KswRxpfImageProtectionState gKswRxpfImageProtection;

static const GUID kGKswRxpfExpectedPdbGuid = {
    0x3E5A9A8BUL,
    0x6B78U,
    0x281FU,
    { 0x3BU, 0xE2U, 0x15U, 0x01U, 0x10U, 0x32U, 0x52U, 0x15U }
};

static const UCHAR kGKswRxpfMmChangeSignature[64] = {
    0x48U, 0x8BU, 0xC4U, 0x48U, 0x89U, 0x58U, 0x08U, 0x48U,
    0x89U, 0x68U, 0x10U, 0x48U, 0x89U, 0x70U, 0x18U, 0x44U,
    0x89U, 0x48U, 0x20U, 0x57U, 0x41U, 0x54U, 0x41U, 0x55U,
    0x41U, 0x56U, 0x41U, 0x57U, 0x48U, 0x83U, 0xECU, 0x30U,
    0x83U, 0x60U, 0xC8U, 0x00U, 0x49U, 0x8BU, 0xD8U, 0x41U,
    0x8DU, 0x41U, 0xFFU, 0x4CU, 0x8BU, 0xE2U, 0x48U, 0x8BU,
    0xF9U, 0x83U, 0xF8U, 0x01U, 0x0FU, 0x87U, 0x41U, 0x02U,
    0x00U, 0x00U, 0x44U, 0x8BU, 0xEBU, 0x49U, 0x3BU, 0xDDU
};

static const UCHAR kGKswRxpfMmChangeSignatureMask[64] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const KswRxpfBuildProfile kGKswRxpfBuildProfiles[] = {
    {
        KSW_RXPF_EXPECTED_NT_BUILD,
        KSW_RXPF_EXPECTED_TIMESTAMP,
        KSW_RXPF_EXPECTED_IMAGE_SIZE,
        KSW_RXPF_EXPECTED_CHECKSUM,
        KSW_RXPF_MM_CHANGE_RVA,
        4UL,
        KSW_RXPF_MM_CHANGE_OPERATION_RX,
        KSW_RXPF_MM_CHANGE_OPERATION_READONLY_NX,
        1UL,
        &kGKswRxpfExpectedPdbGuid,
        kGKswRxpfMmChangeSignature,
        kGKswRxpfMmChangeSignatureMask,
        RTL_NUMBER_OF(kGKswRxpfMmChangeSignature)
    }
};

C_ASSERT(RTL_NUMBER_OF(kGKswRxpfBuildProfiles) == 1U);
C_ASSERT(sizeof(kGKswRxpfMmChangeSignature) == 64U);

/*
 * The linker gives this unique executable section its own page.  No handler or
 * control-path code resides here, so leaving it NX until image unload cannot
 * strand an unload callback.  Bytes encode MOV RAX,12345678h; ADD RAX,1; RET.
 */
#pragma section(".rxpftst", read, execute)
__declspec(allocate(".rxpftst"))
__declspec(align(PAGE_SIZE))
const UCHAR kGKswRxpfSelfImageTestPage[PAGE_SIZE] = {
    0x48U, 0xB8U, 0x78U, 0x56U, 0x34U, 0x12U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x48U, 0x83U, 0xC0U, 0x01U, 0xC3U
};

static BOOLEAN
kswRxpfCanonicalKernelPage(
    _In_ ULONGLONG address
    )
{
    ULONGLONG high = address >> 48;

    /* Require canonical sign extension, kernel range, and page alignment. */
    return high == 0xFFFFULL &&
        address >= (ULONGLONG)(ULONG_PTR)MmSystemRangeStart &&
        (address & (PAGE_SIZE - 1ULL)) == 0ULL;
}

static BOOLEAN
kswRxpfValidateExecutableSection(
    _In_ PVOID imageBase,
    _In_ ULONG rva
    )
{
    BOOLEAN valid = FALSE;

    /* Parse the loaded PE under exception protection before trusting sections. */
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS64 nt = NULL;
        PIMAGE_SECTION_HEADER section = NULL;
        USHORT index = 0U;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 ||
            (ULONG)dos->e_lfanew > 0x1000UL) {
            return FALSE;
        }
        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return FALSE;
        }
        section = IMAGE_FIRST_SECTION(nt);
        for (index = 0U; index < nt->FileHeader.NumberOfSections; ++index) {
            ULONG sectionSize = max(
                section[index].Misc.VirtualSize,
                section[index].SizeOfRawData);
            ULONG sectionEnd = section[index].VirtualAddress + sectionSize;

            if (sectionEnd < section[index].VirtualAddress) {
                continue;
            }
            if (rva >= section[index].VirtualAddress && rva < sectionEnd) {
                valid =
                    (section[index].Characteristics &
                        IMAGE_SCN_MEM_EXECUTE) != 0UL &&
                    (section[index].Characteristics &
                        IMAGE_SCN_MEM_DISCARDABLE) == 0UL;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        valid = FALSE;
    }
    return valid;
}

static BOOLEAN
kswRxpfReadRsds(
    _In_ PVOID imageBase,
    _Out_ GUID* guidOut,
    _Out_ ULONG* ageOut
    )
{
    ULONG matchingEntries = 0UL;

    /* Accept exactly one well-formed RSDS record from the loaded image. */
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS64 nt = NULL;
        IMAGE_DATA_DIRECTORY directory;
        PIMAGE_DEBUG_DIRECTORY entries = NULL;
        ULONG entryCount = 0UL;
        ULONG index = 0UL;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 ||
            (ULONG)dos->e_lfanew > 0x1000UL) {
            return FALSE;
        }
        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->OptionalHeader.NumberOfRvaAndSizes <=
                IMAGE_DIRECTORY_ENTRY_DEBUG) {
            return FALSE;
        }
        directory = nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (directory.VirtualAddress == 0UL ||
            directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
            directory.VirtualAddress + directory.Size <
                directory.VirtualAddress ||
            directory.VirtualAddress + directory.Size >
                nt->OptionalHeader.SizeOfImage) {
            return FALSE;
        }
        entries = (PIMAGE_DEBUG_DIRECTORY)(
            (PUCHAR)imageBase + directory.VirtualAddress);
        entryCount = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (index = 0UL; index < entryCount; ++index) {
            KswRxpfRsdsHeader rsds;

            if (entries[index].Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
                entries[index].AddressOfRawData == 0UL ||
                entries[index].SizeOfData < sizeof(rsds) ||
                entries[index].AddressOfRawData + sizeof(rsds) <
                    entries[index].AddressOfRawData ||
                entries[index].AddressOfRawData + sizeof(rsds) >
                    nt->OptionalHeader.SizeOfImage) {
                continue;
            }
            RtlCopyMemory(
                &rsds,
                (PUCHAR)imageBase + entries[index].AddressOfRawData,
                sizeof(rsds));
            if (rsds.signature != KSW_RXPF_RSDS_SIGNATURE) {
                continue;
            }
            *guidOut = rsds.guid;
            *ageOut = rsds.age;
            matchingEntries += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return matchingEntries == 1UL;
}

static BOOLEAN
kswRxpfSignatureMatches(
    _In_ const KswRxpfBuildProfile* profile,
    _In_reads_(profile->SignatureLength) const UCHAR* address
    )
{
    ULONG index = 0UL;

    /* Compare every masked byte from the exact PDB/disassembly profile. */
    if (profile == NULL || address == NULL ||
        profile->signatureLength == 0UL ||
        profile->signatureLength > 64UL) {
        return FALSE;
    }
    __try {
        for (index = 0UL; index < profile->signatureLength; ++index) {
            if ((address[index] & profile->signatureMask[index]) !=
                (profile->signature[index] &
                    profile->signatureMask[index])) {
                return FALSE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static VOID
kswRxpfResolveExactBuild(
    VOID
    )
{
    static const KswKernelModuleNameMatch kMatches[] = {
        { "ntoskrnl.exe", 0UL },
        { "ntkrnlmp.exe", 0UL },
        { "ntkrnlpa.exe", 0UL },
        { "ntkrpamp.exe", 0UL }
    };
    KSW_DYN_MODULE_IDENTITY_PACKET identity;
    RTL_OSVERSIONINFOW version;
    GUID pdbGuid;
    ULONG pdbAge = 0UL;
    PVOID functionAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    const KswRxpfBuildProfile* profile = NULL;
    ULONG profileIndex = 0UL;

    /* Start from an unsupported state and promote only after every check. */
    gKswRxpfImageProtection.buildStatus =
        KSWORD_ARK_RXPF_BUILD_STATUS_UNINITIALIZED;
    gKswRxpfImageProtection.lastStatus = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&identity, sizeof(identity));
    RtlZeroMemory(&version, sizeof(version));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status)) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_OS_BUILD_MISMATCH;
        gKswRxpfImageProtection.lastStatus = status;
        return;
    }
    gKswRxpfImageProtection.ntBuildNumber = version.dwBuildNumber;
    for (profileIndex = 0UL;
         profileIndex < RTL_NUMBER_OF(kGKswRxpfBuildProfiles);
         ++profileIndex) {
        if (kGKswRxpfBuildProfiles[profileIndex].ntBuildNumber ==
            version.dwBuildNumber) {
            profile = &kGKswRxpfBuildProfiles[profileIndex];
            break;
        }
    }
    if (profile == NULL) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_OS_BUILD_MISMATCH;
        return;
    }

    /* Resolve the loaded nt image instead of trusting an on-disk path. */
    status = kswordArkQueryKernelModuleIdentity(
        kMatches,
        RTL_NUMBER_OF(kMatches),
        &identity);
    if (!NT_SUCCESS(status) || identity.present == 0UL) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_IMAGE_MISMATCH;
        gKswRxpfImageProtection.lastStatus = status;
        return;
    }
    gKswRxpfImageProtection.kernelBase =
        (PVOID)(ULONG_PTR)identity.imageBase;
    gKswRxpfImageProtection.imageTimeDateStamp = identity.timeDateStamp;
    gKswRxpfImageProtection.imageSize = identity.sizeOfImage;
    if (identity.machine != IMAGE_FILE_MACHINE_AMD64 ||
        identity.timeDateStamp != profile->imageTimeDateStamp ||
        identity.sizeOfImage != profile->imageSize) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_IMAGE_MISMATCH;
        return;
    }

    /* Read the checksum from the same loaded PE headers. */
    __try {
        PIMAGE_DOS_HEADER dos =
            (PIMAGE_DOS_HEADER)gKswRxpfImageProtection.kernelBase;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
            (PUCHAR)gKswRxpfImageProtection.kernelBase + dos->e_lfanew);

        gKswRxpfImageProtection.imageCheckSum =
            nt->OptionalHeader.CheckSum;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_IMAGE_MISMATCH;
        gKswRxpfImageProtection.lastStatus = GetExceptionCode();
        return;
    }
    if (gKswRxpfImageProtection.imageCheckSum !=
        profile->imageCheckSum) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_IMAGE_MISMATCH;
        return;
    }

    /* Bind the profile to the exact Microsoft RSDS GUID and age. */
    if (!kswRxpfReadRsds(
            gKswRxpfImageProtection.kernelBase,
            &pdbGuid,
            &pdbAge) ||
        !RtlEqualMemory(
            &pdbGuid,
            profile->pdbGuid,
            sizeof(pdbGuid)) ||
        pdbAge != profile->pdbAge) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_RSDS_MISMATCH;
        return;
    }
    gKswRxpfImageProtection.pdbGuid = pdbGuid;
    gKswRxpfImageProtection.pdbAge = pdbAge;

    /* Require the PDB RVA to land in a live executable PE section. */
    if (!kswRxpfValidateExecutableSection(
            gKswRxpfImageProtection.kernelBase,
            profile->functionRva)) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_SECTION_INVALID;
        return;
    }
    functionAddress =
        (PUCHAR)gKswRxpfImageProtection.kernelBase +
        profile->functionRva;
    if (!kswRxpfSignatureMatches(
            profile,
            (const UCHAR*)functionAddress)) {
        gKswRxpfImageProtection.buildStatus =
            KSWORD_ARK_RXPF_BUILD_STATUS_SIGNATURE_MISMATCH;
        return;
    }

    /* Publish the internal call target only after every independent check. */
    gKswRxpfImageProtection.activeProfile = profile;
    gKswRxpfImageProtection.mmChangeImageProtection =
        (KswRxpfMmChangeImageProtection)functionAddress;
    gKswRxpfImageProtection.buildStatus =
        KSWORD_ARK_RXPF_BUILD_STATUS_SUPPORTED;
    gKswRxpfImageProtection.lastStatus = STATUS_SUCCESS;
    InterlockedExchange(&gKswRxpfImageProtection.buildSupported, 1);
}

NTSTATUS
kswRxpfImageProtectionInitialize(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    /* Record driver identity and resolve but never call the internal routine. */
    if (driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfImageProtection.initialized,
            1,
            1) != 0) {
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(
        &gKswRxpfImageProtection,
        sizeof(gKswRxpfImageProtection));
    gKswRxpfImageProtection.driverObject = driverObject;
    kswRxpfResolveExactBuild();
    InterlockedExchange(&gKswRxpfImageProtection.initialized, 1);
    return STATUS_SUCCESS;
}

VOID
kswRxpfImageProtectionUninitialize(
    VOID
    )
{
    /* Remove the private function pointer before driver-owned state disappears. */
    InterlockedExchange(&gKswRxpfImageProtection.buildSupported, 0);
    InterlockedExchange(&gKswRxpfImageProtection.initialized, 0);
    KeMemoryBarrier();
    RtlZeroMemory(
        &gKswRxpfImageProtection,
        sizeof(gKswRxpfImageProtection));
}

VOID
kswRxpfImageProtectionQuerySupport(
    _Out_ KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE* response
    )
{
    ULONG supportFlags = 0UL;
    const KswRxpfBuildProfile* profile =
        gKswRxpfImageProtection.activeProfile;

    if (profile == NULL) {
        profile = &kGKswRxpfBuildProfiles[0];
    }

    /* Return the exact build profile and signature used by runtime gating. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    if (InterlockedCompareExchange(
            &gKswRxpfImageProtection.initialized,
            1,
            1) != 0) {
        supportFlags |= KSWORD_ARK_RXPF_SUPPORT_INITIALIZED |
            KSWORD_ARK_RXPF_SUPPORT_ALLOCATED_TEST_PAGE |
            KSWORD_ARK_RXPF_SUPPORT_IDT_SHADOW |
            KSWORD_ARK_RXPF_SUPPORT_EMULATOR;
    }
    if (kswRxpfImageProtectionBuildSupported()) {
        supportFlags |= KSWORD_ARK_RXPF_SUPPORT_BUILD_MATCH |
            KSWORD_ARK_RXPF_SUPPORT_ABI_VERIFIED |
            KSWORD_ARK_RXPF_SUPPORT_SELF_IMAGE_TEST_PAGE;
    }
#if KSW_RXPF_ENABLE_EXTERNAL_IMAGE_TARGETS
    supportFlags |= KSWORD_ARK_RXPF_SUPPORT_EXTERNAL_IMAGE_COMPILED;
#endif
    response->supportFlags = supportFlags;
    response->buildStatus = gKswRxpfImageProtection.buildStatus;
    response->ntBuildNumber = gKswRxpfImageProtection.ntBuildNumber;
    response->imageTimeDateStamp =
        gKswRxpfImageProtection.imageTimeDateStamp;
    response->imageSize = gKswRxpfImageProtection.imageSize;
    response->imageCheckSum = gKswRxpfImageProtection.imageCheckSum;
    response->functionRva = profile->functionRva;
    response->functionOperationRx = profile->operationRx;
    response->functionOperationReadOnlyNx =
        profile->operationReadOnlyNx;
    response->functionParameterCount = profile->functionParameterCount;
    response->pdbAge = gKswRxpfImageProtection.pdbAge;
    response->lastStatus = gKswRxpfImageProtection.lastStatus;
    RtlCopyMemory(
        response->pdbGuid,
        &gKswRxpfImageProtection.pdbGuid,
        sizeof(response->pdbGuid));
    RtlCopyMemory(
        response->signature,
        profile->signature,
        profile->signatureLength);
    RtlCopyMemory(
        response->signatureMask,
        profile->signatureMask,
        profile->signatureLength);
}

BOOLEAN
kswRxpfImageProtectionBuildSupported(
    VOID
    )
{
    /* The function pointer and exact identity are published as one gate. */
    return InterlockedCompareExchange(
        &gKswRxpfImageProtection.buildSupported,
        1,
        1) != 0 &&
        gKswRxpfImageProtection.mmChangeImageProtection != NULL;
}

PVOID
kswRxpfImageProtectionSelfTestPage(
    VOID
    )
{
    /* The dedicated image section is page-aligned by declaration and linker. */
    return (PVOID)(ULONG_PTR)kGKswRxpfSelfImageTestPage;
}

static NTSTATUS
kswRxpfCreateAllocatedTestPage(
    _In_ ULONG flags,
    _Out_ KswRxpfPageRecord* recordSource
    )
{
    PHYSICAL_ADDRESS lowAddress;
    PHYSICAL_ADDRESS highAddress;
    PHYSICAL_ADDRESS skipBytes;
    PMDL mdl = NULL;
    PVOID writableMapping = NULL;
    PVOID executeMapping = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Allocate one physical page described by an owned MDL. */
    lowAddress.QuadPart = 0LL;
    highAddress.QuadPart = MAXLONGLONG;
    skipBytes.QuadPart = 0LL;
    mdl = MmAllocatePagesForMdlEx(
        lowAddress,
        highAddress,
        skipBytes,
        PAGE_SIZE,
        MmCached,
        MM_ALLOCATE_FULLY_REQUIRED);
    if (mdl == NULL || MmGetMdlByteCount(mdl) != PAGE_SIZE) {
        if (mdl != NULL) {
            MmFreePagesFromMdl(mdl);
            ExFreePool(mdl);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Seed bytes through a writable/NX mapping before exposing an RX mapping. */
    writableMapping = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,
        FALSE,
        (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute));
    if (writableMapping == NULL) {
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(
        writableMapping,
        kGKswRxpfSelfImageTestPage,
        PAGE_SIZE);
    MmUnmapLockedPages(writableMapping, mdl);

    /* Map the same locked page read/execute for the initial registered state. */
    executeMapping = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,
        FALSE,
        (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoWrite));
    if (executeMapping == NULL) {
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        MmUnmapLockedPages(executeMapping, mdl);
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return status;
    }
    if (!kswRxpfCanonicalKernelPage(
            (ULONGLONG)(ULONG_PTR)executeMapping)) {
        MmUnmapLockedPages(executeMapping, mdl);
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    /* Fill an unpublished source record for the fixed state table. */
    RtlZeroMemory(recordSource, sizeof(*recordSource));
    recordSource->targetKind = KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST;
    recordSource->flags = flags;
    recordSource->pageBase = (LONG64)(ULONG_PTR)executeMapping;
    recordSource->originalMapping = executeMapping;
    recordSource->originalProtection = PAGE_EXECUTE_READ;
    recordSource->currentProtection = PAGE_EXECUTE_READ;
    recordSource->writableAliasProtection = 0UL;
    recordSource->pfn = (ULONGLONG)MmGetMdlPfnArray(mdl)[0];
    recordSource->mdl = mdl;
    recordSource->ownsMdlPages = TRUE;
    recordSource->mappingIsAlias = FALSE;
    recordSource->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswRxpfCreateSelfImageTestPage(
    _In_ ULONGLONG requestedAddress,
    _In_ ULONG flags,
    _Out_ KswRxpfPageRecord* recordSource
    )
{
    PVOID page = kswRxpfImageProtectionSelfTestPage();
    PVOID ownerImageBase = NULL;
    PMDL mdl = NULL;
    BOOLEAN pagesLocked = FALSE;

    /* The internal ABI is unavailable on every non-exact Windows build. */
    if (!kswRxpfImageProtectionBuildSupported()) {
        return STATUS_NOT_SUPPORTED;
    }
    if (((ULONGLONG)(ULONG_PTR)page & (PAGE_SIZE - 1ULL)) != 0ULL ||
        (requestedAddress != 0ULL &&
            requestedAddress != (ULONGLONG)(ULONG_PTR)page)) {
        return STATUS_INVALID_ADDRESS;
    }
    if (RtlPcToFileHeader(page, &ownerImageBase) == NULL ||
        ownerImageBase == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* Probe-and-lock creates the exact low-bit MDL flag state required by nt. */
    mdl = IoAllocateMdl(page, PAGE_SIZE, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionStatus = GetExceptionCode();

        IoFreeMdl(mdl);
        return exceptionStatus;
    }
    if (!pagesLocked ||
        (mdl->MdlFlags &
            (MDL_MAPPED_TO_SYSTEM_VA |
             MDL_PAGES_LOCKED |
             MDL_SOURCE_IS_NONPAGED_POOL)) != MDL_PAGES_LOCKED ||
        MmGetMdlByteOffset(mdl) != 0UL ||
        MmGetMdlByteCount(mdl) != PAGE_SIZE ||
        MmGetMdlVirtualAddress(mdl) != page) {
        if (pagesLocked) {
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
        return STATUS_INVALID_PARAMETER;
    }

    /* Fill the record while the original mapping is still RX and untouched. */
    RtlZeroMemory(recordSource, sizeof(*recordSource));
    recordSource->targetKind = KSWORD_ARK_RXPF_TARGET_SELF_IMAGE_TEST;
    recordSource->flags = flags;
    recordSource->pageBase = (LONG64)(ULONG_PTR)page;
    recordSource->originalMapping = page;
    recordSource->originalProtection = PAGE_EXECUTE_READ;
    recordSource->currentProtection = PAGE_EXECUTE_READ;
    recordSource->writableAliasProtection = 0UL;
    recordSource->pfn = (ULONGLONG)MmGetMdlPfnArray(mdl)[0];
    recordSource->ownerImageBase =
        (ULONGLONG)(ULONG_PTR)ownerImageBase;
    recordSource->mdl = mdl;
    recordSource->pagesLockedByProbe = TRUE;
    recordSource->lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfImageProtectionCreateRecord(
    _In_ ULONG targetKind,
    _In_ ULONGLONG requestedAddress,
    _In_ ULONG flags,
    _Out_ KswRxpfPageRecord* recordSource
    )
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    /* Only documented test kinds are accepted by the default build. */
    if (recordSource == NULL ||
        (flags & ~KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(recordSource, sizeof(*recordSource));
    if (targetKind == KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST) {
        if (requestedAddress != 0ULL) {
            return STATUS_INVALID_PARAMETER;
        }
        status = kswRxpfCreateAllocatedTestPage(flags, recordSource);
    } else if (targetKind == KSWORD_ARK_RXPF_TARGET_SELF_IMAGE_TEST) {
        status = kswRxpfCreateSelfImageTestPage(
            requestedAddress,
            flags,
            recordSource);
    } else if (targetKind == KSWORD_ARK_RXPF_TARGET_EXTERNAL_IMAGE) {
#if KSW_RXPF_ENABLE_EXTERNAL_IMAGE_TARGETS
        /* External image allowlists are intentionally absent in protocol v1. */
        UNREFERENCED_PARAMETER(RequestedAddress);
        status = STATUS_NOT_SUPPORTED;
#else
        UNREFERENCED_PARAMETER(requestedAddress);
        status = STATUS_NOT_SUPPORTED;
#endif
    } else {
        status = STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Keep a complete nonpaged mirror of the page's current bytes. */
    recordSource->currentContent = kswordArkAllocateNonPagedPool(
        PAGE_SIZE,
        KSW_RXPF_CONTENT_TAG);
    if (recordSource->currentContent == NULL) {
        kswRxpfImageProtectionReleaseRecord(recordSource);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Optional backup is allocated on the control path, never by vector 14. */
    if ((flags & KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP) != 0UL) {
        recordSource->backup = kswordArkAllocateNonPagedPool(
            PAGE_SIZE,
            KSW_RXPF_BACKUP_TAG);
        if (recordSource->backup == NULL) {
            kswRxpfImageProtectionReleaseRecord(recordSource);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(
            recordSource->backup,
            recordSource->originalMapping,
            PAGE_SIZE);
    }
    __try {
        RtlCopyMemory(
            recordSource->currentContent,
            recordSource->originalMapping,
            PAGE_SIZE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        kswRxpfImageProtectionReleaseRecord(recordSource);
        return status;
    }
    recordSource->lastWriteOffset = 0UL;
    recordSource->lastWriteLength = 0UL;
    RtlZeroMemory(recordSource->lastWriteBytes, sizeof(recordSource->lastWriteBytes));
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfImageProtectionChangeToRwNx(
    _Inout_ PkswRxpfPageRecord record
    )
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    /* A record transitions exactly once from RX to its persistent NX state. */
    if (record == NULL || record->mdl == NULL ||
        record->state != KSWORD_ARK_RXPF_PAGE_STATE_RX) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (record->targetKind == KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST) {
        /* The public MDL API changes the existing mapping to PAGE_READWRITE/NX. */
        status = MmProtectMdlSystemAddress(record->mdl, PAGE_READWRITE);
        if (NT_SUCCESS(status)) {
            record->writableAlias =
                (ULONGLONG)(ULONG_PTR)record->originalMapping;
            record->mappingIsAlias = FALSE;
            record->currentProtection = PAGE_READWRITE;
            record->writableAliasProtection = PAGE_READWRITE;
        }
    } else if (record->targetKind ==
        KSWORD_ARK_RXPF_TARGET_SELF_IMAGE_TEST) {
        PVOID writableAlias = NULL;

        /* Revalidate the exact MDL low-bit contract immediately before the call. */
        if (!kswRxpfImageProtectionBuildSupported() ||
            (record->mdl->MdlFlags &
                (MDL_MAPPED_TO_SYSTEM_VA |
                 MDL_PAGES_LOCKED |
                 MDL_SOURCE_IS_NONPAGED_POOL)) != MDL_PAGES_LOCKED ||
            MmGetMdlByteOffset(record->mdl) != 0UL ||
            MmGetMdlByteCount(record->mdl) != PAGE_SIZE ||
            MmGetMdlVirtualAddress(record->mdl) !=
                (PVOID)(ULONG_PTR)record->pageBase) {
            return STATUS_INVALID_PARAMETER;
        }
        status = gKswRxpfImageProtection.mmChangeImageProtection(
            record->mdl,
            (PVOID)(ULONG_PTR)record->pageBase,
            PAGE_SIZE,
            KSW_RXPF_MM_CHANGE_OPERATION_READONLY_NX);
        if (!NT_SUCCESS(status)) {
            record->lastStatus = status;
            return status;
        }
        record->currentProtection = PAGE_READONLY;

        /* Map a separate writable/NX alias only after the image mapping is NX. */
        writableAlias = MmMapLockedPagesSpecifyCache(
            record->mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            (MM_PAGE_PRIORITY)(NormalPagePriority | MdlMappingNoExecute));
        if (writableAlias == NULL) {
            record->state = KSWORD_ARK_RXPF_PAGE_STATE_ERROR;
            record->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        record->writableAlias = (ULONGLONG)(ULONG_PTR)writableAlias;
        record->mappingIsAlias = TRUE;
        record->writableAliasProtection = PAGE_READWRITE;
    } else {
        return STATUS_NOT_SUPPORTED;
    }

    /* Publish the completed transition only after a writable alias exists. */
    if (NT_SUCCESS(status)) {
        KeMemoryBarrier();
        InterlockedExchange(
            &record->state,
            KSWORD_ARK_RXPF_PAGE_STATE_RW_NX);
        InterlockedIncrement((volatile LONG*)&record->generation);
    } else {
        record->lastStatus = status;
        record->lastFailureReason =
            KSWORD_ARK_RXPF_EMULATION_INTERNAL_ERROR;
    }
    return status;
}

NTSTATUS
kswRxpfImageProtectionWrite(
    _Inout_ PkswRxpfPageRecord record,
    _In_ ULONG offset,
    _In_reads_bytes_(length) const UCHAR* bytes,
    _In_ ULONG length
    )
{
    ULONGLONG end = (ULONGLONG)offset + (ULONGLONG)length;
    NTSTATUS status = STATUS_SUCCESS;

    /* Writes are bounded to one transitioned page and its explicit alias. */
    if (record == NULL || bytes == NULL || length == 0UL ||
        record->currentContent == NULL ||
        length > KSWORD_ARK_RXPF_MAX_WRITE_BYTES ||
        end > PAGE_SIZE || end < offset ||
        record->state != KSWORD_ARK_RXPF_PAGE_STATE_RW_NX ||
        record->writableAlias == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        RtlCopyMemory(
            (PUCHAR)(ULONG_PTR)record->writableAlias + offset,
            bytes,
            length);
        RtlCopyMemory(
            (PUCHAR)record->currentContent + offset,
            bytes,
            length);
        record->lastWriteOffset = offset;
        record->lastWriteLength = length;
        RtlZeroMemory(record->lastWriteBytes, sizeof(record->lastWriteBytes));
        RtlCopyMemory(record->lastWriteBytes, bytes, length);

        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    record->lastStatus = status;
    if (NT_SUCCESS(status)) {
        InterlockedIncrement((volatile LONG*)&record->generation);
    }
    return status;
}

VOID
kswRxpfImageProtectionReleaseRecord(
    _Inout_ PkswRxpfPageRecord record
    )
{
    /* Release only resources whose ownership flags were recorded at creation. */
    if (record == NULL) {
        return;
    }
    if (record->mappingIsAlias && record->writableAlias != 0ULL &&
        record->mdl != NULL) {
        MmUnmapLockedPages(
            (PVOID)(ULONG_PTR)record->writableAlias,
            record->mdl);
        record->writableAlias = 0ULL;
    } else if (record->ownsMdlPages &&
        record->originalMapping != NULL && record->mdl != NULL) {
        MmUnmapLockedPages(record->originalMapping, record->mdl);
        record->originalMapping = NULL;
        record->writableAlias = 0ULL;
    }
    if (record->pagesLockedByProbe && record->mdl != NULL) {
        MmUnlockPages(record->mdl);
        record->pagesLockedByProbe = FALSE;
    }
    if (record->ownsMdlPages && record->mdl != NULL) {
        MmFreePagesFromMdl(record->mdl);
        ExFreePool(record->mdl);
        record->mdl = NULL;
    } else if (record->mdl != NULL) {
        IoFreeMdl(record->mdl);
        record->mdl = NULL;
    }
    if (record->backup != NULL) {
        ExFreePoolWithTag(record->backup, KSW_RXPF_BACKUP_TAG);
        record->backup = NULL;
    }
    if (record->currentContent != NULL) {
        ExFreePoolWithTag(record->currentContent, KSW_RXPF_CONTENT_TAG);
        record->currentContent = NULL;
    }
}
