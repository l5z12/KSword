/*++

Module Name:

    slat_iommu_audit_ioctl.c

Abstract:

    METHOD_BUFFERED boundary for the read-only SLAT/IOMMU audit.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

NTSTATUS
kswordArkKernelIoctlQuerySlatIommuAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*outputBuffer),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, sizeof(*outputBuffer));
    *bytesReturned = sizeof(*outputBuffer);
    status = kswordArkSlatIommuAuditQuery(&requestSnapshot, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}
