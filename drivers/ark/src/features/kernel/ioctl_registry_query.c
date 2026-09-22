/*++

Module Name:

    ioctl_registry_query.c

Abstract:

    Read-only export of the KswordARK static IOCTL registry.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_registry.h"
#include "../../dispatch/ioctl_validation.h"

// Note: Safely copy the static registry name into the fixed protocol field.
static VOID
kswordArkCopyIoctlRegistryName(
    _Out_writes_(destinationChars) PCHAR destination,
    _In_ SIZE_T destinationChars,
    _In_opt_z_ PCSTR source
    )
{
    // Note: Use an independent index to ensure all exit paths retain the terminating null character.
    SIZE_T characterIndex = 0U;

    // Note: Invalid target buffers cannot be written to; return immediately.
    if (destination == NULL || destinationChars == 0U) {
        return;
    }

    // Note: Clear the first character first so a NULL source yields an empty string.
    destination[0] = '\0';

    // Note: An empty source was already represented as an empty string in the previous step.
    if (source == NULL) {
        return;
    }

    // Note: Copy at most DestinationChars - 1 characters to avoid buffer overflow.
    while ((characterIndex + 1U) < destinationChars && source[characterIndex] != '\0') {
        destination[characterIndex] = source[characterIndex];
        characterIndex += 1U;
    }

    // Note: Always write the terminating null character to facilitate fixed-length parsing by R3.
    destination[characterIndex] = '\0';
}

// Note: Handle read-only IOCTL registry queries; business data comes directly from the unified dispatch registry.
NTSTATUS
kswordArkKernelIoctlQueryIoctlRegistry(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Note: Validate the request version and output budget, then return the control code, name, capabilities, flags, and handler address.

Arguments:

    Device: WDF device object; this query does not modify device state.
    Request - current WDF request.
    InputBufferLength - Input length provided by R3.
    OutputBufferLength - Output length provided by R3.
    BytesReturned - actual number of bytes returned.

Return Value:

    Returns STATUS_SUCCESS or an error for invalid parameters or buffer validation.

--*/
{
    // Note: requestPointer points to METHOD_BUFFERED input; copy before clearing output.
    KSWORD_ARK_QUERY_IOCTL_REGISTRY_REQUEST* requestPointer = NULL;
    // Note: requestCopy preserves validated fixed inputs to prevent input/output sharing SystemBuffer.
    KSWORD_ARK_QUERY_IOCTL_REGISTRY_REQUEST requestCopy;
    // Note: outputBuffer receives the output buffer address validated by WDF.
    PVOID outputBuffer = NULL;
    // Note: response points to the protocol response header and trailing array.
    KSWORD_ARK_QUERY_IOCTL_REGISTRY_RESPONSE* response = NULL;
    // Note: actualInputLength stores the actual input length returned by WDF.
    size_t actualInputLength = 0U;
    // Note: actualOutputLength stores the actual output capacity returned by WDF.
    size_t actualOutputLength = 0U;
    // Note: capacityCount is the number of rows the output buffer can hold.
    ULONG capacityCount = 0UL;
    // Note: requestedCount is the target row count after R3 limiting.
    ULONG requestedCount = 0UL;
    // Note: returnedCount is the final number of rows written.
    ULONG returnedCount = 0UL;
    // Note: totalCount is the total row count of the static registry.
    ULONG totalCount = 0UL;
    // Note: entryIndex iterates over stable registry indices.
    ULONG entryIndex = 0UL;
    // Note: status holds the WDF validation state.
    NTSTATUS status = STATUS_SUCCESS;

    // Note: This parameter exists solely to unify the handler signature; actual capacity is re-validated by WDF.
    UNREFERENCED_PARAMETER(device);
    // Note: Input minimum length is re-confirmed by a unified WDF helper.
    UNREFERENCED_PARAMETER(inputBufferLength);
    // Note: This parameter exists solely to unify the handler signature; actual capacity is re-validated by WDF.
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Note: The caller must provide an address for the completed byte count.
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Note: All failure paths default to not returning response bytes.
    *bytesReturned = 0U;

    // Note: Read fixed request and reject short input.
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_IOCTL_REGISTRY_REQUEST),
        (PVOID*)&requestPointer,
        &actualInputLength);
    // Note: Return status as-is if WDF input validation fails.
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Note: The METHOD_BUFFERED output area can only be cleared after copying the input.
    RtlCopyMemory(&requestCopy, requestPointer, sizeof(requestCopy));

    // Note: Accept only the current protocol version to prevent field layout misinterpretation.
    if (requestCopy.version != KSWORD_ARK_IOCTL_REGISTRY_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    // Note: Output must accommodate at least the fixed response header.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_IOCTL_REGISTRY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    // Note: Return status as-is if WDF output validation fails.
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Note: Clear the entire output to avoid leaking uninitialized kernel bytes.
    RtlZeroMemory(outputBuffer, actualOutputLength);
    // Note: The response header is located at the start of the output buffer.
    response = (KSWORD_ARK_QUERY_IOCTL_REGISTRY_RESPONSE*)outputBuffer;
    // Note: Calculate the actual capacity of the trailing array.
    capacityCount = (ULONG)((actualOutputLength - KSWORD_ARK_IOCTL_REGISTRY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_IOCTL_REGISTRY_ENTRY));
    // Note: Retrieve the total count of elements in the unified dispatch registry.
    totalCount = kswordArkGetRegisteredIoctlCount();
    // Note: 0 indicates using the protocol limit; other values are capped at the protocol limit.
    requestedCount = requestCopy.maxEntries == 0UL
        ? KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES
        : min(requestCopy.maxEntries, KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES);
    // Note: The final row count is constrained by the total count, the requested budget, and the output capacity.
    returnedCount = min(totalCount, min(requestedCount, capacityCount));

    // Note: Fill the fixed response summary.
    response->version = KSWORD_ARK_IOCTL_REGISTRY_PROTOCOL_VERSION;
    // Note: Explicitly mark truncation when the return is incomplete.
    response->status = returnedCount < totalCount
        ? KSWORD_ARK_IOCTL_REGISTRY_STATUS_TRUNCATED
        : KSWORD_ARK_IOCTL_REGISTRY_STATUS_OK;
    // Note: Save the total number of registry rows.
    response->totalCount = totalCount;
    // Note: Save the actual number of rows returned this time.
    response->returnedCount = returnedCount;
    // Note: Publish the trailing structure size for strict R3 validation.
    response->entrySize = (ULONG)sizeof(KSWORD_ARK_IOCTL_REGISTRY_ENTRY);
    // Note: Publish duplicate IOCTL diagnostic count.
    response->duplicateCount = kswordArkGetDuplicateIoctlCount();
    // Note: lastStatus is STATUS_SUCCESS when the query itself succeeds.
    response->lastStatus = STATUS_SUCCESS;

    // Note: Copy read-only registration information in static array order.
    for (entryIndex = 0UL; entryIndex < returnedCount; ++entryIndex) {
        // Note: Retrieve a read-only registry entry by index.
        const KswordArkIoctlEntry* sourceEntry = kswordArkGetIoctlEntryByIndex(entryIndex);
        // Note: destinationEntry points to the current protocol output row.
        KSWORD_ARK_IOCTL_REGISTRY_ENTRY* destinationEntry = &response->entries[entryIndex];

        // Note: Theoretically, the index is constrained by totalCount; stop and report truncation when NULL.
        if (sourceEntry == NULL) {
            response->returnedCount = entryIndex;
            response->status = KSWORD_ARK_IOCTL_REGISTRY_STATUS_TRUNCATED;
            returnedCount = entryIndex;
            break;
        }

        // Note: Copy complete control code.
        destinationEntry->ioControlCode = sourceEntry->ioControlCode;
        // Note: Extract the 12-bit function number from CTL_CODE.
        destinationEntry->functionNumber = (sourceEntry->ioControlCode >> 2U) & 0x0FFFUL;
        // Note: Extract the transfer method from CTL_CODE.
        destinationEntry->method = sourceEntry->ioControlCode & 0x3UL;
        // Note: Extract access requirements from CTL_CODE.
        destinationEntry->access = (sourceEntry->ioControlCode >> 14U) & 0x3UL;
        // Note: Copy dispatch registry flags.
        destinationEntry->flags = sourceEntry->flags;
        // Note: Copy DynData capability threshold bitmap.
        destinationEntry->requiredCapability = sourceEntry->requiredCapability;
        // Note: returns the handler diagnostic address only when explicitly permitted by the request.
        destinationEntry->handlerAddress =
            (requestCopy.flags & KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER) != 0UL
            ? (ULONG64)(ULONG_PTR)sourceEntry->handler
            : 0ULL;
        // Note: Copy a fixed-length readable IOCTL name.
        kswordArkCopyIoctlRegistryName(
            destinationEntry->name,
            KSWORD_ARK_IOCTL_REGISTRY_NAME_CHARS,
            sourceEntry->name);
    }

    // Note: Returns the exact byte count for the fixed header and actual rows.
    *bytesReturned = KSWORD_ARK_IOCTL_REGISTRY_RESPONSE_HEADER_SIZE +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_IOCTL_REGISTRY_ENTRY));
    // Note: Protocol-level truncation remains a success response, expressed via the status field.
    return STATUS_SUCCESS;
}
