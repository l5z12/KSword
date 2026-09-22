/*++ // Declare the driver source file header comment block.

Module Name: // Describes the module name field.

    callback_remove_external.c: Marks the current implementation filename.

Abstract: // Describes the function summary field.

    Implements IOCTL for removing external notify callbacks by callback function address. // Note: This module is used to remove external callbacks by callback function address.

Environment: Field describing the runtime environment.

    Kernel-mode Driver Framework // Indicates the code runs in a Kernel-mode Driver Framework environment.

--*/ // End comment block.

#include "callback_internal.h" // Include internal callback shared declarations.
#define KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL 1 // Enable declaration for complete removal of external callbacks.
#include "callback_external_core.h" // Include external callback safe removal extension declarations.

#define SystemModuleInformation 11 // Declares the system module information class value for ZwQuerySystemInformation.

NTSYSAPI // Declare the kernel-exported ZwQuerySystemInformation routine.
NTSTATUS // Declare function returning NTSTATUS status code.
NTAPI // Declare that the function uses the NTAPI calling convention.
ZwQuerySystemInformation( // Query system-level information buffer.
    _In_ ULONG systemInformationClass, // Input: system information class.
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation, // Output information buffer.
    _In_ ULONG systemInformationLength, // Size of the input information buffer in bytes.
    _Out_opt_ PULONG returnLength // Optional output: required byte count.
    ); // Ends the ZwQuerySystemInformation declaration.

typedef struct KswordArkSystemModuleEntry // Define the system module entry structure.
{ // Start defining the system module item structure.
    HANDLE section; // Records the module section object handle.
    PVOID mappedBase; // Record the module mapped base address.
    PVOID imageBase; // Record the module image base address.
    ULONG imageSize; // Record the module image size.
    ULONG flags; // Record module flags.
    USHORT loadOrderIndex; // Record the load order index.
    USHORT initOrderIndex; // Records the initialization order index.
    USHORT loadCount; // Record load count.
    USHORT offsetToFileName; // Record filename offset.
    UCHAR fullPathName[256]; // ANSI buffer to store the module's full path.
} KswordArkSystemModuleEntry; // Ends the definition of the system module entry structure.

typedef struct KswordArkSystemModuleInformation // Define the system module information structure.
{ // Start defining the system module information structure.
    ULONG numberOfModules; // Record the number of system modules.
    KswordArkSystemModuleEntry modules[1]; // Declare the placeholder for the first element of the module array.
} KswordArkSystemModuleInformation; // Ends the definition of the system module information structure.

typedef VOID // Defines the return type for process callback functions.
(*KswordArkProcessNotifyEx)( // Defines the pointer type for extended process callback functions.
    _Inout_ PEPROCESS process, // Declare process object parameter.
    _In_ HANDLE processId, // Declare process ID parameter.
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo // Declare the create info parameter.
    ); // End of extended process callback function type definition.

typedef VOID // Defines the return type for thread callback functions.
(*KswordArkThreadNotify)( // Defines the thread callback function pointer type.
    _In_ HANDLE processId, // Declare process ID parameter.
    _In_ HANDLE threadId, // Declare the thread ID parameter.
    _In_ BOOLEAN create // Declare the create/exit flag parameter.
    ); // End thread callback function type definition.

typedef VOID // Defines the return type for image callback functions.
(*KswordArkImageNotify)( // Defines the image callback function pointer type.
    _In_opt_ PUNICODE_STRING fullImageName, // Declare the full image path parameter.
    _In_ HANDLE processId, // Declare process ID parameter.
    _In_ PIMAGE_INFO imageInfo // Declare image information parameter.
    ); // End of image callback function type definition.

_Must_inspect_result_ // Caller must inspect the return value.
static // Limits the function visibility to the current compilation unit.
NTSTATUS // Declare function return type as NTSTATUS.
kswordArkCallbackResolveModuleByAddress( // Resolve owning module by callback address.
    _In_ ULONG64 callbackAddress, // Input: callback function address.
    _Out_writes_(modulePathChars) PWCHAR modulePathBuffer, // Output the module path buffer.
    _In_ size_t modulePathChars, // Input module path buffer character count.
    _Out_opt_ ULONG64* moduleBaseOut, // Optional output module base address.
    _Out_opt_ ULONG* moduleSizeOut // Optional output module size.
    ) // End of function parameter list.
{ // Begin module parsing function body.
    NTSTATUS status = STATUS_SUCCESS; // initialize function status value.
    ULONG requiredBytes = 0; // initialize the number of bytes required for the query.
    KswordArkSystemModuleInformation* moduleInfo = NULL; // initialize the module information buffer pointer.
    ULONG moduleIndex = 0; // initialize module traversal index.
    PVOID callbackPointer = (PVOID)(ULONG_PTR)callbackAddress; // Convert address to pointer for comparison.

    if (modulePathBuffer == NULL || modulePathChars == 0U) { // Validate the module path output buffer.
        return STATUS_INVALID_PARAMETER; // Return parameter error when buffer is invalid.
    } // Ends the branch for validating the output buffer parameter.
    modulePathBuffer[0] = L'\0'; // Default: clear the first character of the output path.
    if (moduleBaseOut != NULL) { // Check if module base address output parameter is provided.
        *moduleBaseOut = 0ULL; // Default output base address 0 if unresolved.
    } // End module base address default value branch.
    if (moduleSizeOut != NULL) { // Check if module size output parameter is provided.
        *moduleSizeOut = 0UL; // Default output size 0 if unresolved.
    } // End module size default value branch.

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes); // Query module information length on first attempt.
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) { // Check if the length probe succeeded.
        return STATUS_UNSUCCESSFUL; // Return failure when length probing encounters an anomaly.
    } // End of length probe result judgment branch.

    moduleInfo = (KswordArkSystemModuleInformation*)kswordArkAllocateNonPaged( // Allocate non-paged pool buffer for the module table.
        requiredBytes, // Input required buffer byte count.
        KSWORD_ARK_CALLBACK_TAG_RUNTIME); // Passed-in memory allocation tag.
    if (moduleInfo == NULL) { // Check if allocation of module info buffer succeeded.
        return STATUS_INSUFFICIENT_RESOURCES; // Return insufficient resources on allocation failure.
    } // End memory allocation result check branch.

    status = ZwQuerySystemInformation( // Re-query complete system module information.
        SystemModuleInformation, // Specify the query type as system module information.
        moduleInfo, // Output buffer containing allocated module information.
        requiredBytes, // Provide buffer size.
        &requiredBytes); // Return the actual bytes written or required bytes.
    if (!NT_SUCCESS(status)) { // Check if querying system module information succeeded.
        ExFreePool(moduleInfo); // Free allocated buffer on query failure.
        return status; // Return the system query failure status.
    } // End module information query result branch.

    for (moduleIndex = 0; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) { // Iterate over each system module entry.
        const KswordArkSystemModuleEntry* moduleEntry = // Declare a read-only pointer to the current module entry.
            (const KswordArkSystemModuleEntry*)&moduleInfo->modules[moduleIndex]; // Extract the address of the current indexed module entry.
        const ULONG64 kModuleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase; // Calculate the current module base address.
        const ULONG64 kModuleEnd = kModuleBase + (ULONG64)moduleEntry->imageSize; // Calculate the end address of the current module.
        if ((ULONG64)(ULONG_PTR)callbackPointer < kModuleBase || (ULONG64)(ULONG_PTR)callbackPointer >= kModuleEnd) { // Check if the callback address falls outside the current module range.
            continue; // If not in the current module scope, continue to the next item.
        } // End module address range check branch.

        if (moduleBaseOut != NULL) { // Check if the module base address needs to be output.
            *moduleBaseOut = kModuleBase; // Output: Base address of the matched module.
        } // End module base address output branch.
        if (moduleSizeOut != NULL) { // Check if the module size needs to be output.
            *moduleSizeOut = moduleEntry->imageSize; // Output the size of the matched module.
        } // End module size output branch.
        (VOID)RtlStringCbPrintfW( // Convert the module's full path to a wide-character output.
            modulePathBuffer, // Target output buffer.
            modulePathChars * sizeof(WCHAR), // Target buffer byte size.
            L"%S", // Use an ANSI-to-Unicode formatting template.
            moduleEntry->fullPathName); // Full path of the source module.
        ExFreePool(moduleInfo); // Release module info buffer upon target match.
        return STATUS_SUCCESS; // Successfully resolved the module and returned success.
    } // End module traversal loop.

    ExFreePool(moduleInfo); // Free the buffer if no module was matched.
    return STATUS_NOT_FOUND; // Return module not found status.
} // End address resolution module function.

static VOID
kswordArkCallbackRemoveExSetMessage(
    _Out_writes_(messageChars) PWCHAR messageBuffer,
    _In_ size_t messageChars,
    _In_opt_z_ PCWSTR messageText
    )
/*++

Routine Description:

    Copy a short EX-remove diagnostic message into the fixed shared response.
    The helper always NUL-terminates the destination and accepts NULL text.

Arguments:

    MessageBuffer - Output response message buffer.
    MessageChars - Destination capacity in WCHARs.
    MessageText - Optional message text.

Return Value:

    None.

--*/
{
    if (messageBuffer == NULL || messageChars == 0U) {
        return;
    }

    messageBuffer[0] = L'\0';
    if (messageText == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyNW(messageBuffer, messageChars, messageText, messageChars - 1U);
    messageBuffer[messageChars - 1U] = L'\0';
}

static BOOLEAN
kswordArkCallbackRemoveExClassRequiresCodeModule(
    _In_ ULONG callbackClass
    )
/*++

Routine Description:

    Decide whether callbackAddress must resolve to a loaded kernel module before
    a public remove attempt is allowed. WFP and minifilter rows carry identifiers
    or filter objects, so they intentionally bypass this code-address gate.

Arguments:

    CallbackClass - KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_* value.

Return Value:

    TRUE when callbackAddress is expected to be a kernel code pointer.

--*/
{
    return callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS ||
        callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD ||
        callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE ||
        callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT ||
        callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY ||
        callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
}

static NTSTATUS
kswordArkCallbackRemovePublicApiByPacket(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket
    )
/*++

Routine Description:

    Execute the same documented/safe remove backend that the legacy IOCTL uses,
    but from an already-copied request packet. This keeps EX transport separate
    from METHOD_BUFFERED request parsing and avoids any experimental unlink path.

Arguments:

    RequestPacket - Validated legacy-shaped remove request.
    ResponsePacket - Legacy-shaped response packet used by existing helpers.

Return Value:

    Operation NTSTATUS. Unsupported classes return STATUS_NOT_SUPPORTED or
    STATUS_INVALID_PARAMETER without modifying private kernel lists.

--*/
{
    if (requestPacket == NULL || responsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (requestPacket->callbackClass) {
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS:
    {
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
            (KswordArkProcessNotifyEx)(ULONG_PTR)requestPacket->callbackAddress,
            TRUE);
        if (status == STATUS_PROCEDURE_NOT_FOUND || status == STATUS_INVALID_PARAMETER) {
            status = PsSetCreateProcessNotifyRoutine(
                (PCREATE_PROCESS_NOTIFY_ROUTINE)(ULONG_PTR)requestPacket->callbackAddress,
                TRUE);
        }
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
        return status;
    }

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD:
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
        return PsRemoveCreateThreadNotifyRoutine(
            (KswordArkThreadNotify)(ULONG_PTR)requestPacket->callbackAddress);

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE:
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
        return PsRemoveLoadImageNotifyRoutine(
            (KswordArkImageNotify)(ULONG_PTR)requestPacket->callbackAddress);

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT:
        return kswordArkCallbackExternalRemoveByRequest(requestPacket, responsePacket);

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER:
        return STATUS_NOT_SUPPORTED;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS // Declare the return type of the IOCTL handler function.
kswordArkCallbackIoctlRemoveExternalCallback( // Implement the IOCTL entry point for removing external callbacks.
    _In_ WDFREQUEST request, // Input WDF request object.
    _In_ size_t inputBufferLengthArg, // Input buffer length.
    _In_ size_t outputBufferLengthArg, // Output buffer length.
    _Out_ size_t* completeBytesOut // Output number of completed bytes.
    ) // End of function parameter list.
{ // Begin the body of the IOCTL handler function.
    NTSTATUS status = STATUS_SUCCESS; // initialize the generic status value.
    NTSTATUS operationStatus = STATUS_SUCCESS; // initialize the specific operation status value.
    PVOID inputBuffer = NULL; // initialize the input buffer pointer.
    PVOID outputBuffer = NULL; // initialize the output buffer pointer.
    size_t inputBufferLength = 0; // initialize the actual length of the input buffer.
    size_t outputBufferLength = 0; // initialize the actual length of the output buffer.
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket = NULL; // initialize the request structure pointer.
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket = NULL; // initialize the response structure pointer.
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestCopy; // Cache the full request to avoid METHOD_BUFFERED input/output buffer overwrites.
    ULONG requestVersion = 0UL; // Cache the request protocol version to mitigate the risk of METHOD_BUFFERED overwriting.
    ULONG requestCallbackClass = 0UL; // Cache the request callback class to mitigate the risk of METHOD_BUFFERED overwriting.
    ULONG64 requestCallbackAddress = 0ULL; // Cache the request callback address to mitigate the risk of METHOD_BUFFERED overwriting.
    ULONG64 moduleBase = 0ULL; // initialize the module base address output.
    ULONG moduleSize = 0UL; // initialize the module size output.

    RtlZeroMemory(&requestCopy, sizeof(requestCopy)); // Default clear request copy.

    if (completeBytesOut == NULL) { // Validate the completion bytes output pointer.
        return STATUS_INVALID_PARAMETER; // Returns parameter error if the output pointer is null.
    } // Ends the branch for validating the completed byte count parameter.
    *completeBytesOut = 0U; // Default completion byte count initialized to 0.

    if (inputBufferLengthArg < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST) || // Validate that the input buffer is large enough to hold the request structure.
        outputBufferLengthArg < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE)) { // Validate that the output buffer is large enough to hold the response structure.
        return STATUS_BUFFER_TOO_SMALL; // Return buffer length error when buffer is insufficient.
    } // End input/output length validation branch.

    status = WdfRequestRetrieveInputBuffer( // Retrieve the input buffer from the WDF request.
        request, // Input: Request object
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST), // Specify the minimum input length.
        &inputBuffer, // Output the input buffer address.
        &inputBufferLength); // Output: Actual length of the input buffer.
    if (!NT_SUCCESS(status)) { // Check if input buffer extraction succeeded.
        return status; // Return the error status directly on failure.
    } // End input buffer extraction result branch.

    status = WdfRequestRetrieveOutputBuffer( // Retrieve the output buffer from the WDF request.
        request, // Input: Request object
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE), // Specify the minimum output length.
        &outputBuffer, // Output the output buffer address.
        &outputBufferLength); // Output: Actual length of the output buffer.
    if (!NT_SUCCESS(status)) { // Check if output buffer extraction succeeded.
        return status; // Return the error status directly on failure.
    } // End output buffer extraction result branch.

    requestPacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST*)inputBuffer; // Interpret the input buffer as a request structure.
    responsePacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE*)outputBuffer; // Cast output buffer to response structure.

    if (requestPacket->size < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST) || // Validate the declared size of the request packet.
        requestPacket->version != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION || // Verify if the protocol version matches.
        requestPacket->callbackAddress == 0ULL || // Verify callback address is non-zero.
        requestPacket->flags != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE) { // Validate request flags for correctness.
        return STATUS_INVALID_PARAMETER; // Returns STATUS_INVALID_PARAMETER when the request field is invalid.
    } // Ends the branch for validating request field legality.

    requestVersion = requestPacket->version; // Cache the protocol version first to avoid overwriting input with zeroed output.
    requestCallbackClass = requestPacket->callbackClass; // Cache the callback class first to avoid overwriting input with zeroed output.
    requestCallbackAddress = requestPacket->callbackAddress; // Cache the callback address first to avoid overwriting input with zeroed output.
    requestCopy = *requestPacket; // Save a complete copy of the request for subsequent external submodule removal.
    RtlZeroMemory(responsePacket, sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE)); // Zero out the response structure.
    responsePacket->size = sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE); // Write the response structure size.
    responsePacket->version = requestVersion; // Fill in the protocol version after caching.
    responsePacket->callbackClass = requestCallbackClass; // Fill in the callback class after caching.
    responsePacket->callbackAddress = requestCallbackAddress; // Fill in the callback address after caching.
    responsePacket->moduleBase = 0ULL; // Default module base address is 0.
    responsePacket->moduleSize = 0UL; // Default module size is 0.
    responsePacket->mappingFlags = 0UL; // Default mapping flags are 0.

    // Object Callback cannot be removed safely from a callback-code address.
    // Registry and ETW currently have no verified public removal path either.
    if (requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT ||
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY ||
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER) {
        operationStatus = STATUS_NOT_SUPPORTED;
        goto CompleteRemoveExternalCallback;
    }

    (VOID)kswordArkCallbackResolveModuleByAddress( // Attempt to resolve the module containing the callback address.
        requestCallbackAddress, // Callback address after input buffering.
        responsePacket->modulePath, // Output: Module path buffer.
        RTL_NUMBER_OF(responsePacket->modulePath), // Input module path buffer capacity.
        &moduleBase, // Output: module base address.
        &moduleSize); // Output: module size.
    responsePacket->moduleBase = moduleBase; // Fill in the resolved module base address.
    responsePacket->moduleSize = moduleSize; // Fill in the resolved module size.
    if (responsePacket->modulePath[0] != L'\0') { // Check if a valid module path was parsed.
        responsePacket->mappingFlags = KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE; // Mark module mapping as successful.
    } // End module mapping flag setting branch.

    if (requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS || // Process notify removal must first confirm that the function address falls within the kernel module range.
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD || // Thread notify removal must first verify the function address falls within the kernel module range.
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE || // Image notify removal must first confirm the function address falls within the kernel module range.
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT || // Object callback extension removal must first verify that the function address is valid.
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY || // Registry callback extension removal must first verify the function address is validatable.
        requestCallbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER) { // ETW callback extension removal must first verify the function address is valid.
        if (moduleBase == 0ULL || moduleSize == 0UL) { // If no entry matches in the system module table, refuse to enter any removal path.
            operationStatus = STATUS_INVALID_PARAMETER; // Returns an invalid parameter status to prevent calling the unload API on unverifiable addresses.
            goto CompleteRemoveExternalCallback; // Jump to the unified response and logging path.
        } // End module range validation failure branch.
    } // End requires unified validation of kernel function address categories.

    switch (requestCallbackClass) { // Dispatch removal logic based on the cached callback type.
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS: // Handle process creation callback removal.
        operationStatus = PsSetCreateProcessNotifyRoutineEx( // Prefer calling the Ex version to unload callbacks.
            (KswordArkProcessNotifyEx)(ULONG_PTR)requestCallbackAddress, // Callback address after caching.
            TRUE); // Specify to perform the removal operation.
        if (operationStatus == STATUS_PROCEDURE_NOT_FOUND || operationStatus == STATUS_INVALID_PARAMETER) { // Fallback when Ex version is unavailable or parameters do not match.
            operationStatus = PsSetCreateProcessNotifyRoutine( // Fallback to traditional API for unloading process callbacks.
                (PCREATE_PROCESS_NOTIFY_ROUTINE)(ULONG_PTR)requestCallbackAddress, // Pass the cached callback address with the traditional signature.
                TRUE); // Specify to perform the removal operation.
        } // End process callback rollback logic branch.
        break; // End process callback type processing.

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD: // Handle thread creation callback removal.
        operationStatus = PsRemoveCreateThreadNotifyRoutine( // Call the thread-callback removal API.
            (KswordArkThreadNotify)(ULONG_PTR)requestCallbackAddress); // Thread callback address after caching.
        break; // End thread callback type processing.

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE: // Handle image load callback removal.
        operationStatus = PsRemoveLoadImageNotifyRoutine( // Call the API to remove the image callback.
            (KswordArkImageNotify)(ULONG_PTR)requestCallbackAddress); // Callback address for the image after passing through the buffer.
        break; // End image callback type processing.

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT: // Object callbacks are handled by the external security removal extension.
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY: // Registry callbacks are handled by the external security removal extension.
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER: // Minifilter callbacks prefer paths exposed by the Filter Manager.
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT: // WFP callout callbacks prefer using WFP management APIs.
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER: // ETW provider callbacks are processed only when security-verifiable.
        operationStatus = kswordArkCallbackExternalRemoveByRequest( // Call external callback to safely remove the aggregate function.
            &requestCopy, // Accepts a request copy to prevent METHOD_BUFFERED output zeroing from overwriting input.
            responsePacket); // Pass the response packet to supplement the public API validation result.
        break; // End unsupported type handling.

    default: // Handle unknown callback type.
        operationStatus = STATUS_INVALID_PARAMETER; // Return: Invalid callback type parameter.
        break; // End unknown type handling.
    } // End callback type dispatch branch.

CompleteRemoveExternalCallback: // Unify completion response and logging paths.
    responsePacket->ntstatus = operationStatus; // Fill in the specific operation status code.
    *completeBytesOut = sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE); // Specify the number of output bytes completed.

    kswordArkCallbackLogFormat( // Write the log for the callback removal operation.
        NT_SUCCESS(operationStatus) ? "Info" : "Warn", // Select log level based on the result.
        "External callback remove request: class=%lu, callback=0x%llX, status=0x%08lX.", // Defines the log format string.
        (unsigned long)requestCallbackClass, // Output the cached callback class field.
        requestCallbackAddress, // Output: cached callback address field.
        (unsigned long)operationStatus); // Output: Operation status field.

    return STATUS_SUCCESS; // Return: Status indicating successful IOCTL dispatch execution.
} // Ends the external callback removal IOCTL handler.

static NTSTATUS
kswordArkCallbackRemoveVerifiedObject(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE* responsePacket
    )
/*++

Routine Description:

    Revalidates one profile-gated or explicitly exposed heuristic Object
    Callback row, calls ObUnRegisterCallbacks with the re-enumerated candidate,
    and rebuilds the callback snapshot to confirm the exact row is gone.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN matchPresent = FALSE;
    ULONG matchedFieldFlags = 0UL;
    ULONG64 matchedRegistrationAddress = 0ULL;
    ULONG64 currentGeneration = 0ULL;
    BOOLEAN isPdbCandidate = FALSE;
    BOOLEAN isHeuristicCandidate = FALSE;
    const ULONG kRequiredPdbTrustFlags =
        KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
        KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE |
        KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
    const ULONG kRequiredCommonFieldFlags =
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION;

    if (requestPacket == NULL || responsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    isPdbCandidate = requestPacket->source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE &&
        (requestPacket->trustFlags & kRequiredPdbTrustFlags) == kRequiredPdbTrustFlags &&
        (requestPacket->trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) == 0UL;
    isHeuristicCandidate =
        requestPacket->source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST &&
        (requestPacket->trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0UL &&
        (requestPacket->trustFlags & KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED) != 0UL;

    if ((!isPdbCandidate && !isHeuristicCandidate) ||
        requestPacket->registrationAddress == 0ULL ||
        requestPacket->rawStorageValue == 0ULL ||
        requestPacket->enumerationGeneration == 0ULL ||
        requestPacket->identityHash == 0ULL ||
        requestPacket->operationMask == 0UL ||
        requestPacket->objectTypeMask == 0UL ||
        (requestPacket->flags & KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION) == 0UL ||
        (requestPacket->removeBehavior &
            (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
             KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)) !=
            (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
             KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION) ||
        (isPdbCandidate &&
            (requestPacket->trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0UL)) {
        responsePacket->revalidationStatus = STATUS_INVALID_PARAMETER;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Object Callback removal requires a re-enumerable PDB or heuristic candidate with complete V3 row identity.");
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkCallbackEnumRevalidateObjectRemoveRequest(
        requestPacket,
        TRUE,
        &matchPresent,
        &matchedFieldFlags,
        &matchedRegistrationAddress,
        &currentGeneration);
    responsePacket->revalidationStatus = status;
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            status == STATUS_RETRY
                ? L"Callback snapshot generation changed; refresh enumeration before retrying removal."
                : L"Object Callback re-enumeration failed; no unregister call was made.");
        return status;
    }
    if (!matchPresent ||
        (matchedFieldFlags & kRequiredCommonFieldFlags) != kRequiredCommonFieldFlags ||
        (isPdbCandidate &&
            (matchedFieldFlags &
                (KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
                 KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE)) !=
                (KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
                 KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE)) ||
        (isHeuristicCandidate &&
            (matchedFieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) == 0UL) ||
        matchedRegistrationAddress != requestPacket->registrationAddress) {
        responsePacket->revalidationStatus = STATUS_NOT_FOUND;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Object Callback row identity or re-enumerated registration candidate did not match; no unregister call was made.");
        return STATUS_NOT_FOUND;
    }

    responsePacket->mappingFlags |=
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
    if (isPdbCandidate) {
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED;
    }
    else {
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
    }

    ObUnRegisterCallbacks((PVOID)(ULONG_PTR)matchedRegistrationAddress);

    matchPresent = FALSE;
    status = kswordArkCallbackEnumRevalidateObjectRemoveRequest(
        requestPacket,
        FALSE,
        &matchPresent,
        NULL,
        NULL,
        &currentGeneration);
    responsePacket->revalidationStatus = status;
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"ObUnRegisterCallbacks was called, but the confirmation enumeration failed.");
        return status;
    }
    if (matchPresent) {
        responsePacket->revalidationStatus = STATUS_UNSUCCESSFUL;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"ObUnRegisterCallbacks returned, but the exact Object Callback row is still present.");
        return STATUS_UNSUCCESSFUL;
    }

    responsePacket->revalidationStatus = STATUS_SUCCESS;
    kswordArkCallbackRemoveExSetMessage(
        responsePacket->message,
        RTL_NUMBER_OF(responsePacket->message),
        isPdbCandidate
            ? L"Object Callback RegistrationHandle was revalidated, unregistered, and confirmed absent by re-enumeration."
            : L"Heuristic Object Callback candidate was re-enumerated, unregistered, and confirmed absent.");
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackIoctlRemoveExternalCallbackEx(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLengthArg,
    _In_ size_t outputBufferLengthArg,
    _Out_ size_t* completeBytesOut
    )
/*++

Routine Description:

    Handle the extended callback-remove protocol. EX requests carry the enum
    source, trust bits, generation, identity hash and explicit remove behavior.
    This first implementation intentionally supports only the documented public
    API path; experimental unlink is rejected in-band and never executed as a
    fallback.

Arguments:

    Request - Current WDF request.
    InputBufferLength - Input request size from dispatch.
    OutputBufferLength - Output response size from dispatch.
    CompleteBytesOut - Receives sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE).

Return Value:

    STATUS_SUCCESS when the IOCTL request was handled and a semantic NTSTATUS is
    present in response.ntstatus. Buffer/packet validation errors are returned
    directly before a response is produced.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t inputBufferLength = 0U;
    size_t outputBufferLength = 0U;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* requestPacket = NULL;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE* responsePacket = NULL;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST requestCopy;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST legacyRequest;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE legacyResponse;
    ULONG64 moduleBase = 0ULL;
    ULONG moduleSize = 0UL;

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlZeroMemory(&legacyRequest, sizeof(legacyRequest));
    RtlZeroMemory(&legacyResponse, sizeof(legacyResponse));

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (inputBufferLengthArg < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST) ||
        outputBufferLengthArg < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST),
        &inputBuffer,
        &inputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE),
        &outputBuffer,
        &outputBufferLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    requestPacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST*)inputBuffer;
    if (requestPacket->size < sizeof(KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST) ||
        requestPacket->version != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION ||
        requestPacket->callbackClass == 0UL ||
        requestPacket->callbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    requestCopy = *requestPacket;
    responsePacket = (KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE*)outputBuffer;
    RtlZeroMemory(responsePacket, sizeof(*responsePacket));
    responsePacket->size = sizeof(*responsePacket);
    responsePacket->version = requestCopy.version;
    responsePacket->callbackClass = requestCopy.callbackClass;
    responsePacket->source = requestCopy.source;
    responsePacket->callbackAddress = requestCopy.callbackAddress;
    responsePacket->registrationAddress = requestCopy.registrationAddress;
    responsePacket->rawStorageValue = requestCopy.rawStorageValue;
    responsePacket->enumerationGeneration = requestCopy.enumerationGeneration;
    responsePacket->identityHash = requestCopy.identityHash;
    responsePacket->trustFlags = requestCopy.trustFlags;
    responsePacket->removeBehavior = requestCopy.removeBehavior;
    responsePacket->ntstatus = STATUS_UNSUCCESSFUL;
    responsePacket->revalidationStatus = STATUS_NOT_SUPPORTED;
    responsePacket->mappingFlags = 0UL;
    *completeBytesOut = sizeof(*responsePacket);

    if ((requestCopy.flags &
        ~(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK |
          KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION)) != 0UL) {
        operationStatus = STATUS_INVALID_PARAMETER;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"REMOVE_EXTERNAL_CALLBACK_EX contains unsupported flags.");
        goto CompleteRemoveExternalCallbackEx;
    }
    if (requestCopy.callbackClass != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT &&
        (requestCopy.trustFlags & KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE) != 0UL) {
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED;
    }
    if ((requestCopy.flags & KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK) != 0UL ||
        (requestCopy.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0UL) {
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
        operationStatus = STATUS_NOT_SUPPORTED;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Experimental unlink is intentionally not implemented in R0; no private list or array was modified.");
        goto CompleteRemoveExternalCallbackEx;
    }

    if ((requestCopy.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) == 0UL) {
        operationStatus = STATUS_NOT_SUPPORTED;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"REMOVE_EXTERNAL_CALLBACK_EX request did not ask for a supported public API remove path.");
        goto CompleteRemoveExternalCallbackEx;
    }

    if (requestCopy.callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY ||
        requestCopy.callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER) {
        operationStatus = STATUS_NOT_SUPPORTED;
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Removal is disabled for Registry and ETW callbacks because no reliable public path is available.");
        goto CompleteRemoveExternalCallbackEx;
    }

    if (kswordArkCallbackRemoveExClassRequiresCodeModule(requestCopy.callbackClass)) {
        status = kswordArkCallbackResolveModuleByAddress(
            requestCopy.callbackAddress,
            responsePacket->modulePath,
            RTL_NUMBER_OF(responsePacket->modulePath),
            &moduleBase,
            &moduleSize);
        if (!NT_SUCCESS(status)) {
            operationStatus = STATUS_INVALID_PARAMETER;
            responsePacket->revalidationStatus = status;
            kswordArkCallbackRemoveExSetMessage(
                responsePacket->message,
                RTL_NUMBER_OF(responsePacket->message),
                L"Callback address did not resolve to a loaded kernel module; public remove was refused.");
            goto CompleteRemoveExternalCallbackEx;
        }

        responsePacket->moduleBase = moduleBase;
        responsePacket->moduleSize = moduleSize;
        responsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE;
        responsePacket->revalidationStatus = STATUS_SUCCESS;
    }
    else {
        responsePacket->revalidationStatus = STATUS_SUCCESS;
    }

    if (requestCopy.callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT) {
        operationStatus = kswordArkCallbackRemoveVerifiedObject(&requestCopy, responsePacket);
        goto CompleteRemoveExternalCallbackEx;
    }

    legacyRequest.size = sizeof(legacyRequest);
    legacyRequest.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    legacyRequest.callbackClass = requestCopy.callbackClass;
    legacyRequest.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
    legacyRequest.callbackAddress = requestCopy.callbackAddress;

    legacyResponse.size = sizeof(legacyResponse);
    legacyResponse.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    legacyResponse.callbackClass = requestCopy.callbackClass;
    legacyResponse.callbackAddress = requestCopy.callbackAddress;
    legacyResponse.moduleBase = responsePacket->moduleBase;
    legacyResponse.moduleSize = responsePacket->moduleSize;
    legacyResponse.mappingFlags = responsePacket->mappingFlags;
    kswordArkCallbackEnumCopyWide(
        legacyResponse.modulePath,
        RTL_NUMBER_OF(legacyResponse.modulePath),
        responsePacket->modulePath);

    operationStatus = kswordArkCallbackRemovePublicApiByPacket(&legacyRequest, &legacyResponse);
    responsePacket->moduleBase = legacyResponse.moduleBase;
    responsePacket->moduleSize = legacyResponse.moduleSize;
    responsePacket->mappingFlags = legacyResponse.mappingFlags |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API |
        (responsePacket->mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED);
    kswordArkCallbackEnumCopyWide(
        responsePacket->modulePath,
        RTL_NUMBER_OF(responsePacket->modulePath),
        legacyResponse.modulePath);
    kswordArkCallbackEnumCopyWide(
        responsePacket->serviceName,
        RTL_NUMBER_OF(responsePacket->serviceName),
        legacyResponse.serviceName);
    if (NT_SUCCESS(operationStatus)) {
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Public API remove path completed. Experimental unlink was not used.");
    }
    else if (operationStatus == STATUS_NOT_SUPPORTED) {
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Public API remove path is not yet supported for this callback class; no unlink fallback was executed.");
    }
    else {
        kswordArkCallbackRemoveExSetMessage(
            responsePacket->message,
            RTL_NUMBER_OF(responsePacket->message),
            L"Public API remove path returned a failure NTSTATUS; no unlink fallback was executed.");
    }

CompleteRemoveExternalCallbackEx:
    responsePacket->ntstatus = operationStatus;

    kswordArkCallbackLogFormat(
        NT_SUCCESS(operationStatus) ? "Info" : "Warn",
        "External callback remove EX request: class=%lu, source=%lu, callback=0x%llX, registration=0x%llX, behavior=0x%lX, status=0x%08lX.",
        (unsigned long)requestCopy.callbackClass,
        (unsigned long)requestCopy.source,
        requestCopy.callbackAddress,
        requestCopy.registrationAddress,
        (unsigned long)requestCopy.removeBehavior,
        (unsigned long)operationStatus);

    return STATUS_SUCCESS;
}
