#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkDriverBlindIoctl.h"
#include "../driver/KswordArkDriverDispatchIoctl.h"
#include "../driver/KswordArkDriverImageEditorIoctl.h"

namespace ksword::ark
{
    // IoctlRegistryEntry holds a single read-only diagnostic row for the KswordARK dispatch registry.
    struct IoctlRegistryEntry
    {
        std::uint32_t ioControlCode = 0;       // ioControlCode: Complete CTL_CODE.
        std::uint32_t functionNumber = 0;      // functionNumber: the function part of CTL_CODE.
        std::uint32_t method = 0;              // method: Transfer modes such as METHOD_BUFFERED.
        std::uint32_t access = 0;              // access：FILE_ANY_ACCESS/READ/WRITE。
        std::uint32_t flags = 0;                // flags：dispatch registry flags。
        std::uint64_t requiredCapability = 0;  // requiredCapability: Threshold for DynData capability.
        std::uint64_t handlerAddress = 0;       // handlerAddress: Optional handler diagnostic address.
        std::string name;                       // name: Fixed name in the registry.
    };

    // IoctlRegistryQueryResult carries the KswordARK-specific IOCTL registry query response.
    struct IoctlRegistryQueryResult
    {
        IoResult io;                            // io: DeviceIoControl transfer status.
        bool unsupported = false;               // unsupported: The old driver has not registered the query IOCTL.
        std::uint32_t version = 0;              // version: protocol version.
        std::uint32_t status = 0;               // status: Complete/truncated status.
        std::uint32_t totalCount = 0;           // totalCount: Total number of rows in the R0 registry.
        std::uint32_t returnedCount = 0;        // returnedCount: Number of rows returned in this call.
        std::uint32_t duplicateCount = 0;       // duplicateCount: Count of duplicate control codes.
        long lastStatus = 0;                    // lastStatus: R0 query status.
        std::vector<IoctlRegistryEntry> entries; // entries: Rows ordered by dispatch sequence.
    };

    // DriverCommunicationControlResult：
    // - Purpose: Carry IRP communication blindness, query, and recovery responses for Issue #47;
    // - Boundary: Only R0 return addresses and masks are shown; R3 does not save or return original dispatch pointers.
    struct DriverCommunicationControlResult
    {
        IoResult io;                              // io: DeviceIoControl transfer and protocol validation status.
        std::uint32_t version = 0;               // version: Response protocol version.
        std::uint32_t action = 0;                // action: QUERY, BLIND, or RESTORE.
        std::uint32_t state = KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE; // state: Current R0 record state.
        std::uint32_t responseFlags = 0;         // responseFlags: Diagnostic flags such as foreign-change.
        long lastStatus = 0;                     // lastStatus: The NTSTATUS of the actual control action.
        std::uint32_t targetedMask = 0;          // targetedMask: The fixed MajorFunction mask managed by this feature.
        std::uint32_t changedMask = 0;           // changedMask: Slots successfully modified or restored in this operation.
        std::uint32_t activeMask = 0;            // activeMask: The slot currently pointing to the system-rejected entry.
        std::uint32_t ownedMask = 0;             // ownedMask: Slots currently still owned by this function with recovery eligibility.
        std::uint32_t conflictMask = 0;          // conflictMask: Slots detected as modified by third parties during recovery.
        std::uint32_t generation = 0;            // generation: The idempotent generation of the target record.
        std::uint64_t driverObjectAddress = 0;   // driverObjectAddress: Read-only diagnostic address.
        std::uint64_t driverStart = 0;           // driverStart: Driver image start address used to verify the module base address.
        std::uint64_t rejectDispatchAddress = 0; // rejectDispatchAddress: System rejection entry point captured by R0.
        std::wstring driverName;                 // driverName: The canonical DriverObject name returned by R0.
    };

    // DriverDispatchControlResult: Result of a single-slot transaction for any DriverObject.MajorFunction.
    // Pointer fields are explicit advanced-editing data; R0 does not restrict the target category or address ownership.
    struct DriverDispatchControlResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t action = 0;
        std::uint32_t state = KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE;
        std::uint32_t responseFlags = 0;
        long lastStatus = 0;
        std::uint32_t majorFunction = 0;
        std::uint32_t generation = 0;
        std::uint64_t targetModuleBase = 0;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t currentDispatchAddress = 0;
        std::uint64_t originalDispatchAddress = 0;
        std::uint64_t appliedDispatchAddress = 0;
        std::uint64_t requestedDispatchAddress = 0;
        std::uint64_t selfDriverObjectAddress = 0;
        std::wstring driverName;
    };

    // DriverImageValues: Five independently selectable DriverObject/KLDR image metadata values.
    // All fields are carried as 64-bit in R3; in R0, only the two natural ULONG fields undergo width checks.
    struct DriverImageValues
    {
        std::uint64_t driverStart = 0;       // driverStart：DriverObject->DriverStart。
        std::uint64_t driverSize = 0;        // driverSize：DriverObject->DriverSize。
        std::uint64_t driverSection = 0;     // driverSection：DriverObject->DriverSection。
        std::uint64_t kldrDllBase = 0;       // kldrDllBase：KLDR_DATA_TABLE_ENTRY.DllBase。
        std::uint64_t kldrSizeOfImage = 0;   // kldrSizeOfImage：KLDR SizeOfImage。
    };

    // DriverImageControlResult: Handles arbitrary driver image fields and PsLoadedModuleList transaction responses.
    // All address, chain, and conflict information comes from R0; R3 does not filter by driver category or value ownership.
    struct DriverImageControlResult
    {
        IoResult io;                         // io: Transport, protocol validation, and NTSTATUS.
        bool unsupported = false;            // unsupported: old driver did not register the new IOCTL.
        std::uint32_t version = 0;            // version: protocol version.
        std::uint32_t action = 0;             // action: Query, apply, hide, restore, or abandon.
        std::uint32_t state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
        std::uint32_t responseFlags = 0;      // responseFlags: Flags for chain, ownership, conflict, and recovery location.
        long lastStatus = 0;                  // lastStatus: Actual transaction NTSTATUS.
        long loaderStatus = 0;                // loaderStatus: Loader layout/resource parsing status.
        std::uint32_t generation = 0;         // generation: CAS transaction generation.
        std::uint32_t managedFieldMask = 0;   // managedFieldMask: Fields that still have recovery records.
        std::uint32_t ownedFieldMask = 0;     // ownedFieldMask: Currently still equal to the applied value.
        std::uint32_t conflictFieldMask = 0;  // conflictFieldMask: Fields modified by third parties.
        std::uint32_t changedFieldMask = 0;   // changedFieldMask: Fields actually changed in this operation.
        std::uint32_t layoutFlags = 0;        // layoutFlags: Source for DynData/export validation.
        std::uint64_t targetModuleBase = 0;   // targetModuleBase: The base address of the first identity module.
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t selfDriverObjectAddress = 0;
        std::uint64_t loaderEntryAddress = 0;
        std::uint64_t listHeadAddress = 0;
        std::uint64_t listResourceAddress = 0;
        std::uint64_t loaderLinkAddress = 0;
        std::uint64_t currentLinkFlink = 0;
        std::uint64_t currentLinkBlink = 0;
        std::uint64_t originalLinkFlink = 0;
        std::uint64_t originalLinkBlink = 0;
        DriverImageValues currentValues;
        DriverImageValues originalValues;
        DriverImageValues appliedValues;
        DriverImageValues requestedValues;
        std::wstring driverName;              // driverName: R0 canonical object name.
    };
}
