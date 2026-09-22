#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkKernelIoctl.h"
#include "../driver/KswordArkKernelBaselineIoctl.h"
#include "../driver/KswordArkPiDdbIoctl.h"
#include "../driver/KswordArkUnloadedDriverIoctl.h"

namespace ksword::ark
{
    // DriverIntegrityEvidenceEntry is one driver/kernel integrity evidence row.
    // Input: copied from KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE.
    // Processing: evidenceClass groups DriverObject, LDR, FastIo, MajorFunction, CPU,
    // descriptor-table and MSR rows while riskFlags keeps raw R0 findings.
    // Return behavior: plain data object.
    struct DriverIntegrityEvidenceEntry
    {
        std::uint32_t evidenceClass = 0;
        std::uint32_t riskFlags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t confidence = 0;
        std::uint32_t processorGroup = 0;
        std::uint32_t processorNumber = 0;
        std::uint32_t vector = 0;
        std::uint32_t ownerModuleSize = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t ownerModuleBase = 0;
        std::wstring ownerModule;
        std::wstring detail;
        std::uint32_t entryStatus = 0;              // entryStatus: v2 single-line status; older drivers return 0.
        std::uint32_t statusFlags = 0;              // statusFlags: Bit flags for partial/unsupported/PDB required, etc.
        std::uint32_t fieldMask = 0;                // fieldMask: Bitmask of typed fields actually filled in this row.
        std::uint32_t riskScore = 0;                // riskScore: R0 aggregated risk score, 0-100.
        std::uint32_t rangeState = 0;               // rangeState: Position of the target address relative to the associated driver image.
        std::uint32_t ordinal = 0;                  // ordinal: IRP major/FastIo/attached depth, etc.
        std::uint32_t deviceType = 0;               // deviceType: DeviceObject type field.
        std::uint32_t deviceFlags = 0;              // deviceFlags：DeviceObject flags。
        std::uint64_t driverObjectAddress = 0;      // driverObjectAddress: Associated DriverObject.
        std::uint64_t driverStart = 0;              // driverStart：DriverObject.DriverStart。
        std::uint64_t driverSize = 0;               // driverSize：DriverObject.DriverSize。
        std::uint64_t driverSection = 0;            // driverSection：DriverObject.DriverSection。
        std::uint64_t driverUnload = 0;             // driverUnload：DriverObject.DriverUnload。
        std::uint64_t deviceObjectAddress = 0;      // deviceObjectAddress: DeviceObject address.
        std::uint64_t nextDeviceObjectAddress = 0;  // nextDeviceObjectAddress：NextDevice。
        std::uint64_t attachedDeviceObjectAddress = 0; // attachedDeviceObjectAddress：AttachedDevice。
        std::uint64_t deviceDriverObjectAddress = 0; // deviceDriverObjectAddress：DeviceObject.DriverObject。
        std::uint64_t kldrEntryAddress = 0;         // kldrEntryAddress: Address of KLDR_DATA_TABLE_ENTRY.
        std::uint64_t kldrListHeadAddress = 0;      // kldrListHeadAddress: PsLoadedModuleList list head.
        std::uint64_t kldrDllBase = 0;              // kldrDllBase：KLDR.DllBase。
        std::uint32_t kldrSizeOfImage = 0;          // kldrSizeOfImage：KLDR.SizeOfImage。
        std::uint32_t descriptorSelector = 0;       // descriptorSelector: IDT code selector or GDT selector.
        std::uint32_t descriptorType = 0;           // descriptorType: Architecture gate/segment type.
        std::uint32_t descriptorDpl = 0;            // descriptorDpl: descriptor privilege level.
        std::uint32_t descriptorFlags = 0;          // descriptorFlags: KSWORD_ARK_DESCRIPTOR_FLAG_* bits.
        std::uint32_t descriptorSize = 0;           // descriptorSize: descriptor width of 8 or 16 bytes.
        std::uint32_t descriptorTableLimit = 0;     // descriptorTableLimit：IDTR/GDTR limit。
        std::uint64_t descriptorTableBase = 0;      // descriptorTableBase：IDTR/GDTR base。
        std::uint64_t descriptorBase = 0;           // descriptorBase: IDT handler or GDT segment/TSS base.
        std::uint64_t descriptorLimit = 0;          // descriptorLimit: GDT valid limit.
        std::uint64_t descriptorRawLow = 0;         // descriptorRawLow: Raw value of the first 8 bytes.
        std::uint64_t descriptorRawHigh = 0;        // descriptorRawHigh: Last 8 bytes of a 16-byte descriptor.
        std::uint32_t descriptorBaselineFlags = 0;  // descriptorBaselineFlags: Existence and consistency status of the baseline at startup.
        std::uint32_t descriptorBaselineGeneration = 0; // descriptorBaselineGeneration: The baseline generation number created during this driver load.
        std::uint64_t descriptorBaselineHandler = 0; // descriptorBaselineHandler: IDT handler during boot.
        std::uint64_t descriptorBaselineRawLow = 0;  // descriptorBaselineRawLow: Low 8 bytes of the startup entry.
        std::uint64_t descriptorBaselineRawHigh = 0; // descriptorBaselineRawHigh: The high 8 bytes of the startup table entry.
    };

    // IdtBaselineRestoreResult carries an IDT restore preflight or mutation response.
    // The caller must first issue a non-force request and may only force after an
    // explicit UI confirmation while preserving the exact-current descriptor pair.
    struct IdtBaselineRestoreResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_IDT_RESTORE_STATUS_INVALID_REQUEST;
        std::uint32_t baselineGeneration = 0;
        long lastStatus = 0;
        std::uint64_t entryAddress = 0;
        std::uint64_t beforeRawLow = 0;
        std::uint64_t beforeRawHigh = 0;
        std::uint64_t baselineRawLow = 0;
        std::uint64_t baselineRawHigh = 0;
        std::uint64_t afterRawLow = 0;
        std::uint64_t afterRawHigh = 0;
    };

    struct PiDdbEntry
    {
        std::uint64_t entryAddress = 0;
        std::uint32_t timeDateStamp = 0;
        long loadStatus = 0;
        std::wstring driverName;
    };

    struct PiDdbQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT;
        std::uint32_t responseFlags = 0;
        std::uint32_t totalRows = 0;
        long lastStatus = 0;
        std::vector<PiDdbEntry> entries;
    };

    struct PiDdbDeleteResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_PIDDB_DELETE_STATUS_INVALID_REQUEST;
        std::uint32_t remainingRows = 0;
        long lastStatus = 0;
        PiDdbEntry matchedEntry;
    };

    // DriverIntegrityResult carries DriverObject/LDR/CPU integrity evidence.
    // Input: produced by queryDriverIntegrity or queryKernelCpuIntegrity.
    // Processing: unsupported provides graceful UI fallback for older R0 drivers.
    // Return behavior: returned by value with parsed evidence entries.
    struct DriverIntegrityResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE;
        std::uint32_t flags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t fieldFlags = 0;        // fieldFlags: R0 aggregates the evidence field bits actually filled in this response.
        std::uint32_t statusFlags = 0;       // statusFlags: R0 aggregates partial/unsupported/truncated/PDB-required status bits.
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t cpuCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<DriverIntegrityEvidenceEntry> entries;
    };

    // UnloadedDriverEntry: A read-only record after unifying projection from three kernel sources.
    // The HAS_* bits in flags determine which columns display real values in the UI; missing fields are not interpreted as 0.
    struct UnloadedDriverEntry
    {
        std::uint32_t source = 0;
        std::uint32_t flags = 0;
        std::uint64_t entryAddress = 0;
        std::uint64_t baseAddress = 0;
        std::uint64_t imageSize = 0;
        std::uint64_t unloadTime = 0;
        std::uint32_t timeDateStamp = 0;
        long loadStatus = 0;
        std::wstring driverName;
    };

    // UnloadedDriverQueryResult: Transport, business status, and row collection for a query from a specified source.
    // unsupported only indicates that older drivers lack this IOCTL; missing DynData/profile is expressed by queryStatus.
    struct UnloadedDriverQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t source = 0;
        std::uint32_t queryStatus = KSWORD_ARK_UNLOADED_DRIVER_STATUS_INVALID_REQUEST;
        std::uint32_t responseFlags = 0;
        std::uint32_t totalRows = 0;
        std::uint32_t skippedRows = 0;
        long lastStatus = 0;
        std::vector<UnloadedDriverEntry> entries;
    };

    // CpuHardwareSnapshotResult carries the read-only R0 CPUID hardware packet.
    // Input: produced by DriverClient::queryCpuHardwareSnapshot.
    // Processing: featureMask is a stable KSWORD_ARK_CPU_FEATURE_* projection while
    // raw CPUID leaves remain available for diagnostics and future UI expansion.
    // Return behavior: returned by value; unsupported=true means the loaded driver
    // predates IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE.
    struct CpuHardwareSnapshotResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t logicalProcessorCount = 0;
        std::uint32_t activeProcessorCount = 0;
        std::uint32_t packageCount = 0;
        std::uint32_t family = 0;
        std::uint32_t model = 0;
        std::uint32_t stepping = 0;
        std::uint32_t processorType = 0;
        std::uint32_t brandIndex = 0;
        std::uint32_t clflushLineSize = 0;
        std::uint32_t initialApicId = 0;
        std::uint32_t maxBasicLeaf = 0;
        std::uint32_t maxExtendedLeaf = 0;
        long lastStatus = 0;
        std::uint64_t featureMask = 0;
        std::uint64_t leaf1Ecx = 0;
        std::uint64_t leaf1Edx = 0;
        std::uint64_t leaf7Ebx = 0;
        std::uint64_t leaf7Ecx = 0;
        std::uint64_t leaf7Edx = 0;
        std::uint64_t leaf80000001Ecx = 0;
        std::uint64_t leaf80000001Edx = 0;
        std::string vendor;
        std::string brand;
    };

    // SsdtEntry is the R3 model of one kernel SSDT response row.
    struct SsdtEntry
    {
        std::uint32_t serviceIndex = 0;
        std::uint32_t flags = 0;
        std::uint64_t zwRoutineAddress = 0;
        std::uint64_t serviceRoutineAddress = 0;
        std::uint64_t tableEntryAddress = 0;
        std::uint64_t currentTableValue = 0;
        std::uint32_t tableEntrySize = 0;
        std::string serviceName;
        std::string moduleName;
    };

    // SsdtEnumResult carries parsed SSDT rows and response header metadata.
    struct SsdtEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t serviceTableBase = 0;
        std::uint32_t serviceCountFromTable = 0;
        std::vector<SsdtEntry> entries;
    };

    // KernelInlineHookEntry is an R3 model row returned by R0 Inline Hook scanning.
    struct KernelInlineHookEntry
    {
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN; // Row status.
        std::uint32_t hookType = KSWORD_ARK_INLINE_HOOK_TYPE_NONE;    // Hit patch type.
        std::uint32_t flags = 0;                                      // R0 diagnostic flags.
        std::uint32_t originalByteCount = 0;                          // R0 observed baseline byte length; not the raw disk byte length.
        std::uint32_t currentByteCount = 0;                           // Current byte count.
        std::uint64_t functionAddress = 0;                            // Function entry address.
        std::uint64_t targetAddress = 0;                              // Jump/patch target.
        std::uint64_t moduleBase = 0;                                 // Associated module base address.
        std::uint64_t targetModuleBase = 0;                           // Target module base address.
        std::string functionName;                                     // Exported function name.
        std::wstring moduleName;                                      // Name of the owning module.
        std::wstring targetModuleName;                                // Target module name
        std::vector<std::uint8_t> currentBytes;                       // Current function header bytes
        std::vector<std::uint8_t> expectedBytes;                      // Protocol compatibility field: R0 observation baseline, does not represent raw disk bytes.
    };

    // KernelInlineHookScanResult carries the R0 Inline Hook scan response.
    struct KernelInlineHookScanResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<KernelInlineHookEntry> entries;
    };

    // KernelInlinePatchResult carries the R0 Inline Hook removal/repair response.
    struct KernelInlinePatchResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t bytesPatched = 0;
        std::uint32_t fieldFlags = 0;
        long lastStatus = 0;
        std::uint64_t functionAddress = 0;
        std::vector<std::uint8_t> beforeBytes;
        std::vector<std::uint8_t> afterBytes;
    };

    // KernelIatEatHookEntry represents a single R3 model row for kernel module IAT/EAT pointer validation.
    struct KernelIatEatHookEntry
    {
        std::uint32_t hookClass = KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT; // IAT or EAT.
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN; // Row status.
        std::uint32_t flags = 0;                                      // R0 diagnostic flags.
        std::uint32_t ordinal = 0;                                    // Export ordinal or thunk ordinal.
        std::uint64_t moduleBase = 0;                                 // Associated module base address.
        std::uint64_t thunkAddress = 0;                               // IAT thunk or EAT entry address.
        std::uint64_t currentTarget = 0;                              // Current target address.
        std::uint64_t expectedTarget = 0;                             // Expected target address.
        std::uint64_t targetModuleBase = 0;                           // Target module base address.
        std::string functionName;                                     // Function name or placeholder.
        std::wstring moduleName;                                      // Name of the owning module.
        std::wstring importModuleName;                                // IAT: Declared import module name.
        std::wstring targetModuleName;                                // Current target module name
    };

    // KernelIatEatHookScanResult carries the R0 IAT/EAT scan response.
    struct KernelIatEatHookScanResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<KernelIatEatHookEntry> entries;
    };

    // KernelTimerDpcEntry is a read-only snapshot returned from each KPRCB TimerTable in R0.
    struct KernelTimerDpcEntry
    {
        std::uint16_t processorGroup = 0;
        std::uint16_t processorNumber = 0;
        std::uint32_t bucketIndex = 0;
        std::uint32_t flags = 0;
        std::uint32_t timerType = 0;
        std::int32_t period = 0;
        std::int64_t dueTime = 0;
        std::uint64_t timerAddress = 0;
        std::uint64_t dpcAddress = 0;
        std::uint64_t deferredRoutine = 0;
        std::uint64_t deferredContext = 0;
    };

    // KernelTimerDpcEnumResult preserves enumeration integrity markers; UI does not treat partial results as complete snapshots.
    struct KernelTimerDpcEnumResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED;
        std::uint32_t statusFlags = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processorCount = 0;
        std::uint32_t bucketCount = 0;
        std::uint32_t bucketsVisited = 0;
        std::uint32_t corruptBucketCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t duplicateCount = 0;
        long lastStatus = 0;
        std::vector<KernelTimerDpcEntry> entries;
    };

    // DriverMajorFunctionEntry is a single-line model of Phase-9 DriverObject.MajorFunction.
    struct DriverMajorFunctionEntry
    {
        std::uint32_t majorFunction = 0;       // IRP_MJ_* number.
        std::uint32_t flags = 0;               // R0 diagnostic flags.
        std::uint64_t dispatchAddress = 0;     // dispatch entry address, display only.
        std::uint64_t moduleBase = 0;          // Base address of the owning module, display only.
        std::wstring moduleName;               // Name of the owning module.
    };

    // DriverDeviceEntry is a single-line model for Phase-9 DeviceObject/AttachedDevice.
    struct DriverDeviceEntry
    {
        std::uint32_t relationDepth = 0;       // 0 = DriverObject->DeviceObject chain; >0 = AttachedDevice depth.
        std::uint32_t deviceType = 0;          // DEVICE_TYPE。
        std::uint32_t flags = 0;               // DO_* flags。
        std::uint32_t characteristics = 0;     // FILE_DEVICE_* characteristics。
        std::uint32_t stackSize = 0;           // DeviceObject.StackSize。
        std::uint32_t alignmentRequirement = 0;// DeviceObject.AlignmentRequirement。
        long nameStatus = 0;                   // ObQueryNameString status.
        std::uint64_t rootDeviceObjectAddress = 0; // Root DeviceObject.
        std::uint64_t deviceObjectAddress = 0;     // Current DeviceObject.
        std::uint64_t nextDeviceObjectAddress = 0; // NextDevice。
        std::uint64_t attachedDeviceObjectAddress = 0; // AttachedDevice。
        std::uint64_t driverObjectAddress = 0;    // DeviceObject.DriverObject。
        std::wstring deviceName;              // Device object name, which may be null.
        std::uint64_t ioTimerAddress = 0;      // DeviceObject.Timer; Read-only diagnostic address.
    };

    // DriverObjectQueryResult carries the Phase-9 DriverObject/DeviceObject query response.
    struct DriverObjectQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_UNAVAILABLE;
        std::uint32_t fieldFlags = 0;
        std::uint32_t majorFunctionCount = 0;
        std::uint32_t totalDeviceCount = 0;
        std::uint32_t returnedDeviceCount = 0;
        long lastStatus = 0;
        std::uint32_t driverFlags = 0;
        std::uint32_t driverSize = 0;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t driverStart = 0;
        std::uint64_t driverSection = 0;
        std::uint64_t driverUnload = 0;
        std::wstring driverName;
        std::wstring serviceKeyName;
        std::wstring imagePath;
        std::vector<DriverMajorFunctionEntry> majorFunctions;
        std::vector<DriverDeviceEntry> devices;
    };

    // IoTimerControlResult preserves the re-observation of DriverObject/DeviceObject/PIO_TIMER
    // triple identity from R0, treating the input address as a non-dereferenceable handle.
    struct IoTimerControlResult
    {
        IoResult io;                           // io: DeviceIoControl transfer/protocol status.
        bool unsupported = false;              // unsupported: The old driver has not registered the control IOCTL.
        std::uint32_t version = 0;             // version: Response protocol version.
        std::uint32_t status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST; // status: R0 semantic result.
        std::uint32_t action = 0;              // action: Start/stop action echo.
        long lastStatus = 0;                   // lastStatus: Protocol, object, or enumeration NTSTATUS.
        std::uint64_t observedDriverObjectAddress = 0; // observedDriverObjectAddress: Result of re-referencing by name.
        std::uint64_t observedDeviceObjectAddress = 0; // observedDeviceObjectAddress: Result of a device snapshot with reference.
        std::uint64_t observedTimerAddress = 0;        // observedTimerAddress: Public snapshot of DEVICE_OBJECT.Timer.
    };

    // DriverForceUnloadResult carries the R0 DriverObject forced unload response.
    struct DriverForceUnloadResult
    {
        IoResult io;                         // io: DeviceIoControl call status.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNKNOWN; // status: Aggregated unloading status.
        std::uint32_t flags = 0;             // flags: Request flags echo.
        long lastStatus = 0;                 // lastStatus: Status of the unload thread or backend.
        long waitStatus = 0;                 // waitStatus: Status from KeWaitForSingleObject.
        std::uint32_t cleanupFlagsApplied = 0; // cleanupFlagsApplied: R0 actual persistent cleanup flags executed.
        std::uint32_t deletedDeviceCount = 0;  // deletedDeviceCount: Number of DeviceObject instances actually deleted by R0.
        std::uint64_t driverObjectAddress = 0; // driverObjectAddress: Diagnostic address.
        std::uint64_t driverUnloadAddress = 0; // driverUnloadAddress: DriverUnload entry point.
        std::uint32_t callbackCandidates = 0;  // callbackCandidates: Number of callback candidates matched by module base address.
        std::uint32_t callbacksRemoved = 0;    // callbacksRemoved: Number of callbacks successfully removed by R0.
        std::uint32_t callbackFailures = 0;    // callbackFailures: Number of callbacks that failed to remove or are unsupported in R0.
        long callbackLastStatus = 0;           // callbackLastStatus: Status of the last failed callback removal.
        std::uint32_t threadCandidates = 0;    // threadCandidates: Number of system threads resident in the target image.
        std::uint32_t threadsTerminated = 0;   // threadsTerminated: Count of threads that have terminated and been confirmed as exited.
        std::uint32_t threadFailures = 0;      // threadFailures: The number of threads that failed to terminate or wait.
        long threadLastStatus = 0;             // threadLastStatus: Status of the last failed thread processing.
        std::uint32_t detachedDeviceCount = 0; // detachedDeviceCount: Number of upper/lower device associations removed during a forced detach.
        std::wstring driverName;             // driverName: R0 normalized object name.
    };
}
