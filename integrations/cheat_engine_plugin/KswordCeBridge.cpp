#include "KswordCeBridge.h"

#include "../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ksword::ce
{
    namespace
    {
        // BridgeState purpose: Centrally stores CE function slots, original implementations, and the mapping of proxy handles to PIDs.
        struct BridgeState
        {
            std::mutex mutex;
            std::mutex driverIoMutex;
            ExportedFunctions* exportedFunctions = nullptr;
            int pluginId = -1;
            int pointerChangeRegistrationId = -1;
            ReadProcessMemoryFunction originalReadProcessMemory = nullptr;
            WriteProcessMemoryFunction originalWriteProcessMemory = nullptr;
            OpenProcessFunction originalOpenProcess = nullptr;
            VirtualQueryExFunction originalVirtualQueryEx = nullptr;
            ksword::ark::DriverHandle driverHandle;
            std::unordered_map<HANDLE, DWORD> proxyProcessIds;
            bool initialized = false;
            // r1WindowState usage: Whether the R-1 private page table window is available.
            // -1: Not probed, 0: Unavailable, 1: Available. Probe once and cache: The window is established
            // when the driver loads and will not appear or disappear spontaneously. Since CE reads are
            // high-frequency, failing once and rolling back on every read turns each read into two IOCTLs.
            std::atomic<int> r1WindowState{ -1 };
        };

        BridgeState gBridgeState; // g_bridgeState: Unique bridge state within the plugin process.

        const ksword::ark::DriverClient kGDriverClient; // g_driverClient: Unified KSword R3 driver entry point.

        // r1WindowUsable：
        // - Input: None (reads cache; initiates a probe if necessary).
        // - Processing: Query whether the R-1 private page table window is ready and cache the result.
        // - Returns: true if usable.
        bool r1WindowUsable()
        {
            const int kCached =
                gBridgeState.r1WindowState.load(std::memory_order_relaxed);
            if (kCached >= 0)
            {
                return kCached != 0;
            }
            ksword::ark::HvmMemoryResult probe{};
            {
                std::lock_guard<std::mutex> driverLock(
                    gBridgeState.driverIoMutex);
                if (!gBridgeState.driverHandle.isValid())
                {
                    // Do not cache conclusions before the handle is established: this
                    // only means we cannot query now, not that the window does not exist.
                    return false;
                }
                probe = kGDriverClient.hvmMemory(
                    KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
                    0ULL,
                    0ULL,
                    0UL,
                    nullptr,
                    false,
                    false,
                    0UL,
                    &gBridgeState.driverHandle);
            }
            const bool kReady = probe.io.ok &&
                probe.response.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
                probe.response.windowReady != 0;
            gBridgeState.r1WindowState.store(
                kReady ? 1 : 0,
                std::memory_order_relaxed);
            return kReady;
        }

        // readThroughR1：
        // - Input: Target PID, virtual address, buffer, and length.
        // - Processing: Read through the R-1 private page table window; requires actual window access, no fallback allowed.
        // - Returns: true if the full length bytes are read successfully.
        //
        // requireWindow being true is intentional: if R-1 degrades to MmCopyMemory,
        // it offers no advantage over the existing R0 path and adds an extra layer.
        // In that case, the caller should fall back directly to the mature R0 path.
        //
        // uiConfirmed is true because the R-1 memory channel requires explicit confirmation; this plugin is installed
        // by the user and enabled in CE, so the enable action itself serves as that confirmation. The plugin only
        // initiates requests when CE explicitly asks to read a specific address, never reading elsewhere on its own.
        bool readThroughR1(
            const DWORD processId,
            const std::uint64_t address,
            void* const buffer,
            const std::uint32_t length)
        {
            ksword::ark::HvmMemoryResult result{};
            {
                std::lock_guard<std::mutex> driverLock(
                    gBridgeState.driverIoMutex);
                if (!gBridgeState.driverHandle.isValid())
                {
                    return false;
                }
                result = kGDriverClient.hvmMemory(
                    KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
                    address,
                    0ULL,
                    length,
                    nullptr,
                    true,
                    true,
                    static_cast<unsigned long>(processId),
                    &gBridgeState.driverHandle);
            }
            if (!result.io.ok ||
                result.response.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
                result.response.usedDirectWindow == 0 ||
                result.response.bytesTransferred != length)
            {
                return false;
            }
            std::memcpy(buffer, result.response.data, length);
            return true;
        }

        // resolveProcessId：
        // - Input: real process handle or proxy event handle passed by CE.
        // - Processing: Prioritize checking the proxy mapping, then query the real handle, and finally use the current CE PID.
        // - Returns: PID usable for KSword IOCTL; returns 0 if resolution fails.
        DWORD resolveProcessId(const HANDLE processHandle)
        {
            ULONG* openedProcessId = nullptr;
            {
                std::lock_guard<std::mutex> lock(gBridgeState.mutex);
                const auto kProxyIterator =
                    gBridgeState.proxyProcessIds.find(processHandle);
                if (kProxyIterator != gBridgeState.proxyProcessIds.end())
                {
                    return kProxyIterator->second;
                }
                if (gBridgeState.exportedFunctions != nullptr)
                {
                    openedProcessId =
                        gBridgeState.exportedFunctions->openedProcessId;
                }
            }

            // resolvedProcessId usage: Stores the resolution result of GetProcessId on the real handle.
            const DWORD kResolvedProcessId = ::GetProcessId(processHandle);
            if (kResolvedProcessId != 0U)
            {
                return kResolvedProcessId;
            }
            if (openedProcessId != nullptr)
            {
                return static_cast<DWORD>(*openedProcessId);
            }
            return 0U;
        }

        // bridgeOpenProcess：
        // - Input: OpenProcess parameters from CE.
        // - Processing: Request only query/sync permissions; actual memory access is always delegated to KSword R0.
        // - Returns: A restricted real handle or an event handle mapped to the PID.
        HANDLE bridgeOpenProcessImpl(
            const DWORD desiredAccess,
            const BOOL inheritHandle,
            const DWORD processId)
        {
            UNREFERENCED_PARAMETER(desiredAccess);
            OpenProcessFunction originalOpenProcess = nullptr;
            {
                std::lock_guard<std::mutex> lock(gBridgeState.mutex);
                originalOpenProcess = gBridgeState.originalOpenProcess;
            }

            // processHandle usage: Only provides CE with architecture identification, exit waiting, and non-memory capabilities.
            // Do not forward desiredAccess, otherwise CE will re-acquire the user-mode VM_READ/VM_WRITE channel.
            HANDLE processHandle = nullptr;
            if (originalOpenProcess != nullptr)
            {
                processHandle = originalOpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    inheritHandle,
                    processId);
            }
            if (processHandle != nullptr)
            {
                // Explicitly map the PID even if GetProcessId is available to prevent CE from later replacing the handle semantics.
                std::lock_guard<std::mutex> lock(gBridgeState.mutex);
                gBridgeState.proxyProcessIds[processHandle] = processId;
                ::SetLastError(ERROR_SUCCESS);
                return processHandle;
            }

            // proxyHandle: Allows the CE open flow to proceed while delegating actual access to KSword R0.
            HANDLE proxyHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (proxyHandle == nullptr)
            {
                return nullptr;
            }
            {
                std::lock_guard<std::mutex> lock(gBridgeState.mutex);
                gBridgeState.proxyProcessIds[proxyHandle] = processId;
            }
            ::SetLastError(ERROR_SUCCESS);
            return proxyHandle;
        }

        // bridgeReadProcessMemory：
        // - Input: CE target handle, address, output buffer, and length.
        // - Processing: Slice by R0 single-read limit of 1 MiB and read via DriverClient.
        // - Returns: TRUE on full completion; sets ERROR_PARTIAL_COPY on partial copy.
        BOOL bridgeReadProcessMemoryImpl(
            const HANDLE processHandle,
            const LPCVOID baseAddress,
            const LPVOID buffer,
            const SIZE_T bytesToRead,
            SIZE_T* const bytesRead)
        {
            if (bytesRead != nullptr)
            {
                *bytesRead = 0U;
            }
            if (buffer == nullptr || (bytesToRead > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToRead == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesRead usage: Identify the R0 target and accumulate results across fragments.
            const DWORD kProcessId = resolveProcessId(processHandle);
            SIZE_T totalBytesRead = 0U;
            // The R-1 channel supports only 1 KiB per transaction, three orders of magnitude smaller than
            // R0's 1 MiB. Thus, the strategy is not "prefer R-1" but to route based on read characteristics:
            //   - Small reads (pointer tracking, reading a single struct) are precisely the scenarios requiring stealth; 1 KiB is sufficient.
            //   - Large reads (full-memory scans) cannot be hidden anyway. Splitting them into 1
            //     KiB chunks would be three orders of magnitude slower and make CE scanning unusable.
            // The criterion uses the total request length rather than the current fragment: a 4 KiB read should not
            // switch to R-1 just because a fragment happens to be under 1 KiB, as that would split it into four IOCTLs.
            const bool kPreferR1 = bytesToRead <=
                static_cast<SIZE_T>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);
            if (kProcessId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesRead < bytesToRead)
            {
                const SIZE_T kRemainingBytes = bytesToRead - totalBytesRead;
                const SIZE_T kChunkSize = std::min<SIZE_T>(
                    kRemainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_READ_MAX_BYTES));
                const auto kCurrentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesRead;
                // Private page table windows bypass kernel-level hooks; the read content reflects what the page tables actually point to.
                // Silently fall back to R0 when the window is unavailable or the current read
                // fails, so as not to turn an optional enhanced path into a failure cause.
                if (kPreferR1 &&
                    r1WindowUsable() &&
                    readThroughR1(
                        kProcessId,
                        static_cast<std::uint64_t>(kCurrentAddress),
                        static_cast<std::uint8_t*>(buffer) + totalBytesRead,
                        static_cast<std::uint32_t>(kChunkSize)))
                {
                    totalBytesRead += kChunkSize;
                    continue;
                }

                ksword::ark::VirtualMemoryReadResult readResult{};
                {
                    // CE performs concurrent queries/reads; the same synchronized device handle must be used serially.
                    std::lock_guard<std::mutex> driverLock(
                        gBridgeState.driverIoMutex);
                    if (!gBridgeState.driverHandle.isValid())
                    {
                        ::SetLastError(ERROR_INVALID_HANDLE);
                        break;
                    }
                    readResult = kGDriverClient.readVirtualMemory(
                        kProcessId,
                        static_cast<std::uint64_t>(kCurrentAddress),
                        static_cast<std::uint32_t>(kChunkSize),
                        0UL,
                        &gBridgeState.driverHandle);
                }

                // copiedBytes usage: Constrained simultaneously by response count, data array size, and current chunk length.
                const SIZE_T kCopiedBytes = std::min<SIZE_T>(
                    kChunkSize,
                    std::min<SIZE_T>(
                        static_cast<SIZE_T>(readResult.bytesRead),
                        readResult.data.size()));
                if (kCopiedBytes > 0U)
                {
                    std::memcpy(
                        static_cast<std::uint8_t*>(buffer) + totalBytesRead,
                        readResult.data.data(),
                        kCopiedBytes);
                    totalBytesRead += kCopiedBytes;
                }
                if (!readResult.io.ok || kCopiedBytes != kChunkSize)
                {
                    break;
                }
            }

            if (bytesRead != nullptr)
            {
                *bytesRead = totalBytesRead;
            }
            const BOOL kCompleted = totalBytesRead == bytesToRead ? TRUE : FALSE;
            ::SetLastError(kCompleted != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return kCompleted;
        }

        // bridgeWriteProcessMemory：
        // - Input: CE target handle, address, source buffer, and length.
        // - Processing: Chunk writes according to the R0 256 KiB limit and mark them as write operations confirmed by the CE user.
        // - Return: TRUE if all data was written; FORCE is not auto-enabled to preserve driver security boundaries.
        BOOL bridgeWriteProcessMemoryImpl(
            const HANDLE processHandle,
            const LPVOID baseAddress,
            const LPCVOID buffer,
            const SIZE_T bytesToWrite,
            SIZE_T* const bytesWritten)
        {
            if (bytesWritten != nullptr)
            {
                *bytesWritten = 0U;
            }
            if (buffer == nullptr || (bytesToWrite > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToWrite == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesWritten purpose: identify the R0 target and accumulate cross-shard write volume.
            const DWORD kProcessId = resolveProcessId(processHandle);
            SIZE_T totalBytesWritten = 0U;
            if (kProcessId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesWritten < bytesToWrite)
            {
                const SIZE_T kRemainingBytes = bytesToWrite - totalBytesWritten;
                const SIZE_T kChunkSize = std::min<SIZE_T>(
                    kRemainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_WRITE_MAX_BYTES));
                const auto* chunkBegin =
                    static_cast<const std::uint8_t*>(buffer) +
                    totalBytesWritten;
                std::vector<std::uint8_t> chunk(
                    chunkBegin,
                    chunkBegin + kChunkSize);
                const auto kCurrentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesWritten;
                ksword::ark::VirtualMemoryWriteResult writeResult{};
                {
                    std::lock_guard<std::mutex> driverLock(
                        gBridgeState.driverIoMutex);
                    if (!gBridgeState.driverHandle.isValid())
                    {
                        ::SetLastError(ERROR_INVALID_HANDLE);
                        break;
                    }
                    writeResult = kGDriverClient.writeVirtualMemory(
                        kProcessId,
                        static_cast<std::uint64_t>(kCurrentAddress),
                        chunk,
                        KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED,
                        &gBridgeState.driverHandle);
                }

                // currentWritten usage: Limits the driver return value to not exceed the length of the current request.
                const SIZE_T kCurrentWritten = std::min<SIZE_T>(
                    kChunkSize,
                    static_cast<SIZE_T>(writeResult.bytesWritten));
                totalBytesWritten += kCurrentWritten;
                if (!writeResult.io.ok ||
                    writeResult.writeStatus != KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
                    kCurrentWritten != kChunkSize)
                {
                    break;
                }
            }

            if (bytesWritten != nullptr)
            {
                *bytesWritten = totalBytesWritten;
            }
            const BOOL kCompleted =
                totalBytesWritten == bytesToWrite ? TRUE : FALSE;
            ::SetLastError(kCompleted != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return kCompleted;
        }

        // bridgeVirtualQueryEx：
        // - Input: CE target handle, query address, and MEMORY_BASIC_INFORMATION buffer.
        // - Processing: Invoke the KSword R0 ZwQueryVirtualMemory path and convert the fixed response.
        // - Returns: structure size on success; returns 0 on failure.
        SIZE_T bridgeVirtualQueryExImpl(
            const HANDLE processHandle,
            const LPCVOID address,
            PMEMORY_BASIC_INFORMATION const information,
            const SIZE_T informationLength)
        {
            if (information == nullptr ||
                informationLength < sizeof(MEMORY_BASIC_INFORMATION))
            {
                ::SetLastError(ERROR_BAD_LENGTH);
                return 0U;
            }

            // processId/queryResult usage: Resolve the target and retrieve R0 virtual memory region information.
            const DWORD kProcessId = resolveProcessId(processHandle);
            if (kProcessId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return 0U;
            }
            const std::uint64_t kRequestedAddress = static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(address));
            ksword::ark::VirtualMemoryQueryResult queryResult{};
            {
                std::lock_guard<std::mutex> driverLock(
                    gBridgeState.driverIoMutex);
                if (!gBridgeState.driverHandle.isValid())
                {
                    ::SetLastError(ERROR_INVALID_HANDLE);
                    return 0U;
                }
                queryResult = kGDriverClient.queryVirtualMemory(
                    kProcessId,
                    kRequestedAddress,
                    0UL,
                    &gBridgeState.driverHandle);
            }
            if (!queryResult.io.ok ||
                (queryResult.fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT) == 0U ||
                (queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_OK &&
                 queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL))
            {
                ::SetLastError(
                    queryResult.io.win32Error != ERROR_SUCCESS
                        ? queryResult.io.win32Error
                        : ERROR_PARTIAL_COPY);
                return 0U;
            }

            // CE relies on BaseAddress + RegionSize to advance the enumeration cursor. If the driver returns an empty range, an out-of-bounds range,
            // or a range that cannot be narrowed to the current architecture's address space, it must fail rather than cause CE to loop infinitely.
            const std::uint64_t kRegionEnd =
                queryResult.baseAddress + queryResult.regionSize;
            if (queryResult.regionSize == 0U ||
                queryResult.baseAddress > kRequestedAddress ||
                queryResult.baseAddress >
                    (std::numeric_limits<std::uint64_t>::max)() -
                        queryResult.regionSize ||
                kRequestedAddress >= kRegionEnd ||
                queryResult.baseAddress >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<std::uintptr_t>::max)()) ||
                queryResult.allocationBase >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<std::uintptr_t>::max)()) ||
                queryResult.regionSize >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<SIZE_T>::max)()))
            {
                ::SetLastError(ERROR_INVALID_DATA);
                return 0U;
            }

            // result usage: Fully zero-initialize first, then narrow cross-architecture protocol fields to the current CE architecture.
            MEMORY_BASIC_INFORMATION result{};
            result.BaseAddress = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.baseAddress));
            result.AllocationBase = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.allocationBase));
            result.AllocationProtect =
                static_cast<DWORD>(queryResult.allocationProtect);
            result.RegionSize = static_cast<SIZE_T>(queryResult.regionSize);
            result.State = static_cast<DWORD>(queryResult.state);
            result.Protect = static_cast<DWORD>(queryResult.protect);
            result.Type = static_cast<DWORD>(queryResult.type);
            *information = result;
            ::SetLastError(ERROR_SUCCESS);
            return sizeof(MEMORY_BASIC_INFORMATION);
        }

        // The following WINAPI wrapper is the exception boundary for the CE/Lazarus to C++ bridge.
        // Any C++ exception must be converted to a Win32 failure within the DLL; it cannot cross the plugin ABI.
        HANDLE WINAPI bridgeOpenProcess(
            const DWORD desiredAccess,
            const BOOL inheritHandle,
            const DWORD processId) noexcept
        {
            try
            {
                return bridgeOpenProcessImpl(
                    desiredAccess,
                    inheritHandle,
                    processId);
            }
            catch (...)
            {
                ::SetLastError(ERROR_GEN_FAILURE);
                return nullptr;
            }
        }

        BOOL WINAPI bridgeReadProcessMemory(
            const HANDLE processHandle,
            const LPCVOID baseAddress,
            const LPVOID buffer,
            const SIZE_T bytesToRead,
            SIZE_T* const bytesRead) noexcept
        {
            try
            {
                return bridgeReadProcessMemoryImpl(
                    processHandle,
                    baseAddress,
                    buffer,
                    bytesToRead,
                    bytesRead);
            }
            catch (...)
            {
                if (bytesRead != nullptr)
                {
                    *bytesRead = 0U;
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
        }

        BOOL WINAPI bridgeWriteProcessMemory(
            const HANDLE processHandle,
            const LPVOID baseAddress,
            const LPCVOID buffer,
            const SIZE_T bytesToWrite,
            SIZE_T* const bytesWritten) noexcept
        {
            try
            {
                return bridgeWriteProcessMemoryImpl(
                    processHandle,
                    baseAddress,
                    buffer,
                    bytesToWrite,
                    bytesWritten);
            }
            catch (...)
            {
                if (bytesWritten != nullptr)
                {
                    *bytesWritten = 0U;
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
        }

        SIZE_T WINAPI bridgeVirtualQueryEx(
            const HANDLE processHandle,
            const LPCVOID address,
            PMEMORY_BASIC_INFORMATION const information,
            const SIZE_T informationLength) noexcept
        {
            try
            {
                return bridgeVirtualQueryExImpl(
                    processHandle,
                    address,
                    information,
                    informationLength);
            }
            catch (...)
            {
                if (information != nullptr &&
                    informationLength >= sizeof(MEMORY_BASIC_INFORMATION))
                {
                    *information = MEMORY_BASIC_INFORMATION{};
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return 0U;
            }
        }

        // installFunctionPointerHooks: Save the current implementation and atomically overwrite the CE function slot.
        bool installFunctionPointerHooks()
        {
            ExportedFunctions* exportedFunctions =
                gBridgeState.exportedFunctions;
            if (exportedFunctions == nullptr ||
                exportedFunctions->readProcessMemory == nullptr ||
                exportedFunctions->writeProcessMemory == nullptr ||
                exportedFunctions->openProcess == nullptr ||
                exportedFunctions->virtualQueryEx == nullptr)
            {
                return false;
            }

            // Purpose of each slot variable: CE fields store the 'address of the function pointer variable', which must be dereferenced before replacement.
            auto* readSlot = exportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                exportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                exportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                exportedFunctions->virtualQueryEx);
            if (*readSlot != &bridgeReadProcessMemory)
            {
                gBridgeState.originalReadProcessMemory = *readSlot;
                *readSlot = &bridgeReadProcessMemory;
            }
            if (*writeSlot != &bridgeWriteProcessMemory)
            {
                gBridgeState.originalWriteProcessMemory = *writeSlot;
                *writeSlot = &bridgeWriteProcessMemory;
            }
            if (*openSlot != &bridgeOpenProcess)
            {
                gBridgeState.originalOpenProcess = *openSlot;
                *openSlot = &bridgeOpenProcess;
            }
            if (*querySlot != &bridgeVirtualQueryEx)
            {
                gBridgeState.originalVirtualQueryEx = *querySlot;
                *querySlot = &bridgeVirtualQueryEx;
            }
            return true;
        }
    }

    BOOL initializeBridge(
        ExportedFunctions* const exportedFunctions,
        const int pluginId)
    {
        if (exportedFunctions == nullptr ||
            exportedFunctions->sizeofExportedFunctions <
                static_cast<int>(kRequiredExportedFunctionsSize))
        {
            return FALSE;
        }

        // driverHandle usage: verify read/write control handle before initialization; do not modify CE function table on failure.
        auto driverHandle = kGDriverClient.open();
        if (!driverHandle.isValid())
        {
            if (exportedFunctions->showMessage != nullptr)
            {
                char message[] =
                    "KSword CE Bridge: cannot open \\\\.\\KswordARKLog. "
                    "Load the KSword driver first.";
                exportedFunctions->showMessage(message);
            }
            return FALSE;
        }
        {
            std::lock_guard<std::mutex> driverLock(
                gBridgeState.driverIoMutex);
            gBridgeState.driverHandle = std::move(driverHandle);
        }

        // initialize the state and install hooks within the same critical section to prevent the CE worker thread from observing a half-initialized state.
        {
            std::lock_guard<std::mutex> lock(gBridgeState.mutex);
            gBridgeState.exportedFunctions = exportedFunctions;
            gBridgeState.pluginId = pluginId;
            if (!installFunctionPointerHooks())
            {
                gBridgeState.exportedFunctions = nullptr;
                gBridgeState.pluginId = -1;
                std::lock_guard<std::mutex> driverLock(
                    gBridgeState.driverIoMutex);
                gBridgeState.driverHandle.reset();
                return FALSE;
            }
            gBridgeState.initialized = true;
        }

        // The callback registration may synchronously enter CE code; call it outside the bridge mutex to avoid reentrancy deadlocks.
        if (exportedFunctions->registerFunction != nullptr)
        {
            FunctionPointerChangeInitialization initialization{};
            initialization.callbackRoutine = &notifyFunctionPointersChanged;
            const int kRegistrationId = exportedFunctions->registerFunction(
                pluginId,
                PluginType::kFunctionPointerChange,
                &initialization);
            std::lock_guard<std::mutex> lock(gBridgeState.mutex);
            gBridgeState.pointerChangeRegistrationId = kRegistrationId;
        }

        return TRUE;
    }

    BOOL disableBridge()
    {
        UnregisterFunction unregisterFunction = nullptr;
        int pluginId = -1;
        int registrationId = -1;
        {
            std::lock_guard<std::mutex> lock(gBridgeState.mutex);
            if (!gBridgeState.initialized ||
                gBridgeState.exportedFunctions == nullptr)
            {
                return TRUE;
            }

            // On restore, only modify slots still pointing to this plugin to avoid overwriting implementations installed by other plugins later.
            ExportedFunctions* const kExportedFunctions =
                gBridgeState.exportedFunctions;
            auto* readSlot = kExportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                kExportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                kExportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                kExportedFunctions->virtualQueryEx);
            if (readSlot != nullptr && *readSlot == &bridgeReadProcessMemory)
            {
                *readSlot = gBridgeState.originalReadProcessMemory;
            }
            if (writeSlot != nullptr && *writeSlot == &bridgeWriteProcessMemory)
            {
                *writeSlot = gBridgeState.originalWriteProcessMemory;
            }
            if (openSlot != nullptr && *openSlot == &bridgeOpenProcess)
            {
                *openSlot = gBridgeState.originalOpenProcess;
            }
            if (querySlot != nullptr && *querySlot == &bridgeVirtualQueryEx)
            {
                *querySlot = gBridgeState.originalVirtualQueryEx;
            }

            // Save unregistration parameters, then clear the state first; the actual call into CE is placed outside the mutex.
            unregisterFunction = kExportedFunctions->unregisterFunction;
            pluginId = gBridgeState.pluginId;
            registrationId = gBridgeState.pointerChangeRegistrationId;
            gBridgeState.proxyProcessIds.clear();
            gBridgeState.exportedFunctions = nullptr;
            gBridgeState.pluginId = -1;
            gBridgeState.pointerChangeRegistrationId = -1;
            gBridgeState.initialized = false;
        }

        if (registrationId >= 0 && unregisterFunction != nullptr)
        {
            unregisterFunction(pluginId, registrationId);
        }
        {
            std::lock_guard<std::mutex> driverLock(
                gBridgeState.driverIoMutex);
            gBridgeState.driverHandle.reset();
        }
        return TRUE;
    }

    void __stdcall notifyFunctionPointersChanged(const int reserved)
    {
        UNREFERENCED_PARAMETER(reserved);
        std::lock_guard<std::mutex> lock(gBridgeState.mutex);
        if (gBridgeState.initialized)
        {
            (void)installFunctionPointerHooks();
        }
    }
}
