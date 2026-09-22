#include "DriverLease.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace ksword::core {
namespace {

constexpr wchar_t kLeaseMutexName[] = L"Local\\KswordARKLight.DriverLease.Mutex.v1";
constexpr wchar_t kLeaseMappingName[] = L"Local\\KswordARKLight.DriverLease.Mapping.v1";
constexpr std::uint32_t kLeaseMagic = 0x4C534B41U; // AKSL
constexpr std::uint32_t kLeaseVersion = 1U;
constexpr std::size_t kMaximumLeases = 32U;

struct LeaseEntry final {
    DWORD processId = 0;
    std::uint64_t creationTime100ns = 0;
};

struct SharedLeaseState final {
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t driverOwnedByLight = 0;
    std::uint32_t reserved = 0;
    std::array<LeaseEntry, kMaximumLeases> leases{};
};

class MutexGuard final {
public:
    explicit MutexGuard(HANDLE mutex) : mutex_(mutex) {
        if (mutex_) {
            const DWORD kWait = ::WaitForSingleObject(mutex_, 5000);
            locked_ = kWait == WAIT_OBJECT_0 || kWait == WAIT_ABANDONED;
        }
    }
    ~MutexGuard() {
        if (locked_) {
            ::ReleaseMutex(mutex_);
        }
    }
    bool locked() const noexcept { return locked_; }
private:
    HANDLE mutex_ = nullptr;
    bool locked_ = false;
};

std::uint64_t fileTimeValue(const FILETIME& value) noexcept {
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return integer.QuadPart;
}

std::uint64_t processCreationTime(HANDLE process) noexcept {
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    return process && ::GetProcessTimes(process, &creation, &exit, &kernel, &user)
        ? fileTimeValue(creation)
        : 0U;
}

bool isEntryAlive(const LeaseEntry& entry) noexcept {
    if (entry.processId == 0 || entry.creationTime100ns == 0) {
        return false;
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.processId);
    if (!process) {
        return false;
    }
    const DWORD kWait = ::WaitForSingleObject(process, 0);
    const std::uint64_t kCreation = processCreationTime(process);
    ::CloseHandle(process);
    return kWait == WAIT_TIMEOUT && kCreation == entry.creationTime100ns;
}

void initializeIfNeeded(SharedLeaseState& state) noexcept {
    if (state.magic == kLeaseMagic && state.version == kLeaseVersion) {
        return;
    }
    std::memset(&state, 0, sizeof(state));
    state.magic = kLeaseMagic;
    state.version = kLeaseVersion;
}

std::size_t compactLiveLeases(SharedLeaseState& state) noexcept {
    std::array<LeaseEntry, kMaximumLeases> live{};
    std::size_t count = 0;
    for (const LeaseEntry& entry : state.leases) {
        if (isEntryAlive(entry) && count < live.size()) {
            live[count++] = entry;
        }
    }
    state.leases = live;
    return count;
}

SharedLeaseState* sharedLeaseState(void* shared) noexcept {
    return static_cast<SharedLeaseState*>(shared);
}

} // namespace

DriverLease::~DriverLease() {
    if (!released_) {
        (void)releaseRequestsStop();
    }
    closeHandles();
}

bool DriverLease::acquire() {
    if (registered_) {
        return true;
    }
    released_ = false;
    processId_ = ::GetCurrentProcessId();
    processCreationTime100ns_ = processCreationTime(::GetCurrentProcess());
    if (processCreationTime100ns_ == 0) {
        return false;
    }

    mutex_ = ::CreateMutexW(nullptr, FALSE, kLeaseMutexName);
    if (!mutex_) {
        closeHandles();
        return false;
    }
    mapping_ = ::CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        static_cast<DWORD>(sizeof(SharedLeaseState)),
        kLeaseMappingName);
    if (!mapping_) {
        closeHandles();
        return false;
    }
    shared_ = ::MapViewOfFile(mapping_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedLeaseState));
    if (!shared_) {
        closeHandles();
        return false;
    }

    bool acquired = false;
    {
        MutexGuard guard(mutex_);
        if (guard.locked()) {
            SharedLeaseState& state = *sharedLeaseState(shared_);
            initializeIfNeeded(state);
            const std::size_t kCount = compactLiveLeases(state);
            for (std::size_t index = 0; index < kCount; ++index) {
                if (state.leases[index].processId == processId_ &&
                    state.leases[index].creationTime100ns == processCreationTime100ns_) {
                    acquired = true;
                    break;
                }
            }
            if (!acquired && kCount < state.leases.size()) {
                state.leases[kCount] = { processId_, processCreationTime100ns_ };
                acquired = true;
            }
        }
    }
    if (!acquired) {
        closeHandles();
        return false;
    }
    registered_ = true;
    return true;
}

void DriverLease::observeStartTransition(const bool runningBefore, const bool runningAfter) {
    if (!registered_ || !DriverLeasePolicy::ownsStartTransition(runningBefore, runningAfter)) {
        return;
    }
    MutexGuard guard(mutex_);
    if (guard.locked() && shared_) {
        SharedLeaseState& state = *sharedLeaseState(shared_);
        initializeIfNeeded(state);
        state.driverOwnedByLight = 1U;
    }
}

void DriverLease::observeExplicitStop() {
    if (!registered_) {
        return;
    }
    MutexGuard guard(mutex_);
    if (guard.locked() && shared_) {
        SharedLeaseState& state = *sharedLeaseState(shared_);
        initializeIfNeeded(state);
        state.driverOwnedByLight = 0U;
    }
}

bool DriverLease::releaseRequestsStop() {
    if (released_) {
        return false;
    }
    released_ = true;
    if (!registered_ || !shared_) {
        registered_ = false;
        return false;
    }

    bool shouldStop = false;
    {
        MutexGuard guard(mutex_);
        if (guard.locked()) {
            SharedLeaseState& state = *sharedLeaseState(shared_);
            initializeIfNeeded(state);
            for (LeaseEntry& entry : state.leases) {
                if (entry.processId == processId_ && entry.creationTime100ns == processCreationTime100ns_) {
                    entry = {};
                }
            }
            const std::size_t kRemaining = compactLiveLeases(state);
            shouldStop = DriverLeasePolicy::shouldStopOnLastRelease(state.driverOwnedByLight != 0U, kRemaining);
            if (shouldStop) {
                state.driverOwnedByLight = 0U;
            }
        }
    }
    registered_ = false;
    return shouldStop;
}

void DriverLease::closeHandles() noexcept {
    if (shared_) {
        ::UnmapViewOfFile(shared_);
        shared_ = nullptr;
    }
    if (mapping_) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }
    if (mutex_) {
        ::CloseHandle(mutex_);
        mutex_ = nullptr;
    }
}

} // namespace Ksword::Core
