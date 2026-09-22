#pragma once

// ============================================================
// DiskMonitorStorageLeaseCoordinator.h
// Purpose:
// 1) Provides a volume-unique performance counter lease for the disk storage page.
// 2) Delegate IOCTL_DISK_PERFORMANCE_OFF to a single background worker.
// 3) Retain a bounded, retryable process ledger when OFF persists in failure.
// ============================================================

#include <QString>

#include <array>
#include <cstdint>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace disk_monitor_storage_lease
{
    // Lease：
    // - Created by the coordinator and held uniquely by volume GUID.
    // - Active state is read/written by the sampling thread; after retirement, only the coordinator worker may access it.
    // - ownedEnableReferenceCount precisely tracks the number of OFF compensations required by this process.
    struct Lease
    {
        QString volumeGuidName;               // volumeGuidName: Normalized volume GUID path.
        QString storageManagerName;           // storageManagerName: Performance provider name.
        std::array<std::uint16_t, 8> storageManagerIdentity{}; // storageManagerIdentity: Original provider identity.
        std::uint32_t volumeSerialNumber = 0U; // volumeSerialNumber: Volume serial number.
        std::uint32_t storageDeviceNumber = 0U; // storageDeviceNumber: Performance provider device number.
        HANDLE volumeHandle = INVALID_HANDLE_VALUE; // volumeHandle: Volume handle shared by performance queries and OFF.
        std::uint32_t ownedEnableReferenceCount = 0U; // ownedEnableReferenceCount: The reference count for this process that still requires OFF.
        std::uint32_t lastQueryError = 0U;     // lastQueryError: Last query or balance error.
        std::uint32_t consecutiveQueryFailureCount = 0U; // consecutiveQueryFailureCount: Number of consecutive query failures.
    };

    using LeasePointer = std::shared_ptr<Lease>;

    // tryAcquireActiveLease：
    // - Input: volume GUID before or after normalization;
    // - Return: Returns a unique lease if the volume has no active/retiring slots; otherwise returns null.
    // - Caller must insert the lease into the active table after acquiring it, or call releaseUnusedActiveLease.
    LeasePointer tryAcquireActiveLease(const QString& volumeGuidName);

    // releaseUnusedActiveLease：
    // - Input: active lease that has not yet successfully acquired a performance reference;
    // - Handling: Remove the volume placeholder without executing OFF and without closing handles still held by the caller.
    // - Returns true if the slot matches the provided lease.
    bool releaseUnusedActiveLease(const LeasePointer& lease);

    // retireLeaseAsync：
    // - Input: Active lease requiring compensation for ownedEnableReferenceCount and diagnostic reason;
    // - Processing: Atomically switch to 'retiring' state and wake the unique background worker.
    // - Returns: true if takeover succeeded or the same lease was already retired; no synchronous OFF is performed.
    bool retireLeaseAsync(
        const LeasePointer& lease,
        const QString& reason);

    // turnOffOneReference：
    // - Input: lease and optional error code output.
    // - Processing: Compensate only once for the performance enable reference owned by this process.
    // - Returns: true if no compensation is needed or if the current OFF operation succeeds.
    bool turnOffOneReference(
        Lease* lease,
        DWORD* errorOut = nullptr);
}
