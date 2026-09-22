#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"

namespace ksword::ark
{
    // DebugOutputControlResult stores the registration, capture, and discard status of the R0 debug output callback.
    struct DebugOutputControlResult
    {
        IoResult io;                         // io: DeviceIoControl and fixed-response parsing status.
        bool unsupported = false;            // unsupported: The current driver has not registered the debug output IOCTL.
        std::uint32_t version = 0;           // version: Shared protocol version.
        std::uint32_t runtimeFlags = 0;      // runtimeFlags：REGISTERED/CAPTURING/DROPPED。
        std::uint32_t ringCapacity = 0;      // ringCapacity: Capacity of the fixed R0 ring buffer.
        std::uint32_t queuedCount = 0;       // queuedCount: Number of records currently available for reading.
        std::uint64_t latestSequence = 0;    // latestSequence: Most recently submitted monotonic sequence number.
        std::uint64_t droppedCount = 0;      // droppedCount: Cumulative drop count during high IRQL concurrent writes.
        long registrationStatus = 0;         // registrationStatus: status of DbgSetDebugPrintCallback.
        long lastStatus = 0;                 // lastStatus: NTSTATUS of the most recent control action.
    };

    // DebugOutputRecord: A kernel debug message that has been stably copied to R3.
    struct DebugOutputRecord
    {
        std::uint64_t sequence = 0;          // sequence: R0 monotonic sequence number.
        std::uint64_t interruptTime100ns = 0;// interruptTime100ns: timestamp from KeQueryInterruptTime.
        std::uint32_t componentId = 0;       // componentId: Component ID for DbgPrintEx.
        std::uint32_t level = 0;             // level: DbgPrintEx level.
        std::uint32_t flags = 0;             // flags: Record flags such as TEXT_TRUNCATED.
        std::string text;                    // text: UTF-8/ANSI debug text copied according to protocol length.
    };

    // DebugOutputDrainResult: The result of reading the debug output circular buffer incrementally by cursor.
    struct DebugOutputDrainResult
    {
        IoResult io;                         // io: DeviceIoControl and variable-length response parsing status.
        bool unsupported = false;            // unsupported: The current driver does not support this IOCTL.
        std::uint32_t runtimeFlags = 0;      // runtimeFlags: current callback runtime flags.
        std::uint32_t responseFlags = 0;     // responseFlags：OVERFLOW/MORE/SNAPSHOT_RACE。
        std::uint32_t ringCapacity = 0;      // ringCapacity: R0 ring capacity.
        std::uint64_t firstAvailableSequence = 0; // firstAvailableSequence: Earliest sequence number not yet overwritten.
        std::uint64_t latestSequence = 0;    // latestSequence: Latest sequence number when reading the snapshot.
        std::uint64_t nextSequence = 0;      // nextSequence: The cursor that the next request should carry.
        std::uint64_t droppedCount = 0;      // droppedCount: Cumulative drop count from callback try-lock.
        std::uint64_t lostBeforeFirst = 0;   // lostBeforeFirst: Number of overwrites caused by the caller's cursor lagging behind.
        std::vector<DebugOutputRecord> records; // records: Ascending records successfully parsed in this session.
    };
}
