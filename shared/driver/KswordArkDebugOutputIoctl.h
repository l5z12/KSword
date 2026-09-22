#pragma once

#include "KswordArkDynDataIoctl.h"

// ============================================================
// KswordArkDebugOutputIoctl.h
// Purpose:
// - Defines the protocol for capturing kernel DbgPrint/DbgPrintEx/KdPrintEx output.
// - R0 writes to a fixed circular buffer via DbgSetDebugPrintCallback;
// - R3 controls capture and reads snapshots in order solely through ArkDriverClient.
// ============================================================

#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS 0x0001
#endif

#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif

#define KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_DEBUG_OUTPUT_CONTROL 0x8F8UL
#define KSWORD_ARK_IOCTL_FUNCTION_DEBUG_OUTPUT_DRAIN   0x8F9UL

// Debug output may contain kernel addresses or device state, so both IOCTLs require read/write handles.
#define IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DEBUG_OUTPUT_CONTROL, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DEBUG_OUTPUT_DRAIN, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// Control actions: START clears old snapshots and registers callbacks; STOP unregisters; QUERY reads status only.
#define KSWORD_ARK_DEBUG_OUTPUT_ACTION_START 1UL
#define KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP  2UL
#define KSWORD_ARK_DEBUG_OUTPUT_ACTION_QUERY 3UL

// Runtime status bits: used by R3 to distinguish registered, capturing, and dropped states.
#define KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_REGISTERED 0x00000001UL
#define KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_CAPTURING  0x00000002UL
#define KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_DROPPED    0x00000004UL

// Drain response flags: OVERFLOW indicates the caller's cursor has fallen behind the ring buffer.
#define KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW       0x00000001UL
#define KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_MORE_AVAILABLE 0x00000002UL
#define KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_SNAPSHOT_RACE  0x00000004UL

// Single record bit: TEXT_TRUNCATED indicates the original kernel debug text exceeded the fixed limit.
#define KSWORD_ARK_DEBUG_OUTPUT_RECORD_FLAG_TEXT_TRUNCATED 0x00000001UL

// DbgPrint can pass at most 512 bytes per call; with the trailing NUL reserved, the maximum payload is 511 bytes.
#define KSWORD_ARK_DEBUG_OUTPUT_TEXT_BYTES 512U
#define KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY 256U
#define KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS 32U
#define KSWORD_ARK_DEBUG_OUTPUT_MAX_DRAIN_RECORDS 64U

typedef struct _KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long action;
    unsigned long flags;
} KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST;

typedef struct _KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long runtimeFlags;
    unsigned long ringCapacity;
    unsigned long queuedCount;
    unsigned long reserved0;
    unsigned long long latestSequence;
    unsigned long long droppedCount;
    long registrationStatus;
    long lastStatus;
} KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE;

typedef struct _KSWORD_ARK_DEBUG_OUTPUT_RECORD
{
    unsigned long long sequence;
    unsigned long long interruptTime100ns;
    unsigned long componentId;
    unsigned long level;
    unsigned long textLengthBytes;
    unsigned long flags;
    char text[KSWORD_ARK_DEBUG_OUTPUT_TEXT_BYTES];
} KSWORD_ARK_DEBUG_OUTPUT_RECORD;

typedef struct _KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long maxRecords;
    unsigned long flags;
    unsigned long long afterSequence;
} KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST;

typedef struct _KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long runtimeFlags;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long ringCapacity;
    unsigned long responseFlags;
    unsigned long reserved0;
    unsigned long long firstAvailableSequence;
    unsigned long long latestSequence;
    unsigned long long nextSequence;
    unsigned long long droppedCount;
    unsigned long long lostBeforeFirst;
    KSWORD_ARK_DEBUG_OUTPUT_RECORD records[1];
} KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE;
