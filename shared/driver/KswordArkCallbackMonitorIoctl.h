#pragma once

#include "KswordArkDynDataIoctl.h"

// ============================================================
// KswordArkCallbackMonitorIoctl.h
// Purpose:
// - Defines a read-only kernel callback telemetry protocol independent of callback rules and AskUser;
// - R0 writes six categories of callback events into a fixed circular buffer;
// - R3 uses independent cursors for reading; multiple readers do not consume each other's events.
// ============================================================

#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS 0x0001
#endif

#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif

#define KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_CONTROL 0x88AUL
#define KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_QUERY   0x88BUL
#define KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_READ    0x88CUL

#define IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_CONTROL, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_QUERY, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CALLBACK_MONITOR_READ, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define KSWORD_ARK_CALLBACK_MONITOR_ACTION_START 1UL
#define KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP  2UL

#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS    0x00000001UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD     0x00000002UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE      0x00000004UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY   0x00000008UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT     0x00000010UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER 0x00000020UL
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE \
    (KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS | \
     KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD | \
     KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE | \
     KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY | \
     KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)
#define KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL \
    (KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE | \
     KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)

// The process rule protocol only includes create operations; telemetry extra records do not participate in rule matching for exit operations.
#define KSWORD_ARK_CALLBACK_MONITOR_PROCESS_OP_EXIT 0x00000002UL

#define KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING 0x00000001UL
#define KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_DROPPED   0x00000002UL
#define KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_STOPPING  0x00000004UL

#define KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW       0x00000001UL
#define KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_MORE_AVAILABLE 0x00000002UL
#define KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE  0x00000004UL

#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT 0x00000001UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_TRUNCATED 0x00000002UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_PRESENT 0x00000004UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_TRUNCATED 0x00000008UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_STATUS_PRESENT 0x00000010UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT 0x00000020UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_POST_OPERATION 0x00000040UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_SYSTEM_PROCESS 0x00000080UL
#define KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_OBJECT_THREAD 0x00000100UL

#define KSWORD_ARK_CALLBACK_MONITOR_PROCESS_NAME_CHARS 64U
#define KSWORD_ARK_CALLBACK_MONITOR_PATH_CHARS 520U
#define KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY 2048U
#define KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS 32U
#define KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS 64U

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long action;
    unsigned long categoryMask;
    unsigned long flags;
    unsigned long reserved0;
} KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST;

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long runtimeFlags;
    unsigned long categoryMask;
    unsigned long registeredCategoryMask;
    unsigned long ringCapacity;
    unsigned long queuedCount;
    unsigned long reserved0;
    unsigned long long latestSequence;
    unsigned long long droppedCount;
    long lastStatus;
    long minifilterStartStatus;
} KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE;

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_EVENT
{
    unsigned long version;
    unsigned long size;
    unsigned long long sequence;
    long long timeUtc100ns;
    unsigned long category;
    unsigned long operation;
    unsigned long flags;
    long resultStatus;
    unsigned long originatingProcessId;
    unsigned long originatingThreadId;
    unsigned long targetProcessId;
    unsigned long targetThreadId;
    unsigned long parentProcessId;
    unsigned long sessionId;
    unsigned long originalAccess;
    unsigned long desiredAccess;
    unsigned long objectType;
    unsigned long detailCode;
    unsigned long long address;
    unsigned long long regionSize;
    wchar_t processName[KSWORD_ARK_CALLBACK_MONITOR_PROCESS_NAME_CHARS];
    wchar_t path[KSWORD_ARK_CALLBACK_MONITOR_PATH_CHARS];
} KSWORD_ARK_CALLBACK_MONITOR_EVENT;

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long maxRecords;
    unsigned long flags;
    unsigned long long afterSequence;
} KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST;

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long runtimeFlags;
    unsigned long categoryMask;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long ringCapacity;
    unsigned long responseFlags;
    unsigned long long firstAvailableSequence;
    unsigned long long latestSequence;
    unsigned long long nextSequence;
    unsigned long long droppedCount;
    unsigned long long lostBeforeFirst;
    KSWORD_ARK_CALLBACK_MONITOR_EVENT records[1];
} KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE;
