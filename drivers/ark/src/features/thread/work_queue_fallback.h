#pragma once

#include "../dyndata/dyndata_v4_internal.h"

EXTERN_C_START

// Hard upper limit for System process TID snapshots. The number of System threads is far below this value; excess entries are truncated.
#define KSW_WORK_QUEUE_SYSTEM_THREAD_MAX 4096UL

// A System thread record. StartAddress is taken from SystemProcessInformation and serves solely as a
// runtime reference to infer the _ETHREAD.StartAddress offset; it is not used as direct evidence output.
typedef struct KswWorkQueueSystemThread
{
    ULONG threadId;
    ULONG64 startAddress;
} KswWorkQueueSystemThread;

typedef struct KswWorkQueueSystemThreadSnapshot
{
    ULONG count;
    BOOLEAN truncated;
    KswWorkQueueSystemThread* entries;
} KswWorkQueueSystemThreadSnapshot;

typedef PETHREAD(NTAPI* KswWorkQueueNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

// System process thread cursor. ntoskrnl does not export psGetNextProcessThread, so the primary path uses a TID
// snapshot + PsLookupThreadByThreadId; if a specific version does export a public traversal routine, it is
// preferred. Both paths yield ETHREADs reference-counted by the object manager; the reference count is held by the
// cursor itself and released upon the next advancement or closure. Callers must not dereference independently.
typedef struct KswWorkQueueThreadWalker
{
    KswWorkQueueNextProcessThreadFn nextProcessThread;
    const KswWorkQueueSystemThreadSnapshot* snapshot;
    ULONG nextIndex;
    BOOLEAN finished;
    PETHREAD current;
} KswWorkQueueThreadWalker;

// Capture a snapshot of TID / StartAddress for System processes (PID 4). Only available at PASSIVE_LEVEL.
NTSTATUS
kswordArkWorkQueueCaptureSystemThreads(
    _Out_ KswWorkQueueSystemThreadSnapshot* snapshotOut
    );

VOID
kswordArkWorkQueueReleaseSystemThreads(
    _Inout_ KswWorkQueueSystemThreadSnapshot* snapshot
    );

VOID
kswordArkWorkQueueInitializeThreadWalker(
    _Out_ KswWorkQueueThreadWalker* walker,
    _In_opt_ const KswWorkQueueSystemThreadSnapshot* snapshot
    );

// Whether the cursor has an available thread source; if false, the caller should explicitly record a reference failure rather than a null result.
BOOLEAN
kswordArkWorkQueueThreadWalkerUsable(
    _In_ const KswWorkQueueThreadWalker* walker
    );

PETHREAD
kswordArkWorkQueueThreadWalkerNext(
    _Inout_ KswWorkQueueThreadWalker* walker
    );

VOID
kswordArkWorkQueueThreadWalkerClose(
    _Inout_ KswWorkQueueThreadWalker* walker
    );

NTSTATUS
kswordArkWorkQueueResolveRuntimeLayout(
    _Out_ KswDynV4WorkQueueLayout* layoutOut
    );

NTSTATUS
kswordArkWorkQueueResolveActiveExWorkerField(
    _Out_ KswDynV4BitFieldLayout* fieldOut
    );

EXTERN_C_END
