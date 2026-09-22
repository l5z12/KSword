/* Snapshot sparse AMD exit telemetry without reinterpreting Intel exit numbers. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"

/* Runtime lifetime is protected by the metrics query's existing shared lock. */
VOID kswordSvmMetrics(KswHvmRuntime* runtime, KSWORD_ARK_HVM_METRICS_RESPONSE* response)
{
    /* No processor-private buffer is valid before preparation. */
    KswSvmState* state = runtime->backendContext;
    /* Iterate the exact prepared set, bounded by the shared response capacity. */
    ULONG index;
    /* Always identify the selected architecture, including before prepare. */
    response->backend = runtime->backendId;
    /* Intel shadow counters do not apply to AMD. */
    response->shadowProcessorCount = 0;
    /* A failed or absent preparation leaves zero AMD rows. */
    if (state == NULL || state->cpus == NULL) { return; }
    /* CPU identity remains meaningful even before the first recorded exit. */
    response->svmProcessorCount = state->count;
    /* Copy processor-local snapshots with bounded retries. */
    for (index = 0; index < state->count; ++index) {
        /* Query storage is separate from the live ring. */
        KSWORD_ARK_HVM_SVM_METRICS* output = &response->svmProcessors[index];
        /* Select this processor's private state. */
        KswSvmCpu* cpu = &state->cpus[index];
        /* Limit retry effort under a high exit rate. */
        ULONG attempt;
        /* Stable identity does not imply the exit snapshot is valid. */
        output->group = cpu->resource->row.processorGroup; output->number = cpu->resource->row.processorNumber;
        /* Preserve lifecycle stage independently from any exit record. */
        output->stage = (ULONG)cpu->stage;
        /* Cleanup does not overwrite the cause that required it. */
        output->failureStatus = (ULONG)cpu->failureStatus; output->failureStage = cpu->failureStage;
        /* The initial implementation reserves ASID one per processor. */
        output->asid = 1;
        /* MSR validity is independent of whether a VMEXIT record exists. */
        output->msrValidMask = cpu->caps.valid; output->svmFeatures = cpu->caps.features;
        /* Preserve enumeration used by allocation and ASID selection. */
        output->asidCount = cpu->caps.asidCount; output->physicalBits = cpu->caps.physicalBits;
        /* Preserve each raw ownership observation. */
        output->observedVmCr = cpu->caps.vmCr; output->observedEfer = cpu->caps.efer; output->observedHsave = cpu->caps.hsave;
        /* Tag this snapshot with the public lifecycle generation. */
        output->generation = runtime->generation;
        /* Prepared immutable resource addresses aid dump attribution. */
        output->vmcbPa = cpu->guestPa; output->hsavePa = cpu->hsavePa; output->nptRootPa = state->npt.rootPa;
        /* Observed VMRUN completions requested the baseline full flush. */
        output->tlbRequests = *(volatile ULONGLONG*)&cpu->tlbRequests;
        /* Bounded nested probes publish completion only after native MSR readback. */
        if (cpu->nested) {
            /* A zero sequence means this prepared context has never executed a probe. */
            LONG sequence = InterlockedCompareExchange(&cpu->nested->sequence, 0, 0);
            /* Do not sample an in-progress test as a completed result. */
            if (sequence != 0 && !(sequence & 1)) {
                /* Retain exact status independently from the baseline self-test flags. */
                output->nestedProbeStatus = (ULONG)cpu->nested->completionStatus;
                /* A VMRUN dispatch alone is insufficient; reflection and native return are separate evidence. */
                output->nestedProbeEntries = cpu->nested->entries;
                /* Publish the number of completed virtual host returns. */
                output->nestedProbeReflections = cpu->nested->reflections;
                /* Sparse shadow NPT faults establish that hardware used the composed root. */
                output->nestedProbeFaults = cpu->nested->faults;
                /* Preserve full-width raw inner exit evidence. */
                output->nestedProbeExit = cpu->nested->lastExit;
                /* This marker was read from the real inner CPUID exit. */
                output->nestedProbeMarker = cpu->nested->lastMarker;
                /* A racing new test makes this snapshot explicitly invalid. */
                if (sequence == InterlockedCompareExchange(&cpu->nested->sequence, 0, 0)) {
                    /* Publish coherent evidence without waiting for another processor. */
                    output->nestedProbeValid = 1; output->nestedProbeSequence = (ULONG)sequence;
                }
            }
        }
        /* Read at most three times; an invalid snapshot is preferable to a root stall. */
        for (attempt = 0; attempt < 3; ++attempt) {
            /* Observe the last completely published ring position. */
            ULONG position = (ULONG)InterlockedCompareExchange((volatile LONG*)&cpu->tracePosition, 0, 0);
            /* No exit has been observed yet. */
            KswSvmTrace* row;
            /* Sequence values bracket the entire copy. */
            LONG before, after;
            /* Preserve empty-ring validity explicitly. */
            if (position == 0) { break; }
            /* Select the last published row; wrap is intentional and counted. */
            row = &cpu->trace[(position - 1) % KSW_SVM_TRACE_ROWS];
            /* Odd sequence means a writer has begun reusing this slot. */
            before = InterlockedCompareExchange(&row->sequence, 0, 0);
            /* Avoid copying an already inconsistent row. */
            if (before & 1) { continue; }
            /* Copy all raw 64-bit evidence with no narrowing. */
            output->exitCode = row->exitCode; output->exitInfo1 = row->info1; output->exitInfo2 = row->info2;
            /* Preserve continuation identity. */
            output->rip = row->rip; output->rsp = row->rsp; output->cr3 = row->cr3;
            /* Preserve instruction/event evidence and CPU-local timestamp. */
            output->nrip = row->nrip; output->event = row->event; output->tsc = row->tsc;
            /* Acquire barrier detects a writer that raced the copy. */
            after = InterlockedCompareExchange(&row->sequence, 0, 0);
            /* A stable even sequence proves this row's internal coherence. */
            if (before == after && !(after & 1)) {
                /* Publish the exact observed sequence and overwrite accounting. */
                output->valid = 1; output->sequence = (ULONG)after; output->ringPosition = position;
                /* Ring overwrite is not the same thing as publication failure. */
                output->ringOverwritten = position > KSW_SVM_TRACE_ROWS ? position - KSW_SVM_TRACE_ROWS : 0;
                /* No extra retries after obtaining a coherent snapshot. */
                break;
            }
        }
    }
}
