/*++

Module Name:

    bugcheck_bgp_lifecycle.c

Abstract:

    PASSIVE_LEVEL lifecycle, bitmap parsing, arming, and secondary-dump
    snapshot support for the physical BGP renderer.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"

VOID
kswordArkBugcheckBgpRecordPreparation(
    _In_ KswordArkBgpPreparationStage stage,
    _In_ NTSTATUS status
    )
{
    // Publish the status first so a reader that observes the new stage also
    // observes the status belonging to that operation.
    InterlockedExchange(&gKswordArkBgp.preparationStatus, (LONG)status);
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBgp.preparationStage, (LONG)stage);
}

NTSTATUS
kswordArkBugcheckBgpInitialize(
    VOID
    )
{
    KswordArkBgpScreenInfo screen;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&gKswordArkBgp, sizeof(gKswordArkBgp));
    InterlockedExchange(
        &gKswordArkBgp.state,
        kKswordArkBgpStateUninitialized);
    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationResolveFunctions,
        STATUS_PENDING);
    InterlockedExchange(&gKswordArkBgp.clearStatus, STATUS_PENDING);
    InterlockedExchange(&gKswordArkBgp.drawStatus, STATUS_PENDING);

    status = kswordArkBugcheckBgpResolveFunctions();
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationResolveFunctions,
        status);
    if (NT_SUCCESS(status)) {
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationReadScreen,
            STATUS_PENDING);
        status = kswordArkBugcheckBgpReadScreen(&screen);
        InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationReadScreen,
            status);
        if (NT_SUCCESS(status)) {
            gKswordArkBgp.screen = screen;
        }
    }

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &gKswordArkBgp.state,
            kKswordArkBgpStateQueryOnly);
        return status;
    }

    InterlockedExchange(&gKswordArkBgp.state, kKswordArkBgpStateReady);
    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationBackendReady,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckBgpShutdown(
    VOID
    )
{
    InterlockedExchange(&gKswordArkBgp.state, kKswordArkBgpStateUnloading);
    if (InterlockedExchange(&gKswordArkBgp.lockHeld, 0) != 0 &&
        gKswordArkBgp.release != NULL) {
        kswordArkBugcheckBgpInvokeRelease();
    }
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBgp.resolvedSnapshotReady, 0);
    gKswordArkBgp.clear = NULL;
    gKswordArkBgp.draw = NULL;
    gKswordArkBgp.acquire = NULL;
    gKswordArkBgp.release = NULL;
    gKswordArkBgp.getResolution = NULL;
    gKswordArkBgp.getBpp = NULL;
    gKswordArkBgp.parseBitmap = NULL;
    gKswordArkBgp.destroyRectangle = NULL;
    gKswordArkBgp.acquireOwnership = NULL;
    gKswordArkBgp.featureMask = 0UL;
    gKswordArkBgp.requiredWidth = 0;
    gKswordArkBgp.requiredHeight = 0;
}

NTSTATUS
kswordArkBugcheckBgpGetScreenInfo(
    _Out_ PkswordArkBgpScreenInfo screen
    )
{
    if (screen == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBgp.state,
            0,
            0) != kKswordArkBgpStateReady) {
        RtlZeroMemory(screen, sizeof(*screen));
        return STATUS_DEVICE_NOT_READY;
    }

    *screen = gKswordArkBgp.screen;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckBgpParseBitmap(
    _In_reads_bytes_(bitmapLength) const VOID* bitmap,
    _In_ ULONG bitmapLength,
    _Out_ PVOID* rectangle
    )
{
    PVOID parsedRectangle;
    LONG state;
    NTSTATUS abortStatus;
    NTSTATUS status;

    if (rectangle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *rectangle = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    state = InterlockedCompareExchange(&gKswordArkBgp.state, 0, 0);
    if ((state != kKswordArkBgpStateReady &&
         state != kKswordArkBgpStateArmed) ||
        (state == kKswordArkBgpStateArmed &&
         InterlockedCompareExchange(
             &gKswordArkBgp.resourceUpdateActive,
             0,
             0) == 0) ||
        InterlockedCompareExchange(
            &gKswordArkBgp.resolvedSnapshotReady,
            0,
            0) == 0 ||
        gKswordArkBgp.parseBitmap == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = kswordArkBugcheckBgpValidateBitmap(bitmap, bitmapLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    parsedRectangle = NULL;
    status = kswordArkBugcheckBgpInvokeParseBitmap(
        bitmap,
        &parsedRectangle);
    if (!NT_SUCCESS(status) || parsedRectangle == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    // Re-check the budget after the private parser returns; created rectangles must be destroyed immediately before propagation cancellation.
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        (VOID)kswordArkBugcheckBgpInvokeDestroyRectangle(parsedRectangle);
        return abortStatus;
    }

    *rectangle = parsedRectangle;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckBgpBeginResourceUpdate(
    VOID
    )
{
    LONG state;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    state = InterlockedCompareExchange(&gKswordArkBgp.state, 0, 0);
    if (state != kKswordArkBgpStateReady &&
        state != kKswordArkBgpStateArmed) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBgp.resourceUpdateActive,
            1,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }
    KeMemoryBarrier();
    if (InterlockedCompareExchange(
            &gKswordArkBgp.drawStarted,
            0,
            0) != 0) {
        InterlockedExchange(&gKswordArkBgp.resourceUpdateActive, 0);
        return STATUS_DEVICE_BUSY;
    }
    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckBgpEndResourceUpdate(
    VOID
    )
{
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBgp.resourceUpdateActive, 0);
}

VOID
kswordArkBugcheckBgpDestroyRectangle(
    _In_opt_ PVOID rectangle
    )
{
    if (rectangle != NULL &&
        InterlockedCompareExchange(
            &gKswordArkBgp.resolvedSnapshotReady,
            0,
            0) != 0 &&
        gKswordArkBgp.destroyRectangle != NULL) {
        (VOID)kswordArkBugcheckBgpInvokeDestroyRectangle(rectangle);
    }
}

NTSTATUS
kswordArkBugcheckBgpArm(
    _In_ ULONG requiredWidth,
    _In_ ULONG requiredHeight
    )
{
    if (InterlockedCompareExchange(
            &gKswordArkBgp.resolvedSnapshotReady,
            0,
            0) == 0 ||
        InterlockedCompareExchange(
            &gKswordArkBgp.state,
            0,
            0) != kKswordArkBgpStateReady ||
        requiredWidth == 0 ||
        requiredHeight == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    // Defer the size check when BGP deliberately hides the screen mode until
    // InbvAcquireDisplayOwnership runs inside the bugcheck callback.
    if (gKswordArkBgp.screen.bitsPerPixel !=
            KSWORD_ARK_BGP_UNOWNED_BPP &&
        (requiredWidth > gKswordArkBgp.screen.width ||
         requiredHeight > gKswordArkBgp.screen.height)) {
        return STATUS_NOT_SUPPORTED;
    }

    gKswordArkBgp.requiredWidth = requiredWidth;
    gKswordArkBgp.requiredHeight = requiredHeight;
    InterlockedExchange(&gKswordArkBgp.drawStarted, 0);
    InterlockedExchange(&gKswordArkBgp.resourceUpdateActive, 0);
    InterlockedExchange(&gKswordArkBgp.drawStageStarted, 0);
    InterlockedExchange(&gKswordArkBgp.stage, kKswordArkBgpStageIdle);
    InterlockedExchange(&gKswordArkBgp.clearStatus, STATUS_PENDING);
    InterlockedExchange(&gKswordArkBgp.drawStatus, STATUS_PENDING);
    InterlockedExchange(&gKswordArkBgp.timelineCount, 0);
    RtlZeroMemory(gKswordArkBgp.timeline, sizeof(gKswordArkBgp.timeline));
    InterlockedExchange(&gKswordArkBgp.lastStatus, STATUS_SUCCESS);
    InterlockedExchange(&gKswordArkBgp.state, kKswordArkBgpStateArmed);
    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckBgpRejectPreparation(
    _In_ NTSTATUS status
    )
{
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
    InterlockedExchange(&gKswordArkBgp.preparationStatus, (LONG)status);
    InterlockedExchange(&gKswordArkBgp.state, kKswordArkBgpStateRejected);
    kswordArkBugcheckBgpRecordStage(
        (LONG)(kKswordArkBgpStageRejected | 3UL),
        status);
}
VOID
kswordArkBugcheckBgpSnapshot(
    _Out_ PkswordArkBgpDumpState snapshot
    )
{
    LONG timelineCount;
    ULONG timelineIndex;

    if (snapshot == NULL) {
        return;
    }

    RtlZeroMemory(snapshot, sizeof(*snapshot));
    snapshot->version = 2UL;
    snapshot->size = sizeof(*snapshot);
    snapshot->state = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.state,
        0,
        0);
    snapshot->preparationStage = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.preparationStage,
        0,
        0);
    snapshot->preparationStatus = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.preparationStatus,
        0,
        0);
    snapshot->stage = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.stage,
        0,
        0);
    snapshot->lastStatus = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.lastStatus,
        0,
        0);
    snapshot->clearStatus = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.clearStatus,
        0,
        0);
    snapshot->drawStatus = (ULONG)InterlockedCompareExchange(
        &gKswordArkBgp.drawStatus,
        0,
        0);
    snapshot->featureMask = gKswordArkBgp.featureMask;
    snapshot->screenWidth = gKswordArkBgp.screen.width;
    snapshot->screenHeight = gKswordArkBgp.screen.height;
    snapshot->screenBpp = gKswordArkBgp.screen.bitsPerPixel;
    snapshot->requiredWidth = gKswordArkBgp.requiredWidth;
    snapshot->requiredHeight = gKswordArkBgp.requiredHeight;
    snapshot->drawCount = (ULONG64)InterlockedCompareExchange64(
        &gKswordArkBgp.drawCount,
        0,
        0);
    RtlCopyMemory(
        snapshot->signatureFamily,
        gKswordArkBgp.signatureFamily,
        sizeof(snapshot->signatureFamily));

    timelineCount = InterlockedCompareExchange(
        &gKswordArkBgp.timelineCount,
        0,
        0);
    if (timelineCount < 0) {
        timelineCount = 0;
    }
    snapshot->timelineCount = min(
        (ULONG)timelineCount,
        (ULONG)RTL_NUMBER_OF(snapshot->timeline));
    for (timelineIndex = 0;
         timelineIndex < snapshot->timelineCount;
         ++timelineIndex) {
        snapshot->timeline[timelineIndex].stage =
            (ULONG)InterlockedCompareExchange(
                &gKswordArkBgp.timeline[timelineIndex].stage,
                0,
                0);
        snapshot->timeline[timelineIndex].status =
            (ULONG)InterlockedCompareExchange(
                &gKswordArkBgp.timeline[timelineIndex].status,
                0,
                0);
    }
}
