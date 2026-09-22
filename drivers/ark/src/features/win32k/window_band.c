// Exact-build USER transaction adapter. No code patch, token change, raw band
// write, or Explorer injection. See docs/window-input.md for the verified ABI.
#include <ntifs.h>
#include "win32k_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/runtime_signature_scan.h"
#include "driver/KswordArkWindowBandIoctl.h"

typedef PVOID (*KswBandEnter)(ULONG, ULONG);
typedef VOID (*KswBandLeave)(VOID);
typedef PVOID (*KswBandValidate)(PVOID);
typedef PVOID (*KswBandBegin)(ULONG);
typedef PVOID (*KswBandDefer)(PVOID, PVOID, PVOID, INT, INT, INT, INT, ULONG, ULONG);
typedef LONG (*KswBandEnd)(PVOID, LONG);
typedef VOID (*KswBandLock)(PVOID, PVOID, PVOID);
typedef VOID (*KswBandUnlock)(PVOID, PVOID);
typedef PVOID (*KswBandRootOwner)(PVOID);
typedef ULONGLONG (NTAPI *KswBandCreateTime)(PEPROCESS);

typedef struct KswBandRuntime {
    KswBandEnter enter;
    KswBandLeave leave;
    KswBandValidate validate;
    KswBandBegin begin;
    KswBandDefer defer;
    KswBandEnd end;
    KswBandLock lock;
    KswBandUnlock unlock;
    KswBandRootOwner rootOwner;
    KswBandCreateTime createTime;
} KswBandRuntime;

typedef struct KswBandView {
    ULONG_PTR handle, threadInfo, desktop, shared, next, previous, parent;
    ULONG band;
} KswBandView;

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID, PCSTR);

static BOOLEAN kswBandRead(ULONG_PTR address, PVOID out, SIZE_T bytes)
{
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        address <= MAXULONG_PTR - bytes &&
        kswordArkRuntimeReadMemory((PVOID)address, out, bytes);
}

// Each private hop is read through MmCopyMemory, including pointers returned
// by USER. Exception handling is NOT used as a kernel memory-read primitive.
static BOOLEAN kswBandView(PVOID window, KswBandView* view)
{
    ULONG_PTR words[14];
    RtlZeroMemory(view, sizeof(*view));
    if (!kswBandRead((ULONG_PTR)window, words, sizeof(words))) return FALSE;
    view->handle = words[0]; view->threadInfo = words[2];
    view->desktop = words[3]; view->shared = words[5];
    view->next = words[11]; view->previous = words[12]; view->parent = words[13];
    return kswBandRead(view->shared + 0xEC, &view->band, sizeof(view->band));
}

static BOOLEAN kswBandExactImage(PVOID base, ULONG size)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DEBUG_DIRECTORY debug;
    ULONG i;
    struct { ULONG signature; GUID guid; ULONG age; } rsds;
    static const GUID kExpected = {0x80DB0813,0x4711,0x330D,{0xD7,0x06,0x8D,0x82,0x6F,0xF8,0xE1,0xB0}};
    if (size != 0x428000 || !kswBandRead((ULONG_PTR)base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        (ULONG)dos.e_lfanew > size - sizeof(nt) ||
        !kswBandRead((ULONG_PTR)base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage != size || nt.FileHeader.TimeDateStamp != 0x5CD0A4AF)
        return FALSE;
    {
        const IMAGE_DATA_DIRECTORY kD = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (!kD.VirtualAddress || kD.VirtualAddress > size || kD.Size > size - kD.VirtualAddress ||
            kD.Size / sizeof(debug) > 64) return FALSE;
        for (i = 0; i < kD.Size / sizeof(debug); ++i) {
            if (!kswBandRead((ULONG_PTR)base + kD.VirtualAddress + i * sizeof(debug), &debug, sizeof(debug))) return FALSE;
            if (debug.Type != IMAGE_DEBUG_TYPE_CODEVIEW || debug.SizeOfData < sizeof(rsds) ||
                debug.AddressOfRawData > size - sizeof(rsds)) continue;
            if (kswBandRead((ULONG_PTR)base + debug.AddressOfRawData, &rsds, sizeof(rsds)) &&
                rsds.signature == 0x53445352 && rsds.age == 1 &&
                RtlCompareMemory(&rsds.guid, &kExpected, sizeof(kExpected)) == sizeof(kExpected)) return TRUE;
        }
    }
    return FALSE;
}

static PVOID kswBandRoutine(const KswRuntimeImageView* image, ULONG rva, const UCHAR* bytes, SIZE_T length)
{
    UCHAR actual[32];
    const ULONG_PTR kAddress = image->base + rva;
    if (length > sizeof(actual) || !kswordArkRuntimeAddressIsExecutable(image, kAddress, length) ||
        !kswBandRead(kAddress, actual, length) || RtlCompareMemory(actual, bytes, length) != length) return NULL;
    return (PVOID)kAddress;
}

static NTSTATUS kswBandResolve(KswBandRuntime* runtime)
{
    KswHookSystemModuleInformation* modules = NULL;
    KswHookSystemModuleEntry full, base;
    KswRuntimeImageView image;
    ULONG bytes = 0;
    UNICODE_STRING name;
    NTSTATUS status;
    // Full, position-independent prefixes, backed by exact PE + RSDS identity.
    static const UCHAR kBegin[] = {0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x8b,0xf9};
    static const UCHAR kDefer[] = {0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8b,0xec,0x48,0x83,0xec,0x50};
    static const UCHAR kEnd[] = {0x48,0x89,0x5c,0x24,0x10,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xd9,0x48,0x81,0xec,0xc0,0,0,0};
    static const UCHAR kLock[] = {0x48,0x83,0xec,0x28,0x48,0x8b,0x81,0xc8,1,0,0,0x49,0x89,0,0x4c,0x89,0x81,0xc8,1,0,0};
    static const UCHAR kUnlock[] = {0x48,0x83,0xec,0x38,0x4c,0x8b,0x81,0xc8,1,0,0,0x4c,0x3b,0xc2,0x75,0x20};
    static const UCHAR kOwner[] = {0x48,0x83,0xec,0x28,0x4c,0x8b,0xc1,0xe8,0x6c,0xfa,0xff,0xff,0x48,0x85,0xc0,0x75,0x09};
    RtlZeroMemory(runtime, sizeof(*runtime));
    status = kswordArkHookBuildModuleSnapshot(&modules, &bytes);
    if (!NT_SUCCESS(status)) return status;
    if (!kswordArkWin32kFindModuleByName(modules, "win32kfull.sys", &full) ||
        !kswordArkWin32kFindModuleByName(modules, "win32kbase.sys", &base)) {
        ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
        return STATUS_NOT_FOUND;
    }
    ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
    if (!kswBandExactImage(full.imageBase, full.imageSize) ||
        !kswordArkRuntimeInitializeImageView(full.imageBase, full.imageSize, &image)) return STATUS_REVISION_MISMATCH;
    runtime->begin = (KswBandBegin)kswBandRoutine(&image, 0x980D0, kBegin, sizeof(kBegin));
    runtime->defer = (KswBandDefer)kswBandRoutine(&image, 0x98894, kDefer, sizeof(kDefer));
    runtime->end = (KswBandEnd)kswBandRoutine(&image, 0x9731C, kEnd, sizeof(kEnd));
    runtime->lock = (KswBandLock)kswBandRoutine(&image, 0x26DE0, kLock, sizeof(kLock));
    runtime->unlock = (KswBandUnlock)kswBandRoutine(&image, 0x26170, kUnlock, sizeof(kUnlock));
    runtime->rootOwner = (KswBandRootOwner)kswBandRoutine(&image, 0x742B8, kOwner, sizeof(kOwner));
    runtime->enter = (KswBandEnter)RtlFindExportedRoutineByName(base.imageBase, "EnterCrit");
    runtime->leave = (KswBandLeave)RtlFindExportedRoutineByName(base.imageBase, "UserSessionSwitchLeaveCrit");
    runtime->validate = (KswBandValidate)RtlFindExportedRoutineByName(base.imageBase, "ValidateHwnd");
    RtlInitUnicodeString(&name, L"PsGetProcessCreateTimeQuadPart");
    runtime->createTime = (KswBandCreateTime)MmGetSystemRoutineAddress(&name);
    if (!runtime->begin || !runtime->defer || !runtime->end || !runtime->lock || !runtime->unlock ||
        !runtime->enter || !runtime->leave || !runtime->validate || !runtime->rootOwner || !runtime->createTime)
        return STATUS_NOT_SUPPORTED;
    // The base exports must also resolve to executable code in the loaded base.
    if (!kswordArkRuntimeInitializeImageView(base.imageBase, base.imageSize, &image) ||
        !kswordArkRuntimeAddressIsExecutable(&image, (ULONG_PTR)runtime->enter, 1) ||
        !kswordArkRuntimeAddressIsExecutable(&image, (ULONG_PTR)runtime->leave, 1) ||
        !kswordArkRuntimeAddressIsExecutable(&image, (ULONG_PTR)runtime->validate, 1)) return STATUS_REVISION_MISMATCH;
    return STATUS_SUCCESS;
}

static BOOLEAN kswBandAllowed(ULONG band) { return band == 1 || band == 2; }

// These six private routines are absent from this exact image's GFIDS table.
// Keep the CFG exception confined to wrappers fed only by kswBandResolve's
// exact, kernel-stack-local bindings. Never accept a call address from R3.
__declspec(noinline) __declspec(guard(nocf))
static PVOID kswBandRoot(KswBandRuntime* r, PVOID window)
{ return r->rootOwner(window); }

__declspec(noinline) __declspec(guard(nocf))
static VOID kswBandLockWindow(KswBandRuntime* r, PVOID pti, PVOID window, PVOID lock)
{ r->lock(pti, window, lock); }

__declspec(noinline) __declspec(guard(nocf))
static VOID kswBandUnlockWindow(KswBandRuntime* r, PVOID pti, PVOID lock)
{ r->unlock(pti, lock); }

// Require a top-level target with no owned popup group on the selected desktop.
// The native transaction is responsible for the complete sibling-chain update.
static BOOLEAN kswBandTarget(KswBandRuntime* r, PVOID window, const KswBandView* v)
{
    ULONG_PTR deskInfo, desktopWindow;
    if (!kswBandAllowed(v->band) || kswBandRoot(r, window) != window ||
        !kswBandRead(v->desktop + 8, &deskInfo, sizeof(deskInfo)) ||
        !kswBandRead(deskInfo + 0x18, &desktopWindow, sizeof(desktopWindow)) ||
        v->parent != desktopWindow) return FALSE;
    // The old implementation treated an undocumented THREADINFO slot as a
    // CoreWindow marker. That slot is not part of the validated profile and is
    // populated for ordinary active threads, which rejected normal Explorer
    // windows with STATUS_NOT_SUPPORTED. Root-owner and desktop-parent checks
    // still exclude owned groups and non-desktop windows without guessing at a
    // private THREADINFO field.
    return TRUE;
}

__declspec(noinline) __declspec(guard(nocf))
static BOOLEAN kswBandCommit(KswBandRuntime* r, PVOID window, ULONG band, ULONG position)
{
    PVOID transaction = r->begin(1);
    if (!transaction) return FALSE;
    // 0x60000 is the native band-change transaction mask; the other flags are
    // SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE, as in xxxSetWindowBand.
    transaction = r->defer(transaction, window, position == KSW_BAND_BOTTOM ? (PVOID)1 : NULL,
        0, 0, 0, 0, 0x60013, band);
    // _DeferWindowPos destroys the transaction itself on allocation failure.
    if (!transaction) return FALSE;
    // Synchronous commit: verify the actual chain before acknowledging success.
    // End owns/frees SMWP; it can return TRUE even for a discarded transaction.
    return r->end(transaction, 0) != 0;
}

static BOOLEAN kswBandPosition(KswBandRuntime* r, PVOID window, ULONG band, ULONG position)
{
    KswBandView view, adjacent;
    ULONG_PTR node;
    if (!kswBandView(window, &view) || view.band != band) return FALSE;
    node = position == KSW_BAND_BOTTOM ? view.next : view.previous;
    if (!node) return TRUE;
    if (!kswBandView((PVOID)node, &adjacent) || r->validate((PVOID)adjacent.handle) != (PVOID)node ||
        adjacent.parent != view.parent ||
        (position == KSW_BAND_BOTTOM ? adjacent.previous : adjacent.next) != (ULONG_PTR)window) return FALSE;
    return adjacent.band != band;
}

NTSTATUS kswordArkWindowBandIoctl(WDFDEVICE device, WDFREQUEST request,
    size_t inputLength, size_t outputLength, size_t* bytesReturned)
{
    KSWORD_ARK_WINDOW_BAND_REQUEST* input;
    KSWORD_ARK_WINDOW_BAND_REQUEST q;
    KSWORD_ARK_WINDOW_BAND_RESPONSE* out;
    KswBandRuntime runtime;
    KswBandView view, caller, after;
    PVOID target = NULL, pti = NULL;
    PETHREAD thread = NULL;
    ULONG_PTR threadPointer = 0, targetLock[2];
    BOOLEAN entered = FALSE, locked = FALSE;
    NTSTATUS status;
    size_t bytes;
    KswordWiN32KPsGetThreadWiN32ThreadFn getGuiThread;
    UNREFERENCED_PARAMETER(inputLength); UNREFERENCED_PARAMETER(outputLength);
    *bytesReturned = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || WdfRequestGetRequestorMode(request) != UserMode)
        return STATUS_INVALID_DEVICE_STATE;
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) return status;
    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(q), (PVOID*)&input, &bytes);
    if (!NT_SUCCESS(status)) return status;
    RtlCopyMemory(&q, input, sizeof(q)); // METHOD_BUFFERED input/output may alias.
    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(*out), (PVOID*)&out, &bytes);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(out, sizeof(*out));
    out->size = sizeof(*out); out->version = KSWORD_ARK_WINDOW_BAND_VERSION;
    out->lastStatus = STATUS_INVALID_PARAMETER; *bytesReturned = sizeof(*out);
    if (q.size != sizeof(q) || q.version != KSWORD_ARK_WINDOW_BAND_VERSION || q.reserved ||
        q.operation > KSW_BAND_SET || q.position > KSW_BAND_BOTTOM ||
        (q.operation == KSW_BAND_SET && (q.confirmation != KSW_BAND_CONFIRMED ||
            !q.expectedObject || !kswBandAllowed(q.expectedBand) || !kswBandAllowed(q.newBand)))) return STATUS_SUCCESS;
    status = kswBandResolve(&runtime);
    if (!NT_SUCCESS(status)) { out->lastStatus = status; return STATUS_SUCCESS; }
    out->imageTimeDateStamp = 0x5CD0A4AF; out->imageSize = 0x428000;
    if (q.operation == KSW_BAND_PROBE) {
        out->lastStatus = STATUS_SUCCESS; out->flags = KSW_BAND_VERIFIED; return STATUS_SUCCESS;
    }
    if (!q.hwnd || !q.callerHwnd || !q.processCreated || !q.processId || !q.threadId) return STATUS_SUCCESS;
    getGuiThread = kswordArkWin32kResolvePsGetThreadWin32Thread();
    if (!getGuiThread || !getGuiThread(PsGetCurrentThread()) || KeAreAllApcsDisabled()) {
        out->lastStatus = STATUS_INVALID_DEVICE_STATE; return STATUS_SUCCESS;
    }
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)q.threadId, &thread);
    if (!NT_SUCCESS(status)) { out->lastStatus = status; return STATUS_SUCCESS; }
    if ((ULONG_PTR)PsGetThreadProcessId(thread) != q.processId ||
        runtime.createTime(IoThreadToProcess(thread)) != q.processCreated ||
        PsIsThreadTerminating(thread)) { status = STATUS_INVALID_CID; goto done; }
    if (q.operation == KSW_BAND_SET) {
        KswordArkSafetyContext safety = {0};
        safety.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safety.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safety.targetText = L"win32k native window band transaction";
        safety.targetTextChars = RTL_NUMBER_OF(L"win32k native window band transaction") - 1;
        status = kswordArkSafetyEvaluate(device, &safety);
        if (!NT_SUCCESS(status)) goto done;
    }
    __try {
        pti = runtime.enter(0, 1); entered = TRUE;
        target = runtime.validate((PVOID)(ULONG_PTR)q.hwnd);
        if (!pti || !target || !kswBandView(target, &view) ||
            !kswBandView(runtime.validate((PVOID)(ULONG_PTR)q.callerHwnd), &caller) ||
            caller.threadInfo != (ULONG_PTR)pti || caller.desktop != view.desktop ||
            !kswBandRead(view.threadInfo, &threadPointer, sizeof(threadPointer)) || threadPointer != (ULONG_PTR)thread ||
            !kswBandTarget(&runtime, target, &view)) { status = STATUS_NOT_SUPPORTED; __leave; }
        out->windowObject = (ULONG64)(ULONG_PTR)target;
        out->previousBand = out->currentBand = view.band;
        if (q.operation == KSW_BAND_QUERY) {
            out->flags = KSW_BAND_VERIFIED;
            if (kswBandPosition(&runtime, target, view.band, q.position)) out->flags |= KSW_BAND_POSITION_VERIFIED;
            status = STATUS_SUCCESS; __leave;
        }
        if ((ULONG64)(ULONG_PTR)target != q.expectedObject || view.band != q.expectedBand) {
            status = STATUS_REVISION_MISMATCH; __leave;
        }
        kswBandLockWindow(&runtime, pti, target, targetLock); locked = TRUE;
        if (kswBandCommit(&runtime, target, q.newBand, q.position) &&
            runtime.validate((PVOID)(ULONG_PTR)q.hwnd) == target &&
            kswBandPosition(&runtime, target, q.newBand, q.position)) {
            out->currentBand = q.newBand;
            out->flags = KSW_BAND_VERIFIED | KSW_BAND_CHANGED | KSW_BAND_POSITION_VERIFIED; status = STATUS_SUCCESS;
        } else {
            status = STATUS_UNSUCCESSFUL;
            // Revalidate after native callbacks, which can destroy the target.
            if (runtime.validate((PVOID)(ULONG_PTR)q.hwnd) == target && kswBandView(target, &after)) {
                out->currentBand = after.band;
                if (after.band != view.band) {
                    out->flags |= KSW_BAND_CHANGED;
                    if (kswBandCommit(&runtime, target, view.band, KSW_BAND_TOP) &&
                        runtime.validate((PVOID)(ULONG_PTR)q.hwnd) == target &&
                        kswBandView(target, &after) && after.band == view.band) {
                        out->currentBand = after.band;
                        out->flags |= KSW_BAND_ROLLED_BACK;
                    }
                }
            }
        }
    } __finally {
        if (locked) kswBandUnlockWindow(&runtime, pti, targetLock);
        if (entered) runtime.leave();
    }
done:
    ObDereferenceObject(thread);
    out->lastStatus = status;
    return STATUS_SUCCESS;
}
