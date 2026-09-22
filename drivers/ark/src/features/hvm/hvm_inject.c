/*++

Module Name:

    hvm_inject.c

Abstract:

    R-1 layer process injection. Semantics see hvm_inject.h and protocol headers.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_inject.h"
#include "hvm_ept.h"
#include "hvm_ept_view.h"
#include "hvm_memory.h"

#if defined(_M_AMD64)

/* CR3 lower bits contain PCID and flags; they must be masked before comparison. */
#define KSW_HVM_INJECT_CR3_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Page-aligned mask. */
#define KSW_HVM_INJECT_PAGE_MASK 0xFFFFFFFFFFFFF000ULL

/* Refuse to touch Idle and System processes, for the same reasons as process handling. */
#define KSW_HVM_INJECT_PID_IDLE 0UL
#define KSW_HVM_INJECT_PID_SYSTEM 4UL

/* Guest page table entry: NX is in the MSB, U/S is bit 2. */
#define KSW_HVM_INJECT_PTE_NO_EXECUTE 0x8000000000000000ULL
#define KSW_HVM_INJECT_PTE_USER 0x0000000000000004ULL

/*
 * Note: Maximum number of pages to look ahead when searching for gaps across pages.
 *
 * Padded at the end of the section, while the page currently being executed is typically in the middle of the section, so search in the **higher address** direction.
 * 512 pages is 2 MiB: sufficient to cover the .text section of most modules. Each page involves only one
 * table walk and one page read, both occurring in the PASSIVE installation path, performed only once.
 *
 * Set an upper limit instead of searching indefinitely until no executable code is found: scanning the table may cross section boundaries into
 * other sections or even other modules. Even if gaps exist there, they should not be used — the farther the shellcode is from the hijacked
 * code, the more likely it falls on a mapping with a completely different lifecycle (e.g., a page that can be paged out at any time).
 */
#define KSW_HVM_INJECT_MAX_CAVE_SCAN_PAGES 512UL

/*
 * Fixed overhead of the shell.
 *
 * A save/restore block at the beginning and end, plus an absolute jump at the end and an 8-byte return address slot. For DLL
 * types, additional lea/mov/call instructions and the path itself are required; those are calculated separately as needed.
 */
#define KSW_HVM_INJECT_PROLOGUE_BYTES 35UL
#define KSW_HVM_INJECT_EPILOGUE_BYTES 32UL
/*
 * Fixed part of the DLL type excluding the path stack:
 * mov rcx,rsp(3) + sub rsp,32(4) + mov rax,imm64(10) + call rax(2)。
 */
#define KSW_HVM_INJECT_CALL_BYTES 19UL
/* Path is grouped in chunks of eight bytes; each chunk consists of mov rax,imm64 (10 bytes) + push rax (1 byte). */
#define KSW_HVM_INJECT_PATH_CHUNK_BYTES 11UL

/* Complete driver-side status of an injection entry. */
typedef struct KswHvmInjectSlot
{
    /* Non-zero indicates this slot is in use. */
    BOOLEAN inUse;
    /*
     * Whether the payload has already executed.
     *
     * This is intentional: the hijacked thread is running, and every time it executes to this page, the payload runs
     * again, effectively turning the thread into an uncontrollable loop. To repeat execution, issue a new command.
     */
    BOOLEAN fired;
    UCHAR reserved0[2];
    /* PID at dispatch time, used for reporting only. */
    ULONG processId;
    /* Payload body length. */
    ULONG payloadBytes;
    /* Offset of the shellcode within the page, i.e., the location where RIP will be pointed. */
    ULONG caveOffset;
    /* Total length occupied by the shell payload. */
    ULONG caveBytes;
    /* The operand of the final `jmp rel32` instruction is the offset within the page; on violation, the return offset is written back here. */
    ULONG returnSlotOffset;
    /*
     * Execution view ID for the triggered page.
     *
     * The trigger page is the one specified by the caller—the hijacked thread is currently executing it. Its shadow page is byte-for-byte identical to the
     * real page. The sole purpose of mapping the view is to induce a single instruction fetch fault, allowing modification of the RIP at that exact moment.
     */
    ULONG viewId;
    /*
     * Execution view ID for the cave page; zero if the cave and trigger are on the same page.
     *
     * In the real module, these two pages are typically **not the same page**: the page currently executing is entirely code, while the
     * page at the end of the section is filled. Therefore, the shell is embedded in the shadow of the gap page, with RIP pointing there.
     */
    ULONG caveViewId;
    /* Guest linear address of the hole page, page-aligned. RIP is calculated by adding an offset to it. */
    ULONGLONG caveGuestLinearAddress;
    /* Guest physical address of the hole page, page-aligned. */
    ULONGLONG caveGuestPhysicalAddress;
    /* What fill bytes constitute this gap: 0x00 / 0xCC / 0x90. */
    UCHAR caveFiller;
    UCHAR reserved1[3];
    /* Note: Target address space, already masked to hierarchical physical page frames. */
    ULONGLONG directoryBase;
    /* Guest physical address of the page that was hijacked, page-aligned. */
    ULONGLONG guestPhysicalAddress;
    /* The guest linear address of the page being hijacked, page-aligned. RIP is calculated by adding an offset to it. */
    ULONGLONG guestLinearAddress;
    /* The number of times the payload was executed. It should be 1 after a one-time injection is completed. */
    volatile LONG64 executionCount;
} KswHvmInjectSlot;

/*
 * This table is placed in module static storage, not in KswHvmRuntime.
 *
 * The runtime structure is already large, while this table contains only four entries and is read solely by this module and a single entry in the exit path.
 * Unlike the disposition table placed in runtime (which must be scanned on every CR3 load, a hot path
 * where avoiding one indirect memory access matters), this table is only accessed on view violations—a
 * path that already performs operations far more expensive than a single indirect memory access.
 */
static KswHvmInjectSlot gKswordHvmInjections[KSWORD_ARK_HVM_MAX_INJECTIONS];
static ULONG gKswordHvmInjectionCount;

/* Write a byte to the buffer and advance the cursor. */
static VOID
kswordArkHvmInjectEmit8(
    _Inout_ UCHAR* buffer,
    _Inout_ ULONG* cursor,
    _In_ UCHAR value
    )
{
    buffer[*cursor] = value;
    *cursor += 1UL;
}

/* Write a fixed byte sequence. */
static VOID
kswordArkHvmInjectEmitBytes(
    _Inout_ UCHAR* buffer,
    _Inout_ ULONG* cursor,
    _In_reads_(length) const UCHAR* bytes,
    _In_ ULONG length
    )
{
    RtlCopyMemory(&buffer[*cursor], bytes, length);
    *cursor += length;
}

/* Write a little-endian 32-bit immediate value. */
static VOID
kswordArkHvmInjectEmit32(
    _Inout_ UCHAR* buffer,
    _Inout_ ULONG* cursor,
    _In_ ULONG value
    )
{
    buffer[*cursor + 0UL] = (UCHAR)(value & 0xFFUL);
    buffer[*cursor + 1UL] = (UCHAR)((value >> 8) & 0xFFUL);
    buffer[*cursor + 2UL] = (UCHAR)((value >> 16) & 0xFFUL);
    buffer[*cursor + 3UL] = (UCHAR)((value >> 24) & 0xFFUL);
    *cursor += 4UL;
}

/* Write a little-endian 64-bit immediate value. */
static VOID
kswordArkHvmInjectEmit64(
    _Inout_ UCHAR* buffer,
    _Inout_ ULONG* cursor,
    _In_ ULONGLONG value
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < 8UL; ++index) {
        buffer[*cursor + index] =
            (UCHAR)((value >> (index * 8U)) & 0xFFULL);
    }
    *cursor += 8UL;
}

/*
 * Determine which bytes count as "padding".
 *
 * Recognizing only zeros is insufficient: real .text pages in modules rarely contain consecutive zeros, while
 * **alignment padding between functions is ubiquitous**—MSVC uses 0xCC (int3), some toolchains use 0x90 (nop), and
 * only section tails and uninitialized regions are zero. Originally recognizing only zeros effectively excluded
 * the most common type of gap, resulting in NO_CAVE for everything except specially prepared blank pages.
 *
 * Assume these three are safe not because of accurate guessing, but due to the nature of this view: data reads always go through real pages.
 * Even if a 0xCC byte is actually embedded constant data within .text, readers will still see the original value from the
 * real page—we only modify shadow pages. The only scenario where this would cause issues is if that region is executed;
 * by definition, filler code is never executed (if 0xCC is truly executed, it will immediately break into the debugger).
 */
static BOOLEAN
kswordArkHvmInjectIsFiller(
    _In_ UCHAR value
    )
{
    /* Returns: Whether this byte is one of the three padding types. */
    return (BOOLEAN)(value == 0x00U || value == 0xCCU || value == 0x90U);
}

/*
 * Find a gap in the page that is long enough and composed entirely of the same fill byte.
 *
 * Requires a uniform pattern rather than 'mixed types': mixed segments are likely adjacent actual code or
 * data rather than padding (0x90 is NOP, 0xCC is int3; their interleaving does not occur in normal padding).
 * This constraint significantly reduces false positives at the cost of occasionally missing usable gaps.
 *
 * Also requires a minimum length of KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES: A segment
 * that is too short is likely just coincidentally identical bytes within actual code.
 *
 * Search backwards from the end of the page. The latter half is more likely to be filled with data, while
 * the first half is more likely to be executable code—the hijacked thread's RIP is currently on this page.
 */
static BOOLEAN
kswordArkHvmInjectFindCave(
    _In_reads_(KSWORD_ARK_HVM_VIEW_PAGE_BYTES) const UCHAR* page,
    _In_ ULONG neededBytes,
    _Out_ ULONG* caveOffset,
    _Out_ UCHAR* caveFiller
    )
{
    ULONG index = KSWORD_ARK_HVM_VIEW_PAGE_BYTES;
    /*
     * Take the larger of the two lower bounds: must accommodate both the shellcode and payload, and be long enough to avoid appearing coincidental.
     * A short sequence of identical bytes shorter than MIN_CAVE is likely real code, not padding.
     */
    const ULONG kRequired =
        (neededBytes > KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES)
            ? neededBytes
            : KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES;

    *caveOffset = 0UL;
    *caveFiller = 0U;
    /* Impossible when required length exceeds one page. */
    if (neededBytes == 0UL ||
        kRequired > KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
        /* Return not found. */
        return FALSE;
    }
    while (index > 0UL) {
        const UCHAR kFiller = page[index - 1UL];
        ULONG runStart = index;

        if (!kswordArkHvmInjectIsFiller(kFiller)) {
            /* Not padding; move back one position and continue searching. */
            index -= 1UL;
            continue;
        }
        /* Expand backwards to the start of this same-value fill region. */
        while (runStart > 0UL && page[runStart - 1UL] == kFiller) {
            runStart -= 1UL;
        }
        if ((index - runStart) >= kRequired) {
            /*
             * This lands at the start of the segment. Using the start position instead of counting back 'NeededBytes' from the end
             * ensures the shell stays entirely within the padding, rather than straddling the padding and the subsequent real content.
             */
            *caveOffset = runStart;
            *caveFiller = kFiller;
            /* Return found. */
            return TRUE;
        }
        /* This segment is too short; continue searching from before its start. */
        index = runStart;
    }
    /* Return not found. */
    return FALSE;
}

/*
 * Write the shell and payload into the shadow page gaps.
 *
 * The wrapper performs four tasks; all are required:
 *   1. Save flags and all general-purpose registers. The borrowed thread may be executing at any
 *      instruction boundary; any register modified by the payload will be corrupted upon return.
 *   2. Align stack and reserve 32 bytes of shadow space. Win64 calling convention requires
 *      16-byte alignment of RSP at call sites; RSP alignment at arbitrary instruction
 *      boundaries is unknown. Calling without alignment causes #GP if the callee uses movaps.
 *   3. Execute payload.
 *   4. Restore, then **absolutely jump** back to the original instruction.
 *
 * Step 4 must not use 'ret' as a hard requirement: CET shadow stacks are enabled on this machine. Pushing a return address without a corresponding
 * 'call' and then executing 'ret' will directly trigger a #CP exception. The call/ret pairs in DLL types are matched and unaffected.
 *
 * Return uses `jmp rel32`; the displacement is the immediate value in the instruction stream, not an address read from memory.
 * This was discovered on hardware: the initial `jmp qword ptr [rip+0]` used an eight-byte return-address slot, so the
 * jmp had to **read** the following eight bytes. KIND_HOOK reads the real page but executes the shadow page. Although
 * the shadow slot was populated, the read retrieved zero from the real page, jumping to address 0 and crashing the
 * target. Fetching instructions from the shadow while reading data from the real page is the purpose of these views
 * and imposes a hard constraint: **neither the wrapper nor the payload may read data from the hijacked page**.
 *
 * rel32 will definitely fit: The violation is an instruction fetch fault on this page, so the instruction
 * to jump back and the shell are on the same page, with a displacement of at most a few thousand bytes.
 */
static NTSTATUS
kswordArkHvmInjectBuildShell(
    _Inout_updates_(KSWORD_ARK_HVM_VIEW_PAGE_BYTES) UCHAR* shadow,
    _In_ ULONG caveOffset,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ ULONG* shellBytes,
    _Out_ ULONG* returnSlotOffset
    )
{
    /* pushfq; push rax,rcx,rdx,rbx,rbp,rsi,rdi */
    static const UCHAR kPrologueLow[] = {
        0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57
    };
    /* push r8..r15 */
    static const UCHAR kPrologueHigh[] = {
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
    };
    /* mov rbp,rsp; and rsp,-16; sub rsp,32 */
    static const UCHAR kPrologueFrame[] = {
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xE4, 0xF0,
        0x48, 0x83, 0xEC, 0x20
    };
    /* mov rsp,rbp */
    static const UCHAR kEpilogueFrame[] = { 0x48, 0x89, 0xEC };
    /* pop r15..r8 */
    static const UCHAR kEpilogueHigh[] = {
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58
    };
    /* pop rdi,rsi,rbp,rbx,rdx,rcx,rax; popfq */
    static const UCHAR kEpilogueLow[] = {
        0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D
    };
    ULONG cursor = caveOffset;
    ULONG jumpOperandCursor = 0UL;

    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kPrologueLow, sizeof(kPrologueLow));
    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kPrologueHigh, sizeof(kPrologueHigh));
    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kPrologueFrame, sizeof(kPrologueFrame));

    if (request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) {
        /*
         * Path is assembled on the stack; do not place it in this page.
         *
         * For the same reason as the return offset, but more critical: LoadLibraryW reads this string, and the
         * data read from this page is the real page—writing the path into the shadow means the caller reads
         * the original bytes from the real page. The stack is ordinary read/write memory, unaffected by views.
         *
         * Group by eight bytes and push onto the stack in reverse order, so the string is arranged in forward order at
         * lower addresses. Padding the group count to an even number ensures 16-byte alignment: the previous `and rsp, -16`
         * alignment would be broken by an odd number of groups, causing a #GP exception when the callee uses `movaps`.
         */
        ULONG chunkCount = (request->payloadBytes + 7UL) / 8UL;
        ULONG chunkIndex = 0UL;

        if ((chunkCount & 1UL) != 0UL) {
            chunkCount += 1UL;
        }
        for (chunkIndex = chunkCount; chunkIndex > 0UL; --chunkIndex) {
            const ULONG kOffset = (chunkIndex - 1UL) * 8UL;
            ULONGLONG chunk = 0ULL;
            ULONG byteIndex = 0UL;

            for (byteIndex = 0UL; byteIndex < 8UL; ++byteIndex) {
                const ULONG kSourceIndex = kOffset + byteIndex;

                /* Pad the portion exceeding the path length with zeros while reserving space for the string terminator. */
                if (kSourceIndex < request->payloadBytes) {
                    chunk |= ((ULONGLONG)request->payload[kSourceIndex]) <<
                        (byteIndex * 8U);
                }
            }
            /* mov rax, imm64 ; push rax */
            kswordArkHvmInjectEmit8(shadow, &cursor, 0x48U);
            kswordArkHvmInjectEmit8(shadow, &cursor, 0xB8U);
            kswordArkHvmInjectEmit64(shadow, &cursor, chunk);
            kswordArkHvmInjectEmit8(shadow, &cursor, 0x50U);
        }
        /* mov rcx, rsp — the first argument is the string just assembled. */
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x48U);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x89U);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0xE1U);
        /* sub rsp, 32 — Win64 requires the caller to allocate shadow space for the callee. */
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x48U);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x83U);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0xECU);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x20U);
        /* mov rax, imm64 — The LoadLibraryW resolved by the caller. */
        kswordArkHvmInjectEmit8(shadow, &cursor, 0x48U);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0xB8U);
        kswordArkHvmInjectEmit64(
            shadow, &cursor, request->loadLibraryAddress);
        /* Call rax. It pairs with its own ret, so it does not step on the CET shadow stack. */
        kswordArkHvmInjectEmit8(shadow, &cursor, 0xFFU);
        kswordArkHvmInjectEmit8(shadow, &cursor, 0xD0U);
        /* The stack is reclaimed in one go by the final `mov rsp, rbp`; no need to unwind group by group here. */
    } else {
        /* SHELLCODE: Write as-is; registers and flags are already protected by the shellcode wrapper. */
        kswordArkHvmInjectEmitBytes(
            shadow, &cursor, request->payload, request->payloadBytes);
    }

    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kEpilogueFrame, sizeof(kEpilogueFrame));
    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kEpilogueHigh, sizeof(kEpilogueHigh));
    kswordArkHvmInjectEmitBytes(
        shadow, &cursor, kEpilogueLow, sizeof(kEpilogueLow));
    /*
     * jmp rel32. The displacement is unknown until a violation occurs; reserve zero here and yield the operand position.
     *
     * No indirect jump: that would require reading data from this page, but the data read from this page belongs to the real page.
     */
    kswordArkHvmInjectEmit8(shadow, &cursor, 0xE9U);
    jumpOperandCursor = cursor;
    *returnSlotOffset = jumpOperandCursor;
    kswordArkHvmInjectEmit32(shadow, &cursor, 0UL);
    *shellBytes = cursor - caveOffset;
    /* Return: Complete shell construction result. */
    return STATUS_SUCCESS;
}

/* Calculate total bytes required for shellcode loading. */
static ULONG
kswordArkHvmInjectNeededBytes(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request
    )
{
    ULONG needed = KSW_HVM_INJECT_PROLOGUE_BYTES +
        KSW_HVM_INJECT_EPILOGUE_BYTES;

    if (request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) {
        /*
         * The DLL type does not write the path into the page; instead, it splits the path into 8-byte groups and pushes them onto the stack. This occupies
         * **instruction** space rather than data space, with each group being 11 bytes. The number of groups is padded to an even number to maintain 16-byte alignment.
         */
        ULONG chunkCount = (request->payloadBytes + 7UL) / 8UL;

        if ((chunkCount & 1UL) != 0UL) {
            chunkCount += 1UL;
        }
        needed += KSW_HVM_INJECT_CALL_BYTES +
            chunkCount * KSW_HVM_INJECT_PATH_CHUNK_BYTES;
    } else {
        needed += request->payloadBytes;
    }
    /* Return the complete requirement. */
    return needed;
}

/* Find an injection matching the given physical page. The exit path shares code with the control path. */
static KswHvmInjectSlot*
kswordArkHvmInjectFindByPage(
    _In_ ULONGLONG guestPhysicalPage
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        KswHvmInjectSlot* slot = &gKswordHvmInjections[index];

        if (slot->inUse &&
            slot->guestPhysicalAddress == guestPhysicalPage) {
            /* Return the matching entry. */
            return slot;
        }
    }
    /* Return miss. */
    return NULL;
}

/* Find an injection record by PID. */
static KswHvmInjectSlot*
kswordArkHvmInjectFindByProcessId(
    _In_ ULONG processId
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        KswHvmInjectSlot* slot = &gKswordHvmInjections[index];

        if (slot->inUse && slot->processId == processId) {
            /* Return the matching entry. */
            return slot;
        }
    }
    /* Return miss. */
    return NULL;
}

/* Release the view occupied by an injection entry and clear the record. The caller holds the runtime lock. */
static VOID
kswordArkHvmInjectReleaseSlotLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmInjectSlot* slot
    )
{
    KSWORD_ARK_HVM_VIEW_REQUEST viewRequest = { 0 };
    KSWORD_ARK_HVM_VIEW_RESPONSE viewResponse = { 0 };

    /*
     * Remove the view first, then clear the record: reversing this order loses the view identifier and leaks shadow pages.
     *
     * When gaps and triggers involve different pages, there are **two** views; both must be removed. Removing only one leaves a
     * segment of code in the target that no one will ever jump into, while it holds a shadow page until the resident unload completes.
     */
    viewRequest.version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    viewRequest.size = sizeof(viewRequest);
    viewRequest.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
    viewRequest.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
    viewRequest.confirmationToken =
        KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    if (slot->caveViewId != 0UL) {
        viewRequest.viewId = slot->caveViewId;
        (void)kswordArkHvmEptViewControlLocked(
            runtime,
            &viewRequest,
            &viewResponse);
    }
    if (slot->viewId != 0UL) {
        viewRequest.viewId = slot->viewId;
        (void)kswordArkHvmEptViewControlLocked(
            runtime,
            &viewRequest,
            &viewResponse);
    }
    RtlZeroMemory(slot, sizeof(*slot));
    if (gKswordHvmInjectionCount != 0UL) {
        gKswordHvmInjectionCount -= 1UL;
    }
}

/* Fill protocol row with driver-side records. */
static VOID
kswordArkHvmInjectFillRow(
    _In_ const KswHvmInjectSlot* slot,
    _Out_ KSWORD_ARK_HVM_INJECT_ROW* row
    )
{
    RtlZeroMemory(row, sizeof(*row));
    row->processId = slot->processId;
    row->payloadBytes = slot->payloadBytes;
    row->directoryBase = slot->directoryBase;
    /*
     * Returns the address of the **hole page**, not the triggering page.
     *
     * During troubleshooting, we want to know where the "shell" is located—that is the only place where content has been modified. The shadow page for
     * the trigger page is byte-for-byte identical to the real page; reporting it would only mislead one into thinking that page was tampered with.
     */
    row->guestLinearAddress = slot->caveGuestLinearAddress;
    row->guestPhysicalAddress = slot->caveGuestPhysicalAddress;
    row->caveOffset = slot->caveOffset;
    row->caveBytes = slot->caveBytes;
    row->executionCount = (ULONGLONG)InterlockedCompareExchange64(
        (volatile LONG64*)&slot->executionCount, 0LL, 0LL);
    row->viewId = slot->viewId;
    row->caveFiller = (unsigned long)slot->caveFiller;
}

/* Write the entire table into the response. */
static VOID
kswordArkHvmInjectPublishTable(
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        const KswHvmInjectSlot* slot = &gKswordHvmInjections[index];

        if (!slot->inUse) {
            /* Skip empty slots; otherwise, the caller cannot distinguish empty slots from zero counts. */
            continue;
        }
        kswordArkHvmInjectFillRow(
            slot, &response->rows[response->returnedRows]);
        response->returnedRows += 1UL;
    }
    response->rowCount = gKswordHvmInjectionCount;
}

/*
 * Install one injection. The caller holds the runtime lock and has verified that the resident hypervisor is stopped.
 *
 * The sequence is: read the real page, calculate the gap, build the shadow, then install the view and publish the record.
 * If any step fails, no intermediate state is left where a record exists in the table but the view is not installed. The
 * exit path treats such a record as a usable injection and points the RIP to content that was never replaced.
 */
static NTSTATUS
kswordArkHvmInjectArmLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    )
{
    KswHvmInjectSlot* slot = NULL;
    KSWORD_ARK_HVM_VIEW_REQUEST viewRequest = { 0 };
    KSWORD_ARK_HVM_VIEW_RESPONSE viewResponse = { 0 };
    MM_COPY_ADDRESS copyAddress = { 0 };
    UCHAR* shadow = NULL;
    ULONGLONG directoryBase = 0ULL;
    ULONGLONG guestPhysical = 0ULL;
    ULONGLONG physicalPage = 0ULL;
    ULONGLONG physicalPageVa = 0ULL;
    ULONGLONG cavePageVa = 0ULL;
    ULONGLONG cavePagePhysical = 0ULL;
    ULONG caveViewId = 0UL;
    ULONG triggerViewId = 0UL;
    ULONG neededBytes = 0UL;
    SIZE_T copied = 0U;
    ULONG caveOffset = 0UL;
    UCHAR caveFiller = 0U;
    ULONG shellBytes = 0UL;
    ULONG returnSlotOffset = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse to operate on Idle, System, or the current process. */
    if (request->processId == KSW_HVM_INJECT_PID_IDLE ||
        request->processId == KSW_HVM_INJECT_PID_SYSTEM ||
        request->processId ==
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET;
        /* Return explicit target denial. */
        return STATUS_ACCESS_DENIED;
    }
    /* Validate type and length. */
    if ((request->injectType != KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE &&
         request->injectType != KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH) ||
        request->payloadBytes == 0UL ||
        request->payloadBytes >
            KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES ||
        request->guestLinearAddress == 0ULL ||
        (request->injectType == KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH &&
         request->loadLibraryAddress == 0ULL)) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Scope relies on CR3-load exiting; without this, the policy would be denied rather than downgraded to machine-wide enforcement. */
    if ((runtime->crPolicyFlags &
            KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) == 0UL) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED;
        /* Return explicit precondition missing. */
        return STATUS_NOT_SUPPORTED;
    }
    /* The execution view is provided by the EPTP switch backend. */
    if (!runtime->eptpSwitchArmed) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED;
        /* Return explicit precondition missing. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Only one entry is allowed per process; otherwise, the second view would contend for the same leaf as the first. */
    if (kswordArkHvmInjectFindByProcessId(request->processId) != NULL) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED;
        /* Return explicit duplicate installation rejection. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Allocate an empty slot; reject before any action if full. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        if (!gKswordHvmInjections[index].inUse) {
            slot = &gKswordHvmInjections[index];
            break;
        }
    }
    if (slot == NULL) {
        response->status = KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL;
        /* Return explicit capacity exhaustion. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve the actual hierarchical base address used by the target process. */
    status = kswordArkHvmMemoryResolveProcessDirectoryBase(
        request->processId,
        &directoryBase);
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        /* Return explicit process resolution failure. */
        return status;
    }
    directoryBase &= KSW_HVM_INJECT_CR3_FRAME_MASK;
    /* Translate the page to be hijacked into a guest physical address. */
    status = kswordArkHvmMemoryTranslate(
        directoryBase,
        request->guestLinearAddress,
        &guestPhysical,
        NULL);
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED;
        response->lastStatus = status;
        /* Return explicit translation failure. */
        return status;
    }
    physicalPage = guestPhysical & KSW_HVM_INJECT_PAGE_MASK;
    physicalPageVa =
        request->guestLinearAddress & KSW_HVM_INJECT_PAGE_MASK;
    neededBytes = kswordArkHvmInjectNeededBytes(request);
    /*
     * The shadow is assembled in non-paged memory first, then handed to the view backend.
     *
     * Do not modify the real page directly: The entire purpose of KIND_HOOK is to leave
     * every byte of the real page untouched; readers will still see the original content.
     */
    shadow = (UCHAR*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
        'jnIK');
    if (shadow == NULL) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return explicit resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* The shadow starts as a full copy of the real page; every byte outside the gaps must be preserved verbatim. */
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalPage;
    status = MmCopyMemory(
        shadow,
        copyAddress,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
        MM_COPY_MEMORY_PHYSICAL,
        &copied);
    if (!NT_SUCCESS(status) ||
        copied != (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
        ExFreePool(shadow);
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED;
        response->lastStatus =
            NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        /* Return explicit page fetch failure. */
        return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }
    /*
     * Find a hole: check the triggering page first, then search page by page in the higher address direction.
     *
     * In a real module, the triggering page is typically entirely code—the page currently executing is in the middle
     * of a section, while the padding is at the end of the section. Therefore, "searching only within the triggering
     * page" will almost certainly yield NO_CAVE outside of specially prepared blank pages, as confirmed by testing.
     *
     * Search from high addresses because padding is at the end of sections. Each candidate page must satisfy three conditions: it
     * must be translatable, executable (NX=0), and a user page (U/S set). The last two conditions are mandatory; placing the shell
     * in non-executable memory causes the injection to appear successful but never trigger, indistinguishable from a failure.
     */
    cavePageVa = physicalPageVa;
    cavePagePhysical = physicalPage;
    if (!kswordArkHvmInjectFindCave(
            shadow,
            neededBytes,
            &caveOffset,
            &caveFiller)) {
        ULONG scan = 0UL;
        BOOLEAN found = FALSE;

        for (scan = 1UL;
             scan <= KSW_HVM_INJECT_MAX_CAVE_SCAN_PAGES;
             ++scan) {
            const ULONGLONG kCandidateVa = physicalPageVa +
                ((ULONGLONG)scan * KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
            ULONGLONG candidatePhysical = 0ULL;
            ULONGLONG candidateEntry = 0ULL;

            if (!NT_SUCCESS(kswordArkHvmMemoryTranslate(
                    directoryBase,
                    kCandidateVa,
                    &candidatePhysical,
                    &candidateEntry))) {
                /*
                 * Skip instead of stopping. Image pages are loaded on demand: a page that has never been
                 * accessed does not yet have a 'present' page table entry, and the section tail padding we seek
                 * resides precisely on those rarely executed pages. Previously breaking here would terminate the
                 * scan upon encountering the first unaccessed page, yielding almost nothing on real modules.
                 */
                continue;
            }
            if ((candidateEntry & KSW_HVM_INJECT_PTE_NO_EXECUTE) != 0ULL ||
                (candidateEntry & KSW_HVM_INJECT_PTE_USER) == 0ULL) {
                /*
                 * Non-executable or not a user page: skip instead of stopping. Such pages may be
                 * interspersed between sections, while the padding we seek lies further back.
                 */
                continue;
            }
            candidatePhysical &= KSW_HVM_INJECT_PAGE_MASK;
            copyAddress.PhysicalAddress.QuadPart =
                (LONGLONG)candidatePhysical;
            if (!NT_SUCCESS(MmCopyMemory(
                    shadow,
                    copyAddress,
                    (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
                    MM_COPY_MEMORY_PHYSICAL,
                    &copied)) ||
                copied != (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
                /* Skip if the read fails; pages that cannot be read cannot have shells injected. */
                continue;
            }
            if (kswordArkHvmInjectFindCave(
                    shadow,
                    neededBytes,
                    &caveOffset,
                    &caveFiller)) {
                cavePageVa = kCandidateVa;
                cavePagePhysical = candidatePhysical;
                found = TRUE;
                break;
            }
        }
        if (!found) {
            ExFreePool(shadow);
            response->status = KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE;
            /* Return explicit gap insufficiency. */
            return STATUS_NOT_FOUND;
        }
    }
    status = kswordArkHvmInjectBuildShell(
        shadow,
        caveOffset,
        request,
        &shellBytes,
        &returnSlotOffset);
    if (!NT_SUCCESS(status)) {
        ExFreePool(shadow);
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        response->lastStatus = status;
        /* Return explicit shell construction failure. */
        return status;
    }
    /* Execute view for hole pages: read/write/execute true pages, execute shadow pages with shells. */
    viewRequest.version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    viewRequest.size = sizeof(viewRequest);
    viewRequest.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    viewRequest.kind = KSWORD_ARK_HVM_VIEW_KIND_HOOK;
    viewRequest.physicalAddress = cavePagePhysical;
    viewRequest.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
    viewRequest.confirmationToken =
        KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    RtlCopyMemory(
        viewRequest.shadow,
        shadow,
        (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
    status = kswordArkHvmEptViewControlLocked(
        runtime,
        &viewRequest,
        &viewResponse);
    if (!NT_SUCCESS(status) ||
        viewResponse.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        ExFreePool(shadow);
        response->status = KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED;
        response->lastStatus = viewResponse.lastStatus;
        /* Return explicit view installation failure. */
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    caveViewId = viewResponse.viewId;
    /*
     * If the cave is not on the trigger page, install a view for the trigger page as well.
     *
     * Its shadow is byte-for-byte identical to the real page. The sole purpose of installing it is to trigger a single
     * instruction-fetch violation. Only at that moment do we know the guest is executing this page and can modify the RIP.
     * Without it, there is no trigger point, and even if the shell is installed correctly, it will never be jumped into.
     */
    if (cavePagePhysical != physicalPage) {
        KSWORD_ARK_HVM_VIEW_RESPONSE triggerResponse = { 0 };

        copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalPage;
        status = MmCopyMemory(
            shadow,
            copyAddress,
            (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
        if (NT_SUCCESS(status) &&
            copied == (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES) {
            viewRequest.physicalAddress = physicalPage;
            RtlCopyMemory(
                viewRequest.shadow,
                shadow,
                (SIZE_T)KSWORD_ARK_HVM_VIEW_PAGE_BYTES);
            status = kswordArkHvmEptViewControlLocked(
                runtime,
                &viewRequest,
                &triggerResponse);
        }
        if (!NT_SUCCESS(status) ||
            triggerResponse.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            /*
             * If the view fails to load, remove the gap view as well. Leaving it behind is equivalent to inserting code
             * that will never execute into the target, while the table still records an "injection completed" entry.
             */
            KSWORD_ARK_HVM_VIEW_REQUEST removeRequest = viewRequest;
            KSWORD_ARK_HVM_VIEW_RESPONSE removeResponse = { 0 };

            removeRequest.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
            removeRequest.viewId = caveViewId;
            (void)kswordArkHvmEptViewControlLocked(
                runtime, &removeRequest, &removeResponse);
            ExFreePool(shadow);
            response->status = KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED;
            response->lastStatus = triggerResponse.lastStatus;
            /* Returns a clear indication that the trigger view installation failed. */
            return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
        }
        triggerViewId = triggerResponse.viewId;
    } else {
        /* When on the same page, one view serves both roles. */
        triggerViewId = caveViewId;
    }
    ExFreePool(shadow);
    /* Publish the record only after all data is ready. */
    slot->processId = request->processId;
    slot->payloadBytes = request->payloadBytes;
    slot->caveOffset = caveOffset;
    slot->caveFiller = caveFiller;
    slot->caveBytes = shellBytes;
    slot->returnSlotOffset = returnSlotOffset;
    slot->viewId = triggerViewId;
    slot->caveViewId = (caveViewId != triggerViewId) ? caveViewId : 0UL;
    slot->directoryBase = directoryBase;
    slot->guestPhysicalAddress = physicalPage;
    slot->guestLinearAddress = physicalPageVa;
    slot->caveGuestLinearAddress = cavePageVa;
    slot->caveGuestPhysicalAddress = cavePagePhysical;
    slot->executionCount = 0LL;
    slot->fired = FALSE;
    /* InUse is set last: the exit path uses it to determine if this entry is available. */
    slot->inUse = TRUE;
    gKswordHvmInjectionCount += 1UL;
    response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
    /* Return full installation success. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmInjectControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->generation = runtime->generation;
    response->stateFlags = (ULONGLONG)runtime->stateFlags;
    if (request->version != KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION ||
        request->size != sizeof(*request)) {
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    switch (request->operation) {
    case KSWORD_ARK_HVM_INJECT_OP_QUERY:
        response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        break;
    case KSWORD_ARK_HVM_INJECT_OP_ARM:
        status = kswordArkHvmInjectArmLocked(runtime, request, response);
        break;
    case KSWORD_ARK_HVM_INJECT_OP_RELEASE: {
        KswHvmInjectSlot* slot =
            kswordArkHvmInjectFindByProcessId(request->processId);

        if (slot == NULL) {
            response->status = KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND;
            status = STATUS_NOT_FOUND;
        } else {
            kswordArkHvmInjectReleaseSlotLocked(runtime, slot);
            response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        }
        break;
    }
    case KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL:
        kswordArkHvmInjectResetLocked(runtime);
        response->status = KSWORD_ARK_HVM_INJECT_STATUS_OK;
        break;
    default:
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    kswordArkHvmInjectPublishTable(response);
    response->generation = runtime->generation;
    /* Return the full operation result. */
    return status;
}

NTSTATUS
kswordArkHvmInjectControl(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    )
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || response == NULL || runtime == NULL) {
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Only installation requires the resident hypervisor to be stopped.
     *
     * Installation involves paging and view attachment, which are read-only operations that do not hold locks on the exit path. Reversal
     * only detaches views and clears records; the view backend itself will reject detachment during residency. Therefore, we allow this to
     * proceed, letting the backend reject it and provide its own reason, rather than overriding it here with a more generic error code.
     */
    mutating = request->operation == KSWORD_ARK_HVM_INJECT_OP_ARM;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->lock);
    if (!runtime->initialized) {
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->status =
            KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED;
        response->lastStatus = STATUS_DEVICE_BUSY;
        status = STATUS_SUCCESS;
    } else {
        status = kswordArkHvmInjectControlLocked(
            runtime,
            request,
            response);
    }
    ExReleasePushLockExclusive(&runtime->lock);
    KeLeaveCriticalRegion();
    /* Return the full operation result. */
    return status;
}

BOOLEAN
kswordArkHvmInjectHijackRip(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access,
    _In_ ULONGLONG guestCr3,
    _In_ ULONGLONG guestRip,
    _Out_ ULONGLONG* newRip
    )
{
    KswHvmInjectSlot* slot = NULL;
    volatile UCHAR* shadow = NULL;

    if (runtime == NULL || newRip == NULL) {
        /* Return without hijacking. */
        return FALSE;
    }
    *newRip = 0ULL;
    /* Return immediately when the table is empty to avoid scanning on every view violation. */
    if (gKswordHvmInjectionCount == 0UL) {
        /* Return without hijacking. */
        return FALSE;
    }
    /*
     * Only recognize instruction faults. Read/write faults also traverse the view path, but at that point the guest is not attempting
     * to execute that page; redirecting RIP there would arbitrarily alter an execution flow unrelated to the current access.
     */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        /* Return without hijacking. */
        return FALSE;
    }
    slot = kswordArkHvmInjectFindByPage(
        guestPhysicalAddress & KSW_HVM_INJECT_PAGE_MASK);
    if (slot == NULL || slot->fired) {
        /* Return without hijacking. */
        return FALSE;
    }
    /*
     * Scope check cannot be omitted.
     *
     * The view is attached to guest physical pages and is visible to the entire machine; the same physical page may be
     * mapped by multiple processes (as with shared image sections). If CR3 is not checked, any process executing on that
     * page would be hijacked to run the payload—neither what the caller expects nor a safe context for the payload.
     */
    if ((guestCr3 & KSW_HVM_INJECT_CR3_FRAME_MASK) !=
            slot->directoryBase) {
        /* Return without hijacking. */
        return FALSE;
    }
    /*
     * Write back the calculated displacement into the operand of the jmp rel32 instruction in the shadow page.
     *
     * The shadow is non-paged memory allocated by the driver itself, accessible at any IRQL. It stores "where to jump after the payload
     * finishes"—i.e., the instruction the guest was originally about to execute. This step must be completed before modifying RIP:
     * If the order is reversed and the middle step fails, the guest may jump to a location with a displacement of zero.
     *
     * The base address for rel32 is the address of the next instruction, i.e., after the
     * operand. Since both ends are on the same page, the displacement must fit within 32 bits.
     */
    shadow = kswordArkHvmEptViewShadowForViewId(
        runtime,
        (slot->caveViewId != 0UL) ? slot->caveViewId : slot->viewId);
    if (shadow == NULL) {
        /* Return false: No shadow means no displacement to write back. */
        return FALSE;
    }
    {
        /*
         * The base is the **gap page**, not the trigger page. The shell resides in the shadow of the gap page, and that `jmp` executes
         * there as well—calculating displacement using the trigger page would result in an offset error equal to exactly one page distance.
         */
        const ULONGLONG kNextInstruction = slot->caveGuestLinearAddress +
            (ULONGLONG)slot->returnSlotOffset + 4ULL;
        const LONG kDisplacement =
            (LONG)(LONG64)(guestRip - kNextInstruction);
        ULONG index = 0UL;

        for (index = 0UL; index < 4UL; ++index) {
            shadow[slot->returnSlotOffset + index] =
                (UCHAR)(((ULONG)kDisplacement >> (index * 8U)) & 0xFFUL);
        }
    }
    /* One-time: after setting the flag, subsequent faults on the same page are handled via normal view switching. */
    slot->fired = TRUE;
    InterlockedIncrement64(&slot->executionCount);
    *newRip = slot->caveGuestLinearAddress + (ULONGLONG)slot->caveOffset;
    /* Return hijack. */
    return TRUE;
}

VOID
kswordArkHvmInjectResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    if (runtime == NULL) {
        /* Nothing to do. */
        return;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_INJECTIONS;
         ++index) {
        if (gKswordHvmInjections[index].inUse) {
            kswordArkHvmInjectReleaseSlotLocked(
                runtime,
                &gKswordHvmInjections[index]);
        }
    }
    gKswordHvmInjectionCount = 0UL;
}

#endif /* _M_AMD64 */
