/*++

Module Name:

    token_layout_resolver.c

Abstract:

    Live-validated EPROCESS.Token and TOKEN layout recovery used when an exact
    PDB profile is unavailable.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "token_layout_resolver.h"

#define KSW_RUNTIME_PROCESS_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_TOKEN_SCAN_BYTES 0x0400U
#define KSW_RUNTIME_TOKEN_FIELD_WINDOW 0x0080U
#define KSW_RUNTIME_TOKEN_MAX_GROUPS 0x0100U

typedef struct KswRuntimeSidView
{
    UCHAR revision;
    UCHAR subAuthorityCount;
    SID_IDENTIFIER_AUTHORITY identifierAuthority;
    ULONG subAuthority[ANYSIZE_ARRAY];
} KswRuntimeSidView, *PkswRuntimeSidView;

static BOOLEAN
kswordArkDriverReadPointerGuarded(
    _In_ const VOID* address,
    _Out_ ULONG_PTR* valueOut
    )
{
    if (address == NULL || valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0U;
    __try {
        *valueOut = *(volatile const ULONG_PTR*)address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}
static BOOLEAN
kswordArkDriverEqualSidGuarded(
    _In_ PSID left,
    _In_ PSID right
    )
/*++

Routine Description:

    Compare two SID pointers obtained from private token memory under an exception boundary.

Arguments:

    Left - First candidate SID.
    Right - Second trusted or candidate SID.

Return Value:

    TRUE only when both SIDs are valid and equal.

--*/
{
    BOOLEAN equal = FALSE;

    if (left == NULL || right == NULL) {
        return FALSE;
    }
    __try {
        equal = (RtlValidSid(left) && RtlValidSid(right) && RtlEqualSid(left, right))
            ? TRUE
            : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        equal = FALSE;
    }
    return equal;
}

static BOOLEAN
kswordArkDriverReadSidAndAttributesGuarded(
    _In_ const SID_AND_ATTRIBUTES* source,
    _Out_ SID_AND_ATTRIBUTES* valueOut
    )
/*++

Routine Description:

    Copy one private token group entry while containing faults raised by a
    stale or malformed candidate array.  Callers must not dereference a
    candidate SID_AND_ATTRIBUTES entry before it has passed this boundary.

Arguments:

    Source - Candidate entry inside the token's private group array.
    ValueOut - Receives a stable local copy.

Return Value:

    TRUE when the entry was readable; otherwise FALSE.

--*/
{
    if (source == NULL || valueOut == NULL) {
        return FALSE;
    }

    __try {
        *valueOut = *source;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(valueOut, sizeof(*valueOut));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkDriverIntegrityGroupMatchesLevel(
    _In_ const SID_AND_ATTRIBUTES* group,
    _In_ ULONG integrityLevel
    )
/*++

Routine Description:

    Match a documented TokenGroups entry against the scalar integrity level
    returned by SeQueryInformationToken(TokenIntegrityLevel).  Unlike the
    user-mode token query contract, the kernel SeQueryInformationToken API
    writes the integrity RID directly to the caller's DWORD; it does not
    return a pool-allocated TOKEN_MANDATORY_LABEL for this information class.

Arguments:

    Group - Candidate TokenGroups entry.
    IntegrityLevel - Integrity RID returned by SeQueryInformationToken.

Return Value:

    TRUE only for the mandatory-label SID carrying IntegrityLevel.

--*/
{
    static const SID_IDENTIFIER_AUTHORITY kMandatoryLabelAuthority =
        SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID_AND_ATTRIBUTES groupValue;
    BOOLEAN matches = FALSE;

    RtlZeroMemory(&groupValue, sizeof(groupValue));
    if (!kswordArkDriverReadSidAndAttributesGuarded(group, &groupValue) ||
        groupValue.Sid == NULL) {
        return FALSE;
    }

    __try {
        const KswRuntimeSidView* sid =
            (const KswRuntimeSidView*)groupValue.Sid;
        UCHAR subAuthorityCount = 0U;

        if (!RtlValidSid(groupValue.Sid)) {
            return FALSE;
        }
        subAuthorityCount = sid->subAuthorityCount;
        if (subAuthorityCount == 0U ||
            RtlCompareMemory(
                &sid->identifierAuthority,
                &kMandatoryLabelAuthority,
                sizeof(kMandatoryLabelAuthority)) != sizeof(kMandatoryLabelAuthority)) {
            return FALSE;
        }
        matches = (sid->subAuthority[subAuthorityCount - 1U] == integrityLevel)
            ? TRUE
            : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }
    return matches;
}

static BOOLEAN
kswordArkDriverTokenGroupArrayMatches(
    _In_reads_(expectedCount) const SID_AND_ATTRIBUTES* candidate,
    _In_ ULONG expectedCount,
    _In_ const TOKEN_USER* tokenUser,
    _In_ const TOKEN_GROUPS* tokenGroups
    )
/*++

Routine Description:

    Match a private TOKEN.UserAndGroups array against documented token-query output.

Arguments:

    Candidate - Candidate internal SID_AND_ATTRIBUTES array.
    ExpectedCount - Expected user-plus-groups element count.
    TokenUser - Documented TokenUser query output.
    TokenGroups - Documented TokenGroups query output.

Return Value:

    TRUE when the user and every group SID match in order.

--*/
{
    ULONG index = 0UL;
    SID_AND_ATTRIBUTES candidateEntry;

    if (candidate == NULL || tokenUser == NULL || tokenGroups == NULL ||
        expectedCount == 0UL || expectedCount != tokenGroups->GroupCount + 1UL) {
        return FALSE;
    }
    RtlZeroMemory(&candidateEntry, sizeof(candidateEntry));
    if (!kswordArkDriverReadSidAndAttributesGuarded(&candidate[0], &candidateEntry) ||
        !kswordArkDriverEqualSidGuarded(candidateEntry.Sid, tokenUser->User.Sid)) {
        return FALSE;
    }

    for (index = 0UL; index < tokenGroups->GroupCount; ++index) {
        RtlZeroMemory(&candidateEntry, sizeof(candidateEntry));
        if (!kswordArkDriverReadSidAndAttributesGuarded(
                &candidate[index + 1UL],
                &candidateEntry) ||
            !kswordArkDriverEqualSidGuarded(
                candidateEntry.Sid,
                tokenGroups->Groups[index].Sid)) {
            return FALSE;
        }
    }
    return TRUE;
}

LONG
kswordArkDriverResolveProcessTokenOffset(
    _In_ PEPROCESS process,
    _In_ PACCESS_TOKEN token
    )
/*++

Routine Description:

    Locate the unique EPROCESS EX_FAST_REF whose decoded pointer equals the
    documented primary-token reference returned for the same live process.

Arguments:

    Process - Live process object being scanned.
    Token - Referenced primary token for Process.

Return Value:

    Non-negative EPROCESS.Token offset when unique; otherwise -1.

--*/
{
    const ULONG_PTR kFastRefMask = (sizeof(PVOID) == sizeof(ULONG64)) ? 0x0FU : 0x07U;
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (process == NULL || token == NULL) {
        return -1;
    }
    for (offset = 0UL;
         offset + sizeof(ULONG_PTR) <= KSW_RUNTIME_PROCESS_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR candidate = 0U;

        if (!kswordArkDriverReadPointerGuarded((const UCHAR*)process + offset, &candidate) ||
            (candidate & ~kFastRefMask) != (ULONG_PTR)token) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

VOID
kswordArkDriverResolveTokenLayoutOffsets(
    _In_ PACCESS_TOKEN token,
    _Out_ LONG* userAndGroupCountOffsetOut,
    _Out_ LONG* userAndGroupsOffsetOut,
    _Out_ LONG* integrityLevelIndexOffsetOut,
    _Out_ LONG* mandatoryPolicyOffsetOut
    )
/*++

Routine Description:

    Recover the four token integrity fields by comparing a bounded token-body
    scan with TokenUser, TokenGroups, TokenIntegrityLevel, and
    TokenMandatoryPolicy query results. A field set is accepted only when the
    internal SID array is an exact ordered match and every scalar candidate is
    unique inside its structural window.

Arguments:

    Token - Referenced primary token object.
    UserAndGroupCountOffsetOut - Receives TOKEN.UserAndGroupCount.
    UserAndGroupsOffsetOut - Receives TOKEN.UserAndGroups.
    IntegrityLevelIndexOffsetOut - Receives TOKEN.IntegrityLevelIndex.
    MandatoryPolicyOffsetOut - Receives TOKEN.MandatoryPolicy.

Return Value:

    None. All outputs remain unavailable unless the complete layout validates.

--*/
{
    PTOKEN_USER tokenUser = NULL;
    PTOKEN_GROUPS tokenGroups = NULL;
    ULONG integrityLevel = 0UL;
    PTOKEN_MANDATORY_POLICY mandatoryPolicy = NULL;
    ULONG expectedCount = 0UL;
    ULONG groupsOffset = 0UL;
    LONG foundGroupsOffset = -1;
    LONG foundCountOffset = -1;
    LONG foundPairOffset = -1;
    ULONG integrityIndex = MAXULONG;
    NTSTATUS status = STATUS_SUCCESS;

    if (userAndGroupCountOffsetOut == NULL || userAndGroupsOffsetOut == NULL ||
        integrityLevelIndexOffsetOut == NULL || mandatoryPolicyOffsetOut == NULL) {
        return;
    }
    *userAndGroupCountOffsetOut = -1;
    *userAndGroupsOffsetOut = -1;
    *integrityLevelIndexOffsetOut = -1;
    *mandatoryPolicyOffsetOut = -1;
    // SeQueryInformationToken allocates token-information buffers at PASSIVE_LEVEL.
    if (token == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(token, TokenGroups, (PVOID*)&tokenGroups);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(token, TokenIntegrityLevel, (PVOID*)&integrityLevel);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(token, TokenMandatoryPolicy, (PVOID*)&mandatoryPolicy);
    if (!NT_SUCCESS(status) || tokenGroups->GroupCount >= KSW_RUNTIME_TOKEN_MAX_GROUPS) {
        goto Exit;
    }
    expectedCount = tokenGroups->GroupCount + 1UL;

    for (groupsOffset = 0UL;
         groupsOffset + sizeof(PVOID) <= KSW_RUNTIME_TOKEN_SCAN_BYTES;
         groupsOffset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR candidateAddress = 0U;

        if (!kswordArkDriverReadPointerGuarded((const UCHAR*)token + groupsOffset, &candidateAddress) ||
            candidateAddress == 0U ||
            !kswordArkDriverTokenGroupArrayMatches(
                (const SID_AND_ATTRIBUTES*)candidateAddress,
                expectedCount,
                tokenUser,
                tokenGroups)) {
            continue;
        }
        if (foundGroupsOffset >= 0) {
            goto Exit;
        }
        foundGroupsOffset = (LONG)groupsOffset;
    }
    if (foundGroupsOffset < 0) {
        goto Exit;
    }

    {
        ULONG index = 0UL;
        ULONG matchCount = 0UL;

        for (index = 0UL; index < tokenGroups->GroupCount; ++index) {
            if (kswordArkDriverIntegrityGroupMatchesLevel(
                    &tokenGroups->Groups[index],
                    integrityLevel)) {
                // TOKEN.UserAndGroups stores the user at index zero, followed
                // by the entries returned through TokenGroups.
                integrityIndex = index + 1UL;
                matchCount += 1UL;
            }
        }
        if (matchCount != 1UL || integrityIndex == MAXULONG) {
            goto Exit;
        }
    }

    {
        ULONG searchStart = ((ULONG)foundGroupsOffset > KSW_RUNTIME_TOKEN_FIELD_WINDOW)
            ? (ULONG)foundGroupsOffset - KSW_RUNTIME_TOKEN_FIELD_WINDOW
            : 0UL;
        ULONG offset = 0UL;

        for (offset = searchStart; offset < (ULONG)foundGroupsOffset; offset += sizeof(ULONG)) {
            ULONG value = 0UL;

            __try {
                value = *(volatile const ULONG*)((const UCHAR*)token + offset);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                goto Exit;
            }
            if (value != expectedCount) {
                continue;
            }
            if (foundCountOffset >= 0) {
                goto Exit;
            }
            foundCountOffset = (LONG)offset;
        }
    }
    if (foundCountOffset < 0) {
        goto Exit;
    }

    {
        ULONG pairSearchEnd = (ULONG)foundGroupsOffset + KSW_RUNTIME_TOKEN_FIELD_WINDOW;
        ULONG offset = 0UL;

        if (pairSearchEnd > KSW_RUNTIME_TOKEN_SCAN_BYTES - (2UL * sizeof(ULONG))) {
            pairSearchEnd = KSW_RUNTIME_TOKEN_SCAN_BYTES - (2UL * sizeof(ULONG));
        }
        for (offset = (ULONG)foundGroupsOffset;
             offset <= pairSearchEnd;
             offset += sizeof(ULONG)) {
            ULONG indexValue = 0UL;
            ULONG policyValue = 0UL;

            __try {
                indexValue = *(volatile const ULONG*)((const UCHAR*)token + offset);
                policyValue = *(volatile const ULONG*)((const UCHAR*)token + offset + sizeof(ULONG));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                goto Exit;
            }
            if (indexValue != integrityIndex || policyValue != mandatoryPolicy->Policy) {
                continue;
            }
            if (foundPairOffset >= 0) {
                goto Exit;
            }
            foundPairOffset = (LONG)offset;
        }
    }
    if (foundPairOffset < 0) {
        goto Exit;
    }

    *userAndGroupCountOffsetOut = foundCountOffset;
    *userAndGroupsOffsetOut = foundGroupsOffset;
    *integrityLevelIndexOffsetOut = foundPairOffset;
    *mandatoryPolicyOffsetOut = foundPairOffset + (LONG)sizeof(ULONG);

Exit:
    if (mandatoryPolicy != NULL) {
        ExFreePool(mandatoryPolicy);
    }
    if (tokenGroups != NULL) {
        ExFreePool(tokenGroups);
    }
    if (tokenUser != NULL) {
        ExFreePool(tokenUser);
    }
}
