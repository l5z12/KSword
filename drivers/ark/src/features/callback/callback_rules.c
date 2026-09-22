/*++

Module Name:

    callback_rules.c

Abstract:

    Rule blob validation/build, active snapshot swap and hot-path matching.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_push_lock.h"

typedef struct KswordArkGroupView
{
    ULONG groupId;
    ULONG flags;
    ULONG priority;
    ULONG nameOffsetBytes;
    USHORT nameLengthChars;
} KswordArkGroupView;

static ULONG
kswordArkCallbackCrc32Step(
    _In_reads_bytes_(dataLength) const UCHAR* dataBuffer,
    _In_ ULONG dataLength,
    _In_ ULONG currentCrc
    )
{
    ULONG crcValue = currentCrc;
    ULONG byteIndex = 0;
    ULONG bitIndex = 0;

    if (dataBuffer == NULL || dataLength == 0U) {
        return crcValue;
    }

    for (byteIndex = 0; byteIndex < dataLength; ++byteIndex) {
        crcValue ^= (ULONG)dataBuffer[byteIndex];
        for (bitIndex = 0; bitIndex < 8U; ++bitIndex) {
            if ((crcValue & 1U) != 0U) {
                crcValue = (crcValue >> 1U) ^ 0xEDB88320UL;
            }
            else {
                crcValue >>= 1U;
            }
        }
    }

    return crcValue;
}

static ULONG
kswordArkCallbackCrc32(
    _In_reads_bytes_(dataLength) const UCHAR* dataBuffer,
    _In_ ULONG dataLength
    )
{
    ULONG runningCrc = 0xFFFFFFFFUL;
    runningCrc = kswordArkCallbackCrc32Step(dataBuffer, dataLength, runningCrc);
    return ~runningCrc;
}

static BOOLEAN
kswordArkCallbackValidateBlobString(
    _In_reads_bytes_(stringBytes) const UCHAR* stringBase,
    _In_ ULONG stringBytes,
    _In_ ULONG offsetBytes,
    _In_ USHORT lengthChars
    )
{
    ULONG requiredBytes = 0;
    const WCHAR* stringPointer = NULL;

    if (lengthChars == 0U) {
        return TRUE;
    }

    if (stringBase == NULL || stringBytes == 0U) {
        return FALSE;
    }

    if ((offsetBytes % sizeof(WCHAR)) != 0U) {
        return FALSE;
    }

    requiredBytes = ((ULONG)lengthChars + 1UL) * (ULONG)sizeof(WCHAR);
    if (offsetBytes > stringBytes || requiredBytes > stringBytes || (offsetBytes + requiredBytes) > stringBytes) {
        return FALSE;
    }

    stringPointer = (const WCHAR*)(stringBase + offsetBytes);
    if (stringPointer[lengthChars] != L'\0') {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
kswordArkCallbackActionIsValidForType(
    _In_ ULONG callbackType,
    _In_ ULONG actionType,
    _In_ ULONG matchMode
    )
{
    switch (callbackType) {
    case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
        if (actionType != KSWORD_ARK_RULE_ACTION_ALLOW &&
            actionType != KSWORD_ARK_RULE_ACTION_DENY &&
            actionType != KSWORD_ARK_RULE_ACTION_ASK_USER &&
            actionType != KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
            return FALSE;
        }
        if (matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
            actionType != KSWORD_ARK_RULE_ACTION_ASK_USER) {
            return FALSE;
        }
        return TRUE;

    case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
        if (actionType == KSWORD_ARK_RULE_ACTION_ALLOW ||
            actionType == KSWORD_ARK_RULE_ACTION_DENY ||
            actionType == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
            return TRUE;
        }
        return FALSE;

    case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
    case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
        return (actionType == KSWORD_ARK_RULE_ACTION_LOG_ONLY) ? TRUE : FALSE;

    case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
        if (actionType == KSWORD_ARK_RULE_ACTION_ALLOW ||
            actionType == KSWORD_ARK_RULE_ACTION_STRIP_ACCESS ||
            actionType == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
            return TRUE;
        }
        return FALSE;

    case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
        if (actionType == KSWORD_ARK_RULE_ACTION_ALLOW ||
            actionType == KSWORD_ARK_RULE_ACTION_DENY ||
            actionType == KSWORD_ARK_RULE_ACTION_ASK_USER ||
            actionType == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
            return TRUE;
        }
        return FALSE;

    default:
        return FALSE;
    }
}

static int __cdecl
kswordArkCallbackRuntimeRuleCompare(
    _In_ const VOID* leftRule,
    _In_ const VOID* rightRule
    )
{
    const KswordArkRuntimeRule* left = (const KswordArkRuntimeRule*)leftRule;
    const KswordArkRuntimeRule* right = (const KswordArkRuntimeRule*)rightRule;

    if (left->callbackType != right->callbackType) {
        return (left->callbackType < right->callbackType) ? -1 : 1;
    }
    if (left->groupPriority != right->groupPriority) {
        return (left->groupPriority < right->groupPriority) ? -1 : 1;
    }
    if (left->rulePriority != right->rulePriority) {
        return (left->rulePriority < right->rulePriority) ? -1 : 1;
    }
    if (left->groupId != right->groupId) {
        return (left->groupId < right->groupId) ? -1 : 1;
    }
    if (left->ruleId != right->ruleId) {
        return (left->ruleId < right->ruleId) ? -1 : 1;
    }
    return 0;
}

static VOID
kswordArkCallbackSortRuntimeRules(
    _Inout_updates_(ruleCount) KswordArkRuntimeRule* runtimeRules,
    _In_ ULONG ruleCount
    )
{
    ULONG outerIndex = 0;
    ULONG innerIndex = 0;

    if (runtimeRules == NULL || ruleCount <= 1U) {
        return;
    }

    for (outerIndex = 1U; outerIndex < ruleCount; ++outerIndex) {
        KswordArkRuntimeRule currentRule = runtimeRules[outerIndex];
        innerIndex = outerIndex;

        while (innerIndex > 0U &&
            kswordArkCallbackRuntimeRuleCompare(&runtimeRules[innerIndex - 1U], &currentRule) > 0) {
            runtimeRules[innerIndex] = runtimeRules[innerIndex - 1U];
            innerIndex -= 1U;
        }
        runtimeRules[innerIndex] = currentRule;
    }
}

static KswordArkGroupView*
kswordArkCallbackFindGroupView(
    _Inout_updates_(groupCount) KswordArkGroupView* groupViews,
    _In_ ULONG groupCount,
    _In_ ULONG groupId
    )
{
    ULONG groupIndex = 0;

    if (groupViews == NULL || groupCount == 0U || groupId == 0U) {
        return NULL;
    }

    for (groupIndex = 0; groupIndex < groupCount; ++groupIndex) {
        if (groupViews[groupIndex].groupId == groupId) {
            return &groupViews[groupIndex];
        }
    }
    return NULL;
}

static KswordArkCallbackRuleSnapshot*
kswordArkCallbackAcquireSnapshot(
    VOID
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkCallbackRuleSnapshot* snapshot = NULL;

    if (runtime == NULL) {
        return NULL;
    }

    kswordArkAcquirePushLockShared(&runtime->snapshotLock);
    snapshot = runtime->activeSnapshot;
    if (snapshot != NULL) {
        if (!ExAcquireRundownProtection(&snapshot->rundownRef)) {
            snapshot = NULL;
        }
    }
    kswordArkReleasePushLockShared(&runtime->snapshotLock);
    return snapshot;
}

static VOID
kswordArkCallbackReleaseSnapshot(
    _In_opt_ KswordArkCallbackRuleSnapshot* snapshot
    )
{
    if (snapshot != NULL) {
        ExReleaseRundownProtection(&snapshot->rundownRef);
    }
}

NTSTATUS
kswordArkCallbackBuildSnapshotFromBlob(
    _In_reads_bytes_(blobBytes) const VOID* blobData,
    _In_ size_t blobBytes,
    _Outptr_ KswordArkCallbackRuleSnapshot** snapshotOut
    )
{
    const UCHAR* blobBytesPtr = (const UCHAR*)blobData;
    const KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER* header = NULL;
    const KSWORD_ARK_CALLBACK_GROUP_BLOB* groupTable = NULL;
    const KSWORD_ARK_CALLBACK_RULE_BLOB* ruleTable = NULL;
    const UCHAR* stringPool = NULL;
    KswordArkGroupView groupViews[KSWORD_ARK_CALLBACK_MAX_GROUP_COUNT] = { 0 };
    KswordArkCallbackRuleSnapshot* snapshot = NULL;
    KswordArkRuntimeRule* runtimeRules = NULL;
    UCHAR* snapshotStringPool = NULL;
    ULONG activeRuleCount = 0;
    ULONG ruleIndex = 0;
    ULONG groupIndex = 0;
    ULONG expectedCrc32 = 0;
    ULONG calculatedCrc32 = 0;
    KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER headerCopy = { 0 };
    ULONG runningCrc = 0xFFFFFFFFUL;
    size_t snapshotRulesBytes = 0;
    size_t snapshotBytes = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (snapshotOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;

    if (blobData == NULL || blobBytes < sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    header = (const KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER*)blobData;
    if (header->magic != KSWORD_ARK_CALLBACK_RULE_BLOB_MAGIC ||
        header->protocolVersion != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
        header->schemaVersion != KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    if (header->size > blobBytes ||
        header->size < sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (header->groupCount > KSWORD_ARK_CALLBACK_MAX_GROUP_COUNT ||
        header->ruleCount > KSWORD_ARK_CALLBACK_MAX_RULE_COUNT ||
        header->stringBytes > KSWORD_ARK_CALLBACK_MAX_STRING_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->groupOffsetBytes > header->size ||
        header->ruleOffsetBytes > header->size ||
        header->stringOffsetBytes > header->size) {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->groupCount != 0U) {
        size_t groupTableBytes = (size_t)header->groupCount * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB);
        if ((size_t)header->groupOffsetBytes + groupTableBytes > header->size) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (header->ruleCount != 0U) {
        size_t ruleTableBytes = (size_t)header->ruleCount * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB);
        if ((size_t)header->ruleOffsetBytes + ruleTableBytes > header->size) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if ((size_t)header->stringOffsetBytes + (size_t)header->stringBytes > header->size) {
        return STATUS_INVALID_PARAMETER;
    }

    expectedCrc32 = header->crc32;
    headerCopy = *header;
    headerCopy.crc32 = 0U;
    runningCrc = kswordArkCallbackCrc32Step((const UCHAR*)&headerCopy, sizeof(headerCopy), runningCrc);
    if (header->size > sizeof(headerCopy)) {
        runningCrc = kswordArkCallbackCrc32Step(
            blobBytesPtr + sizeof(headerCopy),
            (ULONG)(header->size - sizeof(headerCopy)),
            runningCrc);
    }
    calculatedCrc32 = ~runningCrc;
    if (expectedCrc32 != calculatedCrc32) {
        return STATUS_CRC_ERROR;
    }

    groupTable = (const KSWORD_ARK_CALLBACK_GROUP_BLOB*)(blobBytesPtr + header->groupOffsetBytes);
    ruleTable = (const KSWORD_ARK_CALLBACK_RULE_BLOB*)(blobBytesPtr + header->ruleOffsetBytes);
    stringPool = blobBytesPtr + header->stringOffsetBytes;

    for (groupIndex = 0; groupIndex < header->groupCount; ++groupIndex) {
        const KSWORD_ARK_CALLBACK_GROUP_BLOB* groupBlob = &groupTable[groupIndex];
        KswordArkGroupView* existingGroup = NULL;

        if ((groupBlob->flags & (~KSWORD_ARK_CALLBACK_GROUP_FLAG_ENABLED)) != 0U) {
            return STATUS_INVALID_PARAMETER;
        }
        if (groupBlob->groupId == 0U) {
            return STATUS_INVALID_PARAMETER;
        }

        existingGroup = kswordArkCallbackFindGroupView(groupViews, groupIndex, groupBlob->groupId);
        if (existingGroup != NULL) {
            return STATUS_OBJECT_NAME_COLLISION;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            groupBlob->nameOffsetBytes,
            groupBlob->nameLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            groupBlob->commentOffsetBytes,
            groupBlob->commentLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        groupViews[groupIndex].groupId = groupBlob->groupId;
        groupViews[groupIndex].flags = groupBlob->flags;
        groupViews[groupIndex].priority = groupBlob->priority;
        groupViews[groupIndex].nameOffsetBytes = groupBlob->nameOffsetBytes;
        groupViews[groupIndex].nameLengthChars = groupBlob->nameLengthChars;
    }

    for (ruleIndex = 0; ruleIndex < header->ruleCount; ++ruleIndex) {
        const KSWORD_ARK_CALLBACK_RULE_BLOB* ruleBlob = &ruleTable[ruleIndex];
        KswordArkGroupView* groupView = NULL;

        if ((ruleBlob->flags & (~KSWORD_ARK_CALLBACK_RULE_FLAG_ENABLED)) != 0U) {
            return STATUS_INVALID_PARAMETER;
        }

        if (ruleBlob->callbackType == KSWORD_ARK_CALLBACK_TYPE_NONE ||
            ruleBlob->callbackType > KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) {
            return STATUS_INVALID_PARAMETER;
        }

        if (ruleBlob->matchMode < KSWORD_ARK_MATCH_MODE_EXACT ||
            ruleBlob->matchMode > KSWORD_ARK_MATCH_MODE_REGEX) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!kswordArkCallbackActionIsValidForType(
            ruleBlob->callbackType,
            ruleBlob->action,
            ruleBlob->matchMode)) {
            return STATUS_NOT_SUPPORTED;
        }

        if (ruleBlob->matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
            ((ruleBlob->callbackType != KSWORD_ARK_CALLBACK_TYPE_REGISTRY &&
                ruleBlob->callbackType != KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) ||
                ruleBlob->action != KSWORD_ARK_RULE_ACTION_ASK_USER)) {
            return STATUS_NOT_SUPPORTED;
        }

        groupView = kswordArkCallbackFindGroupView(groupViews, header->groupCount, ruleBlob->groupId);
        if (groupView == NULL) {
            return STATUS_NOT_FOUND;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            ruleBlob->initiatorOffsetBytes,
            ruleBlob->initiatorLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            ruleBlob->targetOffsetBytes,
            ruleBlob->targetLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            ruleBlob->ruleNameOffsetBytes,
            ruleBlob->ruleNameLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!kswordArkCallbackValidateBlobString(
            stringPool,
            header->stringBytes,
            ruleBlob->commentOffsetBytes,
            ruleBlob->commentLengthChars)) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((groupView->flags & KSWORD_ARK_CALLBACK_GROUP_FLAG_ENABLED) != 0U &&
            (ruleBlob->flags & KSWORD_ARK_CALLBACK_RULE_FLAG_ENABLED) != 0U) {
            activeRuleCount += 1UL;
        }
    }

    if (activeRuleCount == 0U) {
        snapshotRulesBytes = sizeof(KswordArkRuntimeRule);
    }
    else {
        snapshotRulesBytes = (size_t)activeRuleCount * sizeof(KswordArkRuntimeRule);
    }

    if ((FIELD_OFFSET(KswordArkCallbackRuleSnapshot, rules) + snapshotRulesBytes) < snapshotRulesBytes) {
        return STATUS_INTEGER_OVERFLOW;
    }

    snapshotBytes = FIELD_OFFSET(KswordArkCallbackRuleSnapshot, rules) + snapshotRulesBytes + header->stringBytes;
    if (snapshotBytes < snapshotRulesBytes) {
        return STATUS_INTEGER_OVERFLOW;
    }

    snapshot = (KswordArkCallbackRuleSnapshot*)kswordArkAllocateNonPaged(
        snapshotBytes,
        KSWORD_ARK_CALLBACK_TAG_SNAPSHOT);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(snapshot, snapshotBytes);

    runtimeRules = &snapshot->rules[0];
    snapshotStringPool = ((UCHAR*)snapshot) + FIELD_OFFSET(KswordArkCallbackRuleSnapshot, rules) + snapshotRulesBytes;
    if (header->stringBytes > 0U) {
        RtlCopyMemory(snapshotStringPool, stringPool, header->stringBytes);
    }

    snapshot->globalFlags = header->globalFlags;
    snapshot->groupCount = header->groupCount;
    snapshot->ruleCount = header->ruleCount;
    snapshot->activeRuleCount = activeRuleCount;
    snapshot->stringPoolBytes = header->stringBytes;
    snapshot->ruleVersion = header->ruleVersion;
    kswordArkGetSystemTimeUtc100ns(&snapshot->appliedAtUtc100ns);

    activeRuleCount = 0U;
    for (ruleIndex = 0; ruleIndex < header->ruleCount; ++ruleIndex) {
        const KSWORD_ARK_CALLBACK_RULE_BLOB* ruleBlob = &ruleTable[ruleIndex];
        KswordArkGroupView* groupView = kswordArkCallbackFindGroupView(groupViews, header->groupCount, ruleBlob->groupId);
        KswordArkRuntimeRule* runtimeRule = NULL;
        WCHAR* namePointer = NULL;
        WCHAR* ruleNamePointer = NULL;
        WCHAR* initiatorPointer = NULL;
        WCHAR* targetPointer = NULL;

        if (groupView == NULL) {
            status = STATUS_NOT_FOUND;
            break;
        }

        if ((groupView->flags & KSWORD_ARK_CALLBACK_GROUP_FLAG_ENABLED) == 0U ||
            (ruleBlob->flags & KSWORD_ARK_CALLBACK_RULE_FLAG_ENABLED) == 0U) {
            continue;
        }

        runtimeRule = &runtimeRules[activeRuleCount];
        runtimeRule->groupId = ruleBlob->groupId;
        runtimeRule->ruleId = ruleBlob->ruleId;
        runtimeRule->groupPriority = groupView->priority;
        runtimeRule->rulePriority = ruleBlob->priority;
        runtimeRule->callbackType = ruleBlob->callbackType;
        runtimeRule->operationMask = ruleBlob->operationMask;
        runtimeRule->action = ruleBlob->action;
        runtimeRule->matchMode = ruleBlob->matchMode;
        runtimeRule->askTimeoutMs = ruleBlob->askTimeoutMs;
        runtimeRule->askDefaultDecision = ruleBlob->askDefaultDecision;
        if (runtimeRule->askDefaultDecision != KSWORD_ARK_DECISION_ALLOW &&
            runtimeRule->askDefaultDecision != KSWORD_ARK_DECISION_DENY) {
            runtimeRule->askDefaultDecision = KSWORD_ARK_DECISION_ALLOW;
        }
        if (runtimeRule->askTimeoutMs == 0U) {
            runtimeRule->askTimeoutMs = 5000UL;
        }

        initiatorPointer = (WCHAR*)(snapshotStringPool + ruleBlob->initiatorOffsetBytes);
        targetPointer = (WCHAR*)(snapshotStringPool + ruleBlob->targetOffsetBytes);
        namePointer = (WCHAR*)(snapshotStringPool + groupView->nameOffsetBytes);
        ruleNamePointer = (WCHAR*)(snapshotStringPool + ruleBlob->ruleNameOffsetBytes);

        RtlInitUnicodeString(&runtimeRule->initiatorPattern, initiatorPointer);
        runtimeRule->initiatorPattern.Length = ruleBlob->initiatorLengthChars * (USHORT)sizeof(WCHAR);
        runtimeRule->initiatorPattern.MaximumLength =
            runtimeRule->initiatorPattern.Length + (USHORT)sizeof(WCHAR);

        RtlInitUnicodeString(&runtimeRule->targetPattern, targetPointer);
        runtimeRule->targetPattern.Length = ruleBlob->targetLengthChars * (USHORT)sizeof(WCHAR);
        runtimeRule->targetPattern.MaximumLength =
            runtimeRule->targetPattern.Length + (USHORT)sizeof(WCHAR);

        RtlInitUnicodeString(&runtimeRule->groupName, namePointer);
        runtimeRule->groupName.Length = groupView->nameLengthChars * (USHORT)sizeof(WCHAR);
        runtimeRule->groupName.MaximumLength =
            runtimeRule->groupName.Length + (USHORT)sizeof(WCHAR);

        RtlInitUnicodeString(&runtimeRule->ruleName, ruleNamePointer);
        runtimeRule->ruleName.Length = ruleBlob->ruleNameLengthChars * (USHORT)sizeof(WCHAR);
        runtimeRule->ruleName.MaximumLength =
            runtimeRule->ruleName.Length + (USHORT)sizeof(WCHAR);

        activeRuleCount += 1UL;
    }

    if (!NT_SUCCESS(status)) {
        kswordArkCallbackFreeSnapshot(snapshot);
        return status;
    }

    kswordArkCallbackSortRuntimeRules(runtimeRules, snapshot->activeRuleCount);

    for (groupIndex = 0; groupIndex <= KSWORD_ARK_CALLBACK_TYPE_MINIFILTER; ++groupIndex) {
        snapshot->bucketStart[groupIndex] = 0U;
        snapshot->bucketCount[groupIndex] = 0U;
    }

    for (ruleIndex = 0; ruleIndex < snapshot->activeRuleCount; ++ruleIndex) {
        ULONG callbackType = runtimeRules[ruleIndex].callbackType;
        if (callbackType <= KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) {
            if (snapshot->bucketCount[callbackType] == 0U) {
                snapshot->bucketStart[callbackType] = ruleIndex;
            }
            snapshot->bucketCount[callbackType] += 1U;
        }
    }

    ExInitializeRundownProtection(&snapshot->rundownRef);
    *snapshotOut = snapshot;
    return STATUS_SUCCESS;
}

VOID
kswordArkCallbackFreeSnapshot(
    _In_opt_ KswordArkCallbackRuleSnapshot* snapshot
    )
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, KSWORD_ARK_CALLBACK_TAG_SNAPSHOT);
    }
}

NTSTATUS
kswordArkCallbackSwapSnapshot(
    _In_ KswordArkCallbackRuleSnapshot* newSnapshot
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkCallbackRuleSnapshot* oldSnapshot = NULL;

    if (runtime == NULL || newSnapshot == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    kswordArkAcquirePushLockExclusive(&runtime->snapshotLock);
    oldSnapshot = runtime->activeSnapshot;
    runtime->activeSnapshot = newSnapshot;
    kswordArkReleasePushLockExclusive(&runtime->snapshotLock);

    if (oldSnapshot != NULL) {
        ExWaitForRundownProtectionRelease(&oldSnapshot->rundownRef);
        kswordArkCallbackFreeSnapshot(oldSnapshot);
    }

    kswordArkCallbackLogFormat(
        "Info",
        "Callback snapshot switched, ruleVersion=%I64u, groups=%lu, rules=%lu, active=%lu.",
        (unsigned long long)newSnapshot->ruleVersion,
        (unsigned long)newSnapshot->groupCount,
        (unsigned long)newSnapshot->ruleCount,
        (unsigned long)newSnapshot->activeRuleCount);
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkCallbackOperationMatch(
    _In_ ULONG ruleOperationMask,
    _In_ ULONG operationType
    )
{
    if (ruleOperationMask == 0U || operationType == 0U) {
        return TRUE;
    }
    return ((ruleOperationMask & operationType) != 0U) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkCallbackTextMatch(
    _In_ ULONG matchMode,
    _In_ PCUNICODE_STRING patternText,
    _In_opt_ PCUNICODE_STRING valueText
    )
{
    if (patternText == NULL || patternText->Length == 0U) {
        return TRUE;
    }
    if (valueText == NULL || valueText->Buffer == NULL) {
        return FALSE;
    }

    switch (matchMode) {
    case KSWORD_ARK_MATCH_MODE_EXACT:
        return RtlEqualUnicodeString(patternText, valueText, TRUE) ? TRUE : FALSE;

    case KSWORD_ARK_MATCH_MODE_PREFIX:
        return RtlPrefixUnicodeString(patternText, valueText, TRUE) ? TRUE : FALSE;

    case KSWORD_ARK_MATCH_MODE_WILDCARD:
        __try {
            return FsRtlIsNameInExpression(
                (PUNICODE_STRING)patternText,
                (PUNICODE_STRING)valueText,
                TRUE,
                NULL)
                ? TRUE
                : FALSE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

    case KSWORD_ARK_MATCH_MODE_REGEX:
        // Driver side keeps regex rules deterministic-light and defers exact regex
        // confirmation to user-mode.
        return TRUE;

    default:
        return FALSE;
    }
}

NTSTATUS
kswordArkCallbackMatchRule(
    _In_ ULONG callbackType,
    _In_ ULONG operationType,
    _In_opt_ PCUNICODE_STRING initiatorPath,
    _In_opt_ PCUNICODE_STRING targetPath,
    _Out_ KswordArkCallbackMatchResult* matchResultOut
    )
{
    KswordArkCallbackRuleSnapshot* snapshot = NULL;
    ULONG startIndex = 0;
    ULONG ruleCount = 0;
    ULONG currentIndex = 0;

    if (matchResultOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(matchResultOut, sizeof(*matchResultOut));
    if (callbackType == KSWORD_ARK_CALLBACK_TYPE_NONE ||
        callbackType > KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) {
        return STATUS_INVALID_PARAMETER;
    }

    snapshot = kswordArkCallbackAcquireSnapshot();
    if (snapshot == NULL) {
        return STATUS_NOT_FOUND;
    }

    if ((snapshot->globalFlags & KSWORD_ARK_CALLBACK_GLOBAL_FLAG_ENABLED) == 0U) {
        kswordArkCallbackReleaseSnapshot(snapshot);
        return STATUS_NOT_FOUND;
    }

    startIndex = snapshot->bucketStart[callbackType];
    ruleCount = snapshot->bucketCount[callbackType];
    for (currentIndex = 0; currentIndex < ruleCount; ++currentIndex) {
        const KswordArkRuntimeRule* rule = &snapshot->rules[startIndex + currentIndex];
        if (!kswordArkCallbackOperationMatch(rule->operationMask, operationType)) {
            continue;
        }

        if (!kswordArkCallbackTextMatch(rule->matchMode, &rule->initiatorPattern, initiatorPath)) {
            continue;
        }
        if (!kswordArkCallbackTextMatch(rule->matchMode, &rule->targetPattern, targetPath)) {
            continue;
        }

        matchResultOut->matched = TRUE;
        matchResultOut->callbackType = callbackType;
        matchResultOut->ruleOperationMask = rule->operationMask;
        matchResultOut->action = rule->action;
        matchResultOut->matchMode = rule->matchMode;
        matchResultOut->askTimeoutMs = rule->askTimeoutMs;
        matchResultOut->askDefaultDecision = rule->askDefaultDecision;
        matchResultOut->groupId = rule->groupId;
        matchResultOut->ruleId = rule->ruleId;
        matchResultOut->groupPriority = rule->groupPriority;
        matchResultOut->rulePriority = rule->rulePriority;
        kswordArkCopyUnicodeToFixedBuffer(&rule->groupName, matchResultOut->groupName, RTL_NUMBER_OF(matchResultOut->groupName));
        kswordArkCopyUnicodeToFixedBuffer(&rule->ruleName, matchResultOut->ruleName, RTL_NUMBER_OF(matchResultOut->ruleName));
        kswordArkCopyUnicodeToFixedBuffer(&rule->initiatorPattern, matchResultOut->ruleInitiatorPattern, RTL_NUMBER_OF(matchResultOut->ruleInitiatorPattern));
        kswordArkCopyUnicodeToFixedBuffer(&rule->targetPattern, matchResultOut->ruleTargetPattern, RTL_NUMBER_OF(matchResultOut->ruleTargetPattern));
        kswordArkCallbackReleaseSnapshot(snapshot);
        return STATUS_SUCCESS;
    }

    kswordArkCallbackReleaseSnapshot(snapshot);
    return STATUS_NOT_FOUND;
}

VOID
kswordArkCallbackQueryRuntimeState(
    _Out_ KSWORD_ARK_CALLBACK_RUNTIME_STATE* runtimeStateOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkCallbackRuleSnapshot* snapshot = NULL;

    if (runtimeStateOut == NULL) {
        return;
    }

    RtlZeroMemory(runtimeStateOut, sizeof(*runtimeStateOut));
    runtimeStateOut->size = sizeof(*runtimeStateOut);
    runtimeStateOut->version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    runtimeStateOut->driverOnline = (runtime != NULL) ? 1UL : 0UL;

    if (runtime == NULL) {
        return;
    }

    runtimeStateOut->callbacksRegisteredMask = runtime->registeredCallbacksMask;
    runtimeStateOut->pendingDecisionCount = kswordArkCallbackGetPendingDecisionCount();
    runtimeStateOut->waitingReceiverCount = kswordArkCallbackGetWaitingRequestCount();

    // After a degraded startup, return the original registration status item by item so R3 can interpret missing capabilities.
    runtimeStateOut->waitQueueStatus = (long)runtime->waitQueueStatus;
    runtimeStateOut->registryCallbackStatus = (long)runtime->registryRegisterStatus;
    runtimeStateOut->processCallbackStatus = (long)runtime->processRegisterStatus;
    runtimeStateOut->threadCallbackStatus = (long)runtime->threadRegisterStatus;
    runtimeStateOut->imageCallbackStatus = (long)runtime->imageRegisterStatus;
    runtimeStateOut->objectCallbackStatus = (long)runtime->objectRegisterStatus;

    snapshot = kswordArkCallbackAcquireSnapshot();
    if (snapshot == NULL) {
        return;
    }

    runtimeStateOut->globalEnabled =
        ((snapshot->globalFlags & KSWORD_ARK_CALLBACK_GLOBAL_FLAG_ENABLED) != 0U) ? 1UL : 0UL;
    runtimeStateOut->rulesApplied = (snapshot->activeRuleCount > 0U) ? 1UL : 0UL;
    runtimeStateOut->groupCount = snapshot->groupCount;
    runtimeStateOut->ruleCount = snapshot->activeRuleCount;
    runtimeStateOut->appliedRuleVersion = snapshot->ruleVersion;
    runtimeStateOut->appliedAtUtc100ns = (ULONG64)snapshot->appliedAtUtc100ns.QuadPart;

    kswordArkCallbackReleaseSnapshot(snapshot);
}
