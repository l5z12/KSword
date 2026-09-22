#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkHandleIoctl.h"
#include "../driver/KswordArkWorkQueueIoctl.h"
#include "../driver/KswordArkAlpcIoctl.h"
#include "../driver/KswordArkFilterIoctl.h"
#include "../driver/KswordArkKernelObjectIoctl.h"

namespace ksword::ark
{
    // WorkQueueEntry preserves one validated read-only R0 work-item or worker-thread row.
    struct WorkQueueEntry
    {
        std::uint32_t rowKind = 0;
        std::uint32_t queueType = 0;
        std::uint32_t priorityIndex = 0;
        std::uint32_t nodeIndex = 0;
        std::uint32_t flags = 0;
        std::uint32_t status = 0;
        std::uint64_t queueAddress = 0;
        std::uint64_t workItemAddress = 0;
        std::uint64_t routineAddress = 0;
        std::uint64_t parameterAddress = 0;
        std::uint64_t threadObject = 0;
        std::uint32_t threadId = 0;
        std::uint64_t threadCreateTime100ns = 0;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::string moduleName;
        std::string modulePath;
    };

    // WorkQueueEnumResult separates transport success from explicit fail-closed R0 status.
    struct WorkQueueEnumResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
        std::uint32_t statusFlags = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t nodeCount = 0;
        std::uint32_t queuesVisited = 0;
        std::uint32_t corruptListCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t referenceFailureCount = 0;
        long lastStatus = 0;
        std::vector<WorkQueueEntry> entries;
    };

    // HandleEntry is the R3-side model directly enumerated from the R0 HandleTable.
    struct HandleEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t handleValue = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::uint32_t objectTypeIndex = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t epObjectTableOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t htHandleContentionEventOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t obDecodeShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t obAttributesShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
    };

    // HandleEnumResult: Carries the response for enumerating the R0 process HandleTable.
    struct HandleEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processId = 0;
        std::uint32_t overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::vector<HandleEntry> entries;
    };

    // HandleObjectQueryResult carries R0 object type/name query results.
    struct HandleObjectQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint64_t handleValue = 0;
        std::uint64_t objectAddress = 0;
        std::uint32_t objectTypeIndex = 0;
        std::uint32_t queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE;
        long objectReferenceStatus = 0;
        long typeStatus = 0;
        long nameStatus = 0;
        std::uint32_t proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_NOT_REQUESTED;
        long proxyNtStatus = 0;
        std::uint32_t proxyPolicyFlags = 0;
        std::uint32_t requestedAccess = 0;
        std::uint32_t actualGrantedAccess = 0;
        std::uint64_t proxyHandle = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::wstring typeName;
        std::wstring objectName;
    };

    // AlpcPortInfo is the R3 presentation model for a single port node in an R0 ALPC Port query.
    struct AlpcPortInfo
    {
        std::uint32_t relation = KSWORD_ARK_ALPC_PORT_RELATION_QUERY;
        std::uint32_t fieldFlags = 0;
        std::uint32_t ownerProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t state = 0;
        std::uint32_t sequenceNo = 0;
        long basicStatus = 0;
        long nameStatus = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t portContext = 0;
        std::wstring portName;
    };

    // AlpcPortQueryResult carries the Phase-6 R0 ALPC query response.
    struct AlpcPortQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint64_t handleValue = 0;
        std::uint32_t queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE;
        long objectReferenceStatus = 0;
        long typeStatus = 0;
        long basicStatus = 0;
        long communicationStatus = 0;
        long nameStatus = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t alpcCommunicationInfoOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcOwnerProcessOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcConnectionPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcServerCommunicationPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcClientCommunicationPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcHandleTableOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcHandleTableLockOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcAttributesOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcAttributesFlagsOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcPortContextOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcPortObjectLockOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcSequenceNoOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcStateOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::wstring typeName;
        AlpcPortInfo queryPort;
        AlpcPortInfo connectionPort;
        AlpcPortInfo serverPort;
        AlpcPortInfo clientPort;
    };

    // MinifilterInventoryResult: Carries the binding list of fltMgr filters and instances.
    // Input: queryMinifilterInventory return.
    // Note: entries store filter, altitude, volume, and callback-owner states.
    // Return behavior: used for display only; does not unload, detach, or modify callbacks.
    struct MinifilterInventoryResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::vector<KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY> entries;
    };

    // CidTableAuditResult carries the read-only enumeration of PspCidTable.
    // Input: Return from enumCidTable.
    // Handling: entries store CID, object type, reference status, and object address.
    // Return behavior: Does not delete the CID or hide the process/thread.
    struct CidTableAuditResult : VariableAuditResultBase
    {
        std::uint32_t visitedCount = 0;
        std::uint32_t maxVisitCount = 0;
        std::uint64_t pspCidTableAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t htTableCodeOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::uint32_t hteLowValueOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::vector<KSWORD_ARK_CID_TABLE_ENTRY> entries;
    };

    // ObjectTypeTableAuditResult holds a read-only snapshot of R0 ObTypeIndexTable.
    // Input: Returned by enumObjectTypeTable; supports pagination by type index.
    // Note: Preserve table address, DynData offset, snapshot hash, and per-slot cross-validation results.
    // Return behavior: read-only display; does not modify the object type table or object headers.
    struct ObjectTypeTableAuditResult : VariableAuditResultBase
    {
        std::uint32_t nextIndex = 0;
        std::uint64_t tableAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t snapshotHash = 0;
        std::uint32_t otNameOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::vector<KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY> entries;
    };

    // KernelObjectSummaryAuditResult holds the summary of a single object's header, type, and counter.
    // Input: Return value of queryKernelObjectSummary.
    // Handling: directly save the shared fixed response structure in the response.
    // Return behavior: Read-only display of object metadata; does not modify object headers or reference counts.
    struct KernelObjectSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE response{};
    };

    // IpcSummaryAuditResult carries ALPC/Pipe/Mailslot IPC summaries.
    // Input: Return value of queryIpcSummary.
    // Handling: the response retains the handle, object address, typeName, and downgrade details.
    // Return behavior: Do not close the handle, do not send messages, do not modify the IPC object.
    struct IpcSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE response{};
    };
}
