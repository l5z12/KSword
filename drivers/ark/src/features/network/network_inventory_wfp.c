/*++

Module Name:

    network_inventory_wfp.c

Abstract:

    Read-only global BFE/WFP provider, sublayer, callout and filter inventory.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include <ntddk.h>
#include <fwpmk.h>
#include "network_inventory_internal.h"

#define KSWORD_ARK_WFP_ENUM_PAGE_ROWS 128UL
#define KSWORD_ARK_WFP_ENUM_MAX_ROWS 65536UL

typedef struct KswordArkWfpEnumBuilder
{
    HANDLE engineHandle;
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* rows;
    ULONG rowCapacity;
    ULONG totalRows;
    ULONG returnedRows;
} KswordArkWfpEnumBuilder;

static VOID
kswordArkNetworkWfpCopyGuid(
    _Out_writes_(16) UCHAR destination[16],
    _In_opt_ const GUID* source
    )
{
    RtlZeroMemory(destination, 16U);
    if (source != NULL) {
        RtlCopyMemory(destination, source, sizeof(GUID));
    }
}

static ULONG64
kswordArkNetworkWfpReadWeight(
    _In_ const FWP_VALUE0* value
    )
{
    if (value == NULL) {
        return 0ULL;
    }

    switch (value->type) {
    case FWP_UINT8:
        return value->uint8;
    case FWP_UINT16:
        return value->uint16;
    case FWP_UINT32:
        return value->uint32;
    case FWP_UINT64:
        return (value->uint64 != NULL) ? *value->uint64 : 0ULL;
    case FWP_EMPTY:
    default:
        return 0ULL;
    }
}

static ULONG
kswordArkNetworkWfpResolveLayerId(
    _In_ HANDLE engineHandle,
    _In_ const GUID* layerKey
    )
/*++

Routine Description:

    Convert layer GUID to runtime layerId using the official BFE query. On failure, keep it zero;
    the call site already has the FIELD_MISSING flag, so do not guess the ID based on the GUID.

--*/
{
    FWPM_LAYER0* layer = NULL;
    ULONG layerId = 0UL;
    NTSTATUS status = FwpmLayerGetByKey0(engineHandle, layerKey, &layer);

    if (NT_SUCCESS(status) && layer != NULL) {
        layerId = layer->layerId;
    }
    if (layer != NULL) {
        FwpmFreeMemory0((VOID**)&layer);
    }
    return layerId;
}

static KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW*
kswordArkNetworkWfpReserveRow(
    _Inout_ KswordArkWfpEnumBuilder* builder
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (builder == NULL || builder->totalRows >= KSWORD_ARK_WFP_ENUM_MAX_ROWS) {
        return NULL;
    }

    builder->totalRows += 1UL;
    if (builder->rows != NULL && builder->returnedRows < builder->rowCapacity) {
        row = &builder->rows[builder->returnedRows];
        RtlZeroMemory(row, sizeof(*row));
        row->rowId = builder->returnedRows;
        builder->returnedRows += 1UL;
    }
    return row;
}

static VOID
kswordArkNetworkWfpAppendProvider(
    _Inout_ KswordArkWfpEnumBuilder* builder,
    _In_opt_ const FWPM_PROVIDER0* provider
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (provider == NULL) {
        return;
    }
    row = kswordArkNetworkWfpReserveRow(builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    kswordArkNetworkWfpCopyGuid(row->objectKey, &provider->providerKey);
    kswordArkNetworkInventoryCopyWideText(
        row->ownerModule,
        (provider->serviceName != NULL) ? provider->serviceName : provider->displayData.name);
}

static VOID
kswordArkNetworkWfpAppendSubLayer(
    _Inout_ KswordArkWfpEnumBuilder* builder,
    _In_opt_ const FWPM_SUBLAYER0* subLayer
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (subLayer == NULL) {
        return;
    }
    row = kswordArkNetworkWfpReserveRow(builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->weight = subLayer->weight;
    kswordArkNetworkWfpCopyGuid(row->providerKey, subLayer->providerKey);
    kswordArkNetworkWfpCopyGuid(row->objectKey, &subLayer->subLayerKey);
    kswordArkNetworkInventoryCopyWideText(row->ownerModule, subLayer->displayData.name);
}

static VOID
kswordArkNetworkWfpAppendCallout(
    _Inout_ KswordArkWfpEnumBuilder* builder,
    _In_opt_ const FWPM_CALLOUT0* callout
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (callout == NULL) {
        return;
    }
    row = kswordArkNetworkWfpReserveRow(builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->layerId = kswordArkNetworkWfpResolveLayerId(
        builder->engineHandle,
        &callout->applicableLayer);
    row->calloutId = callout->calloutId;
    kswordArkNetworkWfpCopyGuid(row->providerKey, callout->providerKey);
    kswordArkNetworkWfpCopyGuid(row->objectKey, &callout->calloutKey);
    kswordArkNetworkInventoryCopyWideText(row->ownerModule, callout->displayData.name);
}

static VOID
kswordArkNetworkWfpAppendFilter(
    _Inout_ KswordArkWfpEnumBuilder* builder,
    _In_opt_ const FWPM_FILTER0* filter
    )
{
    KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* row = NULL;

    if (filter == NULL) {
        return;
    }
    row = kswordArkNetworkWfpReserveRow(builder);
    if (row == NULL) {
        return;
    }

    row->objectKind = KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    row->layerId = kswordArkNetworkWfpResolveLayerId(
        builder->engineHandle,
        &filter->layerKey);
    row->filterId = filter->filterId;
    row->weight = kswordArkNetworkWfpReadWeight(&filter->effectiveWeight);
    if (row->weight == 0ULL) {
        row->weight = kswordArkNetworkWfpReadWeight(&filter->weight);
    }
    kswordArkNetworkWfpCopyGuid(row->providerKey, filter->providerKey);
    kswordArkNetworkWfpCopyGuid(row->subLayerKey, &filter->subLayerKey);
    kswordArkNetworkWfpCopyGuid(row->objectKey, &filter->filterKey);
    kswordArkNetworkInventoryCopyWideText(row->ownerModule, filter->displayData.name);
}

static NTSTATUS
kswordArkNetworkWfpEnumProviders(
    _In_ HANDLE engineHandle,
    _Inout_ KswordArkWfpEnumBuilder* builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmProviderCreateEnumHandle0(engineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_PROVIDER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - builder->totalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmProviderEnum0(engineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            kswordArkNetworkWfpAppendProvider(builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmProviderDestroyEnumHandle0(engineHandle, enumHandle);
    return status;
}

static NTSTATUS
kswordArkNetworkWfpEnumSubLayers(
    _In_ HANDLE engineHandle,
    _Inout_ KswordArkWfpEnumBuilder* builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmSubLayerCreateEnumHandle0(engineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_SUBLAYER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - builder->totalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmSubLayerEnum0(engineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            kswordArkNetworkWfpAppendSubLayer(builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmSubLayerDestroyEnumHandle0(engineHandle, enumHandle);
    return status;
}

static NTSTATUS
kswordArkNetworkWfpEnumCallouts(
    _In_ HANDLE engineHandle,
    _Inout_ KswordArkWfpEnumBuilder* builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmCalloutCreateEnumHandle0(engineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_CALLOUT0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - builder->totalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmCalloutEnum0(engineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            kswordArkNetworkWfpAppendCallout(builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmCalloutDestroyEnumHandle0(engineHandle, enumHandle);
    return status;
}

static NTSTATUS
kswordArkNetworkWfpEnumFilters(
    _In_ HANDLE engineHandle,
    _Inout_ KswordArkWfpEnumBuilder* builder
    )
{
    HANDLE enumHandle = NULL;
    NTSTATUS status = FwpmFilterCreateEnumHandle0(engineHandle, NULL, &enumHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (;;) {
        FWPM_FILTER0** entries = NULL;
        UINT32 returned = 0U;
        UINT32 index = 0U;
        ULONG remaining = KSWORD_ARK_WFP_ENUM_MAX_ROWS - builder->totalRows;
        UINT32 requested = (remaining < KSWORD_ARK_WFP_ENUM_PAGE_ROWS) ?
            remaining : KSWORD_ARK_WFP_ENUM_PAGE_ROWS;

        if (requested == 0U) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        status = FwpmFilterEnum0(engineHandle, enumHandle, requested, &entries, &returned);
        if (!NT_SUCCESS(status)) {
            if (entries != NULL) {
                FwpmFreeMemory0((VOID**)&entries);
            }
            break;
        }
        for (index = 0U; index < returned; ++index) {
            kswordArkNetworkWfpAppendFilter(builder, entries[index]);
        }
        if (entries != NULL) {
            FwpmFreeMemory0((VOID**)&entries);
        }
        if (returned == 0U) {
            break;
        }
    }

    (VOID)FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);
    return status;
}

NTSTATUS
kswordArkNetworkCollectWfpInventory(
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    )
/*++

Routine Description:

    enumerate system BFE providers, sublayers, callouts, and filters via the official management interfaces
    declared in WDK fwpmk.h. Enumeration is read-only; private netio/BFE linked lists are not accessed.

Return Value:

    STATUS_SUCCESS indicates all four object types were fully enumerated; STATUS_BUFFER_OVERFLOW indicates the hard limit was reached.
    STATUS_PARTIAL_COPY indicates at least one class succeeded while another API failed; other failures indicate no complete class succeeded.

--*/
{
    KswordArkWfpEnumBuilder builder;
    HANDLE engineHandle = NULL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG completedClasses = 0UL;

    if (totalRowsOut == NULL || returnedRowsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *totalRowsOut = 0UL;
    *returnedRowsOut = 0UL;
    if (rows == NULL && rowCapacity != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&builder, sizeof(builder));
    builder.rows = rows;
    builder.rowCapacity = rowCapacity;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    builder.engineHandle = engineHandle;

    status = kswordArkNetworkWfpEnumProviders(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = kswordArkNetworkWfpEnumSubLayers(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = kswordArkNetworkWfpEnumCallouts(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    status = kswordArkNetworkWfpEnumFilters(engineHandle, &builder);
    if (NT_SUCCESS(status)) {
        completedClasses += 1UL;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    (VOID)FwpmEngineClose0(engineHandle);

    if (builder.totalRows > builder.returnedRows && builder.rows != NULL) {
        ULONG index = 0UL;
        for (index = 0UL; index < builder.returnedRows; ++index) {
            builder.rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    *totalRowsOut = builder.totalRows;
    *returnedRowsOut = builder.returnedRows;
    if (completedClasses == 4UL) {
        return STATUS_SUCCESS;
    }
    if (firstFailure == STATUS_BUFFER_OVERFLOW) {
        return STATUS_BUFFER_OVERFLOW;
    }
    if (completedClasses != 0UL) {
        return STATUS_PARTIAL_COPY;
    }
    return NT_SUCCESS(firstFailure) ? STATUS_UNSUCCESSFUL : firstFailure;
}
