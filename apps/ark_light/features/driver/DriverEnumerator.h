#pragma once

// ============================================================
// DriverEnumerator.h
// Purpose:
// 1) Provide a read-only enumeration entry for driver overview and object information.
// 2) Perform R3 queries and local data organization only;
// 3) Does not include any Win32 controls or driver write logic.
// ============================================================

#include "DriverModel.h"

#include <string>
#include <vector>

namespace ksword::features::driver {

// DriverEnumerationResult groups the latest snapshot and diagnostics. Inputs
// are none; processing occurs in DriverEnumerator.cpp; output is consumed by
// DriverActions and the two Win32 views.
struct DriverEnumerationResult {
    bool success = false;                          // success: true only when the snapshot was collected.
    DWORD win32Error = ERROR_SUCCESS;              // win32Error: Win32 error for diagnostics.
    std::wstring diagnosticText;                   // diagnosticText: human-readable result text.
    std::vector<DriverOverviewRow> overviewRows;    // overviewRows: driver overview table rows.
    std::vector<DriverObjectRow> objectRows;        // objectRows: driver object table rows.
};

// enumerateDriverSnapshot refreshes both driver tables in one pass. There is no
// input; processing queries module data and Object Manager directories; output
// contains overview rows, object rows and a diagnostic message for the views.
DriverEnumerationResult enumerateDriverSnapshot();

} // namespace Ksword::Features::Driver
