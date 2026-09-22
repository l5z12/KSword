#pragma once

#include "../../core/Win32Lean.h"

#include <string>
#include <vector>

namespace ksword::features::sys_tools {

// SystemTimeProperty is one name/value pair. Values are already formatted and
// the view never parses them back.
struct SystemTimeProperty {
    std::wstring name;
    std::wstring value;
};

// SystemTimeInfoSection groups properties under one heading so the rendered
// report stays readable without the view knowing what any of the fields mean.
struct SystemTimeInfoSection {
    std::wstring title;
    std::vector<SystemTimeProperty> properties;
};

// SystemTimeInfoSnapshot is one read-only collection pass.
struct SystemTimeInfoSnapshot {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<SystemTimeInfoSection> sections;
};

// collectSystemTimeInfo gathers clock, time zone, uptime and W32Time settings.
// There is no input; processing only reads system state and the registry;
// output is a section list ready to render. This page is read-only by design:
// changing the clock or the time source from an audit tool would invalidate
// every timestamp the rest of the product just collected.
SystemTimeInfoSnapshot collectSystemTimeInfo();

// formatLiveClockLine renders the one-line header the view refreshes once a
// second. There is no input; output is a single line holding local time, UTC
// time and uptime.
std::wstring formatLiveClockLine();

// renderSystemTimeReport flattens a snapshot into the text shown in the pane.
std::wstring renderSystemTimeReport(const SystemTimeInfoSnapshot& snapshot);

} // namespace Ksword::Features::SysTools
