#pragma once

#include "KernelModel.h"

#include <string>
#include <vector>

namespace ksword::features::kernel {

// TopLevelTabSpec describes one outer page still visible in the lightweight
// Kernel dock. Inputs are static captions and feature ids; processing is done by
// KernelPage; return behavior is value-only metadata access.
struct TopLevelTabSpec {
    const wchar_t* title;
    KernelFeatureId featureId;
};

// ObjectNamespaceTabSpec mirrors one inner page under an original grouped
// KernelDock tab. Inputs are static captions and feature ids; output is
// consumed by the Win32 secondary tab control.
struct ObjectNamespaceTabSpec {
    const wchar_t* title;
    KernelFeatureId featureId;
};

// KernelPageLayoutKind describes the original KswordARK visual layout that a
// feature page used. Inputs are feature ids; processing lets KernelPage select
// Win32 controls incrementally; output is metadata, not a widget object.
enum class KernelPageLayoutKind {
    kTable,
    kTree,
    kTreeWithPropertyTable,
    kTableWithDetail,
    kDualTable,
    kRuntimePanel
};

// layoutKindForFeature returns the original visual layout category for one
// KernelDock page. Input is a feature id; output guides Win32 control selection.
KernelPageLayoutKind layoutKindForFeature(KernelFeatureId featureId);

// layoutKindText converts layout metadata into a compact display string. Input
// is a layout enum; output is shown in the page descriptor and diagnostics.
std::wstring layoutKindText(KernelPageLayoutKind kind);

// originalTopLevelTabs returns the visible outer-tab order for the lightweight
// Kernel dock. There is no input; processing keeps hidden-but-retained features
// out of the dock tab list while their descriptors remain available for
// setInitialFeature callers.
const std::vector<TopLevelTabSpec>& originalTopLevelTabs();

// objectNamespaceTabs returns the fixed inner object namespace tab order from
// KswordARK. There is no input; output is stable for KernelPage selection.
const std::vector<ObjectNamespaceTabSpec>& objectNamespaceTabs();

// secondaryTabsForPrimary returns the original inner tab group for a top-level
// KernelDock entry. Input is a primary feature id from originalTopLevelTabs;
// output is empty when the page is not grouped.
const std::vector<ObjectNamespaceTabSpec>& secondaryTabsForPrimary(KernelFeatureId primaryFeatureId);

// canonicalColumnNames returns the original KswordARK table headers for each
// KernelDock page. Input is a feature id; output is a fixed Win32 ListView
// schema that appears before diagnostic extra columns.
std::vector<std::wstring> canonicalColumnNames(KernelFeatureId featureId);

// columnAliases maps generic facade key names to the exact original table
// headers. Inputs are a feature id and a display column; output is a priority
// list of row keys that can populate that original column.
std::vector<std::wstring> columnAliases(KernelFeatureId featureId, const std::wstring& columnName);

} // namespace Ksword::Features::Kernel
