#pragma once

// F-09: Offline result navigation to the current site; F-12: Linkage with existing pages.
//
// When a result in an offline session is clicked, its saved identity must be explicitly validated against the
// identity re-derived from the current context: object exit, PID reuse, and insufficient identity information
// are three distinct failure modes; none of these should delegate operations to a 'seemingly new' object.

#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <string>
#include <vector>

namespace ksword::evidence {

// Live resolution result: the caller queries for objects with the same PID and path using the current enumeration; if found, populate the result.
struct LiveResolution final {
    bool found = false;                 // Whether candidate objects exist at the scene.
    ProcessInstanceId liveProcess;      // found is true: Context identity
};

// Compare the offline-saved process identity with the live resolution result.
LiveNavigationDecision resolveProcessNavigation(const ProcessInstanceId& saved,
                                                const LiveResolution& live) noexcept;

// ---------------------------------------------------------------------------
// F-12: Navigation request with identity and evidence ID.
// ---------------------------------------------------------------------------
enum class NavigationPage {
    kUnknown,
    kRiskCenter,
    kDriver,
    kProcess,
    kThread,
    kMemory,
    kNetwork,
    kTimeline,
    kFile,
    kHandle,
    kRegistry,
};

const char* navigationPageName(NavigationPage page) noexcept;

struct NavigationRequest final {
    NavigationPage page = NavigationPage::kUnknown;
    ObjectRef object;
    std::string evidenceId;      // Used to return to the original evidence; F-12 requires navigation to include it.
    std::string anchor;          // In-page anchor: RVA/address/index as text.
    // requireExactMatch controls only exact anchor placement: false allows navigation to the object's
    // section rather than its exact row. It does not disable the identity requirement, which always applies.
    bool requireExactMatch = true;  // F-12: If the location cannot be found, explain the reason; do not jump to the first line.
};

enum class NavigationOutcome {
    kDelivered,            // Target page received and precisely located.
    kTargetPageMissing,    // Target page closed or not materialized.
    kObjectNotPresent,     // Page exists, but the object is not in the current data.
    kIdentityUnusable,     // Referenced identity is insufficient; navigation is not allowed.
    kEvidenceIdMissing,    // The request did not include an evidence ID at all, so it cannot return to the original evidence.
    kEvidenceNotSaved,     // This data was not saved in the offline session
};

const char* navigationOutcomeName(NavigationOutcome outcome) noexcept;

// Decision logic upon receiving a request on the page side: rely solely on 'target page exists +
// object matches + identity sufficient'; never route to a different row based on similar names.
NavigationOutcome decideNavigation(const NavigationRequest& request,
                                   bool targetPageAvailable,
                                   bool objectPresentInPage,
                                   bool evidencePresentInSession) noexcept;

} // namespace ksword::evidence
