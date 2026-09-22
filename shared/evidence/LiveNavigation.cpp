#include "LiveNavigation.h"

namespace ksword::evidence {

LiveNavigationDecision resolveProcessNavigation(const ProcessInstanceId& saved,
                                                const LiveResolution& live) noexcept {
    if (!live.found) {
        return LiveNavigationDecision::kRejectObjectExited;
    }
    switch (matchProcessInstance(saved, live.liveProcess)) {
    case MatchResult::kConfirmed:
        return LiveNavigationDecision::kAllow;
    case MatchResult::kNoMatch:
        // Same PID but different creation time or startup cycle: the PID has been reused. Never delegate operations to the new process.
        return LiveNavigationDecision::kRejectIdentityMismatch;
    case MatchResult::kCandidate:
        break;
    }
    return LiveNavigationDecision::kRejectIdentityUnverifiable;
}

const char* navigationPageName(NavigationPage page) noexcept {
    switch (page) {
    case NavigationPage::kUnknown:    return "Unknown";
    case NavigationPage::kRiskCenter: return "RiskCenter";
    case NavigationPage::kDriver:     return "Driver";
    case NavigationPage::kProcess:    return "Process";
    case NavigationPage::kThread:     return "Thread";
    case NavigationPage::kMemory:     return "Memory";
    case NavigationPage::kNetwork:    return "Network";
    case NavigationPage::kTimeline:   return "Timeline";
    case NavigationPage::kFile:       return "File";
    case NavigationPage::kHandle:     return "Handle";
    case NavigationPage::kRegistry:   return "Registry";
    }
    return "Unknown";
}

const char* navigationOutcomeName(NavigationOutcome outcome) noexcept {
    switch (outcome) {
    case NavigationOutcome::kDelivered:         return "Delivered";
    case NavigationOutcome::kTargetPageMissing:  return "TargetPageMissing";
    case NavigationOutcome::kObjectNotPresent:   return "ObjectNotPresent";
    case NavigationOutcome::kIdentityUnusable:   return "IdentityUnusable";
    case NavigationOutcome::kEvidenceIdMissing:  return "EvidenceIdMissing";
    case NavigationOutcome::kEvidenceNotSaved:   return "EvidenceNotSaved";
    }
    return "ObjectNotPresent";
}

NavigationOutcome decideNavigation(const NavigationRequest& request,
                                   bool targetPageAvailable,
                                   bool objectPresentInPage,
                                   bool evidencePresentInSession) noexcept {
    // F-12: The identity threshold applies unconditionally. requireExactMatch refers to anchor precision, not whether to validate
    // identity; treating it as a switch would allow calls with requireExactMatch=false to deliver a result with an empty primary key.
    if (!request.object.navigable()) {
        return NavigationOutcome::kIdentityUnusable;
    }
    // F-12: Navigation requires an evidence ID; otherwise, skipping to a target makes it impossible to return to the original evidence. Previously, an empty
    // ID short-circuited the subsequent check (`!empty() && ...`), allowing "missing evidence" to pass more easily than "evidence provided but not saved."
    if (request.evidenceId.empty()) {
        return NavigationOutcome::kEvidenceIdMissing;
    }
    if (!evidencePresentInSession) {
        // M-08: Data not saved in an offline session cannot be silently patched in the live context.
        return NavigationOutcome::kEvidenceNotSaved;
    }
    if (!targetPageAvailable) {
        return NavigationOutcome::kTargetPageMissing;
    }
    if (!objectPresentInPage) {
        return NavigationOutcome::kObjectNotPresent;
    }
    return NavigationOutcome::kDelivered;
}

} // namespace ksword::evidence
