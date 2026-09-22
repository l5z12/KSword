#pragma once

// Minimal assertion support shared across all acceptance test suites. Each suite returns its own failure count; wmain aggregates them.

#include <iostream>
#include <string>

namespace ksword_tests {

class Suite final {
public:
    explicit Suite(const wchar_t* name) : name_(name) {}

    void expect(bool condition, const wchar_t* label) {
        ++checks_;
        if (!condition) {
            ++failures_;
            std::wcerr << L"FAIL [" << name_ << L"] " << label << L'\n';
            // Fallback: If a wide character cannot be converted (due to locale limitations or console redirection to
            // a non-UTF-8 pipe), the stream enters the badbit state and silently discards **all subsequent output**,
            // including failures from other suites and the final summary. Clear the state; it is better to have
            // garbled text on this line than to lose the entire test result due to a single conversion failure.
            clearIfBroken(std::wcerr);
        }
    }

    int failures() const { return failures_; }
    int checks() const { return checks_; }

    void report() const {
        std::wcout << L"  " << name_ << L": " << (checks_ - failures_) << L'/' << checks_
                   << L" checks passed\n";
        clearIfBroken(std::wcout);
    }

    static void clearIfBroken(std::wostream& stream) {
        if (!stream.good()) {
            stream.clear();
        }
    }

private:
    const wchar_t* name_;
    int failures_ = 0;
    int checks_ = 0;
};

} // namespace ksword_tests

// Entry points for each acceptance suite. Names correspond to the module letters in the acceptance specification.
// Declare new test suites here and accumulate their failure counts in wmain.
int runEvidenceContractTests();   // F
int runCrossViewTests();          // X
int runEntityGraphTests();
int runDumpFactsTests();
int runSnapshotCompareTests();
int runSecurityStateTests();
int runWfpTests();
int runTimelineTests();
int runImageIntegrityTests();
int runMemoryEvidenceTests();
int runInjectionSurveyTests();    // J: Process memory injection and integrity check.
int runHvmEptSwitchTests();       // EPTP switch backend (shared/driver, pure arithmetic + state machine).
int runHvmWatchTests();           // First-access watch (shared/driver, pure arithmetic + state machine)
int runDdmaPlanTests();           // DDMA disk DMA (shared/driver, ATA register encoding + slicing + access control)
int runNumericTextParseTests();   // Numeric text parsing (shared/evidence, defaulting to address/quantity bases)
int runMemoryTamperCrossViewTests(); // Memory content cross-view (shared/evidence, comparing multiple read paths).
int runDmaProcessOpPlanTests();      // DMA process operation plan (shared/evidence, gaps/backup/readback verification)
