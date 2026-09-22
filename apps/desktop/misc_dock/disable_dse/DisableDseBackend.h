#pragma once

// ============================================================
// DisableDseBackend.h
// Purpose:
// 1) Dynamically locate CI.dll!g_CiOptions — the master switch for Driver Signature Enforcement (DSE);
// 2) Use KswordARK R0 transactional kernel writes to set this value to 0 (disable) or restore the original value (re-enable).
// 3) Aggregate CI / HVCI / Secure Boot posture to determine if modifying g_CiOptions will actually take effect on this machine.
// 4) Before each write, perform a consistency check between the read-back value and the system-reported state; reject
//    the write if they do not match. Writing to the wrong address is the primary cause of BSODs for this type of tool. Note
//    that g_CiOptions uses the internal encoding of CI.dll (0x6 = enforce signature, 0x8 = allow test signatures, 0 =
//    disable), which is a different set from the CODEINTEGRITY_OPTION_* reported by SystemCodeIntegrityInformation. The two
//    numeric values are inherently unequal, so only the semantic meaning of "enforce signature is active" can be compared.
//
// Locate without relying on any hardcoded offsets: Map CI.dll from disk into this process as
// a SEC_IMAGE, disassemble the exported CiInitialize to find CipInitialize, then search for
// `mov dword ptr [rip+disp32], r32` within it; the target is g_CiOptions. Finally, convert
// the RVA to a kernel virtual address using the real base address of CI.dll in the kernel.
//
// This file handles only data and system access, with no QWidget dependencies; the UI resides in DisableDsePage.
// ============================================================

#include <QString>
#include <QStringList>

#include <cstdint>

namespace ks::misc::disable_dse
{
    // PostureSource：
    // - Purpose: Indicates the source of this CI posture; the UI uses this to explain the data origin.
    enum class PostureSource
    {
        kNone = 0,    // None: Neither channel succeeded.
        kWin32 = 1,   // Win32: Retrieved via R3 NtQuerySystemInformation with fewer fields.
        kDriver = 2   // Driver: Query for KswordARK R0 security status; contains the most complete fields.
    };

    // BlockReason：
    // - Purpose: Explain why DSE modification is currently disallowed; disable operation buttons for any value other than None.
    enum class BlockReason
    {
        kNone = 0,               // None: Allows the operation.
        kDriverUnavailable,      // DriverUnavailable: R0 is not loaded; g_CiOptions can only be written by the kernel.
        kUnsupportedBuild,       // UnsupportedBuild: earlier than Win8, the switch is not present in CI.dll.
        kHvciEnabled,            // HvciEnabled: Memory Integrity is on; writes are blocked by SLAT.
        kNotLocated,             // NotLocated: g_CiOptions has not been located yet.
        kValueMismatch           // ValueMismatch: Read-back value does not match the system-reported value; address is suspicious.
    };

    // CodeIntegrityPosture：
    // - Purpose: Complete result of a single CI/VBS posture query, serving as the pre-operation eligibility criterion.
    struct CodeIntegrityPosture
    {
        bool queried = false;                          // queried: Whether the pose was successfully retrieved.
        PostureSource source = PostureSource::kNone;    // source: The entity that provided the data this time.
        std::uint32_t options = 0;                     // options: the original bitmask for CodeIntegrityOptions.
        bool ciEnabled = false;                        // ciEnabled: Whether KMCI (Kernel Mode Code Integrity) is enabled.
        bool testSigningEnabled = false;               // testSigningEnabled: Indicates whether test signing mode is enabled.
        bool umciEnabled = false;                      // umciEnabled: Whether user-mode code integrity is enabled.
        bool hvciEnabled = false;                      // hvciEnabled: Whether HVCI/Memory Integrity is enabled.
        bool hvciStrictMode = false;                   // hvciStrictMode: HVCI strict mode.
        bool secureBootEnabled = false;                // secureBootEnabled: Indicates whether Secure Boot is enabled; valid only for the R0 channel.
        bool ciModuleLoaded = false;                   // ciModuleLoaded: Indicates whether the CI module is in the kernel module table; valid only in the R0 channel.
        std::uint32_t buildNumber = 0;                 // buildNumber: Current system internal build number.
        QString failureText;                           // failureText: the failure reason when queried is false.
    };

    // TargetLocation：
    // - Purpose: stores the result and trajectory of g_CiOptions resolution. When ok is false, only failureText is meaningful.
    struct TargetLocation
    {
        bool ok = false;                  // ok: Whether the location was found.
        std::uint64_t kernelAddress = 0;  // kernelAddress: Virtual address of g_CiOptions in the kernel.
        std::uint64_t moduleBase = 0;     // moduleBase: Load base address of the CI module in the kernel.
        std::uint32_t moduleSize = 0;     // moduleSize: Image size of the CI module in the kernel.
        std::uint32_t rva = 0;            // rva: Offset relative to the module base in g_CiOptions.
        QString moduleName;               // moduleName: Module name in the kernel module table.
        QString sectionName;              // sectionName: The section where g_CiOptions resides; normally CiPolicy or .data.
        QStringList traceLines;           // traceLines: Values at each step for user verification.
        QString failureText;              // failureText: Failure reason when ok is false.
    };

    // ReadbackResult：
    // - Purpose: Result of reading g_CiOptions once via R0.
    struct ReadbackResult
    {
        bool ok = false;             // ok: whether read succeeded.
        std::uint32_t value = 0;     // value: The 4-byte value read.
        QString failureText;         // failureText: Failure reason when ok is false.
    };

    // ApplyResult：
    // - Purpose: Result of a single g_CiOptions write transaction.
    struct ApplyResult
    {
        bool ok = false;                    // ok: Write and read-back verification passed.
        std::uint32_t previousValue = 0;    // previousValue: The value before writing, used for restoration.
        std::uint32_t writtenValue = 0;     // writtenValue: The value written in this operation.
        std::uint64_t transactionId = 0;    // transactionId: R0 transaction ID, retrievable from change audit logs.
        QStringList traceLines;             // traceLines: Status of each step in the transaction.
        QString detailText;                 // detailText: failure reason or success supplementary explanation.
    };

    // driverAvailable：
    // - Purpose: Detect whether the KswordARK device can be opened.
    // - Return: true indicates the R0 channel is online.
    bool driverAvailable();

    // queryPosture：
    // - Purpose: Query the current CI / HVCI / Secure Boot posture; prefer R0 (full fields), fall back to R3 if R0 is unavailable.
    // - Returns: CodeIntegrityPosture; if queried is false, check failureText.
    CodeIntegrityPosture queryPosture();

    // evaluateBlockReason：
    // - Input posture: current posture; location: localization result (may be in an unlocalized state);
    // - Purpose: Centralize the permission-to-act decision so the UI and write path use the same criteria;
    // - Returns: None indicates the operation is allowed; other values indicate what blocked it.
    BlockReason evaluateBlockReason(
        const CodeIntegrityPosture& posture,
        const TargetLocation& location);

    // blockReasonText：
    // - Input reason: admission control result;
    // - Purpose: Provide user-facing reason explanations and next-step suggestions.
    // - Returns: a single line of text; returns an empty string if None.
    QString blockReasonText(BlockReason reason);

    // locateCiOptions：
    // - Purpose: Map the disk CI.dll to calculate the RVA of g_CiOptions, then convert it to a kernel address using the kernel module base address.
    // - Returns: TargetLocation; read-only throughout the process, does not access the driver, and writes no memory.
    TargetLocation locateCiOptions();

    // readCiOptions：
    // - Input: location: located target
    // - Purpose: Read 4 bytes at the specified R0 kernel virtual address.
    // - Returns: ReadbackResult. Fails immediately if the driver is offline.
    ReadbackResult readCiOptions(const TargetLocation& location);

    // writeCiOptions：
    // - Input location: the located target; expectedValue: the current value just read by the caller; desiredValue: the new value to write.
    // - Purpose: Execute R0 transactional kernel writes in the order of prepare → dry-run → commit → replay.
    //   expectedValue serves as the transaction's expected-before; if the R0 side does not match, the commit is rejected directly.
    // - Return: ApplyResult; ok is true if the write and readback are consistent.
    ApplyResult writeCiOptions(
        const TargetLocation& location,
        std::uint32_t expectedValue,
        std::uint32_t desiredValue);

    // describeOptions：
    // - Input options: CodeIntegrityOptions bitmap reported by SystemCodeIntegrityInformation;
    // - Purpose: Split set bits of CODEINTEGRITY_OPTION_* into readable names.
    // - Return: Text in the format "ENABLED | UMCI_ENABLED"; returns "0" if no bits are set.
    // Note: This encoding applies only to system-reported values and cannot be used to interpret g_CiOptions.
    QString describeOptions(std::uint32_t options);

    // describeCiOptions：
    // - Input: value is the raw value of CI.dll!g_CiOptions read from the kernel.
    // - Purpose: Interpret the value according to CI.dll's internal encoding. It is not the same set as CODEINTEGRITY_OPTION_*.
    //   Bit 0x6 indicates driver signature enforcement is active; 0x8 allows test signatures; 0 means completely disabled.
    // - Returns: Readable description text.
    QString describeCiOptions(std::uint32_t value);

    // ciOptionsAgreesWithPosture：
    // - Input value: g_CiOptions read from the located address; posture: system-reported posture;
    // - Purpose: Trustworthiness criterion before writing. Since the two encodings differ, direct numeric equality comparison is
    //   invalid; only the semantic meaning 'Is Mandatory Signing Active Now?' can be compared: if the system says DSE is on, the read-back
    //   value must have the mandatory bit set; if the system says DSE is off, the mandatory bit in the read-back value must be 0.
    //   If the address is located incorrectly and points to unrelated kernel data, it is highly unlikely to satisfy this relationship by chance;
    // - Returns: true indicates the read-back value is consistent with the system posture, allowing the write to proceed.
    bool ciOptionsAgreesWithPosture(
        std::uint32_t value,
        const CodeIntegrityPosture& posture);

    // kDisabledValue：
    // - Purpose: Value written when disabling DSE. 0 indicates that code integrity is fully disabled.
    inline constexpr std::uint32_t kDisabledValue = 0U;

    // kCiOptionEnforceMask：
    // - Purpose: Bitmask in g_CiOptions representing "enforce driver signature" (internal CI.dll encoding).
    //   On a normally enabled system, both bits are set; together they form the value commonly referred to as 6 in the community.
    inline constexpr std::uint32_t kCiOptionEnforceMask = 0x00000006U;

    // kCiOptionTestSign：
    // - Action: bit in g_CiOptions representing 'allow test signatures'.
    inline constexpr std::uint32_t kCiOptionTestSign = 0x00000008U;
}
