#pragma once

// ============================================================
// KernelDock.h
// Purpose:
// 1) Provides the 'Object Namespace Traversal' tab (default page);
// 2) Provide 'Atomic Table Traversal' tab;
// 3) Provide the "SSDT Traversal" tab;
// 4) Retain the legacy 'NtQuery Info' tab in the history page;
// 5) All time-consuming queries run on background threads to avoid blocking the UI thread.
// ============================================================

#include "../Framework.h"
#include "../internationalization/LanguageManager.h"

#include <QWidget>
#include <QString>

#include <atomic>   // std::atomic_bool: Control asynchronous refresh mutual exclusion.
#include <cstdint>  // std::uintXX_t: Fixed-width integer.
#include <vector>   // std::vector: Cache for snapshot rows of the table.

namespace ksword::kernel_dock_internal
{
    // kernelText：
    // - Input: stable context key and Chinese source text;
    // - Processing: If Chinese, return the original call site text; if English, parse according to the specific KernelDock page context;
    // - Returns: UI or diagnostic text in the current language.
    inline QString kernelText(const char* const contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }
}

// Qt forward declarations: Reduce header file coupling.
class QPoint;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QComboBox;
class QProgressBar;
class QTableWidget;
class QTabWidget;
class QTreeWidget;
class QVBoxLayout;
class QEvent;
class QShowEvent;
class CodeEditorWidget;
class CallbackInterceptController;
class KernelDockCidTab;
class KernelDockIpcTab;
class KernelKnowledgeTab;

// ============================================================
// KernelObjectTypeEntry
// Purpose:
// - Stores R3 ObjectTypesInformation statistics.
// - The Object Type Matrix merges R0 ObTypeIndexTable evidence by typeIndex.
// ============================================================
struct KernelObjectTypeEntry
{
    std::uint32_t typeIndex = 0;                 // typeIndex: Object type index.
    QString typeNameText;                        // typeNameText: Object type name.
    std::uint64_t totalObjectCount = 0;          // totalObjectCount: Object count.
    std::uint64_t totalHandleCount = 0;          // totalHandleCount: Handle count.
    std::uint32_t validAccessMask = 0;           // validAccessMask: Access mask.
    bool securityRequired = false;               // securityRequired: Whether security checks are required.
    bool maintainHandleCount = false;            // maintainHandleCount: Whether to maintain the handle count.
    std::uint32_t poolType = 0;                  // poolType: Pool type.
    std::uint32_t defaultPagedPoolCharge = 0;    // defaultPagedPoolCharge: default paged pool quota.
    std::uint32_t defaultNonPagedPoolCharge = 0; // defaultNonPagedPoolCharge: Default quota for non-paged pool.
    bool r3Present = true;                       // r3Present: Whether the R3 ObjectTypesInformation contains this row.
    bool r0Present = false;                      // r0Present: Whether the R0 table slot contains a valid OBJECT_TYPE address.
    std::uint32_t r0Status = 0;                  // r0Status: Per-slot R0 verification status.
    std::uint32_t r0FieldFlags = 0;              // r0FieldFlags: Bitmap of R0-verified fields.
    long r0LastStatus = 0;                       // r0LastStatus: Read/verify NTSTATUS per slot.
    std::uint64_t r0ObjectTypeAddress = 0;       // r0ObjectTypeAddress: Pointer to the ObTypeIndexTable slot.
    std::uint64_t r0IdentityHash = 0;            // r0IdentityHash: Stable identity hash for slot address/index/name.
    QString r0TypeNameText;                      // r0TypeNameText: The name read from R0 OBJECT_TYPE.Name.
    QString r0ValidationText;                    // r0ValidationText: Cross-validation summary for the UI.
};

// ============================================================
// KernelNtQueryResultEntry
// Purpose:
// - Represents a single NtQuery result.
// - Save table column information and full detail text.
// ============================================================
struct KernelNtQueryResultEntry
{
    QString categoryText;     // categoryText: Category (system/process/thread/object/token/export).
    QString functionNameText; // functionNameText: The called function name.
    QString queryItemText;    // queryItemText: Query item name.
    long statusCode = 0;      // statusCode: Raw NTSTATUS code.
    QString statusText;       // statusText: Readable status text.
    QString summaryText;      // summaryText: Table summary text.
    QString detailText;       // detailText: Complete text for the details panel.
};

// ============================================================
// KernelObjectNamespaceEntry
// Purpose:
// - Represents an enumeration result from the object manager namespace.
// - Simultaneously carry 'directory path + enumeration API + object details + operation information'.
// ============================================================
struct KernelObjectNamespaceEntry
{
    QString rootPathText;            // rootPathText: Root directory (e.g., \Device).
    QString scopeDescriptionText;    // scopeDescriptionText: Purpose description for this root directory.
    QString directoryPathText;       // directoryPathText: Currently enumerated directory path.
    QString objectNameText;          // objectNameText: Object name.
    QString objectTypeText;          // objectTypeText: Object type (Directory/SymbolicLink, etc.).
    QString fullPathText;            // fullPathText: Full path of the object.
    QString enumApiText;             // enumApiText: Enum API used by this record.
    QString symbolicLinkTargetText;  // symbolicLinkTargetText: Symbolic link target (may be null if not a link).
    QString statusText;              // statusText: Status text (success/failure + code).
    QString detailText;              // detailText: Display text for the details panel.
    long statusCode = 0;             // statusCode: Original NTSTATUS.
    bool querySucceeded = false;     // querySucceeded: indicates whether the enumeration succeeded.
    bool isDirectory = false;        // isDirectory: Whether the object is of directory type.
    bool isSymbolicLink = false;     // isSymbolicLink: Whether the object is of the symbolic link type.
};

// ============================================================
// KernelAtomEntry
// Purpose:
// - Represents a record in the atom table;
// - Uniformly carry Atom value, name, source, and details.
// ============================================================
struct KernelAtomEntry
{
    std::uint16_t atomValue = 0; // atomValue: Atom decimal value.
    QString atomNameText;        // atomNameText: Atom name.
    QString sourceText;          // sourceText: Source (GlobalAtom/ClipboardFormat, etc.).
    QString statusText;          // statusText: Status text.
    QString detailText;          // detailText: detail text.
    bool querySucceeded = false; // querySucceeded: Whether this entry is valid.
};

// ============================================================
// KernelSsdtEntry
// Purpose:
// - Represents an SSDT-related entry.
// - Save the service index, Zw export address, table entry address, and details.
// ============================================================
struct KernelSsdtEntry
{
    std::uint32_t serviceIndex = 0;      // serviceIndex: Service index (valid only when indexResolved=true).
    std::uint32_t flags = 0;             // flags: Flags returned by the driver.
    std::uint64_t zwRoutineAddress = 0;  // zwRoutineAddress: Address of Zw* exported routines.
    std::uint64_t serviceRoutineAddress = 0; // serviceRoutineAddress: service routine address parsed from the SSDT table entry.
    std::uint64_t serviceTableBase = 0;  // serviceTableBase: The service table base address returned by the driver.
    std::uint64_t tableEntryAddress = 0; // tableEntryAddress: Kernel address of the SSDT slot itself.
    std::uint64_t currentTableValue = 0; // currentTableValue: Current encoding slot value.
    std::uint64_t cleanTableValue = 0;   // cleanTableValue: disk image RVA-encoded slot value.
    std::uint32_t tableEntrySize = 0;    // tableEntrySize: encoding slot width.
    std::vector<std::uint8_t> currentTableBytes; // currentTableBytes: Little-endian bytes of the current slot.
    std::vector<std::uint8_t> cleanTableBytes;   // cleanTableBytes: Verified disk baseline bytes.
    QString cleanBaselinePath;           // cleanBaselinePath: Path to a verified disk image.
    QString cleanBaselineStatus;         // cleanBaselineStatus: Identity and difference diagnostics.
    QString serviceNameText;             // serviceNameText: Service name (Zw* functions).
    QString moduleNameText;              // moduleNameText: Module name.
    QString statusText;                  // statusText: Status text (e.g., index parsing, table entry parsing).
    QString detailText;                  // detailText: detail text.
    bool indexResolved = false;          // indexResolved: whether the service index was successfully extracted from the stub code.
    bool cleanBaselineAvailable = false; // cleanBaselineAvailable: Indicates whether a disk slot with a matching identity has been obtained.
    bool cleanBaselineDiffers = false;   // cleanBaselineDiffers: Whether the current slot differs from the baseline.
    bool querySucceeded = false;         // querySucceeded: Whether this entry is valid.
};

// ============================================================
// KernelInlineHookEntry
// Purpose:
// - Indicates the Inline Hook detection result at the beginning of a kernel-exported function.
// - Stores function address, jump target, module ownership, byte snapshot, and UI detail text.
// ============================================================
struct KernelInlineHookEntry
{
    std::uint32_t status = 0;               // status: R0 row status.
    std::uint32_t hookType = 0;             // hookType: Inline Hook instruction format.
    std::uint32_t flags = 0;                // flags: R0 diagnostic flags.
    std::uint32_t originalByteCount = 0;    // originalByteCount: R0 observation baseline byte count; does not represent original disk bytes.
    std::uint32_t currentByteCount = 0;     // currentByteCount: Current byte count.
    std::uint64_t functionAddress = 0;      // functionAddress: The function entry address.
    std::uint64_t targetAddress = 0;        // targetAddress: The resolved jump target.
    std::uint64_t moduleBase = 0;           // moduleBase: Base address of the owning module.
    std::uint64_t targetModuleBase = 0;     // targetModuleBase: Target module base address.
    QString moduleNameText;                 // moduleNameText: Name of the owning module.
    QString functionNameText;               // functionNameText: The exported function name.
    QString targetModuleNameText;           // targetModuleNameText: The target module name.
    QString hookTypeText;                   // hookTypeText: Hook type text.
    QString statusText;                     // statusText: Status text.
    QString diskBaselineStatusText;         // diskBaselineStatusText: Status of the difference between the disk baseline and memory bytes.
    QString diskBaselinePathText;           // diskBaselinePathText: Path to the disk baseline source file.
    QString currentBytesText;               // currentBytesText: Current byte hexadecimal text.
    QString observedBytesText;              // observedBytesText: R0 observed baseline hex text, not representing raw disk bytes.
    QString diskBytesText;                  // diskBytesText: Baseline byte text read from disk at the same RVA in R3.
    QString detailText;                     // detailText: detail text.
    std::vector<std::uint8_t> currentBytes; // currentBytes: Current byte buffer.
    std::vector<std::uint8_t> observedBytes; // observedBytes: Observed baseline byte buffer returned from R0.
    std::vector<std::uint8_t> diskBytes;    // diskBytes: R3 disk baseline byte buffer.
    std::uint64_t diskBaselineRva = 0;      // diskBaselineRva: RVA of the function address relative to the module base address.
    bool diskBaselineAvailable = false;     // diskBaselineAvailable: Whether the disk baseline was successfully obtained.
    bool diskBaselineDiffers = false;       // diskBaselineDiffers: Whether memory bytes differ from the disk baseline.
};

// ============================================================
// KernelIatEatHookEntry
// Purpose:
// - Represents kernel module IAT/EAT pointer detection results;
// - Stores thunk/EAT entries, target addresses, declared import modules, and status text.
// ============================================================
struct KernelIatEatHookEntry
{
    std::uint32_t hookClass = 0;          // hookClass: IAT or EAT.
    std::uint32_t status = 0;             // status: R0 row status.
    std::uint32_t flags = 0;              // flags: R0 diagnostic flags.
    std::uint32_t ordinal = 0;            // ordinal: export ordinal or thunk ordinal.
    std::uint64_t moduleBase = 0;         // moduleBase: Base address of the owning module.
    std::uint64_t thunkAddress = 0;       // thunkAddress: IAT thunk or EAT entry address.
    std::uint64_t currentTarget = 0;      // currentTarget: Current target address.
    std::uint64_t expectedTarget = 0;     // expectedTarget: Expected target address.
    std::uint64_t targetModuleBase = 0;   // targetModuleBase: Target module base address.
    QString classText;                    // classText: IAT/EAT text.
    QString statusText;                   // statusText: Status text.
    QString moduleNameText;               // moduleNameText: Name of the owning module.
    QString importModuleNameText;         // importModuleNameText: IAT declaration for imported modules.
    QString functionNameText;             // functionNameText: Function name / placeholder.
    QString targetModuleNameText;         // targetModuleNameText: Current target module name.
    QString detailText;                   // detailText: detail text.
};

// KernelTimerDpcEntry: a displayed record of an owned module in the TimerTable page.
struct KernelTimerDpcEntry
{
    std::uint16_t processorGroup = 0;
    std::uint16_t processorNumber = 0;
    std::uint32_t bucketIndex = 0;
    std::uint32_t flags = 0;
    std::uint32_t timerType = 0;
    std::int32_t period = 0;
    std::int64_t dueTime = 0;
    std::uint64_t timerAddress = 0;
    std::uint64_t dpcAddress = 0;
    std::uint64_t deferredRoutine = 0;
    std::uint64_t deferredContext = 0;
    QString moduleNameText;
    QString statusText;
    QString detailText;
};


// ============================================================
// KernelCallbackEnumEntry
// Purpose:
// - Represents a record returned by R0 callback traversal.
// - Stores callback class, source, address, module, status, and detail text.
// ============================================================
struct KernelCallbackEnumEntry
{
    std::uint32_t callbackClass = 0;       // callbackClass: Callback category.
    std::uint32_t source = 0;              // source: Enumeration source.
    std::uint32_t status = 0;              // status: R0 row status.
    std::uint32_t fieldFlags = 0;          // fieldFlags: Bitmap of valid fields.
    std::uint32_t trustFlags = 0;          // trustFlags: Bits for trusted sources; remains 0 if the old protocol does not return data.
    std::uint32_t removeBehavior = 0;      // removeBehavior: R0 recommended removal behavior; remains 0 if the old protocol does not return a value.
    std::uint32_t removeFlags = 0;         // removeFlags: compatible with legacy UI naming, mirrors removeBehavior.
    std::uint32_t operationMask = 0;       // operationMask: Operation mask.
    std::uint32_t objectTypeMask = 0;      // objectTypeMask: Object type mask.
    std::uint32_t registrationType = 0;    // registrationType: Specific registration API/chain type.
    std::uint64_t generation = 0;          // generation: v3 stable snapshot token; remains 0 if the old protocol does not return.
    long lastStatus = 0;                   // lastStatus: underlying NTSTATUS.
    std::uint64_t callbackAddress = 0;     // callbackAddress: Address of the callback function or object.
    std::uint64_t contextAddress = 0;      // contextAddress: Context or extended diagnostic value.
    std::uint64_t registrationAddress = 0; // registrationAddress: Registration handle/cookie.
    std::uint64_t identityHash = 0;        // identityHash: v3 stable line-by-line identity hash; remains 0 if the old protocol does not return.
    std::uint64_t rawStorageValue = 0;     // rawStorageValue: Raw registration-slot value from R0; retain 0 if an older protocol does not return it.
    std::uint64_t moduleBase = 0;          // moduleBase: Base address of the owning module.
    std::uint32_t moduleSize = 0;          // moduleSize: Size of the owning module.
    QString classText;                     // classText: Category text.
    QString registrationTypeText;          // registrationTypeText: Text for specific types such as Legacy, Ex, Ex2, etc.
    QString sourceText;                    // sourceText: Source text.
    QString sourceTrustText;               // sourceTrustText: Display text for trusted/public API/fallback/unsupported sources.
    QString removePolicyText;              // removePolicyText: Text for safe removal, candidate, experimental, or non-removable policies.
    QString statusText;                    // statusText: Status text.
    QString nameText;                      // nameText: Callback/filter name.
    QString altitudeText;                  // altitudeText：Altitude。
    QString modulePathText;                // modulePathText: Module path.
    QString companyText;                   // companyText: Company in the module version resource.
    QString fileVersionText;               // fileVersionText: The module file version.
    QString fileDescriptionText;           // fileDescriptionText: Module file description.
    QString detailText;                    // detailText: detail text.
    bool requiresSecondConfirmation = false; // requiresSecondConfirmation: Whether the removal action requires a second confirmation.
    bool fallbackPatternOnly = false;      // fallbackPatternOnly: Indicates if the current source is solely for fallback/pattern diagnostics.
};

// ============================================================
// KernelDynDataModuleIdentity
// Purpose:
// - Represents the kernel module identity used for precise DynData matching;
// - Unifies module name, PE Machine, TimeDateStamp, SizeOfImage, and load base address.
// ============================================================
struct KernelDynDataModuleIdentity
{
    bool present = false;                // present: Whether the module is currently loaded and recognized by R0.
    std::uint32_t classId = 0;           // classId：System Informer DynData profile class。
    std::uint32_t machine = 0;           // machine：PE FileHeader.Machine。
    std::uint32_t timeDateStamp = 0;     // timeDateStamp：PE FileHeader.TimeDateStamp。
    std::uint32_t sizeOfImage = 0;       // sizeOfImage：PE OptionalHeader.SizeOfImage。
    std::uint64_t imageBase = 0;         // imageBase: module load base address.
    QString moduleNameText;              // moduleNameText: Module file name.
};

// ============================================================
// KernelDynDataSummary
// Purpose:
// - Represents the summary at the top of the dynamic offset page;
// - Simultaneously cache success status and R0 diagnostic fields for both status and fields IOCTLs.
// ============================================================
struct KernelDynDataSummary
{
    bool statusQueryOk = false;          // statusQueryOk: Whether QUERY_DYN_STATUS succeeded.
    bool fieldsQueryOk = false;          // fieldsQueryOk: whether QUERY_DYN_FIELDS succeeded.
    std::uint32_t statusFlags = 0;       // statusFlags: Bitmap of KSW_DYN_STATUS_FLAG_* bits.
    std::uint32_t systemInformerDataVersion = 0; // systemInformerDataVersion: System Informer data version.
    std::uint32_t systemInformerDataLength = 0;  // systemInformerDataLength: Byte length of KphDynConfig.
    long lastStatus = 0;                 // lastStatus: NTSTATUS from the last DynData activation in R0.
    std::uint32_t matchedProfileClass = 0; // matchedProfileClass: The matched profile class.
    std::uint32_t matchedProfileOffset = 0; // matchedProfileOffset: Offset of the matched field payload.
    std::uint32_t matchedFieldsId = 0;   // matchedFieldsId: Reserved field set identifier.
    std::uint32_t fieldCount = 0;        // fieldCount: Total number of fields declared by R0.
    std::uint64_t capabilityMask = 0;    // capabilityMask: KSW_CAP_* capability bitmask.
    KernelDynDataModuleIdentity ntoskrnl; // ntoskrnl: Current kernel module identity.
    KernelDynDataModuleIdentity lxcore;  // lxcore: Optional WSL/lxcore module identity.
    QString unavailableReasonText;       // unavailableReasonText: Reason R0 is unavailable.
    QString statusIoMessageText;         // statusIoMessageText: R3 status query diagnostic text.
    QString fieldsIoMessageText;         // fieldsIoMessageText: R3 field query diagnostic text.
    bool pdbProfileScanAttempted = false; // pdbProfileScanAttempted: whether the local JSON profile has been scanned.
    bool pdbProfileFound = false;         // pdbProfileFound: Indicates whether a profile exactly matching the current ntoskrnl identity was found.
    bool pdbProfileApplied = false;       // pdbProfileApplied: Whether R0 accepted and applied the PDB profile.
    long pdbProfileStatus = 0;            // pdbProfileStatus: NTSTATUS returned by R0 apply.
    std::uint32_t pdbProfileAppliedFields = 0; // pdbProfileAppliedFields: Number of fields applied in R0.
    std::uint32_t pdbProfileRejectedFields = 0; // pdbProfileRejectedFields: Number of fields rejected in R0.
    std::uint32_t pdbProfileUnknownFields = 0;  // pdbProfileUnknownFields: Number of unsupported fields in R0.
    std::uint32_t pdbProfileIgnoredJsonFields = 0; // pdbProfileIgnoredJsonFields: The count of unknown JSON fields ignored in R3.
    QString pdbProfileSourceText;         // pdbProfileSourceText: profile source, distinguishing between compact pack and scattered JSON.
    QString pdbProfileNameText;           // pdbProfileNameText: Matched profile name.
    QString pdbProfilePathText;           // pdbProfilePathText: Matches the profile file path.
    QString pdbProfileMessageText;        // pdbProfileMessageText: R0/R3 profile diagnostic messages.
    QString pdbProfileIoMessageText;      // pdbProfileIoMessageText: Apply IOCTL for diagnostic transmission.
    bool dynDataV4ModulesQueryOk = false; // dynDataV4ModulesQueryOk: Whether the v4 modules status query succeeded.
    bool dynDataV4ModulesUnsupported = false; // dynDataV4ModulesUnsupported: Indicates whether the old driver lacks the v4 modules query entry point.
    std::uint32_t dynDataV4ModulesTotalCount = 0; // dynDataV4ModulesTotalCount: total count of v4 modules observed in R0.
    std::uint32_t dynDataV4ModulesReturnedCount = 0; // dynDataV4ModulesReturnedCount: Number of v4 module rows returned in this R0 call.
    QString dynDataV4ModulesIoMessageText; // dynDataV4ModulesIoMessageText: Diagnostic text for v4 modules IO query.
    bool dynDataV4CapabilityGroupsQueryOk = false; // dynDataV4CapabilityGroupsQueryOk: Whether the v4 capability groups query succeeded.
    bool dynDataV4CapabilityGroupsUnsupported = false; // dynDataV4CapabilityGroupsUnsupported: whether the old driver lacks the capability groups query entry.
    std::uint32_t dynDataV4CapabilityGroupsTotalCount = 0; // dynDataV4CapabilityGroupsTotalCount: Total number of capability groups observed at R0.
    std::uint32_t dynDataV4CapabilityGroupsReturnedCount = 0; // dynDataV4CapabilityGroupsReturnedCount: number of capability group rows returned in this R0 call.
    QString dynDataV4CapabilityGroupsIoMessageText; // dynDataV4CapabilityGroupsIoMessageText: capability groups query IO diagnostic text.
    bool dynDataV4MissingItemsQueryOk = false; // dynDataV4MissingItemsQueryOk: whether the v4 missing items query succeeded.
    bool dynDataV4MissingItemsUnsupported = false; // dynDataV4MissingItemsUnsupported: Indicates if the old driver lacks the missing items query entry point.
    std::uint32_t dynDataV4MissingItemsTotalCount = 0; // dynDataV4MissingItemsTotalCount: Total number of missing items observed by R0.
    std::uint32_t dynDataV4MissingItemsReturnedCount = 0; // dynDataV4MissingItemsReturnedCount: Number of missing item rows returned by R0 in this call.
    QString dynDataV4MissingItemsIoMessageText; // dynDataV4MissingItemsIoMessageText: Diagnostic text for missing items query IO.
    bool dynDataV4ItemsQueryOk = false; // dynDataV4ItemsQueryOk: Whether the v4 accepted item list query succeeded.
    bool dynDataV4ItemsUnsupported = false; // dynDataV4ItemsUnsupported: whether the old driver lacks the v4 items query entry.
    std::uint32_t dynDataV4ItemsTotalCount = 0; // dynDataV4ItemsTotalCount: Total count of accepted items observed at R0.
    std::uint32_t dynDataV4ItemsReturnedCount = 0; // dynDataV4ItemsReturnedCount: R0 count of accepted items returned in this call.
    QString dynDataV4ItemsIoMessageText; // dynDataV4ItemsIoMessageText: diagnostic text for v4 items IO query.
};

// ============================================================
// KernelDynDataFieldEntry
// Purpose:
// - Represents a row in the dynamic offset field table.
// - Save field source, availability status, capability dependencies, and detail text.
// ============================================================
struct KernelDynDataFieldEntry
{
    std::uint32_t fieldId = 0;           // fieldId：KSW_DYN_FIELD_ID_*。
    std::uint32_t flags = 0;             // flags：KSW_DYN_FIELD_FLAG_*。
    std::uint32_t source = 0;            // source：KSW_DYN_FIELD_SOURCE_*。
    std::uint32_t offset = 0;            // offset: Field offset; sentinel value if unavailable.
    std::uint64_t capabilityMask = 0;    // capabilityMask: KSW_CAP_* bits involved in this field.
    QString fieldNameText;               // fieldNameText: Field name.
    QString sourceNameText;              // sourceNameText: Source name.
    QString featureNameText;             // featureNameText: Associated feature name.
    QString statusText;                  // statusText: Available/Missing status.
    QString detailText;                  // detailText: Details panel text.
};

// ============================================================
// KernelDynDataV4ItemEntry
// Purpose:
// - Represents a row in the DynData v4 accepted item table.
// - Saves R0-accepted and cached PDB items to confirm the profile is not just a summary.
// ============================================================
struct KernelDynDataV4ItemEntry
{
    std::uint32_t moduleClassId = 0;      // moduleClassId: KSW_DYN_PROFILE_CLASS_* module class.
    std::uint32_t itemIndex = 0;          // itemIndex: The R0 storage index within this module.
    std::uint32_t itemId = 0;             // itemId: v4 item stable ID.
    std::uint32_t itemKind = 0;           // itemKind: Types such as StructOffset, GlobalRva, FunctionRva, etc.
    std::uint32_t flags = 0;              // flags: Flags for required/optional items.
    std::uint32_t capabilityGroupId = 0;  // capabilityGroupId: The associated capability group.
    std::uint64_t value = 0;              // value: the 64-bit value merged from valueLow and valueHigh.
    QString kindText;                     // kindText: Human-readable text for itemKind.
    QString flagsText;                    // flagsText: Human-readable text for flags.
    QString auxText;                      // auxText: Summary of aux0..aux3 auxiliary fields.
    QString detailText;                   // detailText: Complete detailed text.
};

// ============================================================
// KernelDriverStatusSummary
// Purpose:
// - Represents a summary of Phase 1 unified driver status queries;
// - Cache protocol version, security policy, DynData status, and the most recent R0 error.
// ============================================================
struct KernelDriverStatusSummary
{
    bool queryOk = false;                    // queryOk: Whether the unified capability IOCTL succeeded.
    bool driverLoaded = false;               // driverLoaded: Whether R3 successfully opened and queried the KswordARK driver.
    bool protocolOk = false;                 // protocolOk: Whether the R0 protocol version matches the current R3 expectation.
    bool dynDataMissing = true;              // dynDataMissing: Whether DynData is missing or failed to match the ntos profile.
    bool limited = true;                     // limited: Whether in a limited capability state.
    std::uint32_t version = 0;               // version: Capability query protocol version.
    std::uint32_t driverProtocolVersion = 0; // driverProtocolVersion: R0 main protocol version.
    std::uint32_t statusFlags = 0;           // statusFlags：KSWORD_ARK_DRIVER_STATUS_FLAG_*。
    std::uint32_t securityPolicyFlags = 0;   // securityPolicyFlags：KSWORD_ARK_SECURITY_POLICY_*。
    std::uint32_t dynDataStatusFlags = 0;    // dynDataStatusFlags：KSW_DYN_STATUS_FLAG_*。
    long lastErrorStatus = 0;                // lastErrorStatus: The NTSTATUS recorded last in R0.
    std::uint32_t totalFeatureCount = 0;     // totalFeatureCount: Total number of features declared by R0.
    std::uint32_t returnedFeatureCount = 0;  // returnedFeatureCount: Number of feature rows returned in this response.
    std::uint64_t dynDataCapabilityMask = 0; // dynDataCapabilityMask: current DynData capability bitmap.
    bool dynDataStatusQueryOk = false;       // dynDataStatusQueryOk: whether QUERY_DYN_STATUS succeeded.
    bool dynDataFieldsQueryOk = false;       // dynDataFieldsQueryOk: whether QUERY_DYN_FIELDS succeeded.
    bool ntoskrnlIdentityPresent = false;    // ntoskrnlIdentityPresent: Indicates whether the R0 driver has detected the current ntoskrnl identity.
    bool localPdbProfileMatched = false;     // localPdbProfileMatched: Whether the local pack exactly matches the current ntoskrnl.
    bool pdbProfileActive = false;           // pdbProfileActive: Whether the R0 PDB profile is currently applied.
    bool callbackProfileActive = false;      // callbackProfileActive: Whether the R0 callback PDB profile is currently applied.
    bool trustedPdbOffsetsActive = false;    // trustedPdbOffsetsActive: Whether trusted PDB offsets are currently participating in DynData.
    bool callbackNotifyTrusted = false;      // callbackNotifyTrusted: whether the global RVA of the notify array is overridden by the profile.
    bool callbackRegistryTrusted = false;    // callbackRegistryTrusted: Whether the registry callback global RVA is overridden by the profile.
    bool callbackObjectTrusted = false;      // callbackObjectTrusted: Whether the object callback structure offset is overridden by the profile.
    std::uint32_t dynDataSystemInformerDataVersion = 0; // dynDataSystemInformerDataVersion: Built-in System Informer DynData version.
    std::uint32_t dynDataSystemInformerDataLength = 0;  // dynDataSystemInformerDataLength: The number of bytes in the built-in DynData configuration.
    std::uint32_t dynDataMatchedProfileClass = 0; // dynDataMatchedProfileClass: The profile class matched at R0.
    std::uint32_t dynDataMatchedProfileOffset = 0; // dynDataMatchedProfileOffset: R0 matched field payload offset.
    std::uint32_t dynDataMatchedFieldsId = 0; // dynDataMatchedFieldsId: R0 matched field set identifier.
    std::uint32_t dynDataFieldCount = 0;      // dynDataFieldCount: Total number of DynData fields declared in R0.
    std::uint32_t dynDataReturnedFieldCount = 0; // dynDataReturnedFieldCount: Number of rows returned in the field list this time.
    std::uint32_t dynDataPresentFieldCount = 0; // dynDataPresentFieldCount: The current number of available fields.
    std::uint32_t dynDataRequiredMissingCount = 0; // dynDataRequiredMissingCount: count of required fields that are missing.
    std::uint32_t dynDataPdbProfileFieldCount = 0; // dynDataPdbProfileFieldCount: The number of available fields sourced from the PDB profile.
    std::uint32_t dynDataRuntimePatternFieldCount = 0; // dynDataRuntimePatternFieldCount: Number of available fields sourced from the runtime pattern.
    std::uint32_t dynDataSystemInformerFieldCount = 0; // dynDataSystemInformerFieldCount: Number of available fields sourced from System Informer.
    std::uint32_t dynDataExtraTableFieldCount = 0; // dynDataExtraTableFieldCount: Number of available fields from the Ksword extra table.
    std::uint32_t dynDataUnavailableFieldCount = 0; // dynDataUnavailableFieldCount: Current number of unavailable fields.
    bool dynDataActiveProcessLinksPresent = false; // dynDataActiveProcessLinksPresent: Whether R0 currently exposes the _EPROCESS.ActiveProcessLinks offset.
    std::uint32_t dynDataActiveProcessLinksOffset = 0xFFFFFFFFU; // dynDataActiveProcessLinksOffset: Offset of the currently active ActiveProcessLinks in R0.
    std::uint32_t dynDataActiveProcessLinksSource = 0; // dynDataActiveProcessLinksSource: The R0 source offset for ActiveProcessLinks.
    std::uint32_t ntoskrnlClassId = 0;       // ntoskrnlClassId: Current ntoskrnl profile class.
    std::uint32_t ntoskrnlMachine = 0;       // ntoskrnlMachine: Current ntoskrnl PE Machine type.
    std::uint32_t ntoskrnlTimeDateStamp = 0; // ntoskrnlTimeDateStamp: Current ntoskrnl PE TimeDateStamp.
    std::uint32_t ntoskrnlSizeOfImage = 0;   // ntoskrnlSizeOfImage: Current ntoskrnl PE SizeOfImage.
    std::uint64_t ntoskrnlImageBase = 0;     // ntoskrnlImageBase: Current ntoskrnl load base address.
    QString ntoskrnlModuleNameText;          // ntoskrnlModuleNameText: Current ntoskrnl module name.
    std::uint32_t localPdbProfilePackProfileCount = 0; // localPdbProfilePackProfileCount: Total number of profiles matching the pack declaration.
    std::uint32_t localPdbProfileFieldCount = 0; // localPdbProfileFieldCount: Number of profile declaration fields hit.
    std::uint32_t localPdbProfileTypedItemCount = 0; // localPdbProfileTypedItemCount: Number of v3 typed items matched in the profile.
    std::uint32_t localPdbProfileCallbackItemCount = 0; // localPdbProfileCallbackItemCount: Number of callbackItems hit in the profile declaration.
    bool localPdbProfileActiveProcessLinksPresent = false; // localPdbProfileActiveProcessLinksPresent: Whether the local pack contains ActiveProcessLinks.
    std::uint32_t localPdbProfileActiveProcessLinksOffset = 0xFFFFFFFFU; // localPdbProfileActiveProcessLinksOffset: offset of ActiveProcessLinks extracted from the local pack.
    double localPdbProfileCoveragePercent = -1.0; // localPdbProfileCoveragePercent: profile coverage written by release_sync; negative values indicate unknown.
    QString localPdbProfileNameText;         // localPdbProfileNameText: Name of the profile matched by the local pack.
    QString localPdbProfileVersionText;      // localPdbProfileVersionText: Windows version extracted from the profile name.
    QString localPdbProfilePathText;         // localPdbProfilePathText: Path to the matched pack file.
    QString dynDataUnavailableReasonText;    // dynDataUnavailableReasonText: Reason why R0 DynData is unavailable.
    QString dynDataStatusIoMessageText;      // dynDataStatusIoMessageText: DynData status IO diagnostics.
    QString dynDataFieldsIoMessageText;      // dynDataFieldsIoMessageText: DynData field IO diagnostics.
    QString localPdbProfileMessageText;      // localPdbProfileMessageText: Local pack matching diagnostics.
    QString lastErrorSourceText;             // lastErrorSourceText: Source of the most recent error.
    QString lastErrorSummaryText;            // lastErrorSummaryText: Summary of the most recent error.
    QString ioMessageText;                   // ioMessageText: R3 I/O diagnostic text.
};

// ============================================================
// KernelDriverCapabilityEntry
// Purpose:
// - Represents a row in the unified capability matrix;
// - Save feature name, status, security policy dependencies, DynData dependencies, and detail text.
// ============================================================
struct KernelDriverCapabilityEntry
{
    std::uint32_t featureId = 0;             // featureId：KSWORD_ARK_FEATURE_ID_*。
    std::uint32_t state = 0;                 // state：KSWORD_ARK_FEATURE_STATE_*。
    std::uint32_t flags = 0;                 // flags：KSWORD_ARK_FEATURE_FLAG_*。
    std::uint32_t requiredPolicyFlags = 0;   // requiredPolicyFlags: Enables required security policy bits.
    std::uint32_t deniedPolicyFlags = 0;     // deniedPolicyFlags: Current policy missing bits.
    std::uint64_t requiredDynDataMask = 0;   // requiredDynDataMask: Enables the required KSW_CAP_* bits.
    std::uint64_t presentDynDataMask = 0;    // presentDynDataMask: Bits currently satisfying KSW_CAP_*.
    QString featureNameText;                 // featureNameText: Feature name.
    QString stateNameText;                   // stateNameText: feature state name.
    QString dependencyText;                  // dependencyText: Description of the dependency field.
    QString reasonText;                      // reasonText: Reason for unavailable or degraded status.
    QString detailText;                      // detailText: Details panel text.
};

// ============================================================
// KernelDock
// Purpose:
// - Main control for kernel analysis;
// - Manages object namespaces, atomic tables, SSDTs, historical NtQuery calls, and driver callback pages;
// - Manages asynchronous refresh, filtering, detail linkage, and right-click menu operations.
// ============================================================
class KernelDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize UI, connect signals/slots, and trigger the first asynchronous refresh.
    // - Parameter parent: Qt parent widget.
    explicit KernelDock(QWidget* parent = nullptr);

    // Destructor:
    // - Resources are automatically released by the Qt parent-child mechanism and containers.
    ~KernelDock() override = default;

    // requestDynDataRefresh：
    // - Purpose: Trigger initialization and asynchronous refresh of the DynData page externally.
    void requestDynDataRefresh();

    // kswordSelfDriverPage：
    // - Inputs: None;
    // - Handles: Returns a container for the 'Dynamic Offset / Driver Status' sub-page.
    // - Output: non-owning pointer; attached to DriverDock by mainWindow, while business logic remains managed by KernelDock.
    QWidget* kswordSelfDriverPage() const;

    // ensureCurrentTabReadyForDisplay：
    // - Input: none, uses the current top-level tab index;
    // - Handling: Ensure the real UI for the current tab is initialized and schedule a repaint.
    // - Returns: No return value. Intended for mainWindow to call as a fallback after ADS restores the layout/display.
    void ensureCurrentTabReadyForDisplay();

    // focusProcessProtectTab：
    // - Inputs: None;
    // - Processing: Switch to 'Kernel Audit and Callbacks -> Driver Callbacks -> Process Protection'.
    // - Return: None. Reuses the same callback protection page for the process tab shortcut entry.
    void focusProcessProtectTab();

    // displayStateSummary：
    // - Inputs: None;
    // - Processing: Summarize visibility, size, and initialization state of top-level Tab, current page, and inner Tab within the object namespace;
    // - Returns: Compact log text for initiating black screen troubleshooting.
    QString displayStateSummary() const;

protected:
    // eventFilter：
    // - Handle the first truly visible event for the driver container that migrated to DriverDock.
    // - Only performs an idempotent initial write for the current second-level page; does not take ownership of page business logic.
    bool eventFilter(QObject* watched, QEvent* event) override;

    // showEvent：
    // - Input event: Qt show event;
    // - Handling: After the Kernel Dock is delayed mounted/restored by ADS, ensure the current internal page is truly initialized again;
    // - Returns: Nothing.
    void showEvent(QShowEvent* event) override;

private:
    // ==================== UI initialization ====================
    // initializeUi：
    // - Purpose: Create the root layout and top-level tab container.
    void initializeUi();

    // initializeObjectNamespaceTab：
    // - Purpose: Create the "Object Namespace Traversal" tab (default tab).
    void initializeObjectNamespaceTab();

    // initializeAtomTableTab：
    // - Purpose: Create the 'Atom Table Traversal' tab.
    void initializeAtomTableTab();

    // initializeNtQueryTab：
    // - Purpose: Create the "Historical NtQuery Information" tab.
    void initializeNtQueryTab();

    // initializeSsdtTab：
    // - Purpose: Create the "SSDT Traversal" page.
    void initializeSsdtTab();

    // initializeIoManagementTab：
    // - Inputs: None;
    // - Handling: Create the I/O management main page and horizontal sub-pages for SSDT, ShadowSSDT, IDT, GDT, and IOCTLS;
    // - Returns: Nothing.
    void initializeIoManagementTab();

    // initializeDynDataTab：
    // - Purpose: Creates the "Dynamic Offset" diagnostic page.
    void initializeDynDataTab();

    // initializeDriverStatusTab：
    // - Purpose: Creates the 'Driver Status' page, displaying a unified status card and capability matrix.
    void initializeDriverStatusTab();

    // initializeCallbackInterceptTab：
    // - Purpose: Create the "Driver Callback" tab (rule groups / rule editing / import-export / apply / status).
    void initializeCallbackInterceptTab();

    // initializeCallbackRemovePanel：
    // - Input: none; depends on the already-created 'Callback Traversal' page layout as the host.
    // - Processing: Create a manual callback removal panel at the bottom of the 'Callback Traversal' page, reusing legacy type/address/result detail controls.
    // - Returns: None; the function records controls via member pointers internally, and repeated calls return immediately.
    void initializeCallbackRemovePanel();

    // initializeCallbackEnumTab：
    // - Purpose: Create the 'Callback Enumeration' tab to display R0-enumerated callback records.
    void initializeCallbackEnumTab();

    // initializeShadowSsdtTab：
    // - Purpose: Create the "SSSDT Parsing" tab to display win32k/win32u shadow syscall information.
    void initializeShadowSsdtTab();

    // initializeInlineHookTab：
    // - Purpose: Create the 'Inline Hook Detection & Removal' tab, providing scan and forced removal entry points.
    void initializeInlineHookTab();

    // initializeIatEatHookTab：
    // - Purpose: Create the "IAT/EAT Hook Detection" tab to display suspicious pointers in import/export tables.
    void initializeIatEatHookTab();

    // initializeTimerDpcTab: Creates the read-only enumeration page for KTIMER/KDPC in the DynData v4 driver.
    void initializeTimerDpcTab();

    // initializeCrossViewTab：
    // - Purpose: Creates a read-only CID / cross-view page.
    void initializeCrossViewTab();

    // initializeIpcTab：
    // - Purpose: Create a read-only aggregated tab for IPC / NamedPipe / ALPC.
    void initializeIpcTab();

    // openKnowledgeRoute：
    // - Input: routeId - Stable internal observation route declared by the knowledge article;
    // - Processing: Switch only to existing read-only pages in the current KernelDock; do not initiate write operations.
    // - Return: None. Unknown routes silently keep the knowledge page.
    void openKnowledgeRoute(const QString& routeId);

    // initializeConnections：
    // - Purpose: Connect buttons, filter controls, linked table interactions, and the context menu.
    void initializeConnections();

    // ensureTabInitialized：
    // - Purpose: initialize the specified Tab's UI and perform initial data loading on demand.
    // - Parameter tabIndex: Top-level tab index.
    void ensureTabInitialized(int tabIndex);

    // ensureSelfDriverCurrentTabRefreshed：
    // - After the outer layer's own driver tab becomes visible or an internal tab switch occurs, defer verification for one round.
    // - Dynamic offsets and driver status each auto-refresh at most once initially.
    void ensureSelfDriverCurrentTabRefreshed();

    // ensureIoManagementTabInitialized：
    // - Input innerTabIndex: index of the internal horizontal sub-tab for I/O management;
    // - Handling: initialize the original lazy UI and perform the first refresh only for SSDT/ShadowSSDT.
    // - Return: None; IDT/GDT are loaded on first display, and IOCTLS have no background queries.
    void ensureIoManagementTabInitialized(int innerTabIndex);

    // ==================== Async Refresh ====================
    // refreshObjectNamespaceAsync：
    // - Purpose: Refresh object namespace enumeration results in the background.
    void refreshObjectNamespaceAsync();

    // refreshAtomTableAsync：
    // - Purpose: Asynchronously refreshes the atom table enumeration results in the background.
    void refreshAtomTableAsync();

    // refreshNtQueryAsync：
    // - Purpose: Refresh historical NtQuery results in the background.
    void refreshNtQueryAsync();

    // refreshSsdtAsync：
    // - Purpose: Refresh SSDT traversal results in the background.
    void refreshSsdtAsync();
    void restoreSelectedSsdtBaseline();

    // refreshDynDataAsync：
    // - Purpose: Asynchronously query R0 DynData status, field list, and capability bitmap.
    void refreshDynDataAsync();

    // refreshDriverStatusAsync：
    // - Purpose: Background query for Phase 1 unified driver capabilities, protocols, security policies, and recent errors.
    void refreshDriverStatusAsync();

    // refreshCallbackEnumAsync：
    // - Purpose: Asynchronously call ArkDriverClient to enumerate callback records in the background.
    void refreshCallbackEnumAsync();

    // refreshShadowSsdtAsync：
    // - Purpose: Asynchronously invoke ArkDriverClient to parse SSSDT/Shadow SSDT in the background.
    void refreshShadowSsdtAsync();
    void restoreSelectedShadowSsdtBaseline();

    // refreshInlineHooksAsync：
    // - Purpose: Background scan of kernel module export functions for Inline Hooks.
    void refreshInlineHooksAsync();

    // refreshIatEatHooksAsync：
    // - Purpose: Scan kernel modules in background for suspicious IAT/EAT pointers.
    void refreshIatEatHooksAsync();

    // refreshTimerDpcAsync: Enumerates the TimerTable per CPU in the background and resolves the module ownership of the routines.
    void refreshTimerDpcAsync();

    // refreshTimerDpcAfterDynDataAsync: Applies DynData profile first, then enumerates Timer/DPC.
    void refreshTimerDpcAfterDynDataAsync();

    // ==================== Table Rendering ====================
    // rebuildObjectNamespaceTable：
    // - Purpose: Rebuild the object namespace tree based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildObjectNamespaceTable(const QString& filterKeyword);

    // rebuildObjectNamespacePropertyTable：
    // - Purpose: Rebuild the 'object property item/value' table to display detailed fields for the current node or object record.
    // - Parameter entry: The current object record; if nullptr, display the tree node summary.
    // - Parameter nodeNameText: tree node name (used when entry is nullptr).
    // - Parameter nodeTypeText: tree node type (used when entry is nullptr).
    // - Parameter nodePathText: tree node path (used when entry is nullptr).
    // - Parameter nodeDescriptionText: Tree node description (used when entry is nullptr).
    void rebuildObjectNamespacePropertyTable(
        const KernelObjectNamespaceEntry* entry,
        const QString& nodeNameText,
        const QString& nodeTypeText,
        const QString& nodePathText,
        const QString& nodeDescriptionText);

    // selectFirstObjectNamespaceEntryItem：
    // - Purpose: Locate and select the first object record node in the tree (excluding root/directory summary nodes).
    void selectFirstObjectNamespaceEntryItem();

    // showTabInitializingProgress：
    // - Purpose: Display an indeterminate progress bar at the top before tab lazy initialization to reduce the feeling of blank waiting.
    // - Parameters: tabIndex is the target tab index; titleText is the tab's Chinese name.
    void showTabInitializingProgress(int tabIndex, const QString& titleText);

    // hideTabInitializingProgress：
    // - Purpose: Hide the initialization progress bar after tab content construction is complete.
    void hideTabInitializingProgress();

    // updateTabIconContrast：
    // - Purpose: Redraw tab icon colors based on the currently selected tab to ensure icons appear white when the background is blue and highlighted.
    void updateTabIconContrast();

    // rebuildAtomTable：
    // - Purpose: Rebuild the atom table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildAtomTable(const QString& filterKeyword);

    // rebuildNtQueryTable：
    // - Purpose: Rebuild the historical NtQuery result table.
    void rebuildNtQueryTable();

    // rebuildSsdtTable：
    // - Purpose: Rebuild the SSDT result table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildSsdtTable(const QString& filterKeyword);

    // rebuildDynDataFieldTable：
    // - Purpose: Rebuild the dynamic offset field table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildDynDataFieldTable(const QString& filterKeyword);

    // rebuildDynDataV4ItemTable：
    // - Purpose: Rebuild the v4 accepted item detail table.
    // - Parameter filterKeyword: Reserved filter keyword, currently shared with the field filter box.
    void rebuildDynDataV4ItemTable(const QString& filterKeyword);

    // rebuildDriverCapabilityTable：
    // - Purpose: Rebuilds the driver capability matrix based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildDriverCapabilityTable(const QString& filterKeyword);

    // rebuildCallbackEnumTable：
    // - Purpose: Rebuild the callback traversal table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildCallbackEnumTable(const QString& filterKeyword);

    // rebuildShadowSsdtTable：
    // - Purpose: Rebuild the SSSDT table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildShadowSsdtTable(const QString& filterKeyword);

    // rebuildInlineHookTable：
    // - Purpose: Rebuild the Inline Hook table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildInlineHookTable(const QString& filterKeyword);

    // rebuildIatEatHookTable：
    // - Purpose: Rebuild the IAT/EAT Hook table based on the filter keyword.
    // - Parameter filterKeyword: filter keyword (empty means no filtering).
    void rebuildIatEatHookTable(const QString& filterKeyword);

    void rebuildTimerDpcTable(const QString& filterKeyword);

    // ==================== Detail Linkage ====================
    // showObjectNamespaceDetailByCurrentRow：
    // - Purpose: Display Object Namespace details based on the currently selected row.
    void showObjectNamespaceDetailByCurrentRow();

    // showAtomDetailByCurrentRow：
    // - Purpose: Display atom details based on the currently selected row.
    void showAtomDetailByCurrentRow();

    // showNtQueryDetailByCurrentRow：
    // - Purpose: Display NtQuery details based on the currently selected row.
    void showNtQueryDetailByCurrentRow();

    // showSsdtDetailByCurrentRow：
    // - Purpose: Display SSDT details based on the currently selected row.
    void showSsdtDetailByCurrentRow();

    // showDynDataDetailByCurrentRow：
    // - Purpose: Display dynamic offset field details based on the currently selected row.
    void showDynDataDetailByCurrentRow();

    // showDriverCapabilityDetailByCurrentRow：
    // - Purpose: Display details for feature dependencies, policies, and DynData bitmaps according to the currently selected row.
    void showDriverCapabilityDetailByCurrentRow();

    // showCallbackEnumDetailByCurrentRow：
    // - Purpose: Displays callback enumeration details based on the currently selected row.
    void showCallbackEnumDetailByCurrentRow();

    // showCallbackEnumDetail：
    // - Purpose: Display callback details passed from the table or Minifilter tree.
    void showCallbackEnumDetail(const KernelCallbackEnumEntry* entry);

    // showShadowSsdtDetailByCurrentRow：
    // - Purpose: Display SSSDT details based on the currently selected row.
    void showShadowSsdtDetailByCurrentRow();

    // showInlineHookDetailByCurrentRow：
    // - Purpose: Display Inline Hook details based on the currently selected row.
    void showInlineHookDetailByCurrentRow();

    // showIatEatHookDetailByCurrentRow：
    // - Purpose: Display IAT/EAT Hook details based on the currently selected row.
    void showIatEatHookDetailByCurrentRow();

    void showTimerDpcDetailByCurrentRow();

    void showTimerDpcContextMenu(const QPoint& localPosition);

    // ==================== Right-click Menu ====================
    // showObjectNamespaceContextMenu：
    // - Purpose: Display the right-click context menu for the object namespace table (copy + object operations).
    // - Parameter localPosition: Table viewport coordinates.
    void showObjectNamespaceContextMenu(const QPoint& localPosition);

    // showAtomContextMenu：
    // - Purpose: Display the right-click context menu for the atom table (copy + atom operations).
    // - Parameter localPosition: Table viewport coordinates.
    void showAtomContextMenu(const QPoint& localPosition);

    // showCallbackEnumContextMenu：
    // - Purpose: Display the right-click context menu for the callback enumeration table.
    // - Supports copying the current column, specified columns, selected rows, and details.
    // - Right-click actions apply to all selected rows after Ctrl-multi-selection.
    // Parameter localPosition: viewport coordinates of the table view.
    // Return value: None.
    void showCallbackEnumContextMenu(const QPoint& localPosition);

    // showShadowSsdtContextMenu：
    // - Purpose: Pop up the context menu for copying the SSSDT table.
    // - Parameter localPosition: Table viewport coordinates.
    void showShadowSsdtContextMenu(const QPoint& localPosition);

    // showInlineHookContextMenu：
    // - Purpose: Display the right-click context menu for the Inline Hook table, supporting copy and removal of selected items.
    // - Parameter localPosition: Table viewport coordinates.
    void showInlineHookContextMenu(const QPoint& localPosition);

    // showIatEatHookContextMenu：
    // - Purpose: Pop up the right-click copy menu for the IAT/EAT Hook table.
    // - Parameter localPosition: Table viewport coordinates.
    void showIatEatHookContextMenu(const QPoint& localPosition);

    // patchSelectedInlineHookWithNop：
    // - Purpose: Issue a standard request for the currently selected Inline Hook, then force NOP removal upon user confirmation.
    void patchSelectedInlineHookWithNop();

    // ==================== Current Row Index Helpers ====================
    // currentObjectNamespaceSourceIndex：
    // - Purpose: Read the index mapping the current object namespace row to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentObjectNamespaceSourceIndex(std::size_t& sourceIndexOut) const;

    // currentAtomSourceIndex：
    // - Purpose: Read the index mapping the current row of the atom table to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentAtomSourceIndex(std::size_t& sourceIndexOut) const;

    // currentSsdtSourceIndex：
    // - Purpose: Read the index mapping the current SSDT table row to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentSsdtSourceIndex(std::size_t& sourceIndexOut) const;

    // currentDynDataFieldSourceIndex：
    // - Purpose: Read the index mapping the current row of the dynamic offset field table to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentDynDataFieldSourceIndex(std::size_t& sourceIndexOut) const;

    // currentDriverCapabilitySourceIndex：
    // - Purpose: Read the index mapping the current row of the capability matrix to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentDriverCapabilitySourceIndex(std::size_t& sourceIndexOut) const;

    // currentCallbackEnumSourceIndex：
    // - Purpose: Read the index mapping the current row of the callback enumeration to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentCallbackEnumSourceIndex(std::size_t& sourceIndexOut) const;

    // currentShadowSsdtSourceIndex：
    // - Purpose: Read the index mapping the current SSSDT row to the cache vector.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentShadowSsdtSourceIndex(std::size_t& sourceIndexOut) const;

    // currentInlineHookSourceIndex：
    // - Purpose: Read the index in the cache vector that the current Inline Hook line maps to.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentInlineHookSourceIndex(std::size_t& sourceIndexOut) const;

    // currentIatEatHookSourceIndex：
    // - Purpose: Read the index in the cache vector mapped to the current IAT/EAT row.
    // - Out: sourceIndexOut, the cache index.
    // - Returns: true = read success; false = no selection or out of bounds.
    bool currentIatEatHookSourceIndex(std::size_t& sourceIndexOut) const;

    // currentObjectNamespaceEntry：
    // - Purpose: Returns the currently selected item in the object namespace.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelObjectNamespaceEntry* currentObjectNamespaceEntry() const;

    // currentAtomEntry：
    // - Purpose: Returns the currently selected item in the atom table.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelAtomEntry* currentAtomEntry() const;

    // currentSsdtEntry：
    // - Purpose: Return the currently selected item in the SSDT table.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelSsdtEntry* currentSsdtEntry() const;

    // currentDynDataFieldEntry：
    // - Purpose: Returns the currently selected dynamic offset field table entry.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelDynDataFieldEntry* currentDynDataFieldEntry() const;

    // currentDriverCapabilityEntry：
    // - Purpose: Returns the currently selected item in the capability matrix.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelDriverCapabilityEntry* currentDriverCapabilityEntry() const;

    // currentCallbackEnumEntry：
    // - Purpose: Returns the currently selected item in the callback traversal.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelCallbackEnumEntry* currentCallbackEnumEntry() const;

    // currentShadowSsdtEntry：
    // - Purpose: Returns the currently selected SSSDT entry.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelSsdtEntry* currentShadowSsdtEntry() const;

    // currentInlineHookEntry：
    // - Purpose: Return the currently selected Inline Hook entry.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelInlineHookEntry* currentInlineHookEntry() const;

    // currentIatEatHookEntry：
    // - Purpose: Return the currently selected IAT/EAT entry.
    // - Returns: pointer on match; nullptr otherwise.
    const KernelIatEatHookEntry* currentIatEatHookEntry() const;

private:
    // ==================== Root Controls ====================
    QVBoxLayout* rootLayout_ = nullptr; // m_rootLayout: KernelDock root layout.
    QTabWidget* tabWidget_ = nullptr;   // m_tabWidget: Top-level tab container.
    QProgressBar* tabInitializingProgressBar_ = nullptr; // m_tabInitializingProgressBar: Indeterminate progress bar at the top during Tab initialization.
    QLabel* tabInitializingStatusLabel_ = nullptr;       // m_tabInitializingStatusLabel: Tab initialization status hint text.
    int objectNamespaceTabIndex_ = -1;  // m_objectNamespaceTabIndex: Object namespace tab index.
    int atomTabIndex_ = -1;             // m_atomTabIndex: Index of the atom tab.
    int ioManagementTabIndex_ = -1;     // m_ioManagementTabIndex: Index of the I/O management top-level tab.
    int ioSsdtTabIndex_ = -1;           // m_ioSsdtTabIndex: Index of the I/O management internal SSDT sub-tab.
    int ioShadowSsdtTabIndex_ = -1;     // m_ioShadowSsdtTabIndex: Index of the internal ShadowSSDT sub-tab.
    int ioIdtTabIndex_ = -1;            // m_ioIdtTabIndex: Internal IDT sub-page index.
    int ioGdtTabIndex_ = -1;            // m_ioGdtTabIndex: Internal GDT sub-page index.
    int ioIoctlTabIndex_ = -1;          // m_ioIoctlTabIndex: Index of the internal IOCTLS decoder sub-tab.
    int dynDataTabIndex_ = -1;          // m_dynDataTabIndex: Index of the internal DynData overview page for the current driver.
    int dynDataProfileTabIndex_ = -1;   // m_dynDataProfileTabIndex: Index of the PDB Profile tab within the driver itself.
    int driverStatusTabIndex_ = -1;      // m_driverStatusTabIndex: Index of the internal status page for this driver.
    int ntQueryTabIndex_ = -1;          // m_ntQueryTabIndex: Index of the history NtQuery tab.
    int kernelAuditTabIndex_ = -1;       // m_kernelAuditTabIndex: Index of the top-level page for kernel auditing and callbacks.
    int callbackTabIndex_ = -1;         // m_callbackTabIndex: audit internal driver callback page index.
    int callbackEnumTabIndex_ = -1;     // m_callbackEnumTabIndex: Index of the audit internal callback enumeration page.
    int inlineHookTabIndex_ = -1;       // m_inlineHookTabIndex: Index of the internal Inline Hook tab for auditing.
    int iatEatHookTabIndex_ = -1;       // m_iatEatHookTabIndex: Index of the audit internal IAT/EAT tab.
    int slatIommuTabIndex_ = -1;        // m_slatIommuTabIndex: Index of the SLAT/IOMMU read-only page tab.
    int textIntegrityTabIndex_ = -1;    // m_textIntegrityTabIndex: Index of the Code Integrity read-only scan tab.
    int vbsPostureTabIndex_ = -1;       // m_vbsPostureTabIndex: Index for the VBS/HVCI posture tab.
    int timerDpcTabIndex_ = -1;          // m_timerDpcTabIndex: Index for the KTIMER/DPC tab.
    int crossViewTabIndex_ = -1;        // m_crossViewTabIndex: CID/Cross-view page tab index.
    int ipcTabIndex_ = -1;              // m_ipcTabIndex: Index of the IPC/NamedPipe/ALPC tab.
    int workQueueThreadTabIndex_ = -1;   // m_workQueueThreadTabIndex: Work queue thread audit page index.
    int knowledgeTabIndex_ = -1;         // m_knowledgeTabIndex: Index of the '71 Special Topics' kernel knowledge center tab.
    KernelKnowledgeTab* knowledgeTab_ = nullptr; // m_knowledgeTab: Retrievable knowledge center instance.
    bool objectNamespaceTabInitialized_ = false; // m_objectNamespaceTabInitialized: Whether the object namespace tab has been initialized.
    bool atomTabInitialized_ = false;            // m_atomTabInitialized: Whether the atom table tab has been initialized.
    bool ssdtTabInitialized_ = false;            // m_ssdtTabInitialized: Whether the SSDT tab has been initialized.
    bool dynDataTabInitialized_ = false;          // m_dynDataTabInitialized: Whether the dynamic offset tab has been initialized.
    bool driverStatusTabInitialized_ = false;     // m_driverStatusTabInitialized: Whether the driver status tab has been initialized.
    bool selfDriverRefreshCheckPending_ = false;  // m_selfDriverRefreshCheckPending: Whether the visibility delay recheck is queued.
    bool dynDataFirstRefreshTriggered_ = false;   // m_dynDataFirstRefreshTriggered: Indicates whether dynamic offset auto-first refresh has occurred.
    bool driverStatusFirstRefreshTriggered_ = false; // m_driverStatusFirstRefreshTriggered: Indicates whether the driver status has been automatically refreshed for the first time.
    bool ntQueryTabInitialized_ = false;         // m_ntQueryTabInitialized: Whether the historical NtQuery page has been initialized.
    bool callbackTabInitialized_ = false;        // m_callbackTabInitialized: Whether the driver callback page has been initialized.
    bool callbackEnumTabInitialized_ = false;    // m_callbackEnumTabInitialized: Whether the callback enumeration tab has been initialized.
    bool shadowSsdtTabInitialized_ = false;      // m_shadowSsdtTabInitialized: Whether the SSSDT page is initialized.
    bool inlineHookTabInitialized_ = false;      // m_inlineHookTabInitialized: Whether the Inline Hook tab has been initialized.
    bool iatEatHookTabInitialized_ = false;      // m_iatEatHookTabInitialized: Whether the IAT/EAT page has been initialized.
    bool timerDpcTabInitialized_ = false;        // m_timerDpcTabInitialized: Whether the KTIMER/DPC tab has been initialized.
    bool crossViewTabInitialized_ = false;       // m_crossViewTabInitialized: Whether the CID tab has been initialized.
    bool ipcTabInitialized_ = false;             // m_ipcTabInitialized: Whether the IPC tab is initialized.

    // ==================== Object Namespace Page ====================
    QWidget* objectNamespacePage_ = nullptr;                  // m_objectNamespacePage: Object namespace page container.
    QVBoxLayout* objectNamespaceLayout_ = nullptr;            // m_objectNamespaceLayout: Layout for the object namespace page.
    QTabWidget* objectNamespaceInnerTabWidget_ = nullptr;      // m_objectNamespaceInnerTabWidget: Object namespace internal capability tab.
    QWidget* objectNamespaceOverviewPage_ = nullptr;           // m_objectNamespaceOverviewPage: object namespace overview page.
    QVBoxLayout* objectNamespaceOverviewLayout_ = nullptr;     // m_objectNamespaceOverviewLayout: Layout for the object namespace overview page.
    QHBoxLayout* objectNamespaceToolLayout_ = nullptr;        // m_objectNamespaceToolLayout: object namespace toolbar layout.
    QPushButton* refreshObjectNamespaceButton_ = nullptr;     // m_refreshObjectNamespaceButton: Object namespace refresh button.
    QLineEdit* objectNamespaceFilterEdit_ = nullptr;          // m_objectNamespaceFilterEdit: Object namespace keyword filter input box.
    QLabel* objectNamespaceStatusLabel_ = nullptr;            // m_objectNamespaceStatusLabel: object namespace status text.
    QTreeWidget* objectNamespaceTree_ = nullptr;              // m_objectNamespaceTree: object namespace tree (file-manager-style structure).
    QTableWidget* objectNamespacePropertyTable_ = nullptr;    // m_objectNamespacePropertyTable: object property item/value table.
    CodeEditorWidget* objectNamespaceDetailEditor_ = nullptr; // m_objectNamespaceDetailEditor: Object namespace detail editor (read-only).

    // ==================== Atomic Table Page ====================
    QWidget* atomPage_ = nullptr;                  // m_atomPage: Atom table page container.
    QVBoxLayout* atomLayout_ = nullptr;            // m_atomLayout: Atom table page layout.
    QHBoxLayout* atomToolLayout_ = nullptr;        // m_atomToolLayout: Atom table toolbar layout.
    QPushButton* refreshAtomButton_ = nullptr;     // m_refreshAtomButton: Atom table refresh button.
    QLineEdit* atomFilterEdit_ = nullptr;          // m_atomFilterEdit: Atom keyword filter input box.
    QLabel* atomStatusLabel_ = nullptr;            // m_atomStatusLabel: Atom table status text.
    QTableWidget* atomTable_ = nullptr;            // m_atomTable: Atom result table.
    CodeEditorWidget* atomDetailEditor_ = nullptr; // m_atomDetailEditor: Atom details editor (read-only).

    // ==================== History NtQuery page ====================
    QWidget* ntQueryPage_ = nullptr;                  // m_ntQueryPage: Historical NtQuery page container.
    QVBoxLayout* ntQueryLayout_ = nullptr;            // m_ntQueryLayout: Historical NtQuery page layout.
    QHBoxLayout* ntQueryToolLayout_ = nullptr;        // m_ntQueryToolLayout: Historical NtQuery toolbar layout.
    QPushButton* refreshNtQueryButton_ = nullptr;     // m_refreshNtQueryButton: Historical NtQuery refresh button.
    QLabel* ntQueryStatusLabel_ = nullptr;            // m_ntQueryStatusLabel: Historical NtQuery status text.
    QTableWidget* ntQueryTable_ = nullptr;            // m_ntQueryTable: Table for historical NtQuery results.
    CodeEditorWidget* ntQueryDetailEditor_ = nullptr; // m_ntQueryDetailEditor: Read-only editor for historical NtQuery details.

    // ==================== I/O Management Aggregation Page ====================
    QWidget* ioManagementPage_ = nullptr;              // m_ioManagementPage: I/O management top-level page container.
    QVBoxLayout* ioManagementLayout_ = nullptr;         // m_ioManagementLayout: I/O management root layout.
    QTabWidget* ioManagementInnerTabWidget_ = nullptr;  // m_ioManagementInnerTabWidget: Horizontal five-tab container.

    // ==================== Kernel Audit and Callback Aggregation Page ====================
    QWidget* kernelAuditPage_ = nullptr;                // m_kernelAuditPage: Top-level container for the four audit business items.
    QVBoxLayout* kernelAuditLayout_ = nullptr;           // m_kernelAuditLayout: Root layout for the aggregation page.
    QTabWidget* kernelAuditInnerTabWidget_ = nullptr;    // m_kernelAuditInnerTabWidget: Inline/IAT/callback secondary page.

    // ==================== Ksword Internal Driver Migration Container ====================
    QWidget* selfDriverPage_ = nullptr;                 // m_selfDriverPage: Container passed to DriverDock for display.
    QVBoxLayout* selfDriverLayout_ = nullptr;            // m_selfDriverLayout: Layout container for the self driver.
    QTabWidget* selfDriverInnerTabWidget_ = nullptr;     // m_selfDriverInnerTabWidget: Dynamic offset/status secondary page.

    // ==================== SSDT Sub-page ====================
    QWidget* ssdtPage_ = nullptr;                     // m_ssdtPage: SSDT page container.
    QVBoxLayout* ssdtLayout_ = nullptr;               // m_ssdtLayout: SSDT page layout.
    QHBoxLayout* ssdtToolLayout_ = nullptr;           // m_ssdtToolLayout: SSDT toolbar layout.
    QPushButton* refreshSsdtButton_ = nullptr;        // m_refreshSsdtButton: SSDT refresh button.
    QPushButton* restoreSsdtButton_ = nullptr;        // m_restoreSsdtButton: Restore slot for verifying disk baseline.
    QLineEdit* ssdtFilterEdit_ = nullptr;             // m_ssdtFilterEdit: SSDT filter input box.
    QLabel* ssdtStatusLabel_ = nullptr;               // m_ssdtStatusLabel: SSDT status text.
    QTableWidget* ssdtTable_ = nullptr;               // m_ssdtTable: SSDT results table.
    CodeEditorWidget* ssdtDetailEditor_ = nullptr;    // m_ssdtDetailEditor: SSDT detail editor (read-only).

    // ==================== ShadowSSDT Sub-page ====================
    QWidget* shadowSsdtPage_ = nullptr;               // m_shadowSsdtPage: SSSDT page container.
    QVBoxLayout* shadowSsdtLayout_ = nullptr;         // m_shadowSsdtLayout: Layout for the SSSDT page.
    QHBoxLayout* shadowSsdtToolLayout_ = nullptr;     // m_shadowSsdtToolLayout: SSSDT toolbar layout.
    QPushButton* refreshShadowSsdtButton_ = nullptr;  // m_refreshShadowSsdtButton: SSSDT refresh button.
    QLineEdit* shadowSsdtFilterEdit_ = nullptr;       // m_shadowSsdtFilterEdit: SSSDT filter field.
    QLabel* shadowSsdtStatusLabel_ = nullptr;         // m_shadowSsdtStatusLabel: SSSDT status text.
    QTableWidget* shadowSsdtTable_ = nullptr;         // m_shadowSsdtTable: SSSDT table.
    CodeEditorWidget* shadowSsdtDetailEditor_ = nullptr; // m_shadowSsdtDetailEditor: SSSDT detail text editor.

    // ==================== Inline Hook Page ====================
    QWidget* inlineHookPage_ = nullptr;                    // m_inlineHookPage: Container for the Inline Hook page.
    QVBoxLayout* inlineHookLayout_ = nullptr;              // m_inlineHookLayout: Inline Hook page layout.
    QHBoxLayout* inlineHookToolLayout_ = nullptr;          // m_inlineHookToolLayout: Inline Hook toolbar layout.
    QPushButton* refreshInlineHookButton_ = nullptr;       // m_refreshInlineHookButton: Refresh button.
    QPushButton* patchInlineHookButton_ = nullptr;         // m_patchInlineHookButton: NOP removal button.
    QLineEdit* inlineHookFilterEdit_ = nullptr;            // m_inlineHookFilterEdit: Local filter box.
    QLineEdit* inlineHookModuleEdit_ = nullptr;            // m_inlineHookModuleEdit: R0 module filter box.
    QComboBox* inlineHookIncludeCombo_ = nullptr;          // m_inlineHookIncludeCombo: Scan range options.
    QLabel* inlineHookStatusLabel_ = nullptr;              // m_inlineHookStatusLabel: Status text.
    QTableWidget* inlineHookTable_ = nullptr;              // m_inlineHookTable: Inline Hook table.
    CodeEditorWidget* inlineHookDetailEditor_ = nullptr;   // m_inlineHookDetailEditor: Detail text box.

    // ==================== IAT/EAT Hook Page ====================
    QWidget* iatEatHookPage_ = nullptr;                    // m_iatEatHookPage: IAT/EAT page container.
    QWidget* timerDpcPage_ = nullptr;                       // m_timerDpcPage: KTIMER/DPC page container.
    QWidget* crossViewPage_ = nullptr;                    // m_crossViewPage: CID / cross-view page container.
    QWidget* ipcPage_ = nullptr;                          // m_ipcPage: IPC / ALPC / NamedPipe page container.
    QVBoxLayout* iatEatHookLayout_ = nullptr;              // m_iatEatHookLayout: IAT/EAT page layout.
    QHBoxLayout* iatEatHookToolLayout_ = nullptr;          // m_iatEatHookToolLayout: IAT/EAT toolbar layout.
    QPushButton* refreshIatEatHookButton_ = nullptr;       // m_refreshIatEatHookButton: Refresh button.
    QLineEdit* iatEatHookFilterEdit_ = nullptr;            // m_iatEatHookFilterEdit: Local filter box.
    QLineEdit* iatEatHookModuleEdit_ = nullptr;            // m_iatEatHookModuleEdit: R0 module filter field.
    QComboBox* iatEatHookIncludeCombo_ = nullptr;          // m_iatEatHookIncludeCombo: IAT/EAT range options.
    QLabel* iatEatHookStatusLabel_ = nullptr;              // m_iatEatHookStatusLabel: Status text.
    QTableWidget* iatEatHookTable_ = nullptr;              // m_iatEatHookTable: IAT/EAT table.
    CodeEditorWidget* iatEatHookDetailEditor_ = nullptr;   // m_iatEatHookDetailEditor: Detail text box.

    // ==================== KTIMER/DPC page ====================
    QVBoxLayout* timerDpcLayout_ = nullptr;
    QHBoxLayout* timerDpcToolLayout_ = nullptr;
    QPushButton* refreshTimerDpcButton_ = nullptr;
    QLineEdit* timerDpcFilterEdit_ = nullptr;
    QLabel* timerDpcStatusLabel_ = nullptr;
    QTableWidget* timerDpcTable_ = nullptr;
    CodeEditorWidget* timerDpcDetailEditor_ = nullptr;

    // ==================== Dynamic Offset Page ====================
    QHBoxLayout* dynDataToolLayout_ = nullptr;        // m_dynDataToolLayout: Dynamic offset toolbar layout.
    QPushButton* refreshDynDataButton_ = nullptr;     // m_refreshDynDataButton: Dynamic offset refresh button.
    QPushButton* copyDynDataReportButton_ = nullptr;  // m_copyDynDataReportButton: Copy diagnostic report button.
    QLineEdit* dynDataFilterEdit_ = nullptr;          // m_dynDataFilterEdit: Dynamic offset field filter input box.
    QLabel* dynDataStatusLabel_ = nullptr;            // m_dynDataStatusLabel: Dynamic offset status text.
    QTableWidget* dynDataSummaryTable_ = nullptr;     // m_dynDataSummaryTable: Dynamic offset summary table.
    QTableWidget* dynDataFieldTable_ = nullptr;       // m_dynDataFieldTable: Dynamic offset field table.
    CodeEditorWidget* dynDataDetailEditor_ = nullptr; // m_dynDataDetailEditor: Dynamic offset detail editor (read-only).
    QWidget* dynDataOverviewPage_ = nullptr;          // m_dynDataOverviewPage: Dynamic offset overview page.
    QVBoxLayout* dynDataOverviewLayout_ = nullptr;    // m_dynDataOverviewLayout: Layout for the dynamic offset overview page.
    QWidget* dynDataProfilePage_ = nullptr;           // m_dynDataProfilePage: PDB profile status page.
    QVBoxLayout* dynDataProfileLayout_ = nullptr;     // m_dynDataProfileLayout: PDB profile status tab layout.
    QLabel* dynDataProfileStatusLabel_ = nullptr;     // m_dynDataProfileStatusLabel: PDB profile status label.
    QTableWidget* dynDataProfileSummaryTable_ = nullptr; // m_dynDataProfileSummaryTable: PDB profile summary table.
    QTableWidget* dynDataV4ItemTable_ = nullptr; // m_dynDataV4ItemTable: PDB profile v4 accepted item detail table.
    CodeEditorWidget* dynDataProfileDetailEditor_ = nullptr; // m_dynDataProfileDetailEditor: PDB profile detail editor.

    // ==================== Driver Status Page ====================
    QWidget* driverStatusPage_ = nullptr;                  // m_driverStatusPage: Driver status page container.
    QVBoxLayout* driverStatusLayout_ = nullptr;            // m_driverStatusLayout: Driver status page layout.
    QHBoxLayout* driverStatusToolLayout_ = nullptr;        // m_driverStatusToolLayout: Driver status toolbar layout.
    QPushButton* refreshDriverStatusButton_ = nullptr;     // m_refreshDriverStatusButton: Refresh unified capabilities button.
    QPushButton* copyDriverStatusReportButton_ = nullptr;  // m_copyDriverStatusReportButton: Button to copy the diagnostic report.
    QLineEdit* driverStatusFilterEdit_ = nullptr;          // m_driverStatusFilterEdit: Capability matrix filter input.
    QLabel* driverStatusLabel_ = nullptr;                  // m_driverStatusLabel: Overall status text.
    QTableWidget* driverStatusSummaryTable_ = nullptr;     // m_driverStatusSummaryTable: Driver status summary table.
    QTableWidget* driverCapabilityTable_ = nullptr;        // m_driverCapabilityTable: Capability matrix table.
    CodeEditorWidget* driverCapabilityDetailEditor_ = nullptr; // m_driverCapabilityDetailEditor: Capability detail editor.

    // ==================== Driver Callback Page ====================
    QWidget* callbackInterceptPage_ = nullptr;                     // m_callbackInterceptPage: Driver callback page container.
    CallbackInterceptController* callbackInterceptController_ = nullptr; // m_callbackInterceptController: Driver callback page controller.
    QWidget* callbackEnumPage_ = nullptr;                          // m_callbackEnumPage: Callback enumeration page container.
    QVBoxLayout* callbackEnumLayout_ = nullptr;                    // m_callbackEnumLayout: Callback enumeration page layout.
    QHBoxLayout* callbackEnumToolLayout_ = nullptr;                // m_callbackEnumToolLayout: Callback enumeration toolbar layout.
    QPushButton* refreshCallbackEnumButton_ = nullptr;             // m_refreshCallbackEnumButton: Callback enumeration refresh button.
    QLineEdit* callbackEnumFilterEdit_ = nullptr;                  // m_callbackEnumFilterEdit: Input box for filtering callback enumeration.
    QLabel* callbackEnumStatusLabel_ = nullptr;                    // m_callbackEnumStatusLabel: Status text for callback enumeration.
    QTableWidget* callbackEnumTable_ = nullptr;                    // m_callbackEnumTable: callback enumeration table.
    QTreeWidget* minifilterCallbackTree_ = nullptr;                // m_minifilterCallbackTree: Filter -> Pre/Post callback tree.
    CodeEditorWidget* callbackEnumDetailEditor_ = nullptr;         // m_callbackEnumDetailEditor: Text box for callback enumeration details.
    QWidget* callbackRemoveContentWidget_ = nullptr;               // m_callbackRemoveContentWidget: Container for the remove panel embedded at the bottom of the callback traversal page.
    QVBoxLayout* callbackRemoveLayout_ = nullptr;                  // m_callbackRemoveLayout: Internal layout for the callback removal panel.
    QHBoxLayout* callbackRemoveToolLayout_ = nullptr;              // m_callbackRemoveToolLayout: Layout for the callback removal toolbar.
    QComboBox* callbackRemoveTypeCombo_ = nullptr;                 // m_callbackRemoveTypeCombo: Callback type dropdown.
    QLineEdit* callbackRemoveAddressEdit_ = nullptr;               // m_callbackRemoveAddressEdit: Callback address input field.
    QPushButton* callbackRemoveButton_ = nullptr;                  // m_callbackRemoveButton: Execute remove button.
    QLabel* callbackRemoveStatusLabel_ = nullptr;                  // m_callbackRemoveStatusLabel: Status text.

    // ==================== Data Cache ====================
    std::vector<KernelObjectNamespaceEntry> objectNamespaceRows_; // m_objectNamespaceRows: Object namespace snapshot rows.
    std::vector<KernelAtomEntry> atomRows_;                       // m_atomRows: Atom snapshot rows.
    std::vector<KernelNtQueryResultEntry> ntQueryResults_;        // m_ntQueryResults: Historical NtQuery snapshot rows.
    std::vector<KernelSsdtEntry> ssdtRows_;                       // m_ssdtRows: SSDT snapshot rows.
    KernelDynDataSummary dynDataSummary_;                         // m_dynDataSummary: Dynamic offset summary snapshot.
    std::vector<KernelDynDataFieldEntry> dynDataRows_;            // m_dynDataRows: Dynamic offset field snapshot rows.
    std::vector<KernelDynDataV4ItemEntry> dynDataV4ItemRows_;      // m_dynDataV4ItemRows: v4 accepted item snapshot rows.
    KernelDriverStatusSummary driverStatusSummary_;               // m_driverStatusSummary: Unified driver status summary snapshot.
    std::vector<KernelDriverCapabilityEntry> driverCapabilityRows_; // m_driverCapabilityRows: Capability matrix snapshot rows.
    std::vector<KernelCallbackEnumEntry> callbackEnumRows_;        // m_callbackEnumRows: Callback enumeration snapshot rows.
    std::vector<KernelSsdtEntry> shadowSsdtRows_;                  // m_shadowSsdtRows: SSSDT snapshot rows.
    std::vector<KernelInlineHookEntry> inlineHookRows_;            // m_inlineHookRows: Inline Hook snapshot rows.
    std::vector<KernelIatEatHookEntry> iatEatHookRows_;            // m_iatEatHookRows: IAT/EAT snapshot rows.
    std::vector<KernelTimerDpcEntry> timerDpcRows_;                 // m_timerDpcRows: KTIMER/DPC snapshot rows.

    // ==================== Refresh Status ====================
    std::atomic_bool objectNamespaceRefreshRunning_{ false }; // m_objectNamespaceRefreshRunning: Object namespace refresh status.
    std::atomic_bool atomRefreshRunning_{ false };            // m_atomRefreshRunning: Atomic table refresh status.
    std::atomic_bool ntQueryRefreshRunning_{ false };         // m_ntQueryRefreshRunning: historical NtQuery refresh status.
    std::atomic_bool ssdtRefreshRunning_{ false };            // m_ssdtRefreshRunning: SSDT refresh status.
    std::atomic_bool dynDataRefreshRunning_{ false };         // m_dynDataRefreshRunning: Dynamic offset refresh status.
    std::atomic_bool driverStatusRefreshRunning_{ false };    // m_driverStatusRefreshRunning: Driver status refresh status.
    std::atomic_bool callbackEnumRefreshRunning_{ false };    // m_callbackEnumRefreshRunning: Callback enumeration refresh status.
    std::atomic_bool shadowSsdtRefreshRunning_{ false };      // m_shadowSsdtRefreshRunning: SSSDT refresh state.
    std::atomic_bool inlineHookRefreshRunning_{ false };      // m_inlineHookRefreshRunning: Inline Hook refresh status.
    std::atomic_bool iatEatHookRefreshRunning_{ false };      // m_iatEatHookRefreshRunning: IAT/EAT refresh status.
    std::atomic_bool timerDpcRefreshRunning_{ false };        // m_timerDpcRefreshRunning: KTIMER/DPC refresh status.
    std::atomic_bool timerDpcRefreshAfterDynData_{ false };   // m_timerDpcRefreshAfterDynData: Automatically retries Timer/DPC after DynData completion.
};
