#pragma once

// Private contracts for FileDock implementation units.
#include "FileDock.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/UiSupport.h"
#include "FilePropertyPeAnalyzer.h"
#include "DriverFileSystemParser.h"
#include "IrpFileSystemParser.h"
#include "FileHandleUsageScanner.h"
#include "../internationalization/LanguageManager.h"
#include "../MainWindow.h"

// ============================================================
// FileDock.cpp
// Notes:
// - This file implements the core interaction of the dual-pane file manager;
// - Supports navigation, filtering, sorting, basic file operations, and file details display.
// ============================================================

#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/HexEditorWidget.h"
#include "../ui/ReportStructuredView.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../kernel_dock/KernelCleanImageBaseline.h"
#include "../PluginHost.h"
#include "../../../shared/platform/file/FileHandleTools.h"
#include "../../../shared/platform/file/FileMetadataTransaction.h"
#include "../../../shared/platform/file/File.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QAction>
#include <QByteArray>
#include <QButtonGroup>
#include <QClipboard>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QEvent>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QFileDialog>
#include <QFileSystemModel>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPair>
#include <QTextEdit>
#include <QPointer>
#include <QPalette>
#include <QProgressBar>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScreen>
#include <QScrollArea>
#include <QSaveFile>
#include <QSet>
#include <QShortcut>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStorageInfo>
#include <QStyle>
#include <QStringList>
#include <QStackedWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeView>
#include <QTimeZone>
#include <QUrl>
#include <QUuid>
#include <QVector>
#include <QVBoxLayout>
#include <QWindow>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>
#include <Wbemidl.h>
#include <fltUser.h>
#include <atlbase.h>
#include <comdef.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cmath>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include <Aclapi.h>
#include <Sddl.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "FltLib.lib")

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000UL
#endif

#ifndef SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 0x1UL
#endif

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif


namespace ksword::ui::file_dock
{
    struct DriverDeleteTarget
    {
        QString path;
        bool isDirectory = false;
    };

    enum class UnlockOperationMode
    {
        kCloseHandleR3 = 0,
        kTerminateProcessR3,
        kTerminateProcessR0
    };

    struct UnlockProcessCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        QStringList matchedTargetList;
        QStringList matchRuleList;
        std::size_t matchCount = 0U;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockHandleCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        std::uint64_t handleValue = 0U;
        std::uint32_t grantedAccess = 0U;
        QString matchedTargetPath;
        bool matchedByDirectoryRule = false;
        QString matchRuleText;
        QString objectName;
        QString enumerationSource;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockSelectionResult
    {
        bool accepted = false;
        UnlockOperationMode operationMode = UnlockOperationMode::kCloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
    };

    // UnlockSelectionSharedState：
    // - Purpose: Pass unlocker selection results between the thread and UI queue.
    // - Note: Managed by shared_ptr to prevent UI callbacks in the queue from accessing released stack variables when FileDock is destructed.
    struct UnlockSelectionSharedState
    {
        std::mutex mutex;                         // mutex: Mutex protecting completed and result.
        std::condition_variable condition;        // condition: notifies the background thread that the UI selection is complete.
        bool completed = false;                   // completed: Marks whether the UI selection process has written results.
        UnlockSelectionResult result;             // result: Stores the user-selected operation mode and handle/PID target.
    };

    struct FileIntegrityLevelPreset
    {
        DWORD rid;              // rid: The last RID of the S-1-16-* Mandatory Label.
        const char* nameText;   // nameText: Stable English name used in menus and logs.
        const char* detailText; // detailText: Chinese explanation for end users.
    };

    inline const FileIntegrityLevelPreset kFileIntegrityLevelPresets[] =
    {
        { SECURITY_MANDATORY_UNTRUSTED_RID, "Untrusted", "不受信任完整性" },
        { SECURITY_MANDATORY_LOW_RID, "Low", "低完整性" },
        { SECURITY_MANDATORY_MEDIUM_RID, "Medium", "中完整性" },
        { SECURITY_MANDATORY_MEDIUM_PLUS_RID, "MediumPlus", "中高完整性" },
        { SECURITY_MANDATORY_HIGH_RID, "High", "高完整性" },
        { SECURITY_MANDATORY_SYSTEM_RID, "System", "系统完整性" }
    };

    // QueryNtQueryInformationFilePtr: Dynamically resolve NtQueryInformationFile
    // to avoid FileDock requiring additional user-mode module dependencies.
    using NtQueryInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

    // FileVolumeAuditSnapshot: A lightweight read-only model summarizing volume, storage, and BitLocker status.
    struct FileVolumeAuditSnapshot
    {
        QString volumeRoot;
        QString mountPointsText;
        QString devicePathText;
        QString fsNameText;
        QString labelText;
        QString storageText;
        QString bitLockerText;
        QString volumeStackText;
        QString filterText;
    };

    // reparseKindMarkerForBatch:
    // - For querying reparse point markers used during tiled model batch population.
    // - The difference from reparseKindMarkerForPath is the **limit**: the batch fill-back performs
    //   at most kMaxBatchReparseProbes synchronous queries; beyond this limit, all return empty.
    // Why limit is required:
    // - Each line requires GetFileAttributesW; reparse point lines additionally
    //   open the file to issue FSCTL. All are synchronous file I/O on the UI thread.
    // - R0/IRP read methods are originally intended to identify paths where the "WinAPI perspective is flawed";
    //   for such paths, Win32 queries may block for a long time or even hang, freezing the entire interface.
    // - Even if each line takes only tens of microseconds, a directory with tens of thousands of lines can accumulate to second-level lag.
    // The cost is that lines exceeding the limit do not display reparse point markers, which is far better than the UI becoming unresponsive.
    inline constexpr int kMaxBatchReparseProbes = 512;

    QString reparseKindMarkerForPath(const QString& path);

    class ReparseAwareFileSystemModel final : public QFileSystemModel
    {
    public:
        explicit ReparseAwareFileSystemModel(QObject* parent = nullptr)
            : QFileSystemModel(parent)
        {
        }

        QVariant data(const QModelIndex& index, const int role = Qt::DisplayRole) const override
        {
            const QVariant kBaseValue = QFileSystemModel::data(index, role);
            if (!index.isValid())
            {
                return kBaseValue;
            }

            if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
            {
                return kBaseValue;
            }

            QVariant localizedBaseValue = kBaseValue;
            if (role == Qt::DisplayRole &&
                (index.column() == 1 || index.column() == 2) &&
                kBaseValue.metaType().id() == QMetaType::QString)
            {
                localizedBaseValue = ks::i18n::displayText(kBaseValue.toString());
            }

            const QString kMarkerText = reparseKindMarkerForPath(filePath(index));
            if (kMarkerText.isEmpty())
            {
                return localizedBaseValue;
            }
            const QString kLocalizedMarkerText = ks::i18n::displayText(kMarkerText);

            if (role == Qt::ToolTipRole)
            {
                QString toolTipText = kBaseValue.toString();
                if (!toolTipText.isEmpty())
                {
                    toolTipText += QLatin1Char('\n');
                }
                toolTipText += ks::i18n::displayText(QStringLiteral("重解析点: %1"))
                    .arg(kLocalizedMarkerText);
                return toolTipText;
            }

            if (index.column() == 0)
            {
                return QStringLiteral("%1 [%2]").arg(kBaseValue.toString(), kLocalizedMarkerText);
            }
            if (index.column() == 2)
            {
                const QString kTypeText = localizedBaseValue.toString().trimmed();
                return kTypeText.isEmpty()
                    ? kLocalizedMarkerText
                    : QStringLiteral("%1 / %2").arg(kLocalizedMarkerText, kTypeText);
            }
            return localizedBaseValue;
        }

        QVariant headerData(
            const int section,
            const Qt::Orientation orientation,
            const int role = Qt::DisplayRole) const override
        {
            const QVariant kBaseValue = QFileSystemModel::headerData(section, orientation, role);
            if (orientation == Qt::Horizontal
                && role == Qt::DisplayRole
                && kBaseValue.metaType().id() == QMetaType::QString)
            {
                return ks::i18n::displayText(kBaseValue.toString());
            }
            return kBaseValue;
        }
    };

    // ============================================================
    // Multi-permission recursive deletion (issue #155)
    // - All seven levels share the same "post-order expansion + item-by-item deletion" semantics; differences lie only in permissions and backend mechanisms.
    // - R0 files are preferred to be unwound internally by the driver to prevent R3 enumeration from being denied by directory DACLs;
    // ============================================================

    // FileDeleteBatchStats: Statistics and failure details for a batch of deletions.
    struct FileDeleteBatchStats
    {
        std::uint64_t recycledCount = 0U;            // Number of items successfully moved to recycle bin.
        std::uint64_t deletedFileCount = 0U;         // Count of permanently deleted files.
        std::uint64_t deletedDirectoryCount = 0U;    // Count of permanently deleted directories.
        std::uint64_t pendingRebootCount = 0U;       // Count of items registered for deletion after reboot.
        std::uint64_t failedCount = 0U;              // Number of failed items.
        std::uint64_t skippedReparseCount = 0U;      // Only the link itself is deleted; reparse points for the target are not followed up.
        std::uint64_t permissionRepairCount = 0U;    // Count of items that triggered 'take ownership + grant permission'.
        bool driverUnavailable = false;              // R0: Driver device cannot be opened.
        bool driverRecursionUnsupported = false;     // R0 mode: Older drivers do not support kernel recursion; fell back to R3 unwind.
        QStringList errors;                          // Failure details, used for logging and prompts.
        QStringList permanentlyDeleted;              // Items in the Recycle Bin demoted to permanent deletion.
    };

    // Manual parsing model column definitions: Name / Size / Type / Modified Time / Full Path / Is Directory.
    enum class ManualModelColumn : int
    {
        kName = 0,
        kSize = 1,
        kType = 2,
        kModifiedTime = 3,
        kFullPath = 4,
        kIsDirectory = 5,
        kCount = 6
    };

    // g_preferPlainTextReportView:
    // - Remember the user's last selected view so that newly opened pages use the same selection.
    // - Valid only in-process and not persisted to disk: this represents 'how I want to view this investigation session', not a preference to be saved long-term.
    extern bool gPreferPlainTextReportView;

    struct FileSecurityAceRow
    {
        QString scopeText;       // scopeText: ACE source scope, currently mainly DACL/SACL.
        QString typeText;        // typeText: ACE type text, e.g., ACCESS_ALLOWED.
        QString flagsText;       // flagsText: Inheritance/audit flag text.
        DWORD mask = 0;          // mask: Original access mask, used for display and subsequent edit location.
        QString rightsText;      // rightsText: Common file permission names derived from the mask.
        QString sidText;         // sidText: string SID, for stable identification.
        QString accountText;     // accountText: Account name resolved by LookupAccountSidW.
        DWORD aceIndex = 0;      // aceIndex: ACE index within the ACL.
        bool canEdit = false;    // canEdit: Whether the current UI allows delete/replace operations on this ACE.
    };

    struct FileSecuritySnapshot
    {
        bool descriptorOk = false;        // descriptorOk: Whether Owner/Group/DACL was read successfully.
        bool saclOk = false;              // saclOk: Whether the SACL was read successfully.
        DWORD descriptorError = ERROR_SUCCESS; // descriptorError: Win32 error code when reading Owner/Group/DACL.
        DWORD saclError = ERROR_SUCCESS;       // saclError: Win32 error code for reading SACL.
        QString ownerSidText;             // ownerSidText: Owner SID string.
        QString ownerAccountText;         // ownerAccountText: Owner account text.
        QString groupSidText;             // groupSidText: Primary Group SID string.
        QString groupAccountText;         // groupAccountText: Primary Group account text.
        QString detailText;               // detailText: Full text details compatible with older versions; retains errors even if reading fails.
        std::vector<FileSecurityAceRow> aceRows; // aceRows: Table-formatted ACE list.
    };

    // kRecoveryVolumeProbeGenerationProperty:
    // - Purpose: Records 'which volume probe request this is' and attaches it as a dynamic property to the volume dropdown on the recovery page;
    // - Input: None (used as a key for QObject::property/setProperty);
    // - Returns: None. It is not stored as a FileDock member to retain the ability
    //   to evict old results superseded by new requests without modifying FileDock.h.
    inline constexpr const char* const kRecoveryVolumeProbeGenerationProperty =
        "ks_recovery_volume_probe_generation";

    // kFileDeleteInProgressProperty:
    // - Purpose: Marks 'deletion task in progress' as a dynamic property on FileDock.
    // - Input: None (used as a key for QObject::property/setProperty);
    // - Return: None. Semantics match m_transferInProgress; used solely to prevent reentrancy.
    inline constexpr const char* const kFileDeleteInProgressProperty = "ks_file_delete_in_progress";

    bool isDeletedFileSafelyRecoverable(
        const ks::file::NtfsDeletedFileEntry& entryValue);

    QString deletedFileRecoveryCapabilityText(
        const ks::file::NtfsDeletedFileEntry& entryValue);

    QString localVolumeRootForPath(const QString& pathText);

    QString safeRecoveryFileName(const QString& requestedFileName);

    QString uniqueRecoveryTargetPath(
        const QString& outputDirectory,
        const QString& requestedFileName,
        const std::uint64_t fileReference,
        QSet<QString>& reservedPathSet);

    bool isSupportedFileMandatoryIntegrityRid(const DWORD integrityRid);

    QString formatFileWin32Error(const QString& stepText, const DWORD errorCode);

    bool enableFileContextPrivilege(const wchar_t* privilegeName);

    bool allocateFileMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        QString* detailText);

    QString fileIntegrityNameFromRid(const DWORD integrityRid);

    bool queryFileIntegrityRid(
        const QString& filePath,
        DWORD* ridOut,
        bool* implicitMediumOut,
        QString* detailText);

    DWORD setFileIntegrityLevelByPath(
        const QString& filePath,
        const DWORD integrityRid,
        QString* detailText);

    QWidget* resolveVisibleDialogParent(QWidget* const preferredParent);

    int calculateFileStandaloneWindowMaxWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth);

    void applyFileStandaloneWindowWidthLimit(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const double ratio);

    QString unlockOperationModeToText(const UnlockOperationMode mode);

    QString formatHandleValueText(const std::uint64_t handleValue);

    void appendUniqueText(QStringList& list, const QString& text);

    QString volumePathFromAnyPath(const QString& pathText);

    QString buildMountPointsText(const QString& volumeRoot);

    QString buildVolumeDevicePathText(const QString& volumeRoot);

    QString buildVolumeInfoText(const QString& volumeRoot);

    bool queryVolumeLabelAndFileSystemText(
        const QString& volumeRoot,
        QString& labelOut,
        QString& fileSystemOut);

    QString buildStorageDescriptorText(const QString& volumeRoot);

    QString buildVolumeStackText(
        const QString& volumeRoot,
        const QString& devicePathText,
        const QString& fsText,
        const QString& mountPointsText);

    QString buildBitLockerStatusText(const QString& volumeRoot);

    FileVolumeAuditSnapshot queryFileVolumeAuditSnapshot(const QString& filePath);

    HANDLE openReadOnlyFileHandle(const QString& pathText, const bool directoryHint);

    bool queryFileStandardInfoText(
        HANDLE fileHandle,
        QString& detailsOut,
        QString& statusOut);

    QWidget* createReadOnlyAuditTextPage(QWidget* parent, const QString& content);

    QString readUtf16FieldAtOffset(
        const void* buffer,
        const std::size_t bytesReturned,
        const USHORT fieldOffset,
        const USHORT fieldLength);

    QString filterFilesystemTypeToText(const FLT_FILESYSTEM_TYPE filesystemType);

    void appendMinifilterRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned);

    QString enumerateMinifilterText();

    void appendInstanceRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned);

    QString enumerateInstanceText();

    void appendVolumeRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned);

    QString enumerateVolumeText();

    QString queryBitLockerVolumeText(const QString& driveLetter);

    bool isCriticalProcessName(const QString& processName);

    bool isPathReparsePoint(const QString& path);

    QString formatWin32ErrorText(const std::uint32_t errorCode);

    QString formatReparseTagText(const std::uint32_t tagValue);

    ks::file::ReparsePointQueryResult queryReparsePointForUi(const QString& path);

    QString reparseKindMarkerForPath(const QString& path);

    QString reparseTargetFromResult(const ks::file::ReparsePointQueryResult& result);

    QString formatReparsePointText(const QString& path);

    QString buildDriverNtPath(const QString& path);

    QString buildLiteralNameFilterPattern(const QString& keywordText);

    QString queryShortPathText(const QString& path);

    QString normalizeFileDockPath(const QString& path);

    bool pathEqualsCaseInsensitive(const QString& left, const QString& right);

    void closeWin32Handle(HANDLE& handleValue);

    QString oplockCompletionText(const bool completionOk, const unsigned long completionError);

    ksword::ark::DriverHandle openKswordArkDriverHandle(std::string* const detailTextOut);

    bool deletePathByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const QString& path,
        const bool isDirectory,
        std::string* const detailTextOut);

    bool shouldFallbackFileIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported);

    DWORD setFileIntegrityLevelByR0ThenR3(
        const QString& filePath,
        const DWORD integrityRid,
        QString* const detailText);

    bool terminateProcessByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const std::uint32_t processId,
        std::string* const detailTextOut);

    bool terminateProcessByR3(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime,
        std::string* const detailTextOut);

    UnlockSelectionResult showUnlockSelectionDialog(
        QWidget* const parent,
        const std::vector<UnlockProcessCandidate>& processCandidateList,
        const std::vector<UnlockHandleCandidate>& handleCandidateList);

    std::vector<std::uint32_t> collectOccupyProcessIdsByPath(
        const QString& path,
        QStringList* const detailTextListOut);

    bool appendDriverDeleteTargetsPostOrder(
        const QString& rootPath,
        std::vector<DriverDeleteTarget>& targetsOut,
        QString& errorTextOut,
        const bool repairPermissionBeforeEnumerate = false);

    bool clearDeleteBlockingAttributes(const QString& path);

    PSID allocateBuiltinAdministratorsSid();

    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        const bool isDirectory,
        QString* const detailTextOut);

    bool removeSinglePathByWin32(
        const QString& path,
        const bool isDirectory,
        DWORD* const lastErrorOut);

    bool schedulePathDeleteOnReboot(const QString& path, DWORD* const lastErrorOut);

    bool deleteExpandedTargetByR3(
        const DriverDeleteTarget& target,
        const bool allowPermissionRepair,
        bool* const permissionRepairedOut,
        QString* const errorTextOut);

    std::vector<DriverDeleteTarget> expandDeleteTargetsForBatch(
        const std::vector<QString>& paths,
        const bool repairPermissionWhileExpanding,
        FileDeleteBatchStats& statsInOut);

    void appendDriverDeleteFailureDetail(
        const QString& path,
        const bool isDirectory,
        const QString& baseDetailText,
        FileDeleteBatchStats& statsInOut);

    void deleteTreeByDriverPerNode(
        ksword::ark::DriverHandle& driverHandle,
        const QString& rootPath,
        FileDeleteBatchStats& statsInOut);

    QString describeDriverDeleteResponse(
        const QString& path,
        const ksword::ark::DeletePathResult& driverResult);

    FileDeleteBatchStats runDriverDeleteBatch(
        const std::vector<QString>& paths,
        const ksword::ark::FileDeleteBackend backend,
        const std::function<void(float)>& progressCallback);

    FileDeleteBatchStats runFileDeleteBatch(
        const std::vector<QString>& paths,
        const FileDeleteMode mode,
        const std::function<void(float)>& progressCallback);

    QString manualFsTypeToText(const ks::file::ManualFsType fsType);

    void markSuspiciousRowIfNeeded(
        const QList<QStandardItem*>& rowItems,
        const QString& entryName,
        const QSet<QString>& suspiciousNameSet);

    QSet<QString> buildSuspiciousNameSet(const QStringList& names);

    QString buildBlueButtonStyle();

    QString buildBlueInputStyle();

    QString buildContextMenuStyle();

    void installFileTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn = -1);

    void installFileTreeCopyMenu(QTreeWidget* treeWidget, const int processIdColumn);

    QString propertyTreeToPlainText(const QTreeWidget* treeWidget);

    void installPropertyTreeCopyMenu(QTreeWidget* treeWidget);

    QTreeWidgetItem* appendPropertyGroup(QTreeWidget* tree, const QString& titleText);

    QTreeWidgetItem* appendPropertyRow(
        QTreeWidgetItem* groupItem,
        const QString& nameText,
        const QString& valueText);

    void configurePropertyTree(QTreeWidget* treeWidget);

    QWidget* buildSwitchableView(
        QWidget* parent,
        QTreeWidget* propertyTree,
        CodeEditorWidget* textEditor);

    QWidget* buildReportView(QWidget* parent, const QString& reportText);

    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName);

    QPalette buildFileDetailDialogPalette(const QWidget* const fallbackWidget);

    void applyFileDetailSurfacePalette(QWidget* const widget, const QPalette& palette);

    QString buildFileDetailDialogStyle();

    QString buildLogPreviewText(const QStringList& sourceLines, const int maxLineCount = 8);

    QString buildBreadcrumbButtonStyle();

    bool copyDirectoryRecursively(const QString& sourcePath, const QString& targetPath, QString& errorTextOut);

    bool copyFileTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut);

    QString uniqueSiblingTransactionPath(const QString& targetPath, const QString& roleText);

    bool removeTransactionPath(const QString& path);

    bool copyDirectoryTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut);

    bool runCommandCaptureText(const QString& commandText, QString& outputTextOut, int& exitCodeOut);

    bool openCommandPromptInDirectory(const QString& workPath, DWORD* const errorCodeOut);

    bool takeOwnershipBySystemCommand(const QString& targetPath, QString& detailTextOut);

    QString sidUseToText(const SID_NAME_USE sidUse);

    QString sidToStringText(PSID sidValue);

    QString sidToAccountText(PSID sidValue);

    QString aceTypeToText(const BYTE aceType);

    QString aceFlagsToText(const BYTE aceFlags);

    QString accessMaskToText(const DWORD accessMask);

    void appendAclRows(const QString& scopeText, PACL aclValue, std::vector<FileSecurityAceRow>& rowsOut);

    QTableWidgetItem* createReadonlyTableItem(const QString& cellText);

    QString formatAccessMaskHex(const DWORD accessMask);

    void appendAclText(const QString& titleText, PACL aclValue, QString& contentOut);

    QVector<QString> collectNtfsVolumeRootList();
}
