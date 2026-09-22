#pragma once

#include "DiskDeletedEntryForensics.h"
#include "DiskFileSystemForensics.h"
#include "DiskRawFileSystemBrowser.h"

#include <QWidget>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QAction;
class QToolButton;

namespace ks::misc
{
    struct DiskForensicsSelection
    {
        int diskIndex = -1;
        unsigned long backend = 1UL;
        std::uint64_t partitionOffset = 0;
        std::uint64_t partitionLength = 0;
        std::uint32_t logicalSectorSize = 512U;
        std::uint32_t backendMask = 1U;
        std::uint32_t capabilityFlags = 0U;
        QString displayText;
    };

    class DiskFileSystemForensicsPanel final : public QWidget
    {
    public:
        using SelectionProvider =
            std::function<std::optional<DiskForensicsSelection>()>;
        using JumpCallback = std::function<void(std::uint64_t)>;

        DiskFileSystemForensicsPanel(
            SelectionProvider selectionProvider,
            JumpCallback jumpCallback,
            QWidget* parent = nullptr);

    private:
        void initializeUi();
        void initializeConnections();
        void probeCurrentPartition();
        void resolveCurrentFile();
        void reverseLookupCurrentCluster();
        void scanDeletedEntries();
        void eraseSelectedDeletedEntry();
        void browseRawDirectory();
        void previewSelectedRawFile();
        void exportSelectedRawFile();
        void analyzeSelectedRawPe();
        void applyProbeResult(
            DiskForensicsSelection selection,
            FileSystemProbeResult result);
        void applyExtentResult(FileExtentResult result);
        void applyReverseResult(ReverseClusterResult result);
        void applyDeletedResult(
            DiskForensicsSelection selection,
            DeletedEntryScanResult result);
        void applyEraseResult(ExtentEraseResult result);
        void applyRawDirectoryResult(
            DiskForensicsSelection selection,
            RawDirectoryResult result);
        void applyRawReadResult(RawFileReadResult result);
        void applyRawExportResult(RawFileExportResult result);

        SelectionProvider selectionProvider_;
        JumpCallback jumpCallback_;
        QPushButton* probeButton_ = nullptr;
        QLabel* probeSummaryLabel_ = nullptr;
        QTableWidget* probeTable_ = nullptr;
        QLineEdit* rawPathEdit_ = nullptr;
        QPushButton* rawUpButton_ = nullptr;
        QPushButton* rawListButton_ = nullptr;
        QPushButton* rawPreviewButton_ = nullptr;
        QPushButton* rawExportButton_ = nullptr;
        QToolButton* rawMoreButton_ = nullptr;
        QAction* rawPeAction_ = nullptr;
        QLabel* rawSummaryLabel_ = nullptr;
        QTableWidget* rawTable_ = nullptr;
        QLineEdit* filePathEdit_ = nullptr;
        QPushButton* fileBrowseButton_ = nullptr;
        QPushButton* extentButton_ = nullptr;
        QTableWidget* extentTable_ = nullptr;
        QLineEdit* volumePathEdit_ = nullptr;
        QLineEdit* clusterEdit_ = nullptr;
        QPushButton* reverseButton_ = nullptr;
        QTableWidget* reverseTable_ = nullptr;
        QPushButton* deletedScanButton_ = nullptr;
        QPushButton* deletedEraseButton_ = nullptr;
        QLabel* deletedSummaryLabel_ = nullptr;
        QTableWidget* deletedTable_ = nullptr;
        std::optional<DiskForensicsSelection> deletedSelection_;
        std::vector<DeletedDirectoryEntry> deletedEntries_;
        std::optional<DiskForensicsSelection> rawSelection_;
        ForensicFileSystemKind rawFileSystem_ =
            ForensicFileSystemKind::kUnknown;
        std::vector<RawFileEntry> rawEntries_;
        bool busy_ = false;
    };
}
