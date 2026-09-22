#pragma once

// ============================================================
// SoundSourcePage.h
// Purpose:
// 1) Provide a global view for 'Misc -> Sound Source'.
// 2) Reuse in PID filter mode for the process detail page.
// 3) Refresh asynchronously while retaining a short-term history of 'recently sounding' sources.
// ============================================================

#include "../../Framework.h"
#include "SoundSourceDetector.h"

#include <QHash>
#include <QWidget>

#include <cstdint>
#include <vector>

class QButtonGroup;
class QCheckBox;
class QEvent;
class QLabel;
class QShowEvent;
class QHideEvent;
class QTableWidget;
class QTimer;
class QToolButton;
class QPoint;

namespace ks::misc
{
    class SoundSourcePage final : public QWidget
    {
        Q_OBJECT

    public:
        // Constructor:
        // - When processIdFilter=0, displays all system output audio sessions;
        // - When processIdFilter != 0, only show the process detail page corresponding to that PID.
        // - The page automatically refreshes after display and stops the timer after hiding.
        explicit SoundSourcePage(
            std::uint32_t processIdFilter = 0,
            std::uint64_t expectedCreationTime100ns = 0,
            QWidget* parent = nullptr);
        ~SoundSourcePage() override = default;

    protected:
        // showEvent/hideEvent: Perform periodic sampling only when the page is visible to avoid background resident scanning.
        void showEvent(QShowEvent* event) override;
        void hideEvent(QHideEvent* event) override;
        void changeEvent(QEvent* event) override;

    private:
        enum class ColumnPreset
        {
            kOverview,
            kAudioPath,
            kKernelEvidence,
            kCustom
        };

        // initializeUi: Creates title, toolbar, A/B/C column group buttons, and result table.
        void initializeUi();
        // initializeConnections: Manual/automatic refresh, column groups, and header menus.
        void initializeConnections();
        // requestRefresh: Queue a single background Core Audio scan plus optional R0 detection.
        void requestRefresh(bool manualRequest);
        // applyScanResult: validates the ticket on the UI thread before merging results with the recent sound history.
        void applyScanResult(
            std::uint64_t ticket,
            const SoundSourceScanResult& result);
        // mergeRecentHistory: Retain transient sound sources to prevent them from disappearing immediately after a refresh.
        void mergeRecentHistory(std::vector<SoundSourceRecord>& records);
        // rebuildTable: Rebuilds the table based on the current silent filter and column groups.
        void rebuildTable();
        // updateSummary: Refresh the top-level conclusion and status based on the current cache.
        void updateSummary(const SoundSourceScanResult& result);
        // applyColumnPreset: Applies complementary Overview/Audio Link/R0 Evidence simplified column groups.
        void applyColumnPreset(ColumnPreset preset);
        // showHeaderContextMenu: Allows users to customize column visibility individually and clears A/B/C selection states.
        void showHeaderContextMenu(const QPoint& position);
        // setCustomColumnLayout: Switches the column group buttons to the 'custom column layout' state.
        void setCustomColumnLayout();
        // applyThemeStyle: Synchronizes button, table, and status colors for both light and dark themes.
        void applyThemeStyle();
        // recordKey: Returns a stable key composed of endpoint + session instance.
        QString recordKey(const SoundSourceRecord& record) const;

    private:
        std::uint32_t processIdFilter_ = 0;          // 0 = global, other values = process-specific scope.
        std::uint64_t expectedCreationTime100ns_ = 0; // Creation time corresponding to the process detail PID.
        QLabel* titleLabel_ = nullptr;               // Page title.
        QLabel* explanationLabel_ = nullptr;         // R3/R0 evidence boundary explanation.
        QLabel* summaryLabel_ = nullptr;             // Current / recent sound summary.
        QLabel* statusLabel_ = nullptr;              // Refresh, downgrade, and error states.
        QToolButton* refreshButton_ = nullptr;       // Iconify the manual refresh button.
        QCheckBox* autoRefreshCheck_ = nullptr;      // Auto-refresh toggle.
        QCheckBox* showSilentCheck_ = nullptr;       // Whether to display all silent sessions.
        QButtonGroup* columnPresetGroup_ = nullptr;  // Mutually exclusive column group A/B/C.
        QToolButton* overviewPresetButton_ = nullptr; // A: Overview column group.
        QToolButton* audioPresetButton_ = nullptr;    // B: Audio link column group.
        QToolButton* kernelPresetButton_ = nullptr;   // C: R0 evidence column group.
        QTableWidget* table_ = nullptr;               // Sound source result table.
        QTimer* refreshTimer_ = nullptr;               // Auto-refresh timer when the page is visible.
        std::vector<SoundSourceRecord> records_;       // Cache merging the most recent session with history.
        QHash<QString, SoundSourceRecord> recentRecords_; // Records recently confirmed to produce sound.
        bool refreshing_ = false;                      // Prevent concurrent re-entrant refresh.
        bool autoKernelProbeEnabled_ = true;           // Auto-refresh after R0 unavailability is R3-only.
        std::uint64_t refreshTicket_ = 0;              // Prevent old background results from overwriting new page state.
        ColumnPreset columnPreset_ = ColumnPreset::kOverview; // Current column layout.
    };
}
