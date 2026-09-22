#pragma once

// ============================================================
// VirtualLocationPage.h
// Purpose:
// 1) Provide a virtual location entry point under 'Miscellaneous' to set arbitrary coordinates as the Windows system default location;
// 2) Displays location services, privacy toggles, and group policies, explaining under what conditions virtual coordinates are accepted.
// 3) Support input interchange and preset points for WGS-84 / GCJ-02 / BD-09 to avoid manual conversion.
// 4) Provides real-time location readings for before-and-after application comparison, with immediate re-read validation after writing.
// ============================================================

#include "VirtualLocationBackend.h"

#include "../../Framework.h"

#include <QWidget>

class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QShowEvent;

namespace ks::misc
{
    // VirtualLocationPage：
    // - Purpose: Virtual location page; all system modifications are applied to the registry and can be cleared with a single click at any time.
    // - Note: The page performs no injection or API hooks; it only affects callers that utilize the Windows location service.
    class VirtualLocationPage final : public QWidget
    {
    public:
        // Constructor: builds only the UI without accessing the registry to avoid triggering a system query when opening 'Misc'.
        explicit VirtualLocationPage(QWidget* parent = nullptr);
        ~VirtualLocationPage() override = default;

    protected:
        // Read system state only once when the page becomes truly visible for the first time.
        void showEvent(QShowEvent* event) override;
        // Semantic colors (Warning and its background) have no palette equivalent in theme.h; embedding them in QSS locks them
        // to the theme at the moment of distribution, whereas text color in the same style block is a dynamic palette(text).
        // If the theme switch does not re-issue the banner, it will appear with a dark background and black text or a light background and white text.
        void changeEvent(QEvent* event) override;

    private:
        // initializeUi: builds the description, status area, coordinate input area, and operation area.
        void initializeUi();
        // applyScopeBannerStyle: Apply scope banner style; shared during construction and theme switching.
        void applyScopeBannerStyle();
        // initializeConnections: Bind buttons, dropdowns, and numeric fields to their respective handlers.
        void initializeConnections();

        // refreshStatus: Synchronously read the location service status and current default location, then refresh to the UI.
        void refreshStatus();
        // applyVirtualLocation: Convert input coordinates to WGS-84, write to the default location, and immediately re-read to verify.
        void applyVirtualLocation();
        // clearVirtualLocation: Clears the five values of the default location, restoring the system to an unset state.
        void clearVirtualLocation();
        // toggleProviderPolicy: Write or delete DisableWindowsLocationProvider based on checkbox state.
        void toggleProviderPolicy(bool disabled);
        // restartLocationService: Stop lfsvc, discard cache, and force the next location lookup to retrieve the default position.
        void restartLocationService();
        // requestLiveFix: Requests a location update from WinRT on a background thread; if fillInputs is true, populates the input fields with the result.
        void requestLiveFix(bool fillInputs);
        // applyLiveFixResult: consolidate live location results on the UI thread.
        void applyLiveFixResult(
            const virtual_location::LiveFixResult& fixResult,
            bool fillInputs);

        // applyPreset: Convert preset points using the current coordinate system and fill them into the input fields.
        void applyPreset(int presetIndex);
        // updateConversionPreview: Display readings for the same location across three coordinate systems.
        void updateConversionPreview();

        // currentCoordinateSystem: Retrieves the currently selected coordinate system from the dropdown.
        virtual_location::CoordinateSystem currentCoordinateSystem() const;
        // inputCoordinate: Assembles the four input fields into a coordinate in the current coordinate system.
        virtual_location::GeoCoordinate inputCoordinate() const;
        // setInputCoordinate: Fill the input box with values based on the current coordinate system, suppressing signals during the process to avoid repeated conversions.
        void setInputCoordinate(const virtual_location::GeoCoordinate& coordinate);

        // setResultText: writes the conclusion of an operation to the bottom; isError determines the color scheme.
        void setResultText(const QString& text, bool isError);
        // setBusy: Disable buttons while a synchronous operation is in progress to prevent repeated clicks.
        void setBusy(bool busy);
        // updateButtons: Refreshes button availability based on busy status and current system state.
        void updateButtons();

    private:
        QLabel* scopeLabel_ = nullptr;            // m_scopeLabel: Scope and limitation description.
        QLabel* serviceLabel_ = nullptr;          // m_serviceLabel: Location service and privacy switch status.
        QLabel* policyLabel_ = nullptr;           // m_policyLabel: Location-related group policy status.
        QLabel* currentLocationLabel_ = nullptr;  // m_currentLocationLabel: Current system default location reading.
        QLabel* conversionLabel_ = nullptr;       // m_conversionLabel: Preview of conversions among three coordinate systems.
        QLabel* liveFixLabel_ = nullptr;          // m_liveFixLabel: The result from the most recent live location fix.
        QLabel* resultLabel_ = nullptr;           // m_resultLabel: Conclusion of the most recent operation.
        QPlainTextEdit* rawValueEdit_ = nullptr;  // m_rawValueEdit: Raw value list under the default location key.
        QComboBox* coordinateSystemCombo_ = nullptr; // m_coordinateSystemCombo: Coordinate system for input coordinates.
        QComboBox* presetCombo_ = nullptr;        // m_presetCombo: Built-in preset coordinate points.
        QDoubleSpinBox* latitudeSpin_ = nullptr;  // m_latitudeSpin: Latitude input.
        QDoubleSpinBox* longitudeSpin_ = nullptr; // m_longitudeSpin: Longitude input.
        QDoubleSpinBox* altitudeSpin_ = nullptr;  // m_altitudeSpin: Altitude input.
        QDoubleSpinBox* accuracySpin_ = nullptr;  // m_accuracySpin: Error radius input.
        QCheckBox* forceProviderCheck_ = nullptr; // m_forceProviderCheck: Whether to disable the Windows location provider.
        QPushButton* refreshButton_ = nullptr;    // m_refreshButton: Re-read system status.
        QPushButton* liveFixButton_ = nullptr;    // m_liveFixButton: Reads the system's live location once.
        QPushButton* useLiveFixButton_ = nullptr; // m_useLiveFixButton: Read live location once and fill back the input.
        QPushButton* applyButton_ = nullptr;      // m_applyButton: Write virtual location.
        QPushButton* clearButton_ = nullptr;      // m_clearButton: Clear virtual location.
        QPushButton* restartServiceButton_ = nullptr; // m_restartServiceButton: Button to restart the location service and clear the cache.

        int lastCoordinateSystemIndex_ = 0;       // m_lastCoordinateSystemIndex: The last selected coordinate system, used for conversion during switching.
        bool busy_ = false;                       // m_busy: Synchronous operation in progress.
        bool liveFixRunning_ = false;             // m_liveFixRunning: Background live fix in progress.
        bool updatingInputs_ = false;             // m_updatingInputs: Programmatically populating input fields.
        bool defaultLocationPresent_ = false;     // m_defaultLocationPresent: Whether a default location currently exists in the system.
        bool providerDisabled_ = false;           // m_providerDisabled: Whether the location provider is currently disabled by Group Policy.
    };
}
