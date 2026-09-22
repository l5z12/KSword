#pragma once

#include "AppearanceSettings.h"

#include <QWidget>

class QButtonGroup;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSlider;
class QSpinBox;
class QTabWidget;
class QToolButton;
class QVBoxLayout;

class SettingsDock : public QWidget
{
    Q_OBJECT

public:
    // Constructor purpose:
    // - initialize the 'Settings' tab container.
    // - Load appearance JSON configuration and synchronize with the UI.
    // - Emit signal for external appearance setting changes.
    // Invocation: Called automatically when mainWindow creates SettingsDock.
    // Input parent: Qt parent object pointer.
    explicit SettingsDock(QWidget* parent = nullptr);

    // applySettings purpose: Saves current settings and emits a change signal; called by the dialog's fixed action bar.
    void applySettings();

    // currentAppearanceSettings:
    // - Returns a snapshot of the current appearance settings in memory.
    // Usage: Read default settings once during mainWindow initialization.
    // Return: A copy of the AppearanceSettings configuration structure.
    ks::settings::AppearanceSettings currentAppearanceSettings() const;

    // showLanguageSettingsTab: Switches to the 'Language' tab for invocation by the welcome page shortcut.
    void showLanguageSettingsTab();

protected:
    void changeEvent(QEvent* event) override;

signals:
    // appearanceSettingsChanged:
    // - Notify the main window when the user clicks 'Apply' and the save succeeds.
    // - Theme/background applies immediately; startup-related options apply on next launch.
    // Invocation: Emit after internal save succeeds.
    // Input settings: latest UI and startup configuration.
    void appearanceSettingsChanged(const ks::settings::AppearanceSettings& settings);

    // pendingChangesChanged: Synchronizes the enabled state of the fixed 'Apply' button in the dialog.
    void pendingChangesChanged(bool hasPendingChanges);

    // bugcheckDiagnosticsAutoInstallChanged: Notifies the main window to update the display status of the currently loaded configuration and page entry.
    void bugcheckDiagnosticsAutoInstallChanged(bool enabled);

    // bugcheckDiagnosticsInstalledForSession purpose: Display the blue screen diagnostic entry and upload runtime resources after this installation completes.
    void bugcheckDiagnosticsInstalledForSession();

    // bugcheckDiagnosticsInstallationStarted purpose: Immediately display the entry point upon user request for this installation, facilitating status checks and failure diagnosis.
    void bugcheckDiagnosticsInstallationStarted();

private:
    // initializeUi:
    // - Constructs the root layout and tab container for SettingsDock.
    // Invocation: Called within the constructor.
    void initializeUi();

    // initializeAppearanceTab:
    // - Create three tab controls for 'Appearance', 'Language', and 'Startup', and maintain a unified save logic.
    // Invocation: called internally by initializeUi.
    void initializeAppearanceTab();

    // initializeFeaturesTab:
    // - Create the 'Features' tab to host runtime behavior switches such as R0 feature hints.
    // - Controls follow the unified 'Apply' save flow.
    // Usage: Call after initializeAppearanceTab and before reading the configuration.
    void initializeFeaturesTab();

    // initializeOnlineScanTab:
    // - Create the 'Online Scan' tab control (input and save buttons for VirusTotal/ThreatBook API Key).
    // Invocation: Called after initializeUi and before reading configuration.
    // Returns: Nothing.
    void initializeOnlineScanTab();

    // initializeBugcheckDiagnosticsControls: Add three configurable Blue Screen diagnostics operations to the 'Features' tab.
    // Invocation: Called after initializeFeaturesTab creates the existing groups.
    // Input parameter featuresRootLayout: The root layout of the feature page; must not be null. Return: None.
    void initializeBugcheckDiagnosticsControls(QVBoxLayout* featuresRootLayout);

    // refreshBugcheckDiagnosticsStatusText: Refreshes the status text based on persistent configuration and the current asynchronous operation state.
    // Invocation: Called during initialization, configuration save, installation completion, and language switch; parameters: none.
    void refreshBugcheckDiagnosticsStatusText();

    // setBugcheckDiagnosticsAutoInstall: Writes only the auto-install switch without committing other pending settings on the same page.
    // Invocation: Called when the Auto-Install or Cancel Auto-Install button is clicked.
    // Parameter enabled: true installs after the driver starts successfully; false does not install. Return: none.
    void setBugcheckDiagnosticsAutoInstall(bool enabled);

    // installBugcheckDiagnosticsForCurrentSession: Sends an R0 IOCTL in the background to install diagnostics; affects only the current driver lifecycle.
    // Invocation: Called when the "Install for this session" button is clicked; Return: None; Results are reflected via status text and signals.
    void installBugcheckDiagnosticsForCurrentSession();

    // setBugcheckDiagnosticsControlsBusy purpose: disable three operations during installation to prevent concurrent BGP scans and callback registration.
    // Usage: called before starting a background task and after posting the result back; parameter busy indicates whether installation is in progress; return: none.
    void setBugcheckDiagnosticsControlsBusy(bool busy);

    // bindAppearanceSignals:
    // - Bind all control events on the Appearance page to the 'Pending Apply' workflow;
    // - Save and apply only after the Apply button is clicked.
    // Call site: invoked at the end of initializeAppearanceTab.
    void bindAppearanceSignals();

    // bindOnlineScanSignals:
    // - Binds the online scan API Key input box and the save button.
    // - Input changes only mark settings as pending save; the unified settings persistence flow is reused upon clicking Save.
    // Invocation: Called at the end of initializeOnlineScanTab.
    // Returns: Nothing.
    void bindOnlineScanSignals();

    // loadSettingsFromJson:
    // - Read JSON configuration and refresh the UI.
    // Called at the end of the constructor.
    void loadSettingsFromJson();

    // applySettingsToUi:
    // - Populate UI controls with configuration structure data.
    // Invocation: Called from loadSettingsFromJson or during internal rollback.
    // Input settings: UI to display and startup configuration.
    void applySettingsToUi(const ks::settings::AppearanceSettings& settings);

    // collectSettingsFromUi:
    // - Read user input from controls and assemble the configuration structure;
    // Call before saving.
    // Returns: The configuration structure generated from the current UI.
    ks::settings::AppearanceSettings collectSettingsFromUi() const;

    // markPendingChanges:
    // - Mark the current UI as having unapplied changes.
    // - Refresh the 'Apply' button's enabled state and tooltip text.
    // Invocation: Call after any setting control value changes.
    // Input parameter triggerReason: Trigger reason text (for debugging and logging assistance).
    void markPendingChanges(const QString& triggerReason);

    // updateApplyButtonState:
    // - Update the Apply button state based on m_hasPendingChanges;
    // - Unified visual feedback for pending changes requiring application.
    // Call after marking for application, after successful save, and after loading configuration.
    void updateApplyButtonState();

    // updateSystemDefaultFontItemText:
    // - Refresh the font dropdown item at index 0 ("System Default") for the current language;
    // - Only modifies the display role; the stable Qt::UserRole empty string semantics remain unchanged.
    // Call when initializing the font list or on LanguageChange; no input/output parameters.
    void updateSystemDefaultFontItemText();

    // saveAndEmitFromUi:
    // - Collect configuration from UI and write to JSON;
    // - Emit a change signal after successful save.
    // Invocation: Call when triggered by user interaction.
    // Parameter triggerReason: Text describing the trigger reason (for logging).
    void saveAndEmitFromUi(const QString& triggerReason);

    // updateThemeButtonStyle:
    // - Update the theme button style highlight based on the current selection state.
    // Usage: called after a button click or after configuration is loaded.
    void updateThemeButtonStyle();

    // updateThemeColorPreview: Refreshes the current theme color preview and the 'Reset to Default' button state.
    // Usage: Called when loading configuration, selecting a color, or restoring defaults.
    void updateThemeColorPreview();

    // chooseCustomThemeColor: First displays an extreme color risk warning, then opens the color picker.
    // Invocation: Called when clicking the 'Custom Theme Color' button.
    void chooseCustomThemeColor();

    // resetThemeColorToDefault: Clears custom theme colors and restores the built-in default theme.
    // Usage: called when the 'One-Click Reset' button is clicked.
    void resetThemeColorToDefault();

    // updateMainBackgroundColorPreview: refreshes the independent main background color preview and the restore button state.
    // Invocation: Called after loading configuration, switching themes, selecting a color, or restoring defaults.
    void updateMainBackgroundColorPreview();

    // chooseCustomMainBackgroundColor purpose: Open the main background color picker without changing the theme accent color.
    // Call context: invoked when clicking the "Choose Custom Main Background Color" button.
    void chooseCustomMainBackgroundColor();

    // resetMainBackgroundColorToDefault: Clears the custom main background color and restores it to follow the light/dark theme.
    // Call context: invoked when clicking the "Reset Main Background Color to Default" button.
    void resetMainBackgroundColorToDefault();

    // updateOpacityValueLabel:
    // - Synchronize the opacity percentage text label.
    // Called when the slider value changes.
    // Parameter opacityPercent: Opacity value ranging from 0 to 100.
    void updateOpacityValueLabel(int opacityPercent);

    // openBackgroundFileDialog:
    // - Open a file selection dialog for the user to choose a background image path.
    // Usage: Called when the 'Browse Background Image' button is clicked.
    void openBackgroundFileDialog();

    // resetBackgroundPathToDefault:
    // - Restore the background image path to the default Style/ksword_background.png.
    // Usage: Called when the 'Restore Default Background Path' button is clicked.
    void resetBackgroundPathToDefault();

    // launchTaskmgrHijackScript:
    // - Launch TaskmgrHijack.ps1 from the program's current directory;
    // - When install=true, writes the taskmgr.exe IFEO Debugger; when install=false, removes this configuration.
    // - The script itself triggers UAC elevation in non-administrator environments.
    // Invocation: Called when clicking the 'Image Hijack Task Manager' or 'Restore Task Manager' button.
    // Input install: true=install image hijacking; false=uninstall and restore Task Manager.
    // Returns: No return value; displays a dialog and writes a log on startup failure.
    void launchTaskmgrHijackScript(bool install);

    // parseWindowScaleFactorFromUi:
    // - Parse and correct the startup window scale factor from the input field;
    // - Invalid input automatically falls back to 1.0.
    // Invocation: called internally by collectSettingsFromUi.
    // Returns: a valid scale factor (0.50 to 2.00).
    double parseWindowScaleFactorFromUi() const;

private:
    // m_tabWidget role: Settings tab container, currently containing at least the 'Appearance' tab.
    QTabWidget* tabWidget_ = nullptr;

    // m_appearanceTab: QWidget container for the appearance settings page.
    QWidget* appearanceTab_ = nullptr;

    // m_languageTab: QWidget container for the interface language settings tab.
    QWidget* languageTab_ = nullptr;

    // m_startupTab: QWidget container for startup behavior settings page.
    QWidget* startupTab_ = nullptr;

    // m_featuresTab role: Feature settings page QWidget container.
    QWidget* featuresTab_ = nullptr;

    // m_onlineScanTab purpose: QWidget container for the Online Scan API Key settings page.
    QWidget* onlineScanTab_ = nullptr;

    // m_themeButtonGroup role: Mutually exclusive grouping for three theme buttons.
    QButtonGroup* themeButtonGroup_ = nullptr;

    // m_detailSchemeButtonGroup: Global mutually exclusive radio group for four strictly matching detail layouts.
    QButtonGroup* detailSchemeButtonGroup_ = nullptr;

    // m_languageCombo purpose: Lists language packs found in the languages directory that have passed validation.
    QComboBox* languageCombo_ = nullptr;

    // m_textAntialiasingCheckBox: Controls whether the application's default font uses text antialiasing.
    QCheckBox* textAntialiasingCheckBox_ = nullptr;

    // m_fontCombo:
    // - The 0th item uses empty itemData to represent "System Default"; other items store the system font family.
    // Display text can change with language, but persistent semantics do not depend on translated text.
    QComboBox* fontCombo_ = nullptr;

    // m_followSystemButton function: Select 'Follow System Theme' mode.
    QToolButton* followSystemButton_ = nullptr;

    // m_lightModeButton action: Select 'Light Theme' mode.
    QToolButton* lightModeButton_ = nullptr;

    // m_darkModeButton function: select 'Dark Mode' theme.
    QToolButton* darkModeButton_ = nullptr;

    // m_themeColorPreviewLabel: Displays the current primary theme color and its #RRGGBB value.
    QLabel* themeColorPreviewLabel_ = nullptr;

    // m_chooseThemeColorButton / m_resetThemeColorButton: Theme color selection and one-click restore buttons.
    QPushButton* chooseThemeColorButton_ = nullptr;
    QPushButton* resetThemeColorButton_ = nullptr;

    // Main background color and theme accent color are saved independently; the preview label displays the actual RGB value currently pending application.
    QLabel* mainBackgroundColorPreviewLabel_ = nullptr;
    QPushButton* chooseMainBackgroundColorButton_ = nullptr;
    QPushButton* resetMainBackgroundColorButton_ = nullptr;

    // m_backgroundPathEdit: Edit field for the background image path.
    QLineEdit* backgroundPathEdit_ = nullptr;

    // m_browseBackgroundButton: Opens the background image file picker.
    QToolButton* browseBackgroundButton_ = nullptr;

    // m_resetBackgroundButton action: Restore default background image path.
    QToolButton* resetBackgroundButton_ = nullptr;

    // m_backgroundOpacitySlider: Adjusts the background image transparency.
    QSlider* backgroundOpacitySlider_ = nullptr;

    // m_backgroundOpacityValueLabel purpose: displays the transparency percentage text.
    QLabel* backgroundOpacityValueLabel_ = nullptr;

    // m_backgroundTransparencyCheckBox function: allows the background image's transparent areas to show through the window behind.
    QCheckBox* backgroundTransparencyCheckBox_ = nullptr;

    // m_backgroundTranslucencyMaterialCombo purpose: Selects the background translucency effect (Auto/Mica/Transparent).
    QComboBox* backgroundTranslucencyMaterialCombo_ = nullptr;

    // m_backgroundBlurRadiusSlider: Adjusts the radius intensity for custom-drawn background glass blur.
    QSlider* backgroundBlurRadiusSlider_ = nullptr;

    // m_backgroundBlurRadiusValueLabel: Displays the current blur radius intensity as a percentage.
    QLabel* backgroundBlurRadiusValueLabel_ = nullptr;

    // m_acrylicTintOpacitySlider purpose: adjusts the opacity of the frosted glass tint layer.
    QSlider* acrylicTintOpacitySlider_ = nullptr;

    // m_acrylicTintOpacityValueLabel: Displays the frosted tint opacity percentage.
    QLabel* acrylicTintOpacityValueLabel_ = nullptr;

    // m_desktopTintOpacitySlider function: Adjusts the opacity of the tint layer in direct desktop mode.
    QSlider* desktopTintOpacitySlider_ = nullptr;

    // m_desktopTintOpacityValueLabel: Displays the solid tint opacity percentage.
    QLabel* desktopTintOpacityValueLabel_ = nullptr;

    // Log notification settings: control the toggle, level, duration, and stacking position of the notification cards on the right.
    QCheckBox* notificationCardsEnabledCheckBox_ = nullptr;
    QComboBox* notificationMinimumLevelCombo_ = nullptr;
    QSpinBox* notificationLogDisplaySecondsSpin_ = nullptr;
    QSpinBox* notificationMaximumVisibleLogCardsSpin_ = nullptr;
    QCheckBox* notificationLogHeightLimitCheckBox_ = nullptr;
    QSpinBox* notificationLogMaximumLinesSpin_ = nullptr;
    QComboBox* notificationDisplayPlacementCombo_ = nullptr;
    QComboBox* notificationStackDirectionCombo_ = nullptr;

    // m_startupMaximizedCheckBox: Sets whether to maximize by default on the next startup.
    QCheckBox* startupMaximizedCheckBox_ = nullptr;

    // m_startupTopMostCheckBox: Sets whether to enable top-most window by default after startup.
    QCheckBox* startupTopMostCheckBox_ = nullptr;

    // m_startupAutoAdminCheckBox: Sets whether to attempt requesting administrator privileges on the next startup.
    QCheckBox* startupAutoAdminCheckBox_ = nullptr;

    // m_startupAutoInstallR0DriverCheckBox purpose: Configures whether to automatically install and start the KswordARK driver on the next startup.
    QCheckBox* startupAutoInstallR0DriverCheckBox_ = nullptr;

    // m_preventMultipleInstancesCheckBox: Configures whether to prevent running multiple instances during normal startup.
    QCheckBox* preventMultipleInstancesCheckBox_ = nullptr;

    // m_unlockerShellContextMenuCheckBox: Sets whether to enable the system right-click 'File Unlocker' menu.
    QCheckBox* unlockerShellContextMenuCheckBox_ = nullptr;

    // m_suppressR0FeaturePromptsCheckBox: Configures whether to suppress automatic prompts when the R0 driver is not enabled or lacks sufficient permissions.
    QCheckBox* suppressR0FeaturePromptsCheckBox_ = nullptr;

    // m_dumpAutoCheckCheckBox: Sets whether to check for recent new crash dumps after startup.
    QCheckBox* dumpAutoCheckCheckBox_ = nullptr;

    // m_bugcheckDiagnosticsStatusLabel: Displays the status of automatic installation configuration and the current session installation result.
    QLabel* bugcheckDiagnosticsStatusLabel_ = nullptr;

    // m_enableBugcheckDiagnosticsAutoInstallButton function: Write configuration item for automatic installation upon subsequent driver startup.
    QPushButton* enableBugcheckDiagnosticsAutoInstallButton_ = nullptr;

    // m_disableBugcheckDiagnosticsAutoInstallButton purpose: removes the configuration option for automatic installation upon subsequent driver startup.
    QPushButton* disableBugcheckDiagnosticsAutoInstallButton_ = nullptr;

    // m_installBugcheckDiagnosticsForSessionButton purpose: send an installation IOCTL to the driver currently loaded in the session.
    QPushButton* installBugcheckDiagnosticsForSessionButton_ = nullptr;

    // m_bugcheckDiagnosticsInstallBusy role: Records whether the asynchronous IOCTL installation is still in progress.
    bool bugcheckDiagnosticsInstallBusy_ = false;

    // m_installTaskmgrHijackButton: Calls TaskmgrHijack.ps1 in the current directory to install the IFEO image hijack for taskmgr.exe.
    QPushButton* installTaskmgrHijackButton_ = nullptr;

    // m_uninstallTaskmgrHijackButton function: Invokes TaskmgrHijack.ps1 in the current directory to remove the IFEO image hijacking for taskmgr.exe.
    QPushButton* uninstallTaskmgrHijackButton_ = nullptr;

    // m_scrollBarWidthCombo: Sets the global scrollbar width (narrow/wide).
    QComboBox* scrollBarWidthCombo_ = nullptr;

    // The privilege button in the top-right corner displays a row of switches, with one checkbox per button.
    // Order matches the button layout itself (UIAccess / Admin / Debug / System / R0
    // / Virtualization), so the settings page reads in the same sequence as the UI.
    QCheckBox* privilegeUiAccessCheckBox_ = nullptr;
    QCheckBox* privilegeAdminCheckBox_ = nullptr;
    QCheckBox* privilegeDebugCheckBox_ = nullptr;
    QCheckBox* privilegeSystemCheckBox_ = nullptr;
    QCheckBox* privilegeR0CheckBox_ = nullptr;
    QCheckBox* privilegeHvmCheckBox_ = nullptr;
    QCheckBox* privilegeDdmaCheckBox_ = nullptr;
    // m_hvmDisplayNameCombo: Selects the display text (KVM / HVM / R-1) on the hardware virtualization button.
    QComboBox* hvmDisplayNameCombo_ = nullptr;

    // m_scrollBarAutoHideCheckBox function: Configures whether the scroll bar is weakly displayed or shown on hover.
    QCheckBox* scrollBarAutoHideCheckBox_ = nullptr;

    // m_smoothScrollingCheckBox: Configure whether global scroll regions enable scroll wheel smoothing.
    QCheckBox* smoothScrollingCheckBox_ = nullptr;

    // m_sliderWheelAdjustCheckBox: Configure whether the scroll wheel can directly adjust the slider value.
    QCheckBox* sliderWheelAdjustCheckBox_ = nullptr;

    // m_startupWindowScaleSpin: Sets the startup window scale percentage (50~200) for the next launch (takes effect after restart).
    QSpinBox* startupWindowScaleSpin_ = nullptr;

    // m_startupWindowScaleHintLabel function: Explains when the scaling takes effect and its relationship with system scaling.
    QLabel* startupWindowScaleHintLabel_ = nullptr;

    // m_virusTotalApiKeyEdit function: Edits the VirusTotal online scanning API Key.
    QLineEdit* virusTotalApiKeyEdit_ = nullptr;

    // m_threatBookApiKeyEdit: Edits the ThreatBook online scan API Key.
    QLineEdit* threatBookApiKeyEdit_ = nullptr;

    // m_applySettingsButton purpose: Uniformly submit current setting changes and trigger actual application.


    // m_saveOnlineScanKeysButton: Button to save the API Key specifically on the online scan page.
    QPushButton* saveOnlineScanKeysButton_ = nullptr;

    // m_currentAppearanceSettings: Caches the current effective UI and startup configuration.
    ks::settings::AppearanceSettings currentAppearanceSettings_;

    // m_pendingCustomThemeColor: Stores the custom theme color value before clicking 'Apply'; null indicates the default color.
    QString pendingCustomThemeColor_;

    // m_pendingCustomMainBackgroundColor: Stores the pending custom main background color; null indicates following the light/dark theme.
    QString pendingCustomMainBackgroundColor_;

    // m_isApplyingUiState: Marks 'UI being repopulated' to prevent recursive save triggers.
    bool isApplyingUiState_ = false;

    // m_hasPendingChanges: Marks whether there are pending changes awaiting application (not yet clicked Apply).
    bool hasPendingChanges_ = false;
};
