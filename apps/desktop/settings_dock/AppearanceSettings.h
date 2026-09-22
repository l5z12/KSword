#pragma once

// ============================================================
// AppearanceSettings.h
// Purpose:
// - Define the 'Interface and Startup Settings' data structure (theme mode, background image path, transparency, default startup tab, startup behavior);
// - Define JSON read/write and path parsing functions for reuse by SettingsDock/mainWindow.
// - Unified default values to avoid multiple hard-coded instances.
// ============================================================

#include <QString>

namespace ks::settings
{
    // ThemeMode: Theme mode enumeration.
    // FollowSystem: Follow system; Light: Light mode; Dark: Dark mode.
    enum class ThemeMode
    {
        kFollowSystem = 0,
        kLight = 1,
        kDark = 2
    };

    // NotificationDisplayPlacement: The container area for notification cards.
    // Screen: Display in the workspace of the monitor where the main window resides; mainWindow: Display in the Dock client area of the main window.
    enum class NotificationDisplayPlacement
    {
        kScreen = 0,
        kMainWindow = 1
    };

    // NotificationStackDirection: The stacking direction of notification cards on the right side.
    enum class NotificationStackDirection
    {
        kBottomUp = 0,
        kTopDown = 1
    };

    // HvmDisplayName: The name for hardware virtualization capability displayed in the UI.
    //
    // The same capability has three common names depending on context: internally it is called KVM (KSwordVM), in hardware and
    // documentation contexts it is called HVM, and when discussing permission layers it is referred to as R-1. All three terms refer
    // to the same capability; making the name an option is more appropriate than selecting one for the user based on their background.
    //
    // Applies only to the identifier at the top-right permission button. Descriptive text mentions do not follow the switch—those sentences
    // embed the name semantically (e.g., 'KVM: KSwordVM hardware virtualization (R-1) resident status...'). Replacing the entire string would
    // break readability; rewriting sentence-by-sentence would require reordering over forty bilingual entries, with costs outweighing benefits.
    enum class HvmDisplayName
    {
        kKvm = 0,
        kHvm = 1,
        kRingMinusOne = 2
    };

    // DetailDisplayScheme: Strictly matches the unified detail layout scheme for the page.
    // BottomCollapsed: Table collapsed below; Right: Table on the right;
    // Embedded: Inserts a detail row after the data row; Floating: Uses a separate detail window for each page.
    enum class DetailDisplayScheme
    {
        kBottomCollapsed = 0,
        kRight = 1,
        kEmbedded = 2,
        kFloating = 3
    };

    // AppearanceSettings: Structure for interface and startup settings.
    // themeMode: Current theme policy.
    // customThemeColor: user-defined primary theme color (#RRGGBB); null value indicates using the built-in default color.
    // customMainBackgroundColor: User-defined main background color (#RRGGBB); null value means follow the current light/dark theme.
    // backgroundImagePath: Background image path (can be relative or absolute).
    // backgroundOpacityPercent: Background image transparency (0~100).
    // backgroundTransparencyEnabled: Whether to allow the background image's own alpha transparent areas to show through to the area behind the window.
    // backgroundTranslucencyMaterial: Transparent background effect (auto = direct transparency with image,
    // frosted without; acrylic = always acrylic frosted; desktop = always direct transparency to desktop).
    //   (blur/mica are legacy values, handled as acrylic).
    // backgroundBlurRadiusPercent: glass blur radius intensity (0~100, 0 = no blur);
    //   Applies to custom-drawn Gaussian blur for window backgrounds; the main window and floating Dock share the same blurred background image.
    //   Note: The blur radius for the system acrylic (frosted glass) effect is fixed internally by Windows DWM. The
    //   ACCENT_POLICY provided by SetWindowCompositionAttribute does not include a radius field, so it cannot be adjusted.
    // acrylicTintOpacityPercent: Opacity of the frosted glass tint layer (0~100).
    //   Directly blends the gradientColor alpha from the combined feature into the system blur result; lower values yield higher transparency.
    // desktopTintOpacityPercent: Opacity of the tint layer in direct mode (0~100).
    //   When system frosted effect is inactive, the root container performs custom drawing; 0 indicates near-total transparency (retaining a 1/255 hit threshold).
    // startupDefaultTabKey: the key of the main tab activated by default upon application startup (e.g., welcome/process/network);
    // launchMaximizedOnStartup: Whether to default to maximized display on the next startup;
    // startupTopMostEnabled: Whether to automatically enable top-most mode after startup; manual pin toggles are synchronized and saved.
    // autoRequestAdminOnStartup: Whether to attempt requesting administrator privileges before the splash screen appears on the next startup.
    // startupAutoInstallR0Driver: Whether to automatically attempt to install and start the KswordARK driver after the main window is displayed next time.
    // preventMultipleInstances: Whether to prevent multiple instances during normal startup; permission switch restarts still allow takeover.
    // startupWindowScaleFactor: main window startup scale factor (1.0=100%, takes effect after restart);
    // startupScaleRecommendPromptDisabled: whether the small-screen recommended scaling prompt is no longer displayed.
    // unlockerShellContextMenuEnabled: Whether to enable the 'System Right-click - File Unlocker' menu (takes effect on next launch).
    // useWideScrollBars: Whether to use wide scrollbars (false = default narrow version);
    // scrollBarAutoHideEnabled: Whether scroll bar auto-hide on hover is enabled.
    // smoothScrollingEnabled: Indicates whether to enable scroll wheel smoothing for global scrollable areas.
    // sliderWheelAdjustEnabled: Indicates whether the scroll wheel can directly adjust the slider value.
    // fontFamily: Application interface font family; null value implies using the system default font.
    // textAntialiasingEnabled: whether to enable text antialiasing using the application's default font.
    // dumpAutoCheckEnabled: Whether to check if new crash dumps were generated recently after startup.
    // dumpAutoCheckPromptedPath / dumpAutoCheckPromptedTimeMsec：
    //   The dump path and modification time already queried from the user, used to avoid repeated popups for the same dump;
    //   The timestamp is recorded because the MEMORY.DMP path is fixed and its content
    //   gets overwritten by subsequent crashes, so only the path would miss new dumps.
    // suppressR0FeaturePrompts: Whether to disable automatic prompts when R0 drivers are not enabled or permissions are insufficient.
    // suppressDangerousActionConfirmations: whether to skip repeated modal confirmations for dangerous actions; risk information, pre-checks, and auditing remain unaffected.
    // bugcheckDiagnosticsAutoInstallEnabled: Whether R3 sends a blue screen diagnostic installation IOCTL after the driver starts successfully.
    // When false, BGP scanning and diagnostic callback registration are skipped unless the session was explicitly installed by the user.
    // virusTotalApiKey: VirusTotal online scanning API Key, read by the OnlineScan module at runtime.
    // threatBookApiKey: ThreatBook (Weibu Online) online scanning API Key, read by the OnlineScan module at runtime.
    struct AppearanceSettings
    {
        ThemeMode themeMode = ThemeMode::kFollowSystem;
        QString customThemeColor;
        QString customMainBackgroundColor;
        QString uiLanguage = QStringLiteral("system");
        QString backgroundImagePath = QStringLiteral("Style/ksword_background.png");
        int backgroundOpacityPercent = 35;
        bool backgroundTransparencyEnabled = false;
        QString backgroundTranslucencyMaterial = QStringLiteral("auto");
        int backgroundBlurRadiusPercent = 0;
        int acrylicTintOpacityPercent = 75;
        int desktopTintOpacityPercent = 65;
        QString startupDefaultTabKey = QStringLiteral("welcome");
        bool launchMaximizedOnStartup = true;
        bool startupTopMostEnabled = false;
        bool autoRequestAdminOnStartup = true;
        bool startupAutoInstallR0Driver = false;
        bool preventMultipleInstances = true;
        double startupWindowScaleFactor = 1.0;
        bool startupScaleRecommendPromptDisabled = false;
        bool unlockerShellContextMenuEnabled = false;
        bool useWideScrollBars = false;
        bool scrollBarAutoHideEnabled = false;
        bool smoothScrollingEnabled = true;
        bool sliderWheelAdjustEnabled = false;
        DetailDisplayScheme detailDisplayScheme = DetailDisplayScheme::kBottomCollapsed;
        QString fontFamily;
        bool textAntialiasingEnabled = true;
        bool notificationCardsEnabled = true;
        int notificationMinimumLevel = 2; // Warn; the numeric value maintains consistency with the severity order of KLogLevel.
        int notificationLogDisplaySeconds = 10;
        int notificationMaximumVisibleLogCards = 0; // 0 indicates no limit; determined by available display space.
        bool notificationLogHeightLimitEnabled = true;
        int notificationLogMaximumLines = 5;
        NotificationDisplayPlacement notificationDisplayPlacement = NotificationDisplayPlacement::kScreen;
        NotificationStackDirection notificationStackDirection = NotificationStackDirection::kBottomUp;
        bool dumpAutoCheckEnabled = true;
        QString dumpAutoCheckPromptedPath;
        qint64 dumpAutoCheckPromptedTimeMsec = 0;
        bool suppressR0FeaturePrompts = false;
        bool suppressDangerousActionConfirmations = false;
        bool bugcheckDiagnosticsAutoInstallEnabled = false;
        QString logWindowGeometryBase64;
        QString virusTotalApiKey;
        QString threatBookApiKey;
        // Whether each button in the top-right privilege button row is visible.
        //
        // Note: Six independent switches instead of a bitmask: Each button in this row has distinct
        // meanings, click behaviors, and risks (UIAccess restarts the program, R0 starts/stops the
        // driver, KVM enters/exits R-1 resident). Using a bitmask would make determining 'which bit
        // is the 3rd' a lookup operation, whereas there is no scenario here requiring set operations.
        //
        // Common privilege entries are shown by default; Debug is hidden by default but can be explicitly enabled in Appearance settings.
        bool privilegeButtonUiAccessVisible = true;
        bool privilegeButtonAdminVisible = true;
        bool privilegeButtonDebugVisible = false;
        bool privilegeButtonSystemVisible = true;
        bool privilegeButtonR0Visible = true;
        bool privilegeButtonHvmVisible = true;
        // DDMA (Direct Disk Memory Access) resident virtual sector indicator light, positioned to the right of R-1.
        // Consistent with other privilege indicators: it is merely an indicator light plus a navigation entry; clicking performs
        // no destructive operations. Actual disk sector occupation requires explicit configuration on the DDMA sub-page.
        bool privilegeButtonDdmaVisible = true;
        // Which name to display on the button in the top-right corner; see the documentation for HvmDisplayName.
        HvmDisplayName hvmDisplayName = HvmDisplayName::kKvm;
    };

    // Purpose of hvmDisplayNameToJsonText: convert the displayName enum to JSON archive text.
    QString hvmDisplayNameToJsonText(HvmDisplayName displayName);

    // hvmDisplayNameFromJsonText: Parses JSON text back into the HvmDisplayName enum.
    // Returns Kvm when unrecognized, consistent with the behavior of an unconfigured state.
    HvmDisplayName hvmDisplayNameFromJsonText(const QString& text);

    // hvmDisplayNameLabel: Returns the literal text displayed for this designation in the UI.
    // These three are product names and architecture terms that do not change with the UI language, so they bypass the localization package.
    QString hvmDisplayNameLabel(HvmDisplayName displayName);

    // tintAlphaFromOpacityPercent:
    // - Convert 0~100 color tint opacity to 0~255 alpha channel values.
    // - Frosted shading (system gradientColor) and direct shading (root container self-drawn) share the same mapping
    //   to avoid discrepancies between the percentage displayed on the settings page and the actual alpha rendered.
    // Invocation: Called before drawing the tint layer or dispatching combined features.
    // Input parameter opacityPercent: tint opacity percentage; out-of-range values are automatically clamped to 0~100.
    // Returns: an alpha value in the range 0–255.
    int tintAlphaFromOpacityPercent(int opacityPercent);

    // themeModeToJsonText:
    // - Convert theme enum to JSON archive text.
    // Call before saving configuration.
    // Input parameter mode: the theme enumeration value.
    // Returns: a string suitable for writing to JSON.
    QString themeModeToJsonText(ThemeMode mode);

    // themeModeFromJsonText:
    // - Reconstructs the theme enumeration from JSON text.
    // Call after reading configuration.
    // Input jsonText: Theme field in JSON.
    // Returns: Parsed theme enum; invalid values fall back to FollowSystem.
    ThemeMode themeModeFromJsonText(const QString& jsonText);

    // detailDisplaySchemeToJsonText / detailDisplaySchemeFromJsonText：
    // - Convert between stable JSON text and detail layout enumeration.
    // - Unknown text falls back to the default collapsed scheme below.
    // Usage: JSON read/write and setting logs for AppearanceSettings.
    // Input scheme/jsonText: layout enum or configuration text; returns corresponding text or valid enum.
    QString detailDisplaySchemeToJsonText(DetailDisplayScheme scheme);
    DetailDisplayScheme detailDisplaySchemeFromJsonText(const QString& jsonText);

    // appearanceSettingsJsonRelativePath:
    // - Returns the default relative path for the appearance configuration JSON.
    // Invocation: Called when building read/write paths.
    // Returns: e.g., Style/appearance_settings.json.
    QString appearanceSettingsJsonRelativePath();

    // resolveSettingsJsonPathForRead:
    // - Get the absolute path to be prioritized when reading JSON.
    // Invocation: called internally by loadAppearanceSettings.
    // Return: The absolute path ultimately used for reading the file.
    QString resolveSettingsJsonPathForRead();

    // settingsJsonFileExistsForRead:
    // - Check if a readable configuration file exists at startup.
    // - Used by main to distinguish between 'first launch' and 'launch with existing configuration'.
    // Returns: true if the configuration file exists; false otherwise.
    bool settingsJsonFileExistsForRead();

    // resolveSettingsJsonPathForWrite:
    // - Get the absolute path used when saving JSON.
    // Invocation: called internally by saveAppearanceSettings.
    // Return: The absolute path ultimately used for writing the file.
    QString resolveSettingsJsonPathForWrite();

    // resolveBackgroundImagePathForLoad:
    // - Parse a 'user-input path' into an absolute path for a loadable image.
    // Usage: Called when mainWindow applies the background image.
    // Input parameter imagePathText: path text from configuration (relative or absolute).
    // Returns: Absolute path (returns empty string if the original path is empty).
    QString resolveBackgroundImagePathForLoad(const QString& imagePathText);

    // loadAppearanceSettings:
    // - Reads interface and startup settings from JSON;
    // - Falls back to default values if the file does not exist or parsing fails.
    // Call when the program starts.
    // Returns: Interface and startup configuration structure.
    AppearanceSettings loadAppearanceSettings();

    // saveAppearanceSettings:
    // - Write interface and startup settings to a JSON file (create directory automatically).
    // Invocation: Called after the user modifies settings on the settings page; the deep dangerous action confirmation strategy menu also reuses this persistence entry.
    // Parameter settings: Configuration to be saved.
    // Parameter errorTextOut: Optional pointer for error text output.
    // Returns: true on success; false on failure.
    bool saveAppearanceSettings(const AppearanceSettings& settings, QString* errorTextOut = nullptr);

    // dangerousActionConfirmationsSuppressed:
    // - Returns whether current persistent settings allow skipping repeated modal confirmations for dangerous actions.
    // - Affects UI modals only; does not bypass driver confirmation tokens, SafetyPolicy, target verification, or auditing.
    // Call context: invoked at dangerous action entry points before deciding whether to show a confirmation dialog.
    // Returns: true to skip repeated modal confirmations; false to require individual confirmation each time.
    bool dangerousActionConfirmationsSuppressed();

    // MinimumWindowScaleFactor / MaximumWindowScaleFactor: Purpose:
    // - The only valid range for the window scale factor; normalizeWindowScaleFactor clamps to this range.
    // - The settings page uses this to generate the selectable range, avoiding mismatches between UI constraints and persisted limits written separately.
    inline constexpr double kMinimumWindowScaleFactor = 0.50;
    inline constexpr double kMaximumWindowScaleFactor = 2.00;

    // normalizeWindowScaleFactor:
    // - normalize window scale factor to a valid range.
    // - Fallback to 1.0 for invalid values (NaN/Inf/<=0).
    // Call when reading configuration, saving configuration, or applying scaling before startup.
    // Input rawScaleFactor: the original scale factor value.
    // Returns: Valid scale factor (range MinimumWindowScaleFactor~MaximumWindowScaleFactor).
    double normalizeWindowScaleFactor(double rawScaleFactor);
}
