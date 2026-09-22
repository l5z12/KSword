#include "AppearanceSettings.h"

#include <QCoreApplication>
#include <QColor>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cmath>

namespace
{
    // kPrimaryStyleDirectoryName / kFallbackStyleDirectoryName: Purpose:
    // - Also support the common "Style" directory in releases and the legacy "style" directory from development.
    // - When reading or writing configuration, prefer the distribution directory name to avoid writing customer configurations back to the source tree.
    constexpr auto kPrimaryStyleDirectoryName = "Style";
    constexpr auto kFallbackStyleDirectoryName = "style";

    // appendUniquePath:
    // - Append a deduplicated, normalized path to the candidate path list.
    // - Uses case-insensitive comparison to comply with Windows path rules.
    // Usage: Called internally by various candidate path collection functions.
    // Input parameter pathList: pointer to the candidate path list.
    // Input rawPath: Path text to append.
    void appendUniquePath(QStringList* pathList, const QString& rawPath)
    {
        if (pathList == nullptr)
        {
            return;
        }

        // normalizedPath: Normalizes the input path to avoid duplicates caused by ".." or separator differences.
        const QString kNormalizedPath = QDir::cleanPath(rawPath.trimmed());
        if (kNormalizedPath.isEmpty())
        {
            return;
        }

        if (!pathList->contains(kNormalizedPath, Qt::CaseInsensitive))
        {
            pathList->append(kNormalizedPath);
        }
    }

    // resolveExecutableDirectoryPath:
    // - Can still retrieve the current executable directory even before QApplication is created.
    // - Used for candidate path probing when reading the configuration file before startup.
    // Returns: absolute path to the directory containing the executable; returns an empty string on failure.
    QString resolveExecutableDirectoryPath()
    {
        wchar_t executablePathBuffer[MAX_PATH] = {};
        const DWORD kPathLength = ::GetModuleFileNameW(nullptr, executablePathBuffer, MAX_PATH);
        if (kPathLength == 0 || kPathLength >= MAX_PATH)
        {
            return QString();
        }

        // executablePathText: Holds the full absolute path text of the current process executable.
        const QString kExecutablePathText = QString::fromWCharArray(executablePathBuffer, static_cast<int>(kPathLength));
        return QFileInfo(kExecutablePathText).absolutePath();
    }

    // directoryContainsStyleFolder:
    // - Check if the specified root directory contains a Style/style subdirectory.
    // - Used for detecting the release root directory and selecting the resource root directory.
    // Input parameter rootDirectoryPath: Root directory to be checked.
    // Return: true if style folder exists; false otherwise.
    bool directoryContainsStyleFolder(const QString& rootDirectoryPath)
    {
        const QDir kRootDirectory(rootDirectoryPath);
        const QFileInfo kPrimaryStyleInfo(kRootDirectory.absoluteFilePath(QString::fromLatin1(kPrimaryStyleDirectoryName)));
        if (kPrimaryStyleInfo.exists() && kPrimaryStyleInfo.isDir())
        {
            return true;
        }

        const QFileInfo kFallbackStyleInfo(kRootDirectory.absoluteFilePath(QString::fromLatin1(kFallbackStyleDirectoryName)));
        return kFallbackStyleInfo.exists() && kFallbackStyleInfo.isDir();
    }

    // resolveStyleDirectoryNameForRoot:
    // - Determine the actual style directory name used under the given root directory;
    // - Prefer "Style" for releases; fall back to "style" during development.
    // Input parameter rootDirectoryPath: Root directory for style resources.
    // Returns: directory name; defaults to "Style" if none exist.
    QString resolveStyleDirectoryNameForRoot(const QString& rootDirectoryPath)
    {
        const QDir kRootDirectory(rootDirectoryPath);
        const QFileInfo kPrimaryStyleInfo(kRootDirectory.absoluteFilePath(QString::fromLatin1(kPrimaryStyleDirectoryName)));
        if (kPrimaryStyleInfo.exists() && kPrimaryStyleInfo.isDir())
        {
            return QString::fromLatin1(kPrimaryStyleDirectoryName);
        }

        const QFileInfo kFallbackStyleInfo(kRootDirectory.absoluteFilePath(QString::fromLatin1(kFallbackStyleDirectoryName)));
        if (kFallbackStyleInfo.exists() && kFallbackStyleInfo.isDir())
        {
            return QString::fromLatin1(kFallbackStyleDirectoryName);
        }
        return QString::fromLatin1(kPrimaryStyleDirectoryName);
    }

    // collectExecutableNearbyRootPaths:
    // - Generate a list of candidate root directories centered on the directory containing the exe.
    // - The first item is always the current directory of the executable, ensuring the customer version consistently prioritizes configuration files at the same level as the executable.
    // - Subsequently backtrack several levels upward to support legacy packages that place Style/style in the parent directory.
    // Returns: Candidate root directories near the executable, sorted by priority.
    QStringList collectExecutableNearbyRootPaths()
    {
        QStringList preferredRootPaths;
        QString walkingPath = QDir::cleanPath(resolveExecutableDirectoryPath());
        if (walkingPath.isEmpty())
        {
            return preferredRootPaths;
        }

        appendUniquePath(&preferredRootPaths, walkingPath);
        for (int depthIndex = 0; depthIndex < 8; ++depthIndex)
        {
            if (depthIndex > 0)
            {
                appendUniquePath(&preferredRootPaths, walkingPath);
            }

            QDir walkingDirectory(walkingPath);
            if (!walkingDirectory.cdUp())
            {
                break;
            }
            walkingPath = QDir::cleanPath(walkingDirectory.absolutePath());
        }
        return preferredRootPaths;
    }

    // collectDevelopmentFallbackRootPaths:
    // - Generate a set of fallback root paths for compatibility during development.
    // - Used solely for reading old configurations/background images to prevent accidental hits on project directories when the customer version lacks source code;
    // - Does not participate in target write decision.
    // Returns a list of development fallback root paths sorted by priority.
    QStringList collectDevelopmentFallbackRootPaths()
    {
        QStringList candidateRootPaths;

        // appendFromStartPath:
        // - Walks up from the starting directory for several levels.
        // - Append both the "current directory" and the "current directory/Ksword5.1 subdirectory" as candidates at each level.
        const auto kAppendFromStartPath = [&candidateRootPaths](const QString& startPath) {
            QString walkingPath = QDir::cleanPath(startPath.trimmed());
            if (walkingPath.isEmpty())
            {
                return;
            }

            for (int depthIndex = 0; depthIndex < 8; ++depthIndex)
            {
                appendUniquePath(&candidateRootPaths, walkingPath);
                appendUniquePath(
                    &candidateRootPaths,
                    QDir(walkingPath).absoluteFilePath(QStringLiteral("Ksword5.1")));

                QDir walkingDir(walkingPath);
                if (!walkingDir.cdUp())
                {
                    break;
                }
                walkingPath = QDir::cleanPath(walkingDir.absolutePath());
            }
        };

        // Retain only common development-time start points to support reading legacy style directories.
        kAppendFromStartPath(QDir::currentPath());
        kAppendFromStartPath(resolveExecutableDirectoryPath());
        kAppendFromStartPath(QCoreApplication::applicationDirPath());
        return candidateRootPaths;
    }

    // resolveExecutablePrimaryRootPath:
    // - Return the primary root directory where user configuration should be stored;
    // - Here, the directory where the current executable resides is used directly, no longer treating the source tree as the default write location.
    // Returns: The directory containing the executable; on extreme failure, falls back to applicationDirPath/currentPath.
    QString resolveExecutablePrimaryRootPath()
    {
        const QString kExecutableDirectoryPath = QDir::cleanPath(resolveExecutableDirectoryPath());
        if (!kExecutableDirectoryPath.isEmpty())
        {
            return kExecutableDirectoryPath;
        }

        const QString kApplicationDirectoryPath = QDir::cleanPath(QCoreApplication::applicationDirPath());
        if (!kApplicationDirectoryPath.isEmpty())
        {
            return kApplicationDirectoryPath;
        }

        return QDir::cleanPath(QDir::currentPath());
    }

    // resolvePreferredReadableRootPath:
    // - Select the preferred root directory to use when reading configuration/resources;
    // - First, fix the check on the current directory of the executable, then check the historical layout of the executable's parent directory;
    // - Only fall back to the style directory in the development source tree as a last resort.
    // Invocation: Called when reading the settings file and resolving relative resource paths.
    // Returns: Absolute path of the preferred root directory for reading.
    QString resolvePreferredReadableRootPath()
    {
        const QStringList kExecutableNearbyRootPaths = collectExecutableNearbyRootPaths();
        for (const QString& preferredRootPath : kExecutableNearbyRootPaths)
        {
            if (directoryContainsStyleFolder(preferredRootPath))
            {
                return preferredRootPath;
            }
        }

        // candidateRootPaths: List of fallback root directories for compatibility during development.
        const QStringList kCandidateRootPaths = collectDevelopmentFallbackRootPaths();
        for (const QString& candidateRootPath : kCandidateRootPaths)
        {
            if (directoryContainsStyleFolder(candidateRootPath))
            {
                return candidateRootPath;
            }
        }

        return resolveExecutablePrimaryRootPath();
    }

    // resolvePreferredWritableRootPath:
    // - Determine the root directory where configuration must be saved.
    // - Always fix to the current directory of the executable to avoid writing customer configuration back to the source tree.
    // Returns: the absolute path of the writable root directory.
    QString resolvePreferredWritableRootPath()
    {
        return resolveExecutablePrimaryRootPath();
    }

    // clampOpacityPercent:
    // - Clamp opacity to 0~100 to prevent invalid values from corrupting the configuration.
    // Usage: Called uniformly before and after reading/writing JSON.
    // Input opacityPercent: the opacity value to be corrected.
    // Returns: The corrected opacity value.
    int clampOpacityPercent(const int opacityPercent)
    {
        if (opacityPercent < 0)
        {
            return 0;
        }
        if (opacityPercent > 100)
        {
            return 100;
        }
        return opacityPercent;
    }

    int clampNotificationLogLevel(const int rawLevel)
    {
        return std::clamp(rawLevel, 0, 4);
    }

    int clampNotificationDisplaySeconds(const int rawSeconds)
    {
        return std::clamp(rawSeconds, 0, 60);
    }

    int clampNotificationMaximumVisibleLogCards(const int rawCount)
    {
        return std::clamp(rawCount, 0, 100);
    }

    int clampNotificationLogMaximumLines(const int rawLines)
    {
        return std::clamp(rawLines, 1, 50);
    }

    // normalizeCustomRgbColor: Accepts only complete RGB values to prevent invalid configurations from entering color calculations.
    // Null value indicates using the product's default color for the corresponding role.
    QString normalizeCustomRgbColor(const QString& rawColorText)
    {
        const QColor kColorValue(rawColorText.trimmed());
        return kColorValue.isValid()
            ? kColorValue.name(QColor::HexRgb).toUpper()
            : QString();
    }

    // clampWindowScaleFactorInternal:
    // - Clamp the window scale factor to the range [MinimumWindowScaleFactor, MaximumWindowScaleFactor].
    // - Fallback to 1.0 for invalid input.
    // Invocation: Called before configuring read/write operations and applying scaling at startup.
    // Input parameter rawScaleFactor: The raw scale factor.
    // Returns: Valid scale factor.
    double clampWindowScaleFactorInternal(const double rawScaleFactor)
    {
        if (!std::isfinite(rawScaleFactor) || rawScaleFactor <= 0.0)
        {
            return 1.0;
        }
        if (rawScaleFactor < ks::settings::kMinimumWindowScaleFactor)
        {
            return ks::settings::kMinimumWindowScaleFactor;
        }
        if (rawScaleFactor > ks::settings::kMaximumWindowScaleFactor)
        {
            return ks::settings::kMaximumWindowScaleFactor;
        }
        return rawScaleFactor;
    }

    // resolveRelativePath:
    // - Convert relative paths to absolute paths based on the root directory;
    // - Absolute paths remain unchanged.
    // Called internally during path resolution.
    // Input parameter rootDirPath: The absolute path of the root directory.
    // Parameter maybeRelativePath: Path to be resolved.
    // Return: The resolved absolute path.
    QString resolveRelativePath(const QString& rootDirPath, const QString& maybeRelativePath)
    {
        if (maybeRelativePath.isEmpty())
        {
            return QString();
        }
        const QFileInfo kInputInfo(maybeRelativePath);
        if (kInputInfo.isAbsolute())
        {
            return QDir::cleanPath(maybeRelativePath);
        }
        const QDir kRootDir(rootDirPath);
        return QDir::cleanPath(kRootDir.absoluteFilePath(maybeRelativePath));
    }

    // resolvePathAgainstCandidateRoots:
    // - Probe multiple root directories with priority to the directory adjacent to the executable, falling back to the development directory for relative paths.
    // - Return the first existing path immediately; if none exist, fall back to concatenating with the 'writable root directory'.
    // Call context: invoked when reading JSON or loading background images.
    // Parameter maybeRelativePath: relative or absolute path string.
    // Returns: An absolute path suitable for subsequent file access.
    QString resolvePathAgainstCandidateRoots(const QString& maybeRelativePath)
    {
        if (maybeRelativePath.trimmed().isEmpty())
        {
            return QString();
        }

        const QFileInfo kInputPathInfo(maybeRelativePath);
        if (kInputPathInfo.isAbsolute())
        {
            return QDir::cleanPath(maybeRelativePath);
        }

        // candidateRootPaths purpose: Read the set of candidate root directories, prioritizing customer directories over development directories.
        QStringList candidateRootPaths = collectExecutableNearbyRootPaths();
        const QStringList kFallbackRootPaths = collectDevelopmentFallbackRootPaths();
        for (const QString& fallbackRootPath : kFallbackRootPaths)
        {
            appendUniquePath(&candidateRootPaths, fallbackRootPath);
        }

        for (const QString& candidateRootPath : candidateRootPaths)
        {
            const QString kResolvedPath = resolveRelativePath(candidateRootPath, maybeRelativePath);
            if (QFileInfo::exists(kResolvedPath))
            {
                return kResolvedPath;
            }
        }

        // preferredRootPath: Provides a stable and writable fallback when no candidate in the set matches.
        const QString kPreferredRootPath = resolvePreferredWritableRootPath();
        return resolveRelativePath(kPreferredRootPath, maybeRelativePath);
    }

    // buildDefaultSettings:
    // - Unify creation of default UI and startup settings to avoid repeated hardcoding.
    // Invocation: Use when reading fails or fields are missing.
    // Returns: Default configuration structure.
    ks::settings::AppearanceSettings buildDefaultSettings()
    {
        ks::settings::AppearanceSettings defaultSettings;
        defaultSettings.themeMode = ks::settings::ThemeMode::kFollowSystem;
        defaultSettings.customThemeColor.clear();
        defaultSettings.customMainBackgroundColor.clear();
        defaultSettings.uiLanguage = QStringLiteral("system");
        defaultSettings.backgroundImagePath = QStringLiteral("Style/ksword_background.png");
        defaultSettings.backgroundOpacityPercent = 35;
        defaultSettings.backgroundTransparencyEnabled = false;
        defaultSettings.backgroundTranslucencyMaterial = QStringLiteral("auto");
        defaultSettings.backgroundBlurRadiusPercent = 0;
        defaultSettings.acrylicTintOpacityPercent = 75;
        defaultSettings.desktopTintOpacityPercent = 65;
        defaultSettings.startupDefaultTabKey = QStringLiteral("welcome");
        defaultSettings.launchMaximizedOnStartup = true;
        defaultSettings.startupTopMostEnabled = false;
        defaultSettings.autoRequestAdminOnStartup = true;
        defaultSettings.startupAutoInstallR0Driver = false;
        defaultSettings.preventMultipleInstances = true;
        defaultSettings.startupWindowScaleFactor = 1.0;
        defaultSettings.startupScaleRecommendPromptDisabled = false;
        defaultSettings.unlockerShellContextMenuEnabled = false;
        defaultSettings.useWideScrollBars = false;
        defaultSettings.scrollBarAutoHideEnabled = false;
        defaultSettings.smoothScrollingEnabled = true;
        defaultSettings.sliderWheelAdjustEnabled = false;
        defaultSettings.fontFamily.clear();
        defaultSettings.textAntialiasingEnabled = true;
        defaultSettings.notificationCardsEnabled = true;
        defaultSettings.notificationMinimumLevel = 2;
        defaultSettings.notificationLogDisplaySeconds = 10;
        defaultSettings.notificationMaximumVisibleLogCards = 0;
        defaultSettings.notificationLogHeightLimitEnabled = true;
        defaultSettings.notificationLogMaximumLines = 5;
        defaultSettings.notificationDisplayPlacement = ks::settings::NotificationDisplayPlacement::kScreen;
        defaultSettings.notificationStackDirection = ks::settings::NotificationStackDirection::kBottomUp;
        defaultSettings.dumpAutoCheckEnabled = true;
        defaultSettings.dumpAutoCheckPromptedPath.clear();
        defaultSettings.dumpAutoCheckPromptedTimeMsec = 0;
        defaultSettings.suppressR0FeaturePrompts = false;
        defaultSettings.suppressDangerousActionConfirmations = false;
        defaultSettings.logWindowGeometryBase64.clear();
        defaultSettings.virusTotalApiKey.clear();
        defaultSettings.threatBookApiKey.clear();
        // Debug is hidden by default; other privilege buttons retain their previous default visibility behavior.
        defaultSettings.privilegeButtonUiAccessVisible = true;
        defaultSettings.privilegeButtonAdminVisible = true;
        defaultSettings.privilegeButtonDebugVisible = false;
        defaultSettings.privilegeButtonSystemVisible = true;
        defaultSettings.privilegeButtonR0Visible = true;
        defaultSettings.privilegeButtonHvmVisible = true;
        // The DDMA indicator light is visible by default, consistent with other privilege lights, but can be disabled in Appearance settings.
        defaultSettings.privilegeButtonDdmaVisible = true;
        defaultSettings.hvmDisplayName = ks::settings::HvmDisplayName::kKvm;
        return defaultSettings;
    }
}

int ks::settings::tintAlphaFromOpacityPercent(const int opacityPercent)
{
    // Clamp before conversion: both the settings page and configuration files may introduce out-of-bounds values; direct
    // multiplication/division would yield negative alpha or values >255, and QColor would silently truncate them, masking configuration errors.
    const int kNormalizedPercent = clampOpacityPercent(opacityPercent);
    return (kNormalizedPercent * 255 + 50) / 100;
}

QString ks::settings::themeModeToJsonText(const ThemeMode mode)
{
    switch (mode)
    {
    case ThemeMode::kLight:
        return QStringLiteral("light");
    case ThemeMode::kDark:
        return QStringLiteral("dark");
    case ThemeMode::kFollowSystem:
    default:
        return QStringLiteral("follow_system");
    }
}

ks::settings::ThemeMode ks::settings::themeModeFromJsonText(const QString& jsonText)
{
    const QString kNormalizedText = jsonText.trimmed().toLower();
    if (kNormalizedText == QStringLiteral("light"))
    {
        return ThemeMode::kLight;
    }
    if (kNormalizedText == QStringLiteral("dark"))
    {
        return ThemeMode::kDark;
    }
    return ThemeMode::kFollowSystem;
}

QString ks::settings::hvmDisplayNameToJsonText(const HvmDisplayName displayName)
{
    // JSON retains stable English values, consistent with themes: archives do not change based on UI language.
    switch (displayName)
    {
    case HvmDisplayName::kHvm:
        return QStringLiteral("hvm");
    case HvmDisplayName::kRingMinusOne:
        return QStringLiteral("ring_minus_one");
    case HvmDisplayName::kKvm:
    default:
        return QStringLiteral("kvm");
    }
}

ks::settings::HvmDisplayName ks::settings::hvmDisplayNameFromJsonText(
    const QString& text)
{
    const QString kNormalizedText = text.trimmed().toLower();
    if (kNormalizedText == QStringLiteral("hvm"))
    {
        return HvmDisplayName::kHvm;
    }
    if (kNormalizedText == QStringLiteral("ring_minus_one"))
    {
        return HvmDisplayName::kRingMinusOne;
    }
    return HvmDisplayName::kKvm;
}

QString ks::settings::hvmDisplayNameLabel(const HvmDisplayName displayName)
{
    switch (displayName)
    {
    case HvmDisplayName::kHvm:
        return QStringLiteral("HVM");
    case HvmDisplayName::kRingMinusOne:
        // Hyphen instead of minus sign: this is the standard notation for permission levels, maintaining visual alignment when placed alongside R0/R3.
        return QStringLiteral("R-1");
    case HvmDisplayName::kKvm:
    default:
        return QStringLiteral("KVM");
    }
}

QString ks::settings::detailDisplaySchemeToJsonText(const DetailDisplayScheme scheme)
{
    // JSON text retains stable English values to avoid configuration compatibility issues during language switching.
    switch (scheme)
    {
    case DetailDisplayScheme::kRight:
        return QStringLiteral("right");
    case DetailDisplayScheme::kEmbedded:
        return QStringLiteral("embedded");
    case DetailDisplayScheme::kFloating:
        return QStringLiteral("floating");
    case DetailDisplayScheme::kBottomCollapsed:
    default:
        return QStringLiteral("bottom_collapsed");
    }
}

ks::settings::DetailDisplayScheme ks::settings::detailDisplaySchemeFromJsonText(
    const QString& jsonText)
{
    // Safely fall back to the default scheme for unknown or historically corrupted values to prevent losing detail entry points on the page at startup.
    const QString kNormalizedText = jsonText.trimmed().toLower();
    if (kNormalizedText == QStringLiteral("right"))
    {
        return DetailDisplayScheme::kRight;
    }
    if (kNormalizedText == QStringLiteral("embedded"))
    {
        return DetailDisplayScheme::kEmbedded;
    }
    if (kNormalizedText == QStringLiteral("floating"))
    {
        return DetailDisplayScheme::kFloating;
    }
    return DetailDisplayScheme::kBottomCollapsed;
}

QString ks::settings::appearanceSettingsJsonRelativePath()
{
    const QString kPreferredRootPath = resolvePreferredWritableRootPath();
    const QString kStyleDirectoryName = resolveStyleDirectoryNameForRoot(kPreferredRootPath);
    return kStyleDirectoryName + QStringLiteral("/appearance_settings.json");
}

QString ks::settings::resolveSettingsJsonPathForRead()
{
    const QString kRelativePath = appearanceSettingsJsonRelativePath();
    return resolvePathAgainstCandidateRoots(kRelativePath);
}

bool ks::settings::settingsJsonFileExistsForRead()
{
    return QFileInfo::exists(resolveSettingsJsonPathForRead());
}

QString ks::settings::resolveSettingsJsonPathForWrite()
{
    // preferredRootPath: Fixed to the directory alongside the executable to prevent customer configurations from being mistakenly written back to the source tree.
    const QString kPreferredRootPath = resolvePreferredWritableRootPath();
    return resolveRelativePath(kPreferredRootPath, appearanceSettingsJsonRelativePath());
}

QString ks::settings::resolveBackgroundImagePathForLoad(const QString& imagePathText)
{
    return resolvePathAgainstCandidateRoots(imagePathText);
}

ks::settings::AppearanceSettings ks::settings::loadAppearanceSettings()
{
    AppearanceSettings loadedSettings = buildDefaultSettings();
    const QString kSettingsJsonPath = resolveSettingsJsonPathForRead();
    QFile settingsFile(kSettingsJsonPath);

    if (!settingsFile.exists())
    {
        return loadedSettings;
    }

    if (!settingsFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        return loadedSettings;
    }

    const QByteArray kJsonBytes = settingsFile.readAll();
    settingsFile.close();

    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(kJsonBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !kJsonDocument.isObject())
    {
        return loadedSettings;
    }

    const QJsonObject kRootObject = kJsonDocument.object();

    // themeText purpose: Reads the theme mode field, falling back to the default value if missing.
    const QString kThemeText = kRootObject.value(QStringLiteral("theme_mode"))
        .toString(themeModeToJsonText(loadedSettings.themeMode));
    loadedSettings.themeMode = themeModeFromJsonText(kThemeText);
    loadedSettings.customThemeColor = normalizeCustomRgbColor(
        kRootObject.value(QStringLiteral("custom_theme_color"))
        .toString(loadedSettings.customThemeColor));
    loadedSettings.customMainBackgroundColor = normalizeCustomRgbColor(
        kRootObject.value(QStringLiteral("custom_main_background_color"))
        .toString(loadedSettings.customMainBackgroundColor));

    const QString kUiLanguageText = kRootObject.value(QStringLiteral("ui_language"))
        .toString(loadedSettings.uiLanguage)
        .trimmed();
    loadedSettings.uiLanguage = kUiLanguageText.isEmpty() ? QStringLiteral("system") : kUiLanguageText;

    // backgroundPathText role: Read the background image path field; use the default path if missing.
    const QString kBackgroundPathText = kRootObject.value(QStringLiteral("background_image_path"))
        .toString(loadedSettings.backgroundImagePath);
    loadedSettings.backgroundImagePath = kBackgroundPathText.trimmed().isEmpty()
        ? (resolveStyleDirectoryNameForRoot(resolvePreferredReadableRootPath()) + QStringLiteral("/ksword_background.png"))
        : kBackgroundPathText;

    // backgroundOpacityPercentValue usage: read the opacity field and apply boundary correction.
    const int kBackgroundOpacityPercentValue = kRootObject.value(QStringLiteral("background_opacity_percent"))
        .toInt(loadedSettings.backgroundOpacityPercent);
    loadedSettings.backgroundOpacityPercent = clampOpacityPercent(kBackgroundOpacityPercentValue);

    loadedSettings.backgroundTransparencyEnabled = kRootObject
        .value(QStringLiteral("background_transparency_enabled"))
        .toBool(loadedSettings.backgroundTransparencyEnabled);

    // Translucent background effects only accept predefined enum text; unknown values fall back to auto to prevent spelling residues from breaking material decisions.
    const QString kTranslucencyMaterialText = kRootObject
        .value(QStringLiteral("background_translucency_material"))
        .toString(loadedSettings.backgroundTranslucencyMaterial)
        .trimmed()
        .toLower();
    // blur/mica are legacy values (both mean 'frosted'); retained for reading to prevent silent reset of
    // old configs. Actual material decision and settings page reflection treat them as acrylic frosted.
    loadedSettings.backgroundTranslucencyMaterial =
        (kTranslucencyMaterialText == QStringLiteral("blur")
            || kTranslucencyMaterialText == QStringLiteral("acrylic")
            || kTranslucencyMaterialText == QStringLiteral("mica")
            || kTranslucencyMaterialText == QStringLiteral("desktop"))
        ? kTranslucencyMaterialText
        : QStringLiteral("auto");

    // The three glass effect parameters (blur radius, frosted tint, and direct tint) and background image transparency share the same 0–100
    // semantics, so they all go through clampOpacityPercent. When old configurations lack these fields, the default values remain unchanged.
    loadedSettings.backgroundBlurRadiusPercent = clampOpacityPercent(
        kRootObject.value(QStringLiteral("background_blur_radius_percent"))
        .toInt(loadedSettings.backgroundBlurRadiusPercent));
    loadedSettings.acrylicTintOpacityPercent = clampOpacityPercent(
        kRootObject.value(QStringLiteral("acrylic_tint_opacity_percent"))
        .toInt(loadedSettings.acrylicTintOpacityPercent));
    loadedSettings.desktopTintOpacityPercent = clampOpacityPercent(
        kRootObject.value(QStringLiteral("desktop_tint_opacity_percent"))
        .toInt(loadedSettings.desktopTintOpacityPercent));

    // Note: startupDefaultTabKeyText purpose: Read the startup default tab key field; fall back to welcome if missing or empty.
    const QString kStartupDefaultTabKeyText = kRootObject.value(QStringLiteral("startup_default_tab_key"))
        .toString(loadedSettings.startupDefaultTabKey)
        .trimmed()
        .toLower();
    loadedSettings.startupDefaultTabKey = kStartupDefaultTabKeyText.isEmpty()
        ? QStringLiteral("welcome")
        : kStartupDefaultTabKeyText;

    // launchMaximizedOnStartup purpose: Reads the 'Maximize on Startup' switch and maintains compatibility with the legacy 'startup_full_screen' field.
    if (kRootObject.contains(QStringLiteral("startup_maximized")))
    {
        loadedSettings.launchMaximizedOnStartup = kRootObject.value(QStringLiteral("startup_maximized"))
            .toBool(loadedSettings.launchMaximizedOnStartup);
    }
    else
    {
        loadedSettings.launchMaximizedOnStartup = kRootObject.value(QStringLiteral("startup_full_screen"))
            .toBool(loadedSettings.launchMaximizedOnStartup);
    }

    // startupTopMostEnabled: Reads the 'Automatically set to topmost after startup' switch; defaults to disabled if missing.
    loadedSettings.startupTopMostEnabled = kRootObject.value(QStringLiteral("startup_topmost_enabled"))
        .toBool(loadedSettings.startupTopMostEnabled);

    // autoRequestAdminOnStartup: Reads the 'Auto-request admin on startup' switch; defaults to true if missing.
    loadedSettings.autoRequestAdminOnStartup = kRootObject.value(QStringLiteral("startup_auto_request_admin"))
        .toBool(loadedSettings.autoRequestAdminOnStartup);

    // startupAutoInstallR0Driver: reads the 'Auto-install driver at startup' switch; defaults to false if missing.
    loadedSettings.startupAutoInstallR0Driver = kRootObject
        .value(QStringLiteral("startup_auto_install_r0_driver"))
        .toBool(loadedSettings.startupAutoInstallR0Driver);

    // preventMultipleInstances: Reads the 'prevent multiple instances' switch; defaults to enabled if missing to maintain legacy behavior.
    loadedSettings.preventMultipleInstances = kRootObject.value(QStringLiteral("prevent_multiple_instances"))
        .toBool(loadedSettings.preventMultipleInstances);

    // startupWindowScaleFactor: Reads the 'startup window scale factor', compatible with the legacy field 'window_scale_factor'.
    double rawWindowScaleFactor = loadedSettings.startupWindowScaleFactor;
    if (kRootObject.contains(QStringLiteral("startup_window_scale_factor")))
    {
        rawWindowScaleFactor = kRootObject.value(QStringLiteral("startup_window_scale_factor"))
            .toDouble(loadedSettings.startupWindowScaleFactor);
    }
    else if (kRootObject.contains(QStringLiteral("window_scale_factor")))
    {
        rawWindowScaleFactor = kRootObject.value(QStringLiteral("window_scale_factor"))
            .toDouble(loadedSettings.startupWindowScaleFactor);
    }
    loadedSettings.startupWindowScaleFactor = clampWindowScaleFactorInternal(rawWindowScaleFactor);

    // startupScaleRecommendPromptDisabled: Read the 'Do not show small-screen scale recommendation prompt' switch.
    loadedSettings.startupScaleRecommendPromptDisabled = kRootObject
        .value(QStringLiteral("startup_scale_recommend_prompt_disabled"))
        .toBool(loadedSettings.startupScaleRecommendPromptDisabled);
    loadedSettings.unlockerShellContextMenuEnabled = kRootObject
        .value(QStringLiteral("unlocker_shell_context_menu_enabled"))
        .toBool(loadedSettings.unlockerShellContextMenuEnabled);
    loadedSettings.useWideScrollBars = kRootObject
        .value(QStringLiteral("use_wide_scroll_bars"))
        .toBool(loadedSettings.useWideScrollBars);
    loadedSettings.scrollBarAutoHideEnabled = kRootObject
        .value(QStringLiteral("scroll_bar_auto_hide_enabled"))
        .toBool(loadedSettings.scrollBarAutoHideEnabled);
    loadedSettings.smoothScrollingEnabled = kRootObject
        .value(QStringLiteral("smooth_scrolling_enabled"))
        .toBool(loadedSettings.smoothScrollingEnabled);
    loadedSettings.sliderWheelAdjustEnabled = kRootObject
        .value(QStringLiteral("slider_wheel_adjust_enabled"))
        .toBool(loadedSettings.sliderWheelAdjustEnabled);
    loadedSettings.detailDisplayScheme = detailDisplaySchemeFromJsonText(
        kRootObject.value(QStringLiteral("detail_display_scheme"))
        .toString(detailDisplaySchemeToJsonText(loadedSettings.detailDisplayScheme)));
    loadedSettings.fontFamily = kRootObject
        .value(QStringLiteral("font_family"))
        .toString(loadedSettings.fontFamily)
        .trimmed();
    loadedSettings.textAntialiasingEnabled = kRootObject
        .value(QStringLiteral("text_antialiasing_enabled"))
        .toBool(loadedSettings.textAntialiasingEnabled);
    loadedSettings.notificationCardsEnabled = kRootObject
        .value(QStringLiteral("notification_cards_enabled"))
        .toBool(loadedSettings.notificationCardsEnabled);
    loadedSettings.notificationMinimumLevel = clampNotificationLogLevel(
        kRootObject.value(QStringLiteral("notification_minimum_level"))
        .toInt(loadedSettings.notificationMinimumLevel));
    loadedSettings.notificationLogDisplaySeconds = clampNotificationDisplaySeconds(
        kRootObject.value(QStringLiteral("notification_log_display_seconds"))
        .toInt(loadedSettings.notificationLogDisplaySeconds));
    loadedSettings.notificationMaximumVisibleLogCards = clampNotificationMaximumVisibleLogCards(
        kRootObject.value(QStringLiteral("notification_maximum_visible_log_cards"))
        .toInt(loadedSettings.notificationMaximumVisibleLogCards));
    loadedSettings.notificationLogHeightLimitEnabled = kRootObject
        .value(QStringLiteral("notification_log_height_limit_enabled"))
        .toBool(loadedSettings.notificationLogHeightLimitEnabled);
    loadedSettings.notificationLogMaximumLines = clampNotificationLogMaximumLines(
        kRootObject.value(QStringLiteral("notification_log_maximum_lines"))
        .toInt(loadedSettings.notificationLogMaximumLines));
    loadedSettings.notificationDisplayPlacement =
        kRootObject.value(QStringLiteral("notification_display_placement")).toString()
        == QStringLiteral("main_window")
        ? NotificationDisplayPlacement::kMainWindow
        : NotificationDisplayPlacement::kScreen;
    loadedSettings.notificationStackDirection =
        kRootObject.value(QStringLiteral("notification_stack_direction")).toString()
        == QStringLiteral("top_down")
        ? NotificationStackDirection::kTopDown
        : NotificationStackDirection::kBottomUp;
    loadedSettings.dumpAutoCheckEnabled = kRootObject
        .value(QStringLiteral("dump_auto_check_enabled"))
        .toBool(loadedSettings.dumpAutoCheckEnabled);
    loadedSettings.dumpAutoCheckPromptedPath = kRootObject
        .value(QStringLiteral("dump_auto_check_prompted_path"))
        .toString();
    // Timestamps are stored as strings: JSON numbers are doubles, and while millisecond-level timestamps within
    // 2^53 do not lose precision, using strings is clearer and avoids serialization differences across Qt versions.
    loadedSettings.dumpAutoCheckPromptedTimeMsec = kRootObject
        .value(QStringLiteral("dump_auto_check_prompted_time_msec"))
        .toString()
        .toLongLong();
    loadedSettings.suppressR0FeaturePrompts = kRootObject
        .value(QStringLiteral("suppress_r0_feature_prompts"))
        .toBool(loadedSettings.suppressR0FeaturePrompts);
    /*
     * Visibility and label of the privilege button.
     *
     * Default to the "current value" (i.e., true from defaults()); if the old config file
     * lacks these keys, reading them must preserve the behavior prior to the setting's
     * existence, rather than returning false and hiding the entire row of buttons.
     */
    loadedSettings.privilegeButtonUiAccessVisible = kRootObject
        .value(QStringLiteral("privilege_button_uiaccess_visible"))
        .toBool(loadedSettings.privilegeButtonUiAccessVisible);
    loadedSettings.privilegeButtonAdminVisible = kRootObject
        .value(QStringLiteral("privilege_button_admin_visible"))
        .toBool(loadedSettings.privilegeButtonAdminVisible);
    loadedSettings.privilegeButtonDebugVisible = kRootObject
        .value(QStringLiteral("privilege_button_debug_visible"))
        .toBool(loadedSettings.privilegeButtonDebugVisible);
    loadedSettings.privilegeButtonSystemVisible = kRootObject
        .value(QStringLiteral("privilege_button_system_visible"))
        .toBool(loadedSettings.privilegeButtonSystemVisible);
    loadedSettings.privilegeButtonR0Visible = kRootObject
        .value(QStringLiteral("privilege_button_r0_visible"))
        .toBool(loadedSettings.privilegeButtonR0Visible);
    loadedSettings.privilegeButtonHvmVisible = kRootObject
        .value(QStringLiteral("privilege_button_hvm_visible"))
        .toBool(loadedSettings.privilegeButtonHvmVisible);
    loadedSettings.privilegeButtonDdmaVisible = kRootObject
        .value(QStringLiteral("privilege_button_ddma_visible"))
        .toBool(loadedSettings.privilegeButtonDdmaVisible);
    loadedSettings.hvmDisplayName = hvmDisplayNameFromJsonText(
        kRootObject
            .value(QStringLiteral("hvm_display_name"))
            .toString(hvmDisplayNameToJsonText(loadedSettings.hvmDisplayName)));
    loadedSettings.suppressDangerousActionConfirmations = kRootObject
        .value(QStringLiteral("suppress_dangerous_action_confirmations"))
        .toBool(loadedSettings.suppressDangerousActionConfirmations);
    // If not configured, keep disabled to ensure that after upgrading legacy configurations, BGP private fields are not scanned during normal driver loading.
    loadedSettings.bugcheckDiagnosticsAutoInstallEnabled = kRootObject
        .value(QStringLiteral("bugcheck_diagnostics_auto_install_enabled"))
        .toBool(loadedSettings.bugcheckDiagnosticsAutoInstallEnabled);
    loadedSettings.logWindowGeometryBase64 = kRootObject
        .value(QStringLiteral("log_window_geometry_base64"))
        .toString();
    // Purpose of the online scanning API Key:
    // - Reads the key saved in the 'Online Scan' tab of the settings page;
    // - The OnlineScan module only reads this configuration; no keys are hardcoded in the code.
    loadedSettings.virusTotalApiKey = kRootObject
        .value(QStringLiteral("virustotal_api_key"))
        .toString(loadedSettings.virusTotalApiKey);
    loadedSettings.threatBookApiKey = kRootObject
        .value(QStringLiteral("threatbook_api_key"))
        .toString(loadedSettings.threatBookApiKey);

    return loadedSettings;
}

bool ks::settings::saveAppearanceSettings(const AppearanceSettings& settings, QString* errorTextOut)
{
    const QString kSettingsJsonPath = resolveSettingsJsonPathForWrite();
    const QFileInfo kSettingsFileInfo(kSettingsJsonPath);

    // settingsDirPath: Directory containing the configuration file; ensure the directory exists before saving.
    const QString kSettingsDirPath = kSettingsFileInfo.absolutePath();
    QDir settingsDir(kSettingsDirPath);
    if (!settingsDir.exists())
    {
        if (!settingsDir.mkpath(QStringLiteral(".")))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建设置目录失败: %1").arg(kSettingsDirPath);
            }
            return false;
        }
    }

    QJsonObject rootObject;
    rootObject.insert(QStringLiteral("theme_mode"), themeModeToJsonText(settings.themeMode));
    rootObject.insert(
        QStringLiteral("custom_theme_color"),
        normalizeCustomRgbColor(settings.customThemeColor));
    rootObject.insert(
        QStringLiteral("custom_main_background_color"),
        normalizeCustomRgbColor(settings.customMainBackgroundColor));
    rootObject.insert(
        QStringLiteral("ui_language"),
        settings.uiLanguage.trimmed().isEmpty() ? QStringLiteral("system") : settings.uiLanguage.trimmed());
    rootObject.insert(QStringLiteral("background_image_path"), settings.backgroundImagePath);
    rootObject.insert(QStringLiteral("background_opacity_percent"), clampOpacityPercent(settings.backgroundOpacityPercent));
    rootObject.insert(QStringLiteral("background_transparency_enabled"), settings.backgroundTransparencyEnabled);
    rootObject.insert(
        QStringLiteral("background_translucency_material"),
        settings.backgroundTranslucencyMaterial.trimmed().isEmpty()
        ? QStringLiteral("auto")
        : settings.backgroundTranslucencyMaterial.trimmed().toLower());
    rootObject.insert(
        QStringLiteral("background_blur_radius_percent"),
        clampOpacityPercent(settings.backgroundBlurRadiusPercent));
    rootObject.insert(
        QStringLiteral("acrylic_tint_opacity_percent"),
        clampOpacityPercent(settings.acrylicTintOpacityPercent));
    rootObject.insert(
        QStringLiteral("desktop_tint_opacity_percent"),
        clampOpacityPercent(settings.desktopTintOpacityPercent));
    rootObject.insert(
        QStringLiteral("startup_default_tab_key"),
        settings.startupDefaultTabKey.trimmed().isEmpty()
        ? QStringLiteral("welcome")
        : settings.startupDefaultTabKey.trimmed().toLower());
    rootObject.insert(QStringLiteral("startup_maximized"), settings.launchMaximizedOnStartup);
    rootObject.insert(QStringLiteral("startup_topmost_enabled"), settings.startupTopMostEnabled);
    rootObject.insert(QStringLiteral("startup_auto_request_admin"), settings.autoRequestAdminOnStartup);
    rootObject.insert(QStringLiteral("startup_auto_install_r0_driver"), settings.startupAutoInstallR0Driver);
    rootObject.insert(QStringLiteral("prevent_multiple_instances"), settings.preventMultipleInstances);
    rootObject.insert(
        QStringLiteral("startup_window_scale_factor"),
        clampWindowScaleFactorInternal(settings.startupWindowScaleFactor));
    rootObject.insert(
        QStringLiteral("startup_scale_recommend_prompt_disabled"),
        settings.startupScaleRecommendPromptDisabled);
    rootObject.insert(
        QStringLiteral("unlocker_shell_context_menu_enabled"),
        settings.unlockerShellContextMenuEnabled);
    rootObject.insert(
        QStringLiteral("use_wide_scroll_bars"),
        settings.useWideScrollBars);
    rootObject.insert(
        QStringLiteral("scroll_bar_auto_hide_enabled"),
        settings.scrollBarAutoHideEnabled);
    rootObject.insert(
        QStringLiteral("smooth_scrolling_enabled"),
        settings.smoothScrollingEnabled);
    rootObject.insert(
        QStringLiteral("slider_wheel_adjust_enabled"),
        settings.sliderWheelAdjustEnabled);
    rootObject.insert(
        QStringLiteral("detail_display_scheme"),
        detailDisplaySchemeToJsonText(settings.detailDisplayScheme));
    rootObject.insert(
        QStringLiteral("font_family"),
        settings.fontFamily.trimmed());
    rootObject.insert(
        QStringLiteral("text_antialiasing_enabled"),
        settings.textAntialiasingEnabled);
    rootObject.insert(
        QStringLiteral("notification_cards_enabled"),
        settings.notificationCardsEnabled);
    rootObject.insert(
        QStringLiteral("notification_minimum_level"),
        clampNotificationLogLevel(settings.notificationMinimumLevel));
    rootObject.insert(
        QStringLiteral("notification_log_display_seconds"),
        clampNotificationDisplaySeconds(settings.notificationLogDisplaySeconds));
    rootObject.insert(
        QStringLiteral("notification_maximum_visible_log_cards"),
        clampNotificationMaximumVisibleLogCards(settings.notificationMaximumVisibleLogCards));
    rootObject.insert(
        QStringLiteral("notification_log_height_limit_enabled"),
        settings.notificationLogHeightLimitEnabled);
    rootObject.insert(
        QStringLiteral("notification_log_maximum_lines"),
        clampNotificationLogMaximumLines(settings.notificationLogMaximumLines));
    rootObject.insert(
        QStringLiteral("notification_display_placement"),
        settings.notificationDisplayPlacement == NotificationDisplayPlacement::kMainWindow
        ? QStringLiteral("main_window")
        : QStringLiteral("screen"));
    rootObject.insert(
        QStringLiteral("notification_stack_direction"),
        settings.notificationStackDirection == NotificationStackDirection::kTopDown
        ? QStringLiteral("top_down")
        : QStringLiteral("bottom_up"));
    rootObject.insert(
        QStringLiteral("dump_auto_check_enabled"),
        settings.dumpAutoCheckEnabled);
    rootObject.insert(
        QStringLiteral("dump_auto_check_prompted_path"),
        settings.dumpAutoCheckPromptedPath);
    rootObject.insert(
        QStringLiteral("dump_auto_check_prompted_time_msec"),
        QString::number(settings.dumpAutoCheckPromptedTimeMsec));
    rootObject.insert(
        QStringLiteral("suppress_r0_feature_prompts"),
        settings.suppressR0FeaturePrompts);
    rootObject.insert(
        QStringLiteral("privilege_button_uiaccess_visible"),
        settings.privilegeButtonUiAccessVisible);
    rootObject.insert(
        QStringLiteral("privilege_button_admin_visible"),
        settings.privilegeButtonAdminVisible);
    rootObject.insert(
        QStringLiteral("privilege_button_debug_visible"),
        settings.privilegeButtonDebugVisible);
    rootObject.insert(
        QStringLiteral("privilege_button_system_visible"),
        settings.privilegeButtonSystemVisible);
    rootObject.insert(
        QStringLiteral("privilege_button_r0_visible"),
        settings.privilegeButtonR0Visible);
    rootObject.insert(
        QStringLiteral("privilege_button_hvm_visible"),
        settings.privilegeButtonHvmVisible);
    rootObject.insert(
        QStringLiteral("privilege_button_ddma_visible"),
        settings.privilegeButtonDdmaVisible);
    rootObject.insert(
        QStringLiteral("hvm_display_name"),
        hvmDisplayNameToJsonText(settings.hvmDisplayName));
    rootObject.insert(
        QStringLiteral("suppress_dangerous_action_confirmations"),
        settings.suppressDangerousActionConfirmations);
    rootObject.insert(
        QStringLiteral("bugcheck_diagnostics_auto_install_enabled"),
        settings.bugcheckDiagnosticsAutoInstallEnabled);
    rootObject.insert(
        QStringLiteral("log_window_geometry_base64"),
        settings.logWindowGeometryBase64.trimmed());
    // Saving the online scanning API Key:
    // - Shares appearance_settings.json with other settings;
    // - Save only user input; do not output the real key in logs.
    rootObject.insert(
        QStringLiteral("virustotal_api_key"),
        settings.virusTotalApiKey.trimmed());
    rootObject.insert(
        QStringLiteral("threatbook_api_key"),
        settings.threatBookApiKey.trimmed());

    const QJsonDocument kJsonDocument(rootObject);
    const QByteArray kJsonBytes = kJsonDocument.toJson(QJsonDocument::Indented);

    QFile settingsFile(kSettingsJsonPath);
    if (!settingsFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("打开设置文件失败: %1").arg(kSettingsJsonPath);
        }
        return false;
    }

    const qint64 kWrittenBytes = settingsFile.write(kJsonBytes);
    settingsFile.close();
    if (kWrittenBytes < 0)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("写入设置文件失败: %1").arg(kSettingsJsonPath);
        }
        return false;
    }

    return true;
}

bool ks::settings::dangerousActionConfirmationsSuppressed()
{
    return loadAppearanceSettings().suppressDangerousActionConfirmations;
}

double ks::settings::normalizeWindowScaleFactor(const double rawScaleFactor)
{
    return clampWindowScaleFactorInternal(rawScaleFactor);
}
