#pragma once

// Central theme helpers for all Qt UI code.
//
// A color used by a widget must be derived from a named theme role and an
// offset.  Keeping the RGB seed and the light/dark offsets here prevents a
// local literal from silently becoming unreadable when the application theme
// changes.

#include <QApplication>
#include <QColor>
#include <QSize>
#include <QString>

#include <cmath>

namespace ksword_theme
{
    inline bool isDarkModeEnabled();

    // Pure icon buttons support only two geometry modes: compact toolbar uses 28x16, while independent or emphasized actions use 32x18.
    // Callers no longer manually combine button dimensions with icon dimensions to prevent similar actions from drifting to 30/34/36px.
    inline QSize compactIconButtonSize()
    {
        return QSize(28, 28);
    }

    inline QSize compactIconSize()
    {
        return QSize(16, 16);
    }

    inline QSize standardIconButtonSize()
    {
        return QSize(32, 32);
    }

    inline QSize standardIconSize()
    {
        return QSize(18, 18);
    }

    template <typename ButtonType>
    inline void applyCompactIconButtonMetrics(ButtonType* button)
    {
        if (button != nullptr)
        {
            button->setFixedSize(compactIconButtonSize());
            button->setIconSize(compactIconSize());
        }
    }

    template <typename ButtonType>
    inline void applyStandardIconButtonMetrics(ButtonType* button)
    {
        if (button != nullptr)
        {
            button->setFixedSize(standardIconButtonSize());
            button->setIconSize(standardIconSize());
        }
    }

    struct RgbOffset
    {
        int red = 0;
        int green = 0;
        int blue = 0;
    };

    // ThemeRgbOffset purpose: Binds dark and light offset values for the same color role into a single group.
    // Both sets of values must be calculated relative to the same base color; the caller cannot pass a single set of values and reuse them for both themes.
    struct ThemeRgbOffset
    {
        RgbOffset dark;
        RgbOffset light;
    };

    inline constexpr RgbOffset uniformOffset(const int value)
    {
        return { value, value, value };
    }

    // uniformThemeOffset: Generates equal RGB offsets independent for dark and light themes.
    // Input parameters are values for dark and light modes respectively; returns a paired configuration suitable for themeOffsetColor.
    inline constexpr ThemeRgbOffset uniformThemeOffset(
        const int darkValue,
        const int lightValue)
    {
        return { uniformOffset(darkValue), uniformOffset(lightValue) };
    }

    inline int clampChannel(const int channelValue)
    {
        return qBound(0, channelValue, 255);
    }

    // offsetColor is the only place where RGB channel arithmetic is allowed.
    // Callers pass a named seed and a named/semantic offset instead of a
    // second hard-coded color for the other theme.
    inline QColor offsetColor(
        const QColor& baseColor,
        const RgbOffset offset,
        const int alphaOverride = -1)
    {
        QColor adjustedColor(
            clampChannel(baseColor.red() + offset.red),
            clampChannel(baseColor.green() + offset.green),
            clampChannel(baseColor.blue() + offset.blue),
            alphaOverride >= 0 ? clampChannel(alphaOverride) : baseColor.alpha());
        return adjustedColor;
    }

    // activeThemeOffset purpose: selects the corresponding set of RGB offsets based on the current theme.
    // Input is a paired configuration; returns the dark or light branch without performing any color arithmetic.
    inline RgbOffset activeThemeOffset(const ThemeRgbOffset& themeOffset)
    {
        return isDarkModeEnabled() ? themeOffset.dark : themeOffset.light;
    }

    // themeOffsetColor purpose: generates the current theme color using the same base color and two independent offset sets.
    // When alphaOverride is negative, preserve the base color's alpha; otherwise, override the alpha.
    inline QColor themeOffsetColor(
        const QColor& baseColor,
        const ThemeRgbOffset& themeOffset,
        const int alphaOverride = -1)
    {
        return offsetColor(baseColor, activeThemeOffset(themeOffset), alphaOverride);
    }

    inline QColor offsetColor(const QColor& baseColor, const int channelOffset)
    {
        return offsetColor(baseColor, uniformOffset(channelOffset));
    }

    inline QColor withAlpha(const QColor& baseColor, const int alphaValue)
    {
        return offsetColor(baseColor, {}, alphaValue);
    }

    // blendColors function: Mixes the overlay color into the base color by overlayWeight/255.
    // Used for 'neutral background + accent color' interaction states to avoid breaking custom theme colors with fixed blue RGB offsets.
    inline QColor blendColors(
        const QColor& baseColor,
        const QColor& overlayColor,
        const int overlayWeight)
    {
        const int kSafeWeight = clampChannel(overlayWeight);
        const int kBaseWeight = 255 - kSafeWeight;
        const auto kBlendChannel = [kBaseWeight, kSafeWeight](
            const int baseChannel,
            const int overlayChannel) {
            return (baseChannel * kBaseWeight + overlayChannel * kSafeWeight + 127) / 255;
        };

        return QColor(
            kBlendChannel(baseColor.red(), overlayColor.red()),
            kBlendChannel(baseColor.green(), overlayColor.green()),
            kBlendChannel(baseColor.blue(), overlayColor.blue()),
            baseColor.alpha());
    }

    inline QColor themeLighterColor(const QColor& baseColor)
    {
        return themeOffsetColor(baseColor, uniformThemeOffset(10, 18));
    }

    inline QColor themeDarkerColor(const QColor& baseColor)
    {
        return themeOffsetColor(baseColor, uniformThemeOffset(-22, -28));
    }

    inline QColor whiteColor(const int alphaValue = 255)
    {
        return QColor(255, 255, 255, clampChannel(alphaValue));
    }

    inline QColor blackColor(const int alphaValue = 255)
    {
        return QColor(0, 0, 0, clampChannel(alphaValue));
    }

    inline QString themeColorName(const QColor& colorValue)
    {
        return colorValue.name(QColor::HexRgb).toUpper();
    }

    // hslLightness purpose: Extracts only the lightness component of HSL.
    // For neutral families, all hierarchy is expressed via lightness; extracting lightness separately allows the theme to determine hue and saturation.
    inline int hslLightness(const QColor& colorValue)
    {
        int hue = 0;
        int saturation = 0;
        int lightness = 0;
        colorValue.getHsl(&hue, &saturation, &lightness);
        return lightness;
    }

    // shiftLightness effect: only the HSL lightness is shifted; hue and saturation remain unchanged.
    // Grayscale colors have a hue of -1; getHsl/setHsl round-trip without extra processing.
    inline QColor shiftLightness(const QColor& baseColor, const int lightnessDelta)
    {
        int hue = 0;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        baseColor.getHsl(&hue, &saturation, &lightness, &alpha);

        QColor shiftedColor;
        shiftedColor.setHsl(hue, saturation, clampChannel(lightness + lightnessDelta), alpha);
        return shiftedColor;
    }

    inline QString rgbaColorName(const QColor& colorValue, const int alphaValue)
    {
        return QStringLiteral("rgba(%1,%2,%3,%4)")
            .arg(colorValue.red())
            .arg(colorValue.green())
            .arg(colorValue.blue())
            .arg(clampChannel(alphaValue));
    }

    inline double relativeLuminance(const QColor& colorValue)
    {
        const auto kLinearize = [](const int channelValue) {
            const double kChannel = static_cast<double>(channelValue) / 255.0;
            return kChannel <= 0.03928
                ? kChannel / 12.92
                : std::pow((kChannel + 0.055) / 1.055, 2.4);
        };

        return 0.2126 * kLinearize(colorValue.red())
            + 0.7152 * kLinearize(colorValue.green())
            + 0.0722 * kLinearize(colorValue.blue());
    }

    inline double contrastRatio(const QColor& firstColor, const QColor& secondColor)
    {
        const double kFirstLuminance = relativeLuminance(firstColor);
        const double kSecondLuminance = relativeLuminance(secondColor);
        const double kBrighter = qMax(kFirstLuminance, kSecondLuminance);
        const double kDarker = qMin(kFirstLuminance, kSecondLuminance);
        return (kBrighter + 0.05) / (kDarker + 0.05);
    }

    // ensureTextContrast keeps the hue where possible, then moves only the
    // HSL lightness until the requested WCAG-style ratio is reached.
    inline QColor ensureTextContrast(
        const QColor& preferredColor,
        const QColor& backgroundColor,
        const double minimumRatio = 4.5)
    {
        QColor candidate = preferredColor;
        candidate.setAlpha(255);
        if (contrastRatio(candidate, backgroundColor) >= minimumRatio)
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);

        const bool kShouldLighten = relativeLuminance(backgroundColor) < 0.5;
        const auto kFindAdjustedColor = [&](const bool lighten) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int kAdjustedLightness = lighten
                    ? qMin(255, lightness + lightnessOffset)
                    : qMax(0, lightness - lightnessOffset);
                adjustedColor.setHsl(hue, saturation, kAdjustedLightness, 255);
                if (contrastRatio(adjustedColor, backgroundColor) >= minimumRatio)
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor kPreferredDirectionColor = kFindAdjustedColor(kShouldLighten);
        if (kPreferredDirectionColor.isValid())
        {
            return kPreferredDirectionColor;
        }

        const QColor kOppositeDirectionColor = kFindAdjustedColor(!kShouldLighten);
        if (kOppositeDirectionColor.isValid())
        {
            return kOppositeDirectionColor;
        }

        const QColor kWhiteColor = whiteColor();
        const QColor kBlackColor = blackColor();
        return contrastRatio(kWhiteColor, backgroundColor) >= contrastRatio(kBlackColor, backgroundColor)
            ? kWhiteColor
            : kBlackColor;
    }

    // ensureTextContrastForBackgrounds ensures that the same foreground color is readable against multiple candidate backgrounds.
    // Calibrating for a single surface is insufficient: the same text role can appear on the window background, panel background, alternating row background,
    // and muted background, which have different brightness levels. Satisfying only one surface causes the text to become indistinct on the others.
    // Handling: First check if the original color already satisfies all backgrounds. If not, preserve the hue and search incrementally along the HSL brightness
    //       axis, taking the first value that meets all backgrounds. If both directions fail, fall back to the more stable option between black and white.
    inline QColor ensureTextContrastForBackgrounds(
        const QColor& preferredColor,
        const QColor* backgroundColors,
        const int backgroundCount,
        const double minimumRatio = 4.5)
    {
        if (backgroundColors == nullptr || backgroundCount <= 0)
        {
            return preferredColor;
        }

        const auto kSatisfiesAll = [&](const QColor& candidateColor) {
            for (int index = 0; index < backgroundCount; ++index)
            {
                if (contrastRatio(candidateColor, backgroundColors[index]) < minimumRatio)
                {
                    return false;
                }
            }
            return true;
        };

        QColor candidate = preferredColor;
        candidate.setAlpha(255);
        if (kSatisfiesAll(candidate))
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);

        // If the background family is generally dark, look for brightness; if generally bright, look for darkness; use average luminance to determine direction.
        double luminanceSum = 0.0;
        for (int index = 0; index < backgroundCount; ++index)
        {
            luminanceSum += relativeLuminance(backgroundColors[index]);
        }
        const bool kShouldLighten = (luminanceSum / backgroundCount) < 0.5;

        const auto kFindAdjustedColor = [&](const bool lighten) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int kAdjustedLightness = lighten
                    ? qMin(255, lightness + lightnessOffset)
                    : qMax(0, lightness - lightnessOffset);
                adjustedColor.setHsl(hue, saturation, kAdjustedLightness, 255);
                if (kSatisfiesAll(adjustedColor))
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor kPreferredDirectionColor = kFindAdjustedColor(kShouldLighten);
        if (kPreferredDirectionColor.isValid())
        {
            return kPreferredDirectionColor;
        }
        const QColor kOppositeDirectionColor = kFindAdjustedColor(!kShouldLighten);
        if (kOppositeDirectionColor.isValid())
        {
            return kOppositeDirectionColor;
        }

        // No hue-brightness combination can satisfy all backgrounds (when the background family spans too widely). Fall
        // back to the 'best of the worst' option in black/white to ensure no completely illegible combinations occur.
        const auto kWorstRatio = [&](const QColor& candidateColor) {
            double worst = 1000.0;
            for (int index = 0; index < backgroundCount; ++index)
            {
                worst = qMin(worst, contrastRatio(candidateColor, backgroundColors[index]));
            }
            return worst;
        };
        return kWorstRatio(whiteColor()) >= kWorstRatio(blackColor()) ? whiteColor() : blackColor();
    }

    // ==============================
    // Theme state and neutral surfaces
    // ==============================

    // ==============================
    // Theme seed generation and per-role cache
    // ==============================

    // ThemeSeedGeneration purpose: increments once for each change in dark/light mode, accent color, or main background seed.
    // Role evaluation under custom themes requires brightness search across multiple backgrounds, taking up to tens of
    // microseconds per operation; these roles are called frame-by-frame and line-by-line in paintEvent and item delegates.
    // The cache invalidates based on this counter, recalculates immediately upon theme switch, and hits directly otherwise.
    inline quint64 themeSeedGeneration = 1;

    inline void invalidateThemeColorCache()
    {
        ++themeSeedGeneration;
    }

    // cachedThemeColor purpose: Store the evaluation result of a role into the slot provided by the caller.
    // The slot is a static thread_local variable exclusive to this role: thread_local ensures each background thread (logging, export)
    // holds its own copy, eliminating the need for locking and preventing reads of partially computed values from other threads.
    template <typename ComputeFunction>
    inline QColor cachedThemeColor(
        QColor& cachedColor,
        quint64& cachedGeneration,
        ComputeFunction computeFunction)
    {
        if (cachedGeneration != themeSeedGeneration || !cachedColor.isValid())
        {
            cachedColor = computeFunction();
            cachedGeneration = themeSeedGeneration;
        }
        return cachedColor;
    }

    inline const char* darkModePropertyKey = "ksword_dark_mode_enabled";

    inline void setDarkModeEnabled(const bool enabled)
    {
        if (qApp != nullptr)
        {
            qApp->setProperty(darkModePropertyKey, enabled);
        }
        invalidateThemeColorCache();
    }

    inline bool isDarkModeEnabled()
    {
        return qApp != nullptr && qApp->property(darkModePropertyKey).toBool();
    }

    // The following configurations for dark/light are independent numeric values for dark and light modes.
    // Each configuration must remain consistent with the base color used by its color function to avoid channel truncation resulting in pure black or pure white.
    inline constexpr ThemeRgbOffset kWindowOffset{
        { -245, -240, -233 },
        { -7, -4, 0 }
    };
    inline constexpr ThemeRgbOffset kSurfaceOffset{
        { -238, -230, -219 },
        { 0, 0, 0 }
    };
    inline constexpr ThemeRgbOffset kSurfaceAltOffset{
        { 7, 10, 14 },
        { -12, -7, 0 }
    };
    inline constexpr ThemeRgbOffset kSurfaceMutedOffset{
        { 13, 18, 24 },
        { -29, -14, 0 }
    };
    inline constexpr ThemeRgbOffset kBorderOffset{
        { 38, 55, 70 },
        { -65, -44, -22 }
    };
    inline constexpr ThemeRgbOffset kBorderStrongOffset{
        { 55, 80, 102 },
        { -104, -65, -24 }
    };
    inline constexpr ThemeRgbOffset kTextPrimaryOffset{
        { -18, -9, 0 },
        { -239, -220, -201 }
    };
    inline constexpr ThemeRgbOffset kTextSecondaryOffset{
        { -76, -52, -11 },
        { -176, -156, -135 }
    };
    inline constexpr ThemeRgbOffset kTextDisabledOffset{
        { -130, -109, -84 },
        { -129, -113, -95 }
    };
    inline constexpr ThemeRgbOffset kPaletteDarkOffset{
        { 3, 5, 6 },
        { -111, -90, -67 }
    };

    inline QColor defaultMainBackgroundColor(const bool darkModeEnabled)
    {
        return offsetColor(
            whiteColor(),
            darkModeEnabled ? kWindowOffset.dark : kWindowOffset.light);
    }

    inline QColor defaultSurfaceColor(const bool darkModeEnabled)
    {
        return offsetColor(
            whiteColor(),
            darkModeEnabled ? kSurfaceOffset.dark : kSurfaceOffset.light);
    }

    inline QColor defaultSurfaceAltColor(const bool darkModeEnabled)
    {
        return offsetColor(
            defaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? kSurfaceAltOffset.dark : kSurfaceAltOffset.light);
    }

    inline QColor defaultSurfaceMutedColor(const bool darkModeEnabled)
    {
        return offsetColor(
            defaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? kSurfaceMutedOffset.dark : kSurfaceMutedOffset.light);
    }

    inline QColor defaultBorderColor(const bool darkModeEnabled)
    {
        return offsetColor(
            defaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? kBorderOffset.dark : kBorderOffset.light);
    }

    inline QColor defaultBorderStrongColor(const bool darkModeEnabled)
    {
        return offsetColor(
            defaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? kBorderStrongOffset.dark : kBorderStrongOffset.light);
    }

    inline QColor defaultPaletteDarkColor(const bool darkModeEnabled)
    {
        return offsetColor(
            defaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? kPaletteDarkOffset.dark : kPaletteDarkOffset.light);
    }

    inline QColor defaultTextPrimaryColor(const bool darkModeEnabled)
    {
        return offsetColor(
            whiteColor(),
            darkModeEnabled ? kTextPrimaryOffset.dark : kTextPrimaryOffset.light);
    }

    inline QColor defaultTextSecondaryColor(const bool darkModeEnabled)
    {
        return offsetColor(
            whiteColor(),
            darkModeEnabled ? kTextSecondaryOffset.dark : kTextSecondaryOffset.light);
    }

    inline QColor defaultTextDisabledColor(const bool darkModeEnabled)
    {
        return offsetColor(
            whiteColor(),
            darkModeEnabled ? kTextDisabledOffset.dark : kTextDisabledOffset.light);
    }

    // CustomMainBackgroundColor is the independent seed for the entire neutral background palette: windows, panels, tables,
    // trees, editors, dialogs, and borders all derive from it; accent colors remain controlled separately by PrimaryBlueColor.
    // Invalid value indicates continuing to use the built-in neutral palette of the current light/dark mode.
    inline QColor customMainBackgroundColor;

    inline void setMainBackgroundColor(const QString& customColorText)
    {
        const QColor kRequestedColor(customColorText.trimmed());
        customMainBackgroundColor = kRequestedColor.isValid()
            ? kRequestedColor.toRgb()
            : QColor();
        invalidateThemeColorCache();
    }

    inline QColor computeMainBackgroundColor()
    {
        return customMainBackgroundColor.isValid()
            ? customMainBackgroundColor
            : defaultMainBackgroundColor(isDarkModeEnabled());
    }

    inline QColor mainBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeMainBackgroundColor);
    }

    inline QColor windowColor()
    {
        return mainBackgroundColor();
    }

    // neutralRoleTone purpose: Map an internal neutral role to the user's main background tone, with brightness determined by the caller.
    //
    // Background: The built-in dark neutral palette is not neutral gray but a full set of deep blue-grays: Window (10,15,22),
    // Border (55,80,106), Strong Border (72,105,138), where the blue channel exceeds the red channel by 12 to 66.
    // Originally, the entire RGB channel difference was shifted to the user's main background; this blue tint was carried over. After setting the main background to
    // pure black, the border calculation still yields (45,65,84), resulting in blue borders and separators appearing everywhere on the black-gray theme interface.
    //
    // Handling: The hue is taken from the user's primary background; the saturation is scaled by the ratio of "user primary background relative to built-in primary background" applied to
    // the role's own saturation. Directly applying the primary background's saturation is not feasible here because HSL expands saturation significantly at low lightness values (e.g., (10,
    // 15, 22) near pure black has a saturation of 96, while the border itself is only 37). Consequently, applying the primary background's saturation to high-lightness roles results in
    // colors that are bluer than the built-in version. Scaling by ratio ensures invariance: when the user's primary background exactly matches the built-in one, the value remains unchanged.
    inline QColor neutralRoleTone(const QColor& defaultRoleColor, const int targetLightness)
    {
        int roleHue = 0;
        int roleSaturation = 0;
        int roleLightness = 0;
        defaultRoleColor.getHsl(&roleHue, &roleSaturation, &roleLightness);

        int backgroundHue = 0;
        int backgroundSaturation = 0;
        int backgroundLightness = 0;
        mainBackgroundColor().getHsl(&backgroundHue, &backgroundSaturation, &backgroundLightness);

        int defaultHue = 0;
        int defaultSaturation = 0;
        int defaultLightness = 0;
        defaultMainBackgroundColor(isDarkModeEnabled())
            .getHsl(&defaultHue, &defaultSaturation, &defaultLightness);

        const int kScaledSaturation = defaultSaturation > 0
            ? clampChannel(roleSaturation * backgroundSaturation / defaultSaturation)
            : 0;
        // The HSL hue for grayscale is -1 (undefined), which Qt uses to represent achromatic colors. When saturation is
        // scaled to 0, the hue value does not affect the result; unify it to -1 to avoid storing a fake angle in the color.
        const int kTonedHue = (backgroundHue < 0 || kScaledSaturation == 0) ? -1 : backgroundHue;

        QColor tonedColor;
        tonedColor.setHsl(kTonedHue, kScaledSaturation, clampChannel(targetLightness), 255);
        return tonedColor;
    }

    // retintedNeutralColor: Preserves the role's own lightness, only moving the hue to the user's main background.
    // For text roles: text lightness is absolute (should be bright in dark themes) and does not shift with the main background.
    inline QColor retintedNeutralColor(const QColor& defaultRoleColor)
    {
        return neutralRoleTone(defaultRoleColor, hslLightness(defaultRoleColor));
    }

    // NeutralLayerMinimumSeparation: The minimum luminance spacing between adjacent neutral layers after desaturation.
    //
    // The built-in neutral family's hierarchy is supported by two dimensions: minimal luminance difference and increasing blue tint. In dark
    // themes, the luminance difference between Surface and PaletteDark is only 4 (luminance contrast 1.031), and between PaletteDark and SurfaceAlt
    // is 6. Human eyes cannot distinguish a 3% luminance difference; what truly distinguishes them is the increasing blue tint: 19→22→26→30→51→66.
    // When the main background is set to grayscale, the hue dimension vanishes entirely, causing these levels to blur together—not an illusion, but
    // the inevitable result of projecting a 2D palette onto 1D. Setting the adjacent spacing to this value restores the weakest adjacent contrast from
    //1.027 to 1.067 (compared to 1.051 with built-in hue), while the brightness of the brightest level remains unchanged, avoiding increased glare.
    //
    // It also incidentally exposes a class of silent failures: desaturation causes roles with different semantics to collapse to the same grayscale value.
    // ThemeColorRemap, looking up by the old value, can no longer distinguish them, causing clashing roles to be mapped to others' new values (in practice,
    //controlAccentColor clashes with controlOutlineColor, causing interactive controls to lose their accent color entirely after switching back to the default theme).
    inline constexpr int kNeutralLayerMinimumSeparation = 10;

    // neutralLayerRank purpose: the position of a role on the neutral family lightness ladder, counting outward from the main background; the closest is 1.
    // Do not hardcode indices: the sort order differs completely between light and dark themes. In dark mode, PaletteDark is adjacent to
    // Surface (2nd tier), while in light mode it is the farthest from the background. Calculate based on the current theme's built-in values.
    inline int neutralLayerRank(const QColor& defaultRoleColor)
    {
        const bool kDarkModeEnabled = isDarkModeEnabled();
        const int kBackgroundLightness = hslLightness(defaultMainBackgroundColor(kDarkModeEnabled));
        const int kRoleDistance = qAbs(hslLightness(defaultRoleColor) - kBackgroundLightness);

        const QColor kFamilyColors[] = {
            defaultSurfaceColor(kDarkModeEnabled),
            defaultPaletteDarkColor(kDarkModeEnabled),
            defaultSurfaceAltColor(kDarkModeEnabled),
            defaultSurfaceMutedColor(kDarkModeEnabled),
            defaultBorderColor(kDarkModeEnabled),
            defaultBorderStrongColor(kDarkModeEnabled)
        };

        int rank = 1;
        for (const QColor& familyColor : kFamilyColors)
        {
            if (qAbs(hslLightness(familyColor) - kBackgroundLightness) < kRoleDistance)
            {
                ++rank;
            }
        }
        return rank;
    }

    // rebasedNeutralRoleColor maps the built-in neutral role's luminance difference relative to the default window to the user's
    // primary background seed. If not customized, it returns the original role color to ensure default theme pixels remain unchanged.
    inline QColor rebasedNeutralRoleColor(const QColor& defaultRoleColor)
    {
        if (!customMainBackgroundColor.isValid())
        {
            return defaultRoleColor;
        }

        // Only transfer the lightness delta. Transferring RGB deltas would incorrectly apply the blue tint of the built-in neutral family to the user's main background; see neutralRoleTone.
        const int kLightnessDelta =
            hslLightness(defaultRoleColor)
            - hslLightness(defaultMainBackgroundColor(isDarkModeEnabled()));

        // Compensation fades linearly with background saturation: when the main background still has hue, the hue helps distinguish layers; adding
        // compensation would deviate from the built-in luminance design. Compensation becomes zero when saturation matches the built-in main background.
        int backgroundHue = 0;
        int backgroundSaturation = 0;
        int backgroundLightness = 0;
        mainBackgroundColor().getHsl(&backgroundHue, &backgroundSaturation, &backgroundLightness);
        int defaultHue = 0;
        int defaultSaturation = 0;
        int defaultLightness = 0;
        defaultMainBackgroundColor(isDarkModeEnabled())
            .getHsl(&defaultHue, &defaultSaturation, &defaultLightness);
        const int kCompensationPermille = defaultSaturation > 0
            ? qBound(0, 1000 - backgroundSaturation * 1000 / defaultSaturation, 1000)
            : 1000;

        const int kSeparation =
            neutralLayerRank(defaultRoleColor)
            * kNeutralLayerMinimumSeparation
            * kCompensationPermille / 1000;
        // Only amplify the distance, not the direction: In light themes, Surface is on the brighter side of the background, while other roles are
        // on the darker side. Following the sign of the original lightness delta prevents pushing any tier to the opposite side of the background.
        const int kBoostedDistance = qMax(qAbs(kLightnessDelta), kSeparation);
        const int kTargetLightness = kLightnessDelta >= 0
            ? backgroundLightness + kBoostedDistance
            : backgroundLightness - kBoostedDistance;

        return neutralRoleTone(defaultRoleColor, kTargetLightness);
    }

    inline QColor computeSurfaceColor()
    {
        return rebasedNeutralRoleColor(defaultSurfaceColor(isDarkModeEnabled()));
    }

    inline QColor surfaceColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeSurfaceColor);
    }

    inline QColor computeSurfaceAltColor()
    {
        return rebasedNeutralRoleColor(defaultSurfaceAltColor(isDarkModeEnabled()));
    }

    inline QColor surfaceAltColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeSurfaceAltColor);
    }

    inline QColor computeSurfaceMutedColor()
    {
        return rebasedNeutralRoleColor(defaultSurfaceMutedColor(isDarkModeEnabled()));
    }

    inline QColor surfaceMutedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeSurfaceMutedColor);
    }

    inline QColor computeBorderColor()
    {
        return rebasedNeutralRoleColor(defaultBorderColor(isDarkModeEnabled()));
    }

    inline QColor borderColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeBorderColor);
    }

    inline QColor computeBorderStrongColor()
    {
        return rebasedNeutralRoleColor(defaultBorderStrongColor(isDarkModeEnabled()));
    }

    inline QColor borderStrongColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeBorderStrongColor);
    }

    inline QColor computePaletteDarkColor()
    {
        return rebasedNeutralRoleColor(defaultPaletteDarkColor(isDarkModeEnabled()));
    }

    inline QColor paletteDarkColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computePaletteDarkColor);
    }

    // neutralSurfaceFamily: Lists the four neutral surfaces that generic text roles actually land on.
    // When text is calibrated only against surfaceColor, if the custom main background pushes SurfaceAlt / SurfaceMuted to a
    // different brightness level, the same text will blend into the background on buttons, alternating rows, and muted areas.
    // Writes to the caller's array as an output parameter and returns the count of valid elements to avoid introducing container dependencies in the header.
    inline int neutralSurfaceFamily(QColor* surfaceBuffer)
    {
        surfaceBuffer[0] = mainBackgroundColor();
        surfaceBuffer[1] = surfaceColor();
        surfaceBuffer[2] = surfaceAltColor();
        surfaceBuffer[3] = surfaceMutedColor();
        return 4;
    }

    // The following three roles only perform contrast calibration when the user defines a custom main background: values from the built-in
    // palette are manually tuned, and the default theme must preserve original pixels without being altered by automatic calibration.
    inline QColor computeTextPrimaryColor()
    {
        const QColor kDefaultTextColor = defaultTextPrimaryColor(isDarkModeEnabled());
        if (!customMainBackgroundColor.isValid())
        {
            return kDefaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int kSurfaceCount = neutralSurfaceFamily(surfaceBuffer);
        // The built-in dark text color is blue-white (237, 246, 255). Contrast calibration adjusts only luminance while preserving hue.
        // Without first shifting the hue to the main background, body text in pure black/gray themes will always appear blue-tinted.
        return ensureTextContrastForBackgrounds(
            retintedNeutralColor(kDefaultTextColor), surfaceBuffer, kSurfaceCount);
    }

    inline QColor textPrimaryColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeTextPrimaryColor);
    }

    inline QColor computeTextSecondaryColor()
    {
        const QColor kDefaultTextColor = defaultTextSecondaryColor(isDarkModeEnabled());
        if (!customMainBackgroundColor.isValid())
        {
            return kDefaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int kSurfaceCount = neutralSurfaceFamily(surfaceBuffer);
        // Secondary text is the most neutral role in the project's blue tone: the built-in value is (179, 203, 244), with the blue channel 65 higher than the red channel.
        return ensureTextContrastForBackgrounds(
            retintedNeutralColor(kDefaultTextColor), surfaceBuffer, kSurfaceCount);
    }

    inline QColor textSecondaryColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeTextSecondaryColor);
    }

    inline QColor computeTextDisabledColor()
    {
        const QColor kDefaultTextColor = defaultTextDisabledColor(isDarkModeEnabled());
        if (!customMainBackgroundColor.isValid())
        {
            return kDefaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int kSurfaceCount = neutralSurfaceFamily(surfaceBuffer);
        // Disabled text is non-critical information, evaluated according to WCAG Graphics/Large Text 3.0.
        return ensureTextContrastForBackgrounds(
            retintedNeutralColor(kDefaultTextColor), surfaceBuffer, kSurfaceCount, 3.0);
    }

    inline QColor textDisabledColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeTextDisabledColor);
    }

    inline QColor computeMainBackgroundTextColor()
    {
        return ensureTextContrast(textPrimaryColor(), mainBackgroundColor());
    }

    inline QColor mainBackgroundTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeMainBackgroundTextColor);
    }

    inline QString windowColorHex() { return themeColorName(windowColor()); }
    inline QString mainBackgroundColorHex() { return themeColorName(mainBackgroundColor()); }
    inline QString mainBackgroundTextColorHex() { return themeColorName(mainBackgroundTextColor()); }
    inline QString surfaceColorHex() { return themeColorName(surfaceColor()); }
    inline QString surfaceAltColorHex() { return themeColorName(surfaceAltColor()); }
    inline QString surfaceMutedColorHex() { return themeColorName(surfaceMutedColor()); }
    inline QString borderColorHex() { return themeColorName(borderColor()); }
    inline QString borderStrongColorHex() { return themeColorName(borderStrongColor()); }
    inline QString textPrimaryColorHex() { return themeColorName(textPrimaryColor()); }
    inline QString textSecondaryColorHex() { return themeColorName(textSecondaryColor()); }
    inline QString textDisabledColorHex() { return themeColorName(textDisabledColor()); }

    // ==============================
    // Named accent seeds and offsets
    // ==============================

    enum class AccentRole
    {
        kBlue,
        kPurple,
        kGreen,
        kOrange,
        kCyan,
        kYellow,
        kRed,
        kTeal,
        kIndigo,
        kBrown,
        kLime,
        kSlate,
        kViolet
    };

    inline QColor defaultPrimaryAccentColor()
    {
        return QColor(67, 160, 255);
    }

    // PrimaryBlueColor is the runtime seed for all blue accent controls. When user-customized, only this seed is
    // replaced; original light/dark theme offsets continue to apply, and other semantic colors remain unaffected.
    inline QColor primaryBlueColor = defaultPrimaryAccentColor();

    inline QColor primaryAccentColor()
    {
        return primaryBlueColor;
    }

    inline void setPrimaryAccentColor(const QString& customColorText)
    {
        const QColor kRequestedColor(customColorText.trimmed());
        primaryBlueColor = kRequestedColor.isValid()
            ? kRequestedColor.toRgb()
            : defaultPrimaryAccentColor();
        invalidateThemeColorCache();
    }

    inline QColor accentSeed(const AccentRole role)
    {
        switch (role)
        {
        case AccentRole::kBlue: return primaryAccentColor();
        case AccentRole::kPurple: return QColor(184, 99, 255);
        case AccentRole::kGreen: return QColor(47, 125, 50);
        case AccentRole::kOrange: return QColor(217, 119, 6);
        case AccentRole::kCyan: return QColor(0, 188, 212);
        case AccentRole::kYellow: return QColor(245, 158, 11);
        case AccentRole::kRed: return QColor(220, 50, 47);
        case AccentRole::kTeal: return QColor(0, 150, 136);
        case AccentRole::kIndigo: return QColor(63, 81, 181);
        case AccentRole::kBrown: return QColor(121, 85, 72);
        case AccentRole::kLime: return QColor(139, 195, 74);
        case AccentRole::kSlate: return QColor(96, 125, 139);
        case AccentRole::kViolet: return QColor(121, 76, 210);
        }
        return primaryAccentColor();
    }

    // accentColor function: Generate accent colors using independent brightness offsets for dark and light themes.
    // When the caller needs to customize brightness, both darkOffset and lightOffset must be provided; reusing a single numeric value is prohibited.
    inline QColor accentColor(
        const AccentRole role,
        const int darkOffset,
        const int lightOffset)
    {
        return themeOffsetColor(
            accentSeed(role),
            uniformThemeOffset(darkOffset, lightOffset));
    }

    // The default accent color explicitly retains two sets of values: increasing brightness for dark backgrounds and slightly decreasing it for light backgrounds.
    inline QColor accentColor(const AccentRole role)
    {
        return accentColor(role, 18, -8);
    }

    inline QColor accentTextColor(
        const AccentRole role,
        const QColor& backgroundColor = QColor())
    {
        const QColor kEffectiveBackground = backgroundColor.isValid()
            ? backgroundColor
            : surfaceColor();
        return ensureTextContrast(accentColor(role), kEffectiveBackground);
    }

    inline QString accentHex(
        const AccentRole role,
        const int darkOffset,
        const int lightOffset)
    {
        return themeColorName(accentColor(role, darkOffset, lightOffset));
    }

    inline QString accentHex(const AccentRole role)
    {
        return themeColorName(accentColor(role));
    }

    inline QColor computeSuccessBackgroundColor();
    inline QColor computeWarningBackgroundColor();
    inline QColor computeErrorBackgroundColor();

    // semanticTextColor purpose: Semantic text color must be readable on both neutral surfaces and its own semantic background.
    // When calibrating only surfaceColor, placing the same 'success green' on alternating row backgrounds or success backgrounds causes it to appear gray.
    // An invalid semanticBackground indicates no dedicated background for this semantic; only neutral surface family is calibrated.
    // The default palette is manually tuned and not auto-calibrated to avoid altering existing pixels of built-in themes.
    inline QColor semanticTextColor(const AccentRole role, const QColor& semanticBackground)
    {
        const QColor kPreferredColor = accentColor(role);
        if (!customMainBackgroundColor.isValid())
        {
            return ensureTextContrast(kPreferredColor, surfaceColor());
        }

        QColor backgroundBuffer[5];
        int backgroundCount = neutralSurfaceFamily(backgroundBuffer);
        if (semanticBackground.isValid())
        {
            backgroundBuffer[backgroundCount] = semanticBackground;
            ++backgroundCount;
        }
        return ensureTextContrastForBackgrounds(kPreferredColor, backgroundBuffer, backgroundCount);
    }

    inline QColor errorBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeErrorBackgroundColor);
    }

    inline QColor warningBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeWarningBackgroundColor);
    }

    inline QColor successBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeSuccessBackgroundColor);
    }

    inline QColor computeSuccessColor() { return semanticTextColor(AccentRole::kGreen, successBackgroundColor()); }

    inline QColor successColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeSuccessColor);
    }
    inline QColor computeWarningColor() { return semanticTextColor(AccentRole::kOrange, warningBackgroundColor()); }

    inline QColor warningColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeWarningColor);
    }
    inline QColor computeErrorColor() { return semanticTextColor(AccentRole::kRed, errorBackgroundColor()); }

    inline QColor errorColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeErrorColor);
    }
    inline QColor computeInfoColor() { return semanticTextColor(AccentRole::kBlue, QColor()); }

    inline QColor infoColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeInfoColor);
    }
    inline QString successHex() { return themeColorName(successColor()); }
    inline QString warningHex() { return themeColorName(warningColor()); }
    inline QString errorHex() { return themeColorName(errorColor()); }
    inline QString infoHex() { return themeColorName(infoColor()); }

    // Semantic backgrounds and editor status colors use independent light/dark RGB offsets, with the base color unified as surfaceColor.
    inline constexpr ThemeRgbOffset kSuccessBackgroundOffset{
        { 8, 32, 14 },
        { -32, 0, -28 }
    };
    inline constexpr ThemeRgbOffset kWarningBackgroundOffset{
        { 38, 24, 4 },
        { 0, -24, -62 }
    };
    inline constexpr ThemeRgbOffset kErrorBackgroundOffset{
        { 36, 4, 4 },
        { 0, -31, -31 }
    };
    inline constexpr ThemeRgbOffset kEditorMatchOffset{
        { 10, 28, 6 },
        { -8, -10, -42 }
    };
    inline constexpr ThemeRgbOffset kEditorCurrentMatchOffset{
        { 20, 62, 10 },
        { -8, -42, -1 }
    };

    // readableStateBackgroundColor purpose: Ensure contrast between row/block status background colors and the main text color.
    // These background colors use 'surfaceColor + fixed RGB offset'. When a custom primary background pushes surfaceColor to medium brightness,
    // adding the offset brings it close to the text color. In this case, the background must be adjusted: the text color may already be near pure
    // white, and further adjustment cannot increase the contrast. The default palette preserves original pixels without automatic calibration.
    // readableSurfaceColor: Pushes the background color away from the text color and disabled text color until both are readable.
    //
    // ensureTextContrast cannot be chained twice: that function determines the push direction based on the 'absolute brightness of the reference
    // color'. In dark themes, it disables text brightness below 0.5, deciding to brighten the background, which exactly counteracts the previous
    // step's darkening and pushes the text color back near the original. The direction must be determined by the relative brightness between the
    // background and text: if the background is naturally on the darker side of the text, continue pushing darker; otherwise, push lighter.
    inline QColor readableSurfaceColor(const QColor& surfaceColor)
    {
        const QColor kPrimaryTextColor = textPrimaryColor();
        const QColor kDisabledTextColor = textDisabledColor();
        const auto kIsReadable = [&](const QColor& candidateColor) {
            return contrastRatio(candidateColor, kPrimaryTextColor) >= 4.5
                && contrastRatio(candidateColor, kDisabledTextColor) >= 3.0;
        };

        QColor candidate = surfaceColor;
        candidate.setAlpha(255);
        if (kIsReadable(candidate))
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);
        const bool kShouldDarken =
            relativeLuminance(candidate) < relativeLuminance(kPrimaryTextColor);

        const auto kFindAdjustedColor = [&](const bool darken) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int kAdjustedLightness = darken
                    ? qMax(0, lightness - lightnessOffset)
                    : qMin(255, lightness + lightnessOffset);
                adjustedColor.setHsl(hue, saturation, kAdjustedLightness, 255);
                if (kIsReadable(adjustedColor))
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor kPreferredDirectionColor = kFindAdjustedColor(kShouldDarken);
        if (kPreferredDirectionColor.isValid())
        {
            return kPreferredDirectionColor;
        }
        const QColor kOppositeDirectionColor = kFindAdjustedColor(!kShouldDarken);
        if (kOppositeDirectionColor.isValid())
        {
            return kOppositeDirectionColor;
        }

        // If no brightness of the same hue can satisfy both foregrounds simultaneously, fall back to the more stable option between black and white.
        const auto kWorstRatio = [&](const QColor& candidateColor) {
            return qMin(
                contrastRatio(candidateColor, kPrimaryTextColor),
                contrastRatio(candidateColor, kDisabledTextColor));
        };
        return kWorstRatio(whiteColor()) >= kWorstRatio(blackColor()) ? whiteColor() : blackColor();
    }

    // readableStateBackgroundColor purpose: ensures readability for row/block state backgrounds.
    // The default palette retains original pixels; calibration occurs only when a custom main background is set.
    inline QColor readableStateBackgroundColor(const QColor& stateBackgroundColor)
    {
        if (!customMainBackgroundColor.isValid())
        {
            return stateBackgroundColor;
        }
        return readableSurfaceColor(stateBackgroundColor);
    }

    inline QColor computeSuccessBackgroundColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kSuccessBackgroundOffset));
    }

    inline QColor computeWarningBackgroundColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kWarningBackgroundOffset));
    }

    inline QColor computeErrorBackgroundColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kErrorBackgroundOffset));
    }

    inline QColor computeEditorMatchColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kEditorMatchOffset));
    }

    inline QColor editorMatchColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeEditorMatchColor);
    }

    inline QColor computeEditorCurrentMatchColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kEditorCurrentMatchOffset));
    }

    inline QColor editorCurrentMatchColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeEditorCurrentMatchColor);
    }

    inline QColor computeEditorSelectionColor()
    {
        return accentColor(AccentRole::kBlue, -2, -28);
    }

    inline QColor editorSelectionColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeEditorSelectionColor);
    }

    // The accent color may be set by the user to a high-brightness color. Selected text must adapt to the actual accent color;
    // it cannot be fixed to white, or readability on bright green, yellow, or similar backgrounds will degrade significantly.
    //
    // The parameterized version is used when the background color is not primaryAccentColor itself: the editor's selected block, the error red
    // background for bracket matching, and the button's pressed-state background are all different from the accent color. Using the parameterless
    // version would apply the foreground calibrated for the accent color to a different background, resulting in a mismatched appearance.
    inline QColor onAccentColor(const QColor& accentBackgroundColor)
    {
        return ensureTextContrast(textPrimaryColor(), accentBackgroundColor);
    }

    inline QColor onAccentColor()
    {
        return onAccentColor(primaryAccentColor());
    }
    inline QString onAccentHex() { return themeColorName(onAccentColor()); }

    inline bool usesBuiltInColorSeeds()
    {
        return !customMainBackgroundColor.isValid()
            && primaryAccentColor() == defaultPrimaryAccentColor();
    }

    inline constexpr ThemeRgbOffset kDefaultActiveTabBackgroundOffset{
        { 38, 55, 70 },
        { -65, -44, -22 }
    };

    // The default theme preserves the original active tab pixel; after customizing any color, the emphasis color takes precedence
    // to avoid blending complementary background colors with the theme color at a low ratio, which would result in a brownish-gray.
    inline QColor computeActiveTabBackgroundColor()
    {
        if (usesBuiltInColorSeeds())
        {
            return themeOffsetColor(surfaceColor(), kDefaultActiveTabBackgroundOffset);
        }
        return accentColor(AccentRole::kBlue, -18, -26);
    }

    inline QColor activeTabBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeActiveTabBackgroundColor);
    }

    inline QColor computeActiveTabTextColor()
    {
        return ensureTextContrast(textPrimaryColor(), activeTabBackgroundColor());
    }

    inline QColor activeTabTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeActiveTabTextColor);
    }

    inline QString activeTabBackgroundHex() { return themeColorName(activeTabBackgroundColor()); }
    inline QString activeTabTextHex() { return themeColorName(activeTabTextColor()); }

    // ==============================
    // Reusable chart roles
    // ==============================

    enum class PerformanceRole
    {
        kCpu,
        kMemory,
        kDisk,
        kNetwork,
        kGpu,
        kRead,
        kWrite,
        kDedicatedMemory,
        kSharedMemory,
        kVideoEncode,
        kVideoDecode,
        kCopy
    };

    inline QColor performanceColor(const PerformanceRole role)
    {
        // Explicitly define dark/light theme offsets for each performance role to prevent theme distortion caused by shared brightness parameters.
        switch (role)
        {
        case PerformanceRole::kCpu: return accentColor(AccentRole::kBlue, 40, 14);
        case PerformanceRole::kMemory: return accentColor(AccentRole::kPurple);
        case PerformanceRole::kDisk: return accentColor(AccentRole::kGreen, 40, 14);
        case PerformanceRole::kNetwork: return accentColor(AccentRole::kOrange, 26, 0);
        case PerformanceRole::kGpu: return accentColor(AccentRole::kBlue, 26, 0);
        case PerformanceRole::kRead: return accentColor(AccentRole::kBlue, 30, 4);
        case PerformanceRole::kWrite: return accentColor(AccentRole::kOrange, 40, 14);
        case PerformanceRole::kDedicatedMemory: return accentColor(AccentRole::kBlue, 30, 4);
        case PerformanceRole::kSharedMemory: return accentColor(AccentRole::kCyan, 22, -4);
        case PerformanceRole::kVideoEncode: return accentColor(AccentRole::kBlue, 36, 10);
        case PerformanceRole::kVideoDecode: return accentColor(AccentRole::kBlue, 48, 22);
        case PerformanceRole::kCopy: return accentColor(AccentRole::kCyan, 36, 10);
        }
        return accentColor(AccentRole::kBlue);
    }

    enum class TimelineRole
    {
        kProcess,
        kThread,
        kImage,
        kFile,
        kRegistry,
        kNetwork,
        kDns,
        kPowerShell,
        kWmi,
        kSecurity,
        kStorage,
        kKernel
    };

    inline QColor timelineColor(const TimelineRole role)
    {
        // Timeline roles also have independent dual-theme configurations; all values are total offsets relative to accentSeed.
        switch (role)
        {
        case TimelineRole::kProcess: return accentColor(AccentRole::kGreen, 40, 14);
        case TimelineRole::kThread: return accentColor(AccentRole::kLime, 26, 0);
        case TimelineRole::kImage: return accentColor(AccentRole::kCyan, 28, 2);
        case TimelineRole::kFile: return accentColor(AccentRole::kBlue, 36, 10);
        case TimelineRole::kRegistry: return accentColor(AccentRole::kPurple, 8, -18);
        case TimelineRole::kNetwork: return accentColor(AccentRole::kOrange, 36, 10);
        case TimelineRole::kDns: return accentColor(AccentRole::kYellow, 26, 0);
        case TimelineRole::kPowerShell: return accentColor(AccentRole::kIndigo, 36, 10);
        case TimelineRole::kWmi: return accentColor(AccentRole::kTeal, 28, 2);
        case TimelineRole::kSecurity: return accentColor(AccentRole::kRed);
        case TimelineRole::kStorage: return accentColor(AccentRole::kBrown, 26, 0);
        case TimelineRole::kKernel: return accentColor(AccentRole::kSlate, 26, 0);
        }
        return accentColor(AccentRole::kBlue);
    }

    // ==============================
    // Compatibility helpers used by existing style builders
    // ==============================

    // These compatibility values are intentionally palette roles: existing QSS
    // builders therefore follow the active light/dark palette at render time.
    inline const QString kPrimaryBlueHex = QStringLiteral("palette(highlight)");
    inline const QString kPrimaryBlueHoverHex = QStringLiteral("palette(highlight)");
    inline const QString kPrimaryBluePressedHex = QStringLiteral("palette(highlight)");
    inline const QString kPrimaryBlueBorderHex = QStringLiteral("palette(highlight)");
    inline const QString kPrimaryBlueActiveHex = QStringLiteral("palette(highlight)");

    inline constexpr ThemeRgbOffset kExitedRowBackgroundOffset{
        { 26, 28, 28 },
        { -19, -13, -7 }
    };
    inline constexpr ThemeRgbOffset kDefaultPrimaryBlueSubtleOffset{
        { 6, 28, 47 },
        { -21, -11, 0 }
    };
    inline constexpr ThemeRgbOffset kDefaultPrimaryBlueSurfacePressedOffset{
        { -1, -1, 26 },
        { -41, -19, 0 }
    };

    inline QColor computePrimaryBlueSubtleColor()
    {
        if (usesBuiltInColorSeeds())
        {
            return themeOffsetColor(surfaceColor(), kDefaultPrimaryBlueSubtleOffset);
        }
        // The blend weight must be low: 'subtle' means 'a surface with a hint of the accent color', not the accent color itself.
        // The original 160/128 (63%/50%) pushes the brightness too close to the accent color, causing the body text to become illegible.
        // 46/38 (18%/15%) matches the visual appearance of the built-in branch surfaceColor+(6,28,47).
        const QColor kBlendedColor = blendColors(
            surfaceColor(),
            primaryAccentColor(),
            isDarkModeEnabled() ? 46 : 38);
        // Extra safety check: a background color blended from a high-saturation accent may still be too close to the body text color.
        // Adjust the background instead of the text to avoid pushing the global text role to an extreme for a single local background.
        return readableSurfaceColor(kBlendedColor);
    }

    inline QColor primaryBlueSubtleColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computePrimaryBlueSubtleColor);
    }

    inline QString primaryBlueSubtleHex()
    {
        return themeColorName(primaryBlueSubtleColor());
    }

    inline QString primaryBlueSolidHoverHex()
    {
        return accentHex(AccentRole::kBlue, 6, -20);
    }

    inline QColor computePrimaryBlueSurfacePressedColor()
    {
        if (usesBuiltInColorSeeds())
        {
            return themeOffsetColor(surfaceColor(), kDefaultPrimaryBlueSurfacePressedOffset);
        }
        // Pressed state must be more obvious than subtle, but still uses 'surface' rather than a solid emphasis color block:
        // The original 196/170 (77%/67%) is already equivalent to the accent color, causing the button text to blend into the background.
        const QColor kBlendedColor = blendColors(
            surfaceColor(),
            primaryAccentColor(),
            isDarkModeEnabled() ? 72 : 60);
        return readableSurfaceColor(kBlendedColor);
    }

    inline QColor primaryBlueSurfacePressedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computePrimaryBlueSurfacePressedColor);
    }

    // accentButtonTextColor purpose: Button text on neutral background buttons that uses only the accent color for text without filling the background.
    // For these buttons (permission badge, R0 badge, test mode button), the background changes to PrimaryBlueSubtle
    // on hover and PrimaryBlueSurfacePressed on press, while the text color remains constant throughout.
    // Calibrating only against surfaceColor would cause the text to blend into the background upon pressing.
    inline QColor computeAccentButtonTextColor()
    {
        QColor backgroundBuffer[3] = {
            surfaceColor(),
            primaryBlueSubtleColor(),
            primaryBlueSurfacePressedColor()
        };
        return ensureTextContrastForBackgrounds(accentColor(AccentRole::kBlue), backgroundBuffer, 3);
    }

    inline QColor accentButtonTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeAccentButtonTextColor);
    }

    inline QString accentButtonTextHex() { return themeColorName(accentButtonTextColor()); }

    // Boundaries and state markers for interactive controls are non-text information and require at least a 3:1 contrast ratio.
    // These roles are exclusively for checkboxes, radio buttons, sliders, and scrollbars; they cannot be directly reused for standard panel borders.
    inline QColor computeControlOutlineColor()
    {
        return ensureTextContrast(borderStrongColor(), surfaceColor(), 3.0);
    }

    inline QColor controlOutlineColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlOutlineColor);
    }

    // ControlAccentOutlineSeparation: The luminance distance by which the control accent color must be brighter or darker than the neutral outline color.
    // In grayscale themes, the accent color and outline color are pushed to the same value by calibration 3.0: the fill color for checked
    // checkboxes, radio buttons, and sliders equals the unchecked outline color, making the checked state visually indistinguishable.
    // This distance also allows ThemeColorRemap to keep these two roles separate — it performs lookups by color
    // value, and once the two roles collide into the same value, one is silently remapped to the other's new value.
    inline constexpr int kControlAccentOutlineSeparation = 26;

    inline QColor computeControlAccentColor()
    {
        const QColor kAccentColor = ensureTextContrast(primaryAccentColor(), surfaceColor(), 3.0);
        const QColor kOutlineColor = controlOutlineColor();

        // The accent color must stand out more than the outline: shift towards lighter in dark themes, and darker in light themes.
        const int kDirection = isDarkModeEnabled() ? 1 : -1;
        const int kCurrentDistance = kDirection * (hslLightness(kAccentColor) - hslLightness(kOutlineColor));
        if (kCurrentDistance >= kControlAccentOutlineSeparation)
        {
            // Under the color theme, the two values are inherently distinct; keep the values unchanged.
            return kAccentColor;
        }

        const QColor kSeparatedColor = shiftLightness(
            kAccentColor,
            kDirection * kControlAccentOutlineSeparation - (hslLightness(kAccentColor) - hslLightness(kOutlineColor)));
        // After pushing, maintain a 3.0 contrast ratio against the surface; otherwise, pushing a light theme too dark may cause it to blend into the surface.
        return ensureTextContrast(kSeparatedColor, surfaceColor(), 3.0);
    }

    inline QColor controlAccentColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlAccentColor);
    }

    inline QColor computeControlAccentHoverColor()
    {
        return ensureTextContrast(
            accentColor(AccentRole::kBlue, 6, -20),
            surfaceColor(),
            3.0);
    }

    inline QColor controlAccentHoverColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlAccentHoverColor);
    }

    inline QColor computeControlAccentPressedColor()
    {
        return ensureTextContrast(
            primaryBlueSurfacePressedColor(),
            surfaceColor(),
            3.0);
    }

    inline QColor controlAccentPressedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlAccentPressedColor);
    }

    inline QColor computeControlDisabledOutlineColor()
    {
        return ensureTextContrast(textDisabledColor(), surfaceColor(), 3.0);
    }

    inline QColor controlDisabledOutlineColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlDisabledOutlineColor);
    }

    inline QColor computeControlDisabledFillColor()
    {
        const QColor kMutedAccentColor = blendColors(
            surfaceMutedColor(),
            controlAccentColor(),
            isDarkModeEnabled() ? 72 : 56);
        return ensureTextContrast(kMutedAccentColor, surfaceColor(), 3.0);
    }

    inline QColor controlDisabledFillColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeControlDisabledFillColor);
    }

    inline QColor maximumContrastMonochromeColor(const QColor& backgroundColor)
    {
        return contrastRatio(whiteColor(), backgroundColor)
                >= contrastRatio(blackColor(), backgroundColor)
            ? whiteColor()
            : blackColor();
    }

    inline QString controlOutlineHex() { return themeColorName(controlOutlineColor()); }
    inline QString controlAccentHex() { return themeColorName(controlAccentColor()); }
    inline QString controlAccentHoverHex() { return themeColorName(controlAccentHoverColor()); }
    inline QString controlAccentPressedHex() { return themeColorName(controlAccentPressedColor()); }
    inline QString controlDisabledOutlineHex() { return themeColorName(controlDisabledOutlineColor()); }
    inline QString controlDisabledFillHex() { return themeColorName(controlDisabledFillColor()); }

    // This group returns QSS dynamic palette roles, not color values. They can only be written into style sheets.
    // Rich text for QLabel/QTextEdit uses QTextDocument; its CSS parser does not recognize palette(...) (that is a QSS-specific
    // extension). The entire declaration is ignored, text falls back to inherited colors, and no error is reported.
    // For rich text, QPainter drawing, and colors passed to other processes, always use *ColorHex().
    inline QString surfaceHex() { return QStringLiteral("palette(base)"); }
    inline QString surfaceAltHex() { return QStringLiteral("palette(alternate-base)"); }
    inline QString borderHex() { return QStringLiteral("palette(mid)"); }
    inline QString textPrimaryHex() { return QStringLiteral("palette(text)"); }
    // Secondary text must use the dedicated dynamic text role; palette(mid) is a border color with insufficient contrast on dark backgrounds.
    inline QString textSecondaryHex() { return QStringLiteral("palette(placeholder-text)"); }
    // onAccentDynamicHex: Text color on top of the accent color, retrieved from the palette role rather than evaluated on the spot.
    // Note: applyAppearanceSettings sets QPalette::HighlightedText to onAccentColor(), so both values are consistent.
    // This version follows theme changes, making it suitable for QSS that is applied once during construction and never rebuilt.
    inline QString onAccentDynamicHex() { return QStringLiteral("palette(highlighted-text)"); }

    // The following three roles are written into the QApplication palette in mainWindow::applyAppearanceSettings:
    //   QPalette::Window   = mainBackgroundColor()
    //   QPalette::windowText = mainBackgroundTextColor()
    //   QPalette::Midlight = borderStrongColor()
    // Therefore, these three colors can naturally be expressed via dynamic roles, with values identical to the corresponding *ColorHex() functions;
    // the only difference is that they follow theme switches. QSS that is constructed once at initialization and never rebuilt should prefer this set.
    inline QString mainBackgroundHex() { return QStringLiteral("palette(window)"); }
    inline QString mainBackgroundTextHex() { return QStringLiteral("palette(window-text)"); }
    inline QString borderStrongHex() { return QStringLiteral("palette(midlight)"); }

    // SurfaceMuted and TextDisabled have no corresponding dynamic roles: QSS's palette(...) can only select roles from
    // the current group, not the disabled group, and the remaining free roles (light/bright-text/shadow) are used by
    // QStyle for rendering native control bevels. Repurposing them would alter the appearance of non-QSS controls.
    // These two colors must continue using *ColorHex(), so pages using them must handle entry reconstruction
    // themselves (via changeEvent handling for ApplicationPaletteChange, or by regenerating styles on each display).

    // ControlCornerRadius: Unifies the rounded corners of the outline for buttons, combo box bodies, and combo box popups.
    inline constexpr int kControlCornerRadius = 3;

    inline QString themedButtonStyle()
    {
        return QStringLiteral(
            "QPushButton,QToolButton{"
            "background-color:%1 !important;color:%2 !important;border:1px solid %3 !important;"
            "border-radius:%8px;padding:4px 10px;font-weight:600;}"
            "QPushButton:hover,QToolButton:hover{background-color:%4 !important;color:%5 !important;border-color:%4 !important;}"
            "QPushButton:pressed,QToolButton:pressed{background-color:%6 !important;color:%5 !important;border-color:%6 !important;}"
            "QPushButton:disabled,QToolButton:disabled{background-color:%1 !important;color:%7 !important;border-color:%3 !important;}")
            .arg(surfaceAltHex())
            .arg(textPrimaryHex())
            .arg(borderHex())
            .arg(primaryBlueSolidHoverHex())
            .arg(onAccentHex())
            .arg(kPrimaryBluePressedHex)
            .arg(textSecondaryHex())
            .arg(kControlCornerRadius);
    }

    // themedComboBoxPopupViewStyle / themedComboBoxStyle purpose:
    // - Provide the same opaque surface, arrow area, and popup list rules for standard, editable, and embedded-in-table combo boxes.
    // - Popup uses an explicit base surface to avoid top-level windows falling back to the platform's default transparent/black background.
    // - All interactive borders and selected states use Control* roles, updating synchronously with custom theme colors and the main background color.
    inline QString themedComboBoxPopupViewStyle()
    {
        const QColor kAccentColor = controlAccentColor();
        const QString kSurfaceColor = surfaceColorHex();
        const QString kTextColor = textPrimaryColorHex();
        const QString kOutlineColor = controlOutlineHex();
        const QString kHoverColor = surfaceAltColorHex();
        const QString kAccentColorText = themeColorName(kAccentColor);
        const QString kAccentTextColor = themeColorName(maximumContrastMonochromeColor(kAccentColor));

        return QStringLiteral(
            "QAbstractItemView{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  border-radius:%7px;"
            "  selection-background-color:%5 !important;"
            "  selection-color:%6 !important;"
            "  outline:0;"
            "}"
            "QAbstractScrollArea::viewport{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "}"
            "QAbstractItemView::item{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  min-height:22px;"
            "  padding:2px 6px;"
            "}"
            "QAbstractItemView::item:hover{"
            "  background:%4 !important;"
            "  background-color:%4 !important;"
            "  color:%2 !important;"
            "}"
            "QAbstractItemView::item:selected{"
            "  background:%5 !important;"
            "  background-color:%5 !important;"
            "  color:%6 !important;"
            "}")
            .arg(kSurfaceColor)
            .arg(kTextColor)
            .arg(kOutlineColor)
            .arg(kHoverColor)
            .arg(kAccentColorText)
            .arg(kAccentTextColor)
            .arg(kControlCornerRadius);
    }

    inline QString themedComboBoxStyle()
    {
        const QColor kAccentColor = controlAccentColor();
        const QString kSurfaceColor = surfaceColorHex();
        const QString kSurfaceAltColor = surfaceAltColorHex();
        const QString kSurfaceMutedColor = surfaceMutedColorHex();
        const QString kTextColor = textPrimaryColorHex();
        const QString kDisabledTextColor = textDisabledColorHex();
        const QString kOutlineColor = controlOutlineHex();
        const QString kAccentColorText = themeColorName(kAccentColor);
        const QString kAccentHoverColor = controlAccentHoverHex();
        const QString kAccentPressedColor = controlAccentPressedHex();
        const QString kDisabledOutlineColor = controlDisabledOutlineHex();
        const QString kAccentTextColor = themeColorName(maximumContrastMonochromeColor(kAccentColor));
        const auto kArrowPathForBackground = [](const QColor& backgroundColor) {
            return maximumContrastMonochromeColor(backgroundColor) == whiteColor()
                ? QStringLiteral(":/Icon/ks_control_down_white.svg")
                : QStringLiteral(":/Icon/ks_control_down_black.svg");
        };
        const QString kArrowPath = kArrowPathForBackground(surfaceAltColor());
        const QString kDisabledArrowPath = kArrowPathForBackground(surfaceMutedColor());

        return QStringLiteral(
            "QComboBox{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  border:1px solid %6 !important;"
            "  border-radius:%14px;"
            "  padding:2px 24px 2px 6px;"
            "  min-height:22px;"
            "  selection-background-color:%7 !important;"
            "  selection-color:%11 !important;"
            "}"
            "QComboBox:hover{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  color:%4 !important;"
            "  border-color:%8 !important;"
            "}"
            "QComboBox:focus,QComboBox:on{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  border-color:%9 !important;"
            "}"
            "QComboBox:disabled{"
            "  background:%3 !important;"
            "  background-color:%3 !important;"
            "  color:%5 !important;"
            "  border-color:%10 !important;"
            "}"
            "QComboBox::drop-down{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  border:none !important;"
            "  border-left:1px solid %6 !important;"
            "  width:20px;"
            "}"
            "QComboBox::drop-down:disabled{"
            "  background:%3 !important;"
            "  background-color:%3 !important;"
            "  border-left-color:%10 !important;"
            "}"
            "QComboBox::down-arrow{"
            "  image:url(%12);"
            "  width:12px;"
            "  height:12px;"
            "  margin-right:4px;"
            "  subcontrol-origin:padding;"
            "  subcontrol-position:center right;"
            "}"
            "QComboBox::down-arrow:disabled{image:url(%13);}"
            "QComboBox QAbstractItemView{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%1 !important;"
            "  color:%4 !important;"
            "  border:1px solid %6 !important;"
            "  border-radius:%14px;"
            "  selection-background-color:%7 !important;"
            "  selection-color:%11 !important;"
            "  outline:0;"
            "}"
            "QComboBox QAbstractItemView::viewport{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "}"
            "QComboBox QAbstractItemView::item{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  min-height:22px;"
            "  padding:2px 6px;"
            "}"
            "QComboBox QAbstractItemView::item:hover{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  color:%4 !important;"
            "}"
            "QComboBox QAbstractItemView::item:selected{"
            "  background:%7 !important;"
            "  background-color:%7 !important;"
            "  color:%11 !important;"
            "}")
            .arg(kSurfaceColor)
            .arg(kSurfaceAltColor)
            .arg(kSurfaceMutedColor)
            .arg(kTextColor)
            .arg(kDisabledTextColor)
            .arg(kOutlineColor)
            .arg(kAccentColorText)
            .arg(kAccentHoverColor)
            .arg(kAccentPressedColor)
            .arg(kDisabledOutlineColor)
            .arg(kAccentTextColor)
            .arg(kArrowPath)
            .arg(kDisabledArrowPath)
            .arg(kControlCornerRadius);
    }

    inline QString contextMenuStyle()
    {
        return QStringLiteral(
            "QMenu{background-color:%1 !important;color:%2 !important;border:1px solid %3 !important;padding:3px;}"
            "QMenu::item{color:%2 !important;padding:5px 18px 5px 14px;background-color:transparent !important;}"
            "QMenu::item:selected{background-color:%4 !important;color:%5 !important;}"
            "QMenu::item:disabled{color:%6 !important;background-color:transparent !important;}"
            "QMenu::separator{height:1px;background-color:%3;margin:2px 6px;}")
            .arg(surfaceColorHex())
            .arg(textPrimaryColorHex())
            .arg(borderColorHex())
            .arg(kPrimaryBlueHex)
            .arg(onAccentHex())
            .arg(textDisabledColorHex());
    }

    inline QString opaqueDialogStyle(const QString& dialogObjectName)
    {
        if (dialogObjectName.trimmed().isEmpty())
        {
            return QString();
        }

        return QStringLiteral(
            "QDialog#%1{background-color:palette(window) !important;color:palette(text) !important;}"
            "QDialog#%1 QPlainTextEdit,QDialog#%1 QTextEdit,QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,QDialog#%1 QAbstractScrollArea,QDialog#%1 QAbstractScrollArea::viewport{"
            "background-color:palette(base) !important;color:palette(text) !important;}"
            "QDialog#%1 QHeaderView::section{background:transparent !important;background-color:transparent !important;color:palette(text) !important;}"
            "QDialog#%1 QMenu{background-color:palette(base) !important;color:palette(text) !important;border:1px solid palette(mid) !important;}"
            "QDialog#%1 QMenu::item:selected{background-color:%2 !important;color:%3 !important;}"
            "QDialog#%1 QMenu::separator{height:1px;background-color:palette(mid) !important;}")
            .arg(dialogObjectName)
            .arg(kPrimaryBlueHex)
            .arg(onAccentHex());
    }

    inline QColor newRowBackgroundColor() { return successBackgroundColor(); }
    inline QColor computeExitedRowBackgroundColor()
    {
        return readableStateBackgroundColor(
            themeOffsetColor(surfaceColor(), kExitedRowBackgroundOffset));
    }

    inline QColor exitedRowBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return cachedThemeColor(cachedColor, cachedGeneration, &computeExitedRowBackgroundColor);
    }
    inline QColor exitedRowForegroundColor() { return textSecondaryColor(); }
    inline QColor warningAccentColor() { return warningColor(); }
} // namespace ksword_theme
