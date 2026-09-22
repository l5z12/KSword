#include "ThemeColorRemap.h"

#include "../Theme.h"

#include <QApplication>
#include <QBrush>
#include <QHash>
#include <QPalette>
#include <QPointer>
#include <QSet>
#include <QWidget>
#include <QWidgetList>

namespace ks::ui
{
    namespace
    {
        // appendThemeColorSeries purpose: Append grouped roles with enumerations to the token table in a fixed order.
        // Two collections must traverse the same code path so that indices correspond one-to-one.
        void appendThemeColorSeries(QList<QColor>& colors)
        {
            using ksword_theme::AccentRole;
            using ksword_theme::PerformanceRole;
            using ksword_theme::TimelineRole;

            const AccentRole kAccentRoles[] = {
                AccentRole::kBlue, AccentRole::kPurple, AccentRole::kGreen, AccentRole::kOrange,
                AccentRole::kCyan, AccentRole::kYellow, AccentRole::kRed, AccentRole::kTeal,
                AccentRole::kIndigo, AccentRole::kBrown, AccentRole::kLime, AccentRole::kSlate,
                AccentRole::kViolet
            };
            for (const AccentRole kRole : kAccentRoles)
            {
                colors.append(ksword_theme::accentColor(kRole));
                colors.append(ksword_theme::accentTextColor(kRole));
            }

            const PerformanceRole kPerformanceRoles[] = {
                PerformanceRole::kCpu, PerformanceRole::kMemory, PerformanceRole::kDisk,
                PerformanceRole::kNetwork, PerformanceRole::kGpu, PerformanceRole::kRead,
                PerformanceRole::kWrite, PerformanceRole::kDedicatedMemory,
                PerformanceRole::kSharedMemory, PerformanceRole::kVideoEncode,
                PerformanceRole::kVideoDecode, PerformanceRole::kCopy
            };
            for (const PerformanceRole kRole : kPerformanceRoles)
            {
                colors.append(ksword_theme::performanceColor(kRole));
            }

            const TimelineRole kTimelineRoles[] = {
                TimelineRole::kProcess, TimelineRole::kThread, TimelineRole::kImage,
                TimelineRole::kFile, TimelineRole::kRegistry, TimelineRole::kNetwork,
                TimelineRole::kDns, TimelineRole::kPowerShell, TimelineRole::kWmi,
                TimelineRole::kSecurity, TimelineRole::kStorage, TimelineRole::kKernel
            };
            for (const TimelineRole kRole : kTimelineRoles)
            {
                colors.append(ksword_theme::timelineColor(kRole));
            }
        }

        // collectThemeColors purpose: Evaluate all theme roles that are 'frozen upon invocation'.
        // Only collect static tokens; dynamic tokens in the palette(...) form are handled by Qt automatically and do not require reimplementation.
        // Registration order determines collision priority, from large areas to small: neutral surfaces -> text -> interactive controls.
        // -> Accent color -> Semantic colors -> Editor and line states -> Chart color schemes. Insert new roles according to this gradient.
        QList<QColor> collectThemeColors()
        {
            QList<QColor> colors;
            colors.reserve(96);

            colors.append(ksword_theme::mainBackgroundColor());
            colors.append(ksword_theme::mainBackgroundTextColor());
            colors.append(ksword_theme::surfaceColor());
            colors.append(ksword_theme::surfaceAltColor());
            colors.append(ksword_theme::surfaceMutedColor());
            colors.append(ksword_theme::borderColor());
            colors.append(ksword_theme::borderStrongColor());
            colors.append(ksword_theme::paletteDarkColor());
            colors.append(ksword_theme::textPrimaryColor());
            colors.append(ksword_theme::textSecondaryColor());
            colors.append(ksword_theme::textDisabledColor());
            colors.append(ksword_theme::onAccentColor());

            colors.append(ksword_theme::controlOutlineColor());
            colors.append(ksword_theme::controlAccentColor());
            colors.append(ksword_theme::controlAccentHoverColor());
            colors.append(ksword_theme::controlAccentPressedColor());
            colors.append(ksword_theme::controlDisabledOutlineColor());
            colors.append(ksword_theme::controlDisabledFillColor());

            colors.append(ksword_theme::primaryAccentColor());
            // accentColor(Blue) is the most frequently used emphasis color style across the project (accentHex(AccentRole::Blue)).
            // In dark themes, it shares the same value as infoColor, but diverges to different new values when switching themes. It must
            // be placed before semantic colors; otherwise, these calls would be assigned to infoColor, which has single-digit usage.
            colors.append(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue));
            colors.append(ksword_theme::accentButtonTextColor());
            colors.append(ksword_theme::primaryBlueSubtleColor());
            colors.append(ksword_theme::primaryBlueSurfacePressedColor());
            colors.append(ksword_theme::activeTabBackgroundColor());
            colors.append(ksword_theme::activeTabTextColor());

            colors.append(ksword_theme::successColor());
            colors.append(ksword_theme::warningColor());
            colors.append(ksword_theme::errorColor());
            colors.append(ksword_theme::infoColor());
            colors.append(ksword_theme::successBackgroundColor());
            colors.append(ksword_theme::warningBackgroundColor());
            colors.append(ksword_theme::errorBackgroundColor());

            colors.append(ksword_theme::editorMatchColor());
            colors.append(ksword_theme::editorCurrentMatchColor());
            colors.append(ksword_theme::editorSelectionColor());
            colors.append(ksword_theme::newRowBackgroundColor());
            colors.append(ksword_theme::exitedRowBackgroundColor());
            colors.append(ksword_theme::exitedRowForegroundColor());

            // The actual accent color brightness variants used in the project: they are not default offsets and must be explicitly registered.
            colors.append(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, 6, -20));
            colors.append(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, -12, -38));
            colors.append(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, -18, -26));
            colors.append(ksword_theme::accentTextColor(
                ksword_theme::AccentRole::kRed,
                ksword_theme::blackColor()));

            appendThemeColorSeries(colors);
            return colors;
        }

        // buildColorMapping: Builds a remapping table from 'old value -> new value'.
        // It is normal for different roles to resolve to the same old value under a specific theme; for example, in the built-in dark
        // theme, the offsets for borderColor and activeTabBackgroundColor are identical. After switching themes, however, they diverge to
        // different new values. In this case, the first new value is taken according to the registration order in collectThemeColors: this
        // order is deliberately set by priority, with neutral surfaces, borders, and text placed before accent colors and chart colors, as
        // they determine the vast majority of the interface area. Skipping this entirely would cause these primary colors to lose their
        // ability to follow changes, a cost far greater than allowing a few small-area exceptions to follow the primary colors.
        QHash<QRgb, QRgb> buildColorMapping(
            const QList<QString>& previousColorTexts,
            const QList<QColor>& currentColors,
            int* ambiguousColorCount)
        {
            QHash<QRgb, QRgb> preferredMapping;
            QSet<QRgb> ambiguousColors;
            const int kPairCount = qMin(previousColorTexts.size(), currentColors.size());
            for (int index = 0; index < kPairCount; ++index)
            {
                const QColor kPreviousColor(previousColorTexts.at(index));
                const QColor kCurrentColor = currentColors.at(index);
                if (!kPreviousColor.isValid() || !kCurrentColor.isValid())
                {
                    continue;
                }
                const QRgb kPreviousValue =
                    qRgb(kPreviousColor.red(), kPreviousColor.green(), kPreviousColor.blue());
                const QRgb kCurrentValue =
                    qRgb(kCurrentColor.red(), kCurrentColor.green(), kCurrentColor.blue());

                const auto kExistingIterator = preferredMapping.constFind(kPreviousValue);
                if (kExistingIterator == preferredMapping.constEnd())
                {
                    preferredMapping.insert(kPreviousValue, kCurrentValue);
                    continue;
                }
                if (kExistingIterator.value() != kCurrentValue)
                {
                    ambiguousColors.insert(kPreviousValue);
                }
            }

            QHash<QRgb, QRgb> colorMapping;
            for (auto iterator = preferredMapping.constBegin();
                iterator != preferredMapping.constEnd();
                ++iterator)
            {
                // Roles with unchanged values do not need rewriting; leaving them in the table only slows down scanning.
                if (iterator.value() != iterator.key())
                {
                    colorMapping.insert(iterator.key(), iterator.value());
                }
            }

            if (ambiguousColorCount != nullptr)
            {
                *ambiguousColorCount = static_cast<int>(ambiguousColors.size());
            }
            return colorMapping;
        }

        bool isHexDigit(const QChar character)
        {
            return (character >= QLatin1Char('0') && character <= QLatin1Char('9'))
                || (character >= QLatin1Char('a') && character <= QLatin1Char('f'))
                || (character >= QLatin1Char('A') && character <= QLatin1Char('F'));
        }

        // formatHexChannels: Write back color values preserving original case and bit width to prevent unnecessary style text flickering.
        QString formatHexChannels(const QRgb colorValue, const bool upperCase)
        {
            const QString kHexText = QStringLiteral("%1%2%3")
                .arg(qRed(colorValue), 2, 16, QLatin1Char('0'))
                .arg(qGreen(colorValue), 2, 16, QLatin1Char('0'))
                .arg(qBlue(colorValue), 2, 16, QLatin1Char('0'));
            return upperCase ? kHexText.toUpper() : kHexText;
        }

        // tryRewriteHexColor purpose: Handles both #RRGGBB and #AARRGGBB formats.
        // Rewrite only when the entire hexadecimal string is exactly 6 or 8 characters; retain original formatting for other lengths.
        bool tryRewriteHexColor(
            const QHash<QRgb, QRgb>& colorMapping,
            const QString& styleText,
            const int hashIndex,
            QString* rewrittenText,
            int* nextIndex)
        {
            int scanIndex = hashIndex + 1;
            while (scanIndex < styleText.size() && isHexDigit(styleText.at(scanIndex)))
            {
                ++scanIndex;
            }
            const int kDigitCount = scanIndex - hashIndex - 1;
            if (kDigitCount != 6 && kDigitCount != 8)
            {
                return false;
            }

            // In 8-digit notation, the first two digits represent the alpha channel; color matching considers only the subsequent RGB values.
            const int kRgbOffset = hashIndex + 1 + (kDigitCount == 8 ? 2 : 0);
            const QString kRgbText = styleText.mid(kRgbOffset, 6);
            bool parsedOk = false;
            const uint kParsedValue = kRgbText.toUInt(&parsedOk, 16);
            if (!parsedOk)
            {
                return false;
            }

            const auto kMappedIterator = colorMapping.constFind(
                qRgb((kParsedValue >> 16) & 0xFF, (kParsedValue >> 8) & 0xFF, kParsedValue & 0xFF));
            if (kMappedIterator == colorMapping.constEnd())
            {
                return false;
            }

            const bool kUpperCase = (kRgbText == kRgbText.toUpper());
            rewrittenText->append(styleText.mid(hashIndex, kRgbOffset - hashIndex));
            rewrittenText->append(formatHexChannels(kMappedIterator.value(), kUpperCase));
            *nextIndex = scanIndex;
            return true;
        }

        // tryRewriteFunctionalColor: Handles both rgb(r,g,b) and rgba(r,g,b,a) formats.
        // Rewrite only the first three channels; the alpha parameter is preserved as-is, so transparency design is not altered by theme switching.
        bool tryRewriteFunctionalColor(
            const QHash<QRgb, QRgb>& colorMapping,
            const QString& styleText,
            const int startIndex,
            QString* rewrittenText,
            int* nextIndex)
        {
            int scanIndex = startIndex;
            if (styleText.mid(scanIndex, 4).compare(QStringLiteral("rgba"), Qt::CaseInsensitive) == 0)
            {
                scanIndex += 4;
            }
            else if (styleText.mid(scanIndex, 3).compare(QStringLiteral("rgb"), Qt::CaseInsensitive) == 0)
            {
                scanIndex += 3;
            }
            else
            {
                return false;
            }
            while (scanIndex < styleText.size() && styleText.at(scanIndex).isSpace())
            {
                ++scanIndex;
            }
            if (scanIndex >= styleText.size() || styleText.at(scanIndex) != QLatin1Char('('))
            {
                return false;
            }
            const int kOpenParenIndex = scanIndex;
            const int kCloseParenIndex = styleText.indexOf(QLatin1Char(')'), kOpenParenIndex + 1);
            if (kCloseParenIndex < 0)
            {
                return false;
            }

            const QString kArgumentText =
                styleText.mid(kOpenParenIndex + 1, kCloseParenIndex - kOpenParenIndex - 1);
            const QList<QStringView> kArgumentParts = QStringView(kArgumentText).split(QLatin1Char(','));
            if (kArgumentParts.size() < 3 || kArgumentParts.size() > 4)
            {
                return false;
            }

            int channelValues[3] = { 0, 0, 0 };
            for (int channelIndex = 0; channelIndex < 3; ++channelIndex)
            {
                bool parsedOk = false;
                channelValues[channelIndex] = kArgumentParts.at(channelIndex).trimmed().toInt(&parsedOk);
                if (!parsedOk || channelValues[channelIndex] < 0 || channelValues[channelIndex] > 255)
                {
                    return false;
                }
            }

            const auto kMappedIterator = colorMapping.constFind(
                qRgb(channelValues[0], channelValues[1], channelValues[2]));
            if (kMappedIterator == colorMapping.constEnd())
            {
                return false;
            }

            const QRgb kMappedColor = kMappedIterator.value();
            rewrittenText->append(styleText.mid(startIndex, kOpenParenIndex + 1 - startIndex));
            rewrittenText->append(QStringLiteral("%1,%2,%3")
                .arg(qRed(kMappedColor))
                .arg(qGreen(kMappedColor))
                .arg(qBlue(kMappedColor)));
            if (kArgumentParts.size() == 4)
            {
                rewrittenText->append(QLatin1Char(','));
                rewrittenText->append(kArgumentParts.at(3).trimmed().toString());
            }
            rewrittenText->append(QLatin1Char(')'));
            *nextIndex = kCloseParenIndex + 1;
            return true;
        }

        // rewriteColorsInText purpose: Perform all rewrites in a single pass.
        // A single pass is necessary: performing QString::replace for each rule individually would chain rules like A->B and B->C into A->C.
        QString rewriteColorsInText(const QHash<QRgb, QRgb>& colorMapping, const QString& styleText)
        {
            if (colorMapping.isEmpty() || styleText.isEmpty())
            {
                return styleText;
            }

            QString rewrittenText;
            rewrittenText.reserve(styleText.size());
            int scanIndex = 0;
            while (scanIndex < styleText.size())
            {
                const QChar kCurrentCharacter = styleText.at(scanIndex);
                int nextIndex = scanIndex;
                if (kCurrentCharacter == QLatin1Char('#')
                    && tryRewriteHexColor(colorMapping, styleText, scanIndex, &rewrittenText, &nextIndex))
                {
                    scanIndex = nextIndex;
                    continue;
                }
                if ((kCurrentCharacter == QLatin1Char('r') || kCurrentCharacter == QLatin1Char('R'))
                    && tryRewriteFunctionalColor(
                        colorMapping, styleText, scanIndex, &rewrittenText, &nextIndex))
                {
                    scanIndex = nextIndex;
                    continue;
                }
                rewrittenText.append(kCurrentCharacter);
                ++scanIndex;
            }
            return rewrittenText;
        }

        // rewritePaletteColors purpose: Rewrite a QPalette set by the control itself.
        // Only iterate over groups/roles where isBrushSet is true: roles not explicitly set still inherit from the QApplication
        // palette and naturally follow the theme; rewriting them would unnecessarily hardcode the inheritance relationship.
        bool rewritePaletteColors(const QHash<QRgb, QRgb>& colorMapping, QWidget* const widget)
        {
            QPalette widgetPalette = widget->palette();
            bool paletteChanged = false;
            for (int groupIndex = 0; groupIndex < QPalette::NColorGroups; ++groupIndex)
            {
                const auto kColorGroup = static_cast<QPalette::ColorGroup>(groupIndex);
                for (int roleIndex = 0; roleIndex < QPalette::NColorRoles; ++roleIndex)
                {
                    const auto kColorRole = static_cast<QPalette::ColorRole>(roleIndex);
                    if (!widgetPalette.isBrushSet(kColorGroup, kColorRole))
                    {
                        continue;
                    }
                    const QBrush kRoleBrush = widgetPalette.brush(kColorGroup, kColorRole);
                    // Gradient or texture brushes are not single colors; looking them up by color would cause incorrect modifications, so skip entirely.
                    if (kRoleBrush.style() != Qt::SolidPattern)
                    {
                        continue;
                    }
                    const QColor kRoleColor = kRoleBrush.color();
                    const auto kMappedIterator = colorMapping.constFind(
                        qRgb(kRoleColor.red(), kRoleColor.green(), kRoleColor.blue()));
                    if (kMappedIterator == colorMapping.constEnd())
                    {
                        continue;
                    }
                    const QRgb kMappedColor = kMappedIterator.value();
                    widgetPalette.setColor(
                        kColorGroup,
                        kColorRole,
                        QColor(
                            qRed(kMappedColor),
                            qGreen(kMappedColor),
                            qBlue(kMappedColor),
                            kRoleColor.alpha()));
                    paletteChanged = true;
                }
            }
            if (paletteChanged)
            {
                widget->setPalette(widgetPalette);
            }
            return paletteChanged;
        }
    }

    ThemeColorSnapshot captureThemeColorSnapshot()
    {
        ThemeColorSnapshot snapshot;
        const QList<QColor> kColors = collectThemeColors();
        snapshot.colorTexts.reserve(kColors.size());
        for (const QColor& color : kColors)
        {
            snapshot.colorTexts.append(ksword_theme::themeColorName(color));
        }
        return snapshot;
    }

    QString remapStaleThemeColorsInText(
        const ThemeColorSnapshot& previousSnapshot,
        const QString& styleText)
    {
        if (previousSnapshot.colorTexts.isEmpty() || styleText.isEmpty())
        {
            return styleText;
        }
        const QHash<QRgb, QRgb> kColorMapping =
            buildColorMapping(previousSnapshot.colorTexts, collectThemeColors(), nullptr);
        return rewriteColorsInText(kColorMapping, styleText);
    }

    ThemeColorRemapResult remapStaleThemeColors(const ThemeColorSnapshot& previousSnapshot)
    {
        ThemeColorRemapResult result;
        if (previousSnapshot.colorTexts.isEmpty())
        {
            return result;
        }

        const QHash<QRgb, QRgb> kColorMapping = buildColorMapping(
            previousSnapshot.colorTexts,
            collectThemeColors(),
            &result.ambiguousColorCount);
        result.mappedColorCount = static_cast<int>(kColorMapping.size());
        if (kColorMapping.isEmpty())
        {
            return result;
        }

        // allWidgets() returns a snapshot of raw pointers, while setStyleSheet / setPalette trigger polish and
        // style recalculation, during which controls may be asynchronously destroyed. Wrapping them all in QPointer
        // upfront and validating during iteration prevents dereferencing a destroyed QWidget later in the process.
        const QWidgetList kWidgetSnapshot = QApplication::allWidgets();
        QList<QPointer<QWidget>> guardedWidgets;
        guardedWidgets.reserve(kWidgetSnapshot.size());
        for (QWidget* const kWidget : kWidgetSnapshot)
        {
            guardedWidgets.append(QPointer<QWidget>(kWidget));
        }

        for (const QPointer<QWidget>& guardedWidget : guardedWidgets)
        {
            QWidget* const kWidget = guardedWidget.data();
            if (kWidget == nullptr)
            {
                continue;
            }
            // Widgets with an explicit setPalette no longer accept QApplication palette updates and must be rewritten individually.
            if (kWidget->testAttribute(Qt::WA_SetPalette)
                && rewritePaletteColors(kColorMapping, kWidget))
            {
                ++result.rewrittenPaletteWidgetCount;
            }

            const QString kCurrentStyleSheet = kWidget->styleSheet();
            if (kCurrentStyleSheet.isEmpty())
            {
                continue;
            }
            ++result.inspectedWidgetCount;
            const QString kRewrittenStyleSheet =
                rewriteColorsInText(kColorMapping, kCurrentStyleSheet);
            if (kRewrittenStyleSheet != kCurrentStyleSheet)
            {
                kWidget->setStyleSheet(kRewrittenStyleSheet);
                ++result.rewrittenWidgetCount;
            }
        }
        return result;
    }
}
