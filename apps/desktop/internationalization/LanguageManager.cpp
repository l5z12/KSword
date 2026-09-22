#include "LanguageManager.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QChildEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QDoubleSpinBox>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QMutex>
#include <QMutexLocker>
#include <QPlainTextEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QScopedValueRollback>
#include <QSet>
#include <QTabWidget>
#include <QSpinBox>
#include <QTableView>
#include <QTextEdit>
#include <QTimer>
#include <QToolBox>
#include <QTreeView>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace
{
    constexpr auto kLanguagePackSchema = "ksword-language-pack";
    constexpr int kLanguagePackFormatVersion = 1;
    constexpr qint64 kMaximumLanguagePackBytes = 32 * 1024 * 1024;
    constexpr auto kSystemLanguagePreferenceId = "system";
    constexpr auto kEnglishFallbackLanguageId = "en-US";
    constexpr auto kProductFallbackLanguageId = "zh-CN";
    constexpr int kComboKeyRole = Qt::UserRole + 91;
    constexpr int kComboFallbackRole = Qt::UserRole + 92;

    constexpr auto kTextKeyProperty = "ks_i18n_text_key";
    constexpr auto kTextFallbackProperty = "ks_i18n_text_fallback";
    constexpr auto kToolTipKeyProperty = "ks_i18n_tooltip_key";
    constexpr auto kToolTipFallbackProperty = "ks_i18n_tooltip_fallback";
    constexpr auto kPlaceholderKeyProperty = "ks_i18n_placeholder_key";
    constexpr auto kPlaceholderFallbackProperty = "ks_i18n_placeholder_fallback";
    constexpr auto kSuffixKeyProperty = "ks_i18n_suffix_key";
    constexpr auto kSuffixFallbackProperty = "ks_i18n_suffix_fallback";
    constexpr auto kWindowTitleKeyProperty = "ks_i18n_window_title_key";
    constexpr auto kWindowTitleFallbackProperty = "ks_i18n_window_title_fallback";
    constexpr auto kTabKeyProperty = "ks_i18n_tab_key";
    constexpr auto kTabFallbackProperty = "ks_i18n_tab_fallback";
    constexpr auto kTabToolTipKeyProperty = "ks_i18n_tab_tooltip_key";
    constexpr auto kTabToolTipFallbackProperty = "ks_i18n_tab_tooltip_fallback";

    constexpr auto kRuntimeRefreshPendingProperty = "ks_i18n_runtime_refresh_pending";
    constexpr auto kRuntimeWindowTitleSourceProperty = "ks_i18n_runtime_window_title_source";
    constexpr auto kRuntimeWindowTitleAppliedProperty = "ks_i18n_runtime_window_title_applied";
    constexpr auto kRuntimeToolTipSourceProperty = "ks_i18n_runtime_tooltip_source";
    constexpr auto kRuntimeToolTipAppliedProperty = "ks_i18n_runtime_tooltip_applied";
    constexpr auto kRuntimeStatusTipSourceProperty = "ks_i18n_runtime_status_tip_source";
    constexpr auto kRuntimeStatusTipAppliedProperty = "ks_i18n_runtime_status_tip_applied";
    constexpr auto kRuntimeWhatsThisSourceProperty = "ks_i18n_runtime_whats_this_source";
    constexpr auto kRuntimeWhatsThisAppliedProperty = "ks_i18n_runtime_whats_this_applied";
    constexpr auto kRuntimeAccessibleNameSourceProperty = "ks_i18n_runtime_accessible_name_source";
    constexpr auto kRuntimeAccessibleNameAppliedProperty = "ks_i18n_runtime_accessible_name_applied";
    constexpr auto kRuntimeAccessibleDescriptionSourceProperty = "ks_i18n_runtime_accessible_description_source";
    constexpr auto kRuntimeAccessibleDescriptionAppliedProperty = "ks_i18n_runtime_accessible_description_applied";
    constexpr auto kRuntimeTextSourceProperty = "ks_i18n_runtime_text_source";
    constexpr auto kRuntimeTextAppliedProperty = "ks_i18n_runtime_text_applied";
    constexpr auto kRuntimeTitleSourceProperty = "ks_i18n_runtime_title_source";
    constexpr auto kRuntimeTitleAppliedProperty = "ks_i18n_runtime_title_applied";
    constexpr auto kRuntimePlaceholderSourceProperty = "ks_i18n_runtime_placeholder_source";
    constexpr auto kRuntimePlaceholderAppliedProperty = "ks_i18n_runtime_placeholder_applied";
    constexpr auto kRuntimePrefixSourceProperty = "ks_i18n_runtime_prefix_source";
    constexpr auto kRuntimePrefixAppliedProperty = "ks_i18n_runtime_prefix_applied";
    constexpr auto kRuntimeSuffixSourceProperty = "ks_i18n_runtime_suffix_source";
    constexpr auto kRuntimeSuffixAppliedProperty = "ks_i18n_runtime_suffix_applied";
    constexpr auto kRuntimeSpecialValueSourceProperty = "ks_i18n_runtime_special_value_source";
    constexpr auto kRuntimeSpecialValueAppliedProperty = "ks_i18n_runtime_special_value_applied";
    constexpr auto kRuntimeTabSourceProperty = "ks_i18n_runtime_tab_source";
    constexpr auto kRuntimeTabAppliedProperty = "ks_i18n_runtime_tab_applied";
    constexpr auto kRuntimeTabToolTipSourceProperty = "ks_i18n_runtime_tab_tooltip_source";
    constexpr auto kRuntimeTabToolTipAppliedProperty = "ks_i18n_runtime_tab_tooltip_applied";
    constexpr int kRuntimeComboSourceRole = Qt::UserRole + 1517;
    constexpr int kRuntimeComboAppliedRole = Qt::UserRole + 1518;
    constexpr int kRuntimeHeaderSourceRole = Qt::UserRole + 1519;
    constexpr int kRuntimeHeaderAppliedRole = Qt::UserRole + 1520;
    constexpr int kRuntimeModelSourceRole = Qt::UserRole + 1521;
    constexpr int kRuntimeModelAppliedRole = Qt::UserRole + 1522;

    // containsHanCharacters: Checks if the text contains Chinese characters (CJK Unified Ideographs and Extension A within the BMP).
    bool containsHanCharacters(const QStringView text)
    {
        for (const QChar kUnit : text)
        {
            const ushort kCode = kUnit.unicode();
            if ((kCode >= 0x3400 && kCode <= 0x4DBF) || (kCode >= 0x4E00 && kCode <= 0x9FFF))
            {
                return true;
            }
        }
        return false;
    }

    bool isAsciiDigit(const QChar unit)
    {
        return unit.unicode() >= u'0' && unit.unicode() <= u'9';
    }

    // findPlaceholder:
    // - Finds the next placeholder starting from 'from'; syntax equivalent to regex %(?:L?\d+|n)|\{\d+\};
    // - Replace regex with handwritten scanning to eliminate the resident memory usage of thousands of compiled regexes per package.
    // - Returns true with startOut/lengthOut indicating the placeholder position.
    bool findPlaceholder(
        const QStringView text,
        const qsizetype from,
        qsizetype* startOut,
        qsizetype* lengthOut)
    {
        const qsizetype kSize = text.size();
        for (qsizetype index = from; index < kSize; ++index)
        {
            const QChar kCurrent = text[index];
            if (kCurrent == u'%')
            {
                qsizetype cursor = index + 1;
                if (cursor < kSize && text[cursor] == u'n')
                {
                    *startOut = index;
                    *lengthOut = 2;
                    return true;
                }
                if (cursor < kSize && text[cursor] == u'L')
                {
                    ++cursor;
                }
                const qsizetype kDigitsBegin = cursor;
                while (cursor < kSize && isAsciiDigit(text[cursor]))
                {
                    ++cursor;
                }
                if (cursor > kDigitsBegin)
                {
                    *startOut = index;
                    *lengthOut = cursor - index;
                    return true;
                }
            }
            else if (kCurrent == u'{')
            {
                qsizetype cursor = index + 1;
                while (cursor < kSize && isAsciiDigit(text[cursor]))
                {
                    ++cursor;
                }
                if (cursor > index + 1 && cursor < kSize && text[cursor] == u'}')
                {
                    *startOut = index;
                    *lengthOut = cursor + 1 - index;
                    return true;
                }
            }
        }
        return false;
    }

    struct ManagedTextResult
    {
        QString sourceText;
        QString appliedText;
        bool setText = false;
        bool updateMetadata = false;
        bool clearMetadata = false;
    };

    ManagedTextResult resolveManagedText(
        const ks::i18n::LanguageManager& languageManager,
        const QString& currentText,
        const QVariant& sourceValue,
        const QVariant& appliedValue,
        const bool allowRenderedSource = true)
    {
        ManagedTextResult result;
        const bool kHasSource = sourceValue.isValid();
        const bool kIsLastAppliedValue = appliedValue.isValid()
            && currentText == appliedValue.toString();

        QString sourceText;
        if (!kHasSource)
        {
            if (containsHanCharacters(currentText))
            {
                sourceText = currentText;
            }
            else if (allowRenderedSource)
            {
                sourceText = languageManager.sourceForRenderedText(currentText);
                if (sourceText.isEmpty())
                {
                    return result;
                }
            }
            else
            {
                return result;
            }
        }
        else if (kIsLastAppliedValue)
        {
            sourceText = sourceValue.toString();
        }
        else
        {
            // A caller replaced a previously translated property. Treat a new
            // Chinese value as the next source string; non-Chinese content is
            // user/runtime data and must no longer be managed by this fallback.
            if (!containsHanCharacters(currentText))
            {
                result.clearMetadata = true;
                return result;
            }
            sourceText = currentText;
        }

        result.sourceText = sourceText;
        result.appliedText = languageManager.sourceText(sourceText);
        if (!kHasSource && result.appliedText == sourceText)
        {
            // Unknown Chinese text can be user data (for example a path or a
            // file name). Only manage text for which the active language pack
            // supplies an actual translation.
            return ManagedTextResult{};
        }
        result.setText = currentText != result.appliedText;
        result.updateMetadata = result.setText
            || !sourceValue.isValid()
            || sourceValue.toString() != result.sourceText
            || !appliedValue.isValid()
            || appliedValue.toString() != result.appliedText;
        return result;
    }

    template <typename Setter>
    void applyManagedObjectText(
        const ks::i18n::LanguageManager& languageManager,
        QObject* storageObject,
        const char* sourceProperty,
        const char* appliedProperty,
        const QString& currentText,
        Setter&& setter)
    {
        if (storageObject == nullptr)
        {
            return;
        }

        const ManagedTextResult kResult = resolveManagedText(
            languageManager,
            currentText,
            storageObject->property(sourceProperty),
            storageObject->property(appliedProperty));
        if (kResult.clearMetadata)
        {
            storageObject->setProperty(sourceProperty, QVariant());
            storageObject->setProperty(appliedProperty, QVariant());
            return;
        }
        if (!kResult.updateMetadata)
        {
            return;
        }
        if (kResult.setText)
        {
            setter(kResult.appliedText);
        }
        storageObject->setProperty(sourceProperty, kResult.sourceText);
        storageObject->setProperty(appliedProperty, kResult.appliedText);
    }

    QObject* runtimeTranslationRoot(QObject* object)
    {
        if (QWidget* widget = qobject_cast<QWidget*>(object))
        {
            return widget->window() != nullptr ? widget->window() : widget;
        }

        QObject* currentObject = object;
        while (currentObject != nullptr)
        {
            if (QWidget* parentWidget = qobject_cast<QWidget*>(currentObject))
            {
                return parentWidget->window() != nullptr ? parentWidget->window() : parentWidget;
            }
            currentObject = currentObject->parent();
        }
        return object;
    }

    void appendUniqueDirectory(QStringList* directoryList, const QString& directoryPath)
    {
        if (directoryList == nullptr)
        {
            return;
        }

        const QString kNormalizedPath = QDir::cleanPath(directoryPath.trimmed());
        if (!kNormalizedPath.isEmpty() && !directoryList->contains(kNormalizedPath, Qt::CaseInsensitive))
        {
            directoryList->append(kNormalizedPath);
        }
    }

    QStringList languageDirectoryCandidates()
    {
        QStringList directoryList;
        const QString kApplicationDirectory = QCoreApplication::applicationDirPath();
        appendUniqueDirectory(&directoryList, QDir(kApplicationDirectory).absoluteFilePath(QStringLiteral("languages")));
#ifdef Q_OS_WIN
        constexpr DWORD kExecutablePathCapacity = 32768U;
        std::vector<wchar_t> executablePathBuffer(kExecutablePathCapacity, L'\0');
        const DWORD kExecutablePathLength = ::GetModuleFileNameW(
            nullptr,
            executablePathBuffer.data(),
            kExecutablePathCapacity);
        if (kExecutablePathLength > 0 && kExecutablePathLength < kExecutablePathCapacity)
        {
            const QString kExecutableDirectory = QFileInfo(
                QString::fromWCharArray(executablePathBuffer.data(), static_cast<int>(kExecutablePathLength))).absolutePath();
            appendUniqueDirectory(
                &directoryList,
                QDir(kExecutableDirectory).absoluteFilePath(QStringLiteral("languages")));
        }
#endif

        QString walkingPath = QDir::currentPath();
        for (int depth = 0; depth < 8; ++depth)
        {
            const QDir kWalkingDirectory(walkingPath);
            appendUniqueDirectory(&directoryList, kWalkingDirectory.absoluteFilePath(QStringLiteral("languages")));
            appendUniqueDirectory(
                &directoryList,
                kWalkingDirectory.absoluteFilePath(QStringLiteral("apps/desktop/languages")));

            QDir parentDirectory(walkingPath);
            if (!parentDirectory.cdUp())
            {
                break;
            }
            walkingPath = parentDirectory.absolutePath();
        }
        return directoryList;
    }

    bool isHistoricalChineseLanguage(const QString& languageId)
    {
        // zh-CN is the checked-in source-language baseline. Other zh-* packs
        // remain extensible and must be allowed to provide their own values.
        return languageId.compare(
            QString::fromLatin1(kProductFallbackLanguageId),
            Qt::CaseInsensitive) == 0;
    }
}

namespace
{
    // StringEntry:
    // - the position of a translation in LoadedPack::text; both keys and values record only offsets and lengths, without allocating separate QStrings;
    // - When the value is identical to the key (identity mapping), valueOffset directly points to the key, avoiding storing a second copy of the text.
    struct StringEntry
    {
        quint32 keyOffset = 0;
        quint32 keyLength = 0;
        quint32 valueOffset = 0;
        quint32 valueLength = 0;
    };

    // TemplateRef description: Index of a Chinese source string with placeholders (e.g., "Status: %1").
    // Split the source string into literals and placeholders only when matching, rather than retaining a compiled regex for every entry.
    struct TemplateRef
    {
        quint32 entryIndex = 0;    // entryIndex: Index within sourceTranslations.
        quint32 literalLength = 0; // literalLength: Total literal length; longer values are more specific and matched first.
        quint32 prefixLength = 0;  // prefixLength: Length of the literal before the first placeholder, used for quick exclusion.
        quint32 suffixLength = 0;  // suffixLength: Length of the literal after the last placeholder, used for quick exclusion.
    };

    // LoadedPack:
    // - All translation texts in a language pack are merged into a single contiguous text; after sorting the three tables by key, binary search is used.
    // - Reduces two heap allocations and hash node overhead per entry compared to QHash<QString,QString>;
    // - renderedIndex: reverse lookup index from 'translated string' to 'source string', built only when first needed.
    struct LoadedPack
    {
        QString text;
        std::vector<StringEntry> translations;
        std::vector<StringEntry> contextTranslations;
        std::vector<StringEntry> sourceTranslations;
        std::vector<TemplateRef> sourceTemplates;
        mutable std::once_flag renderedOnce;
        mutable std::vector<quint32> renderedIndex;

        QStringView keyOf(const StringEntry& entry) const
        {
            return QStringView(text).sliced(entry.keyOffset, entry.keyLength);
        }

        QStringView valueOf(const StringEntry& entry) const
        {
            return QStringView(text).sliced(entry.valueOffset, entry.valueLength);
        }

        const StringEntry* find(const std::vector<StringEntry>& table, const QStringView key) const
        {
            const auto kIterator = std::lower_bound(
                table.begin(),
                table.end(),
                key,
                [this](const StringEntry& entry, const QStringView wanted) {
                    return keyOf(entry).compare(wanted) < 0;
                });
            if (kIterator == table.end() || keyOf(*kIterator) != key)
            {
                return nullptr;
            }
            return &*kIterator;
        }

        // renderedSource purpose: Looks up the unique source string corresponding to the translated text; returns an empty view if no result is found or if the translation maps to multiple source strings.
        QStringView renderedSource(const QStringView renderedText) const
        {
            std::call_once(renderedOnce, [this]() { buildRenderedIndex(); });
            const auto kIterator = std::lower_bound(
                renderedIndex.begin(),
                renderedIndex.end(),
                renderedText,
                [this](const quint32 entryIndex, const QStringView wanted) {
                    return valueOf(sourceTranslations[entryIndex]).compare(wanted) < 0;
                });
            if (kIterator == renderedIndex.end()
                || valueOf(sourceTranslations[*kIterator]) != renderedText)
            {
                return {};
            }
            return keyOf(sourceTranslations[*kIterator]);
        }

    private:
        // buildRenderedIndex:
        // - Retain only entries where the translation is non-empty and differs from the source string.
        // - When multiple source strings share the same translation, it is impossible to determine which one to revert to; discard the entire group to avoid guessing incorrectly.
        void buildRenderedIndex() const
        {
            std::vector<quint32> candidates;
            candidates.reserve(sourceTranslations.size());
            for (quint32 index = 0; index < sourceTranslations.size(); ++index)
            {
                const StringEntry& entry = sourceTranslations[index];
                const QStringView kValue = valueOf(entry);
                if (kValue.isEmpty() || kValue == keyOf(entry))
                {
                    continue;
                }
                candidates.push_back(index);
            }
            std::sort(
                candidates.begin(),
                candidates.end(),
                [this](const quint32 left, const quint32 right) {
                    const int kOrder = valueOf(sourceTranslations[left]).compare(
                        valueOf(sourceTranslations[right]));
                    return kOrder != 0 ? kOrder < 0 : left < right;
                });
            renderedIndex.reserve(candidates.size());
            for (std::size_t runBegin = 0; runBegin < candidates.size();)
            {
                std::size_t runEnd = runBegin + 1;
                const QStringView kRunValue = valueOf(sourceTranslations[candidates[runBegin]]);
                while (runEnd < candidates.size()
                    && valueOf(sourceTranslations[candidates[runEnd]]) == kRunValue)
                {
                    ++runEnd;
                }
                if (runEnd - runBegin == 1)
                {
                    renderedIndex.push_back(candidates[runBegin]);
                }
                runBegin = runEnd;
            }
            renderedIndex.shrink_to_fit();
        }
    };

    // PackMetadata description: Scalar fields at the top level of the language pack; shared by manifest scanning and full loading.
    struct PackMetadata
    {
        QString schema;
        QString id;
        QString name;
        QString nativeName;
        QString author;
        QString textDirection = QStringLiteral("ltr");
        QString fallback;
        int formatVersion = -1;
        bool hasTranslations = false;
    };

    int hexDigitValue(const char digit)
    {
        if (digit >= '0' && digit <= '9')
        {
            return digit - '0';
        }
        if (digit >= 'a' && digit <= 'f')
        {
            return digit - 'a' + 10;
        }
        if (digit >= 'A' && digit <= 'F')
        {
            return digit - 'A' + 10;
        }
        return -1;
    }

    // JsonCursor:
    // - The language pack format is fixed (top-level scalars plus three string tables), so a generic DOM is not needed.
    // - Stream-scan UTF-8 JSON, decoding strings directly and appending them to the QString provided by the caller without generating a QJsonDocument.
    // - When a null sink is passed, only validate and skip, used to skip large tables during manifest scanning.
    class JsonCursor
    {
    public:
        explicit JsonCursor(const QByteArray& bytes)
            : begin_(bytes.constData())
            , cursor_(bytes.constData())
            , end_(bytes.constData() + bytes.size())
        {
            if (bytes.size() >= 3
                && static_cast<unsigned char>(cursor_[0]) == 0xEF
                && static_cast<unsigned char>(cursor_[1]) == 0xBB
                && static_cast<unsigned char>(cursor_[2]) == 0xBF)
            {
                cursor_ += 3;
            }
        }

        bool failed() const { return !error_.isEmpty(); }
        const QString& error() const { return error_; }

        // fail:
        // reasonCode is a snake_case error code, not a sentence: it is used only to diagnose corrupted language packs.
        //   Making it a translatable UI string would require translating the parser's internal state for every new language.
        // - Appended to the registered error message 'Invalid language pack JSON (%1): %2' as the %2 component.
        bool fail(const char* reasonCode)
        {
            if (error_.isEmpty())
            {
                error_ = QString::fromLatin1(reasonCode)
                    + QLatin1Char('@')
                    + QString::number(cursor_ - begin_);
            }
            return false;
        }

        void skipWhitespace()
        {
            while (cursor_ < end_
                && (*cursor_ == ' ' || *cursor_ == '\t' || *cursor_ == '\n' || *cursor_ == '\r'))
            {
                ++cursor_;
            }
        }

        char peek()
        {
            skipWhitespace();
            return cursor_ < end_ ? *cursor_ : '\0';
        }

        bool atEnd()
        {
            skipWhitespace();
            return cursor_ >= end_;
        }

        bool consumeIf(const char expected)
        {
            if (peek() == expected && cursor_ < end_)
            {
                ++cursor_;
                return true;
            }
            return false;
        }

        bool expect(const char expected)
        {
            if (consumeIf(expected))
            {
                return true;
            }
            // Note: The byte offset already points to the error location, allowing direct visibility of the expected delimiter during troubleshooting without embedding it in the error code.
            return fail("expected_character");
        }

        // objectHasMembers purpose: Do not consume input; check if there is at least one member after the next '{'.
        bool objectHasMembers()
        {
            if (peek() != '{')
            {
                return false;
            }
            const char* const kSaved = cursor_;
            ++cursor_;
            skipWhitespace();
            const bool kHasMembers = cursor_ < end_ && *cursor_ != '}';
            cursor_ = kSaved;
            return kHasMembers;
        }

        // scanString:
        // - Read a JSON string; if sink is non-null, append the decoded result to the end of sink and fill in the offset and length (UTF-16 units).
        // - Only validate escapes and skip if sink is null.
        bool scanString(QString* sink, quint32* offsetOut, quint32* lengthOut)
        {
            if (peek() != '"' || cursor_ >= end_)
            {
                return fail("expected_string");
            }
            const qsizetype kStartSize = sink != nullptr ? sink->size() : 0;
            ++cursor_;
            const char* runBegin = cursor_;
            while (cursor_ < end_)
            {
                const unsigned char kByte = static_cast<unsigned char>(*cursor_);
                if (kByte == '"')
                {
                    flushRun(sink, runBegin);
                    ++cursor_;
                    if (offsetOut != nullptr)
                    {
                        *offsetOut = static_cast<quint32>(kStartSize);
                    }
                    if (lengthOut != nullptr)
                    {
                        *lengthOut = sink != nullptr
                            ? static_cast<quint32>(sink->size() - kStartSize)
                            : 0U;
                    }
                    return true;
                }
                if (kByte == '\\')
                {
                    flushRun(sink, runBegin);
                    ++cursor_;
                    if (cursor_ >= end_)
                    {
                        break;
                    }
                    char16_t unit = 0;
                    switch (*cursor_)
                    {
                    case '"': unit = u'"'; break;
                    case '\\': unit = u'\\'; break;
                    case '/': unit = u'/'; break;
                    case 'b': unit = u'\b'; break;
                    case 'f': unit = u'\f'; break;
                    case 'n': unit = u'\n'; break;
                    case 'r': unit = u'\r'; break;
                    case 't': unit = u'\t'; break;
                    case 'u':
                    {
                        if (end_ - cursor_ < 5)
                        {
                            return fail("truncated_unicode_escape");
                        }
                        for (int index = 1; index <= 4; ++index)
                        {
                            const int kDigit = hexDigitValue(cursor_[index]);
                            if (kDigit < 0)
                            {
                                return fail("invalid_unicode_escape");
                            }
                            unit = static_cast<char16_t>((unit << 4) | kDigit);
                        }
                        cursor_ += 4;
                        break;
                    }
                    default:
                        return fail("invalid_escape");
                    }
                    if (sink != nullptr)
                    {
                        sink->append(QChar(unit));
                    }
                    ++cursor_;
                    runBegin = cursor_;
                    continue;
                }
                if (kByte < 0x20)
                {
                    return fail("control_character_in_string");
                }
                ++cursor_;
            }
            return fail("unterminated_string");
        }

        bool readNumber(double* valueOut)
        {
            skipWhitespace();
            const char* const kTokenBegin = cursor_;
            while (cursor_ < end_
                && (*cursor_ == '-' || *cursor_ == '+' || *cursor_ == '.'
                    || *cursor_ == 'e' || *cursor_ == 'E'
                    || (*cursor_ >= '0' && *cursor_ <= '9')))
            {
                ++cursor_;
            }
            if (cursor_ == kTokenBegin)
            {
                return fail("expected_number");
            }
            bool converted = false;
            const double kValue = QByteArray::fromRawData(kTokenBegin, static_cast<qsizetype>(cursor_ - kTokenBegin))
                .toDouble(&converted);
            if (!converted)
            {
                return fail("invalid_number");
            }
            *valueOut = kValue;
            return true;
        }

        // skipValue: Validate and skip any single JSON value.
        bool skipValue(const int depth = 0)
        {
            if (depth > 64)
            {
                return fail("nesting_too_deep");
            }
            const char kLead = peek();
            if (cursor_ >= end_)
            {
                return fail("unexpected_end_of_data");
            }
            if (kLead == '"')
            {
                return scanString(nullptr, nullptr, nullptr);
            }
            if (kLead == '{')
            {
                ++cursor_;
                if (consumeIf('}'))
                {
                    return true;
                }
                for (;;)
                {
                    if (!scanString(nullptr, nullptr, nullptr) || !expect(':') || !skipValue(depth + 1))
                    {
                        return false;
                    }
                    if (consumeIf(','))
                    {
                        continue;
                    }
                    return expect('}');
                }
            }
            if (kLead == '[')
            {
                ++cursor_;
                if (consumeIf(']'))
                {
                    return true;
                }
                for (;;)
                {
                    if (!skipValue(depth + 1))
                    {
                        return false;
                    }
                    if (consumeIf(','))
                    {
                        continue;
                    }
                    return expect(']');
                }
            }
            if (skipLiteral("true") || skipLiteral("false") || skipLiteral("null"))
            {
                return true;
            }
            double ignoredNumber = 0.0;
            return readNumber(&ignoredNumber);
        }

    private:
        void flushRun(QString* sink, const char* runBegin) const
        {
            if (sink != nullptr && cursor_ > runBegin)
            {
                sink->append(QString::fromUtf8(runBegin, static_cast<qsizetype>(cursor_ - runBegin)));
            }
        }

        bool skipLiteral(const char* literal)
        {
            const qsizetype kLength = static_cast<qsizetype>(std::char_traits<char>::length(literal));
            if (end_ - cursor_ >= kLength && std::char_traits<char>::compare(cursor_, literal, kLength) == 0)
            {
                cursor_ += kLength;
                return true;
            }
            return false;
        }

        const char* begin_ = nullptr;
        const char* cursor_ = nullptr;
        const char* end_ = nullptr;
        QString error_;
    };

    // parseStringMap:
    // - Note: Reads a {"key":"value"} table; key-value text is appended to the blob, and entries only store positions.
    // - If the value equals the key, revert to the just-written value so the value directly reuses the key's text.
    // - Any non-string value indicates a corrupted language pack.
    bool parseStringMap(JsonCursor& cursor, QString& blob, std::vector<StringEntry>& table)
    {
        if (!cursor.expect('{'))
        {
            return false;
        }
        if (cursor.consumeIf('}'))
        {
            return true;
        }
        for (;;)
        {
            StringEntry entry;
            if (!cursor.scanString(&blob, &entry.keyOffset, &entry.keyLength) || !cursor.expect(':'))
            {
                return false;
            }
            if (cursor.peek() != '"')
            {
                return cursor.fail("translation_value_is_not_a_string");
            }
            if (!cursor.scanString(&blob, &entry.valueOffset, &entry.valueLength))
            {
                return false;
            }
            const QStringView kBlobView(blob);
            if (entry.keyLength == entry.valueLength
                && kBlobView.sliced(entry.keyOffset, entry.keyLength)
                    == kBlobView.sliced(entry.valueOffset, entry.valueLength))
            {
                blob.truncate(entry.valueOffset);
                entry.valueOffset = entry.keyOffset;
            }
            table.push_back(entry);
            if (cursor.consumeIf(','))
            {
                continue;
            }
            return cursor.expect('}');
        }
    }

    // finalizeTable: Sorts by key; retains the last entry for duplicate keys (consistent with old QHash::insert overwrite behavior).
    void finalizeTable(const QString& text, std::vector<StringEntry>& table)
    {
        const QStringView kBase(text);
        const auto kKeyOf = [&kBase](const StringEntry& entry) {
            return kBase.sliced(entry.keyOffset, entry.keyLength);
        };
        std::stable_sort(
            table.begin(),
            table.end(),
            [&kKeyOf](const StringEntry& left, const StringEntry& right) {
                return kKeyOf(left).compare(kKeyOf(right)) < 0;
            });
        std::size_t written = 0;
        for (std::size_t index = 0; index < table.size(); ++index)
        {
            if (index + 1 < table.size() && kKeyOf(table[index]) == kKeyOf(table[index + 1]))
            {
                continue;
            }
            table[written++] = table[index];
        }
        table.resize(written);
        table.shrink_to_fit();
    }

    // buildSourceTemplates: Register source strings containing Chinese characters and placeholders, sorted by literal length in descending order.
    void buildSourceTemplates(LoadedPack* pack)
    {
        for (quint32 index = 0; index < pack->sourceTranslations.size(); ++index)
        {
            const QStringView kKey = pack->keyOf(pack->sourceTranslations[index]);
            if (!containsHanCharacters(kKey))
            {
                continue;
            }
            qsizetype start = 0;
            qsizetype length = 0;
            if (!findPlaceholder(kKey, 0, &start, &length))
            {
                continue;
            }
            const qsizetype kFirstStart = start;
            qsizetype lastEnd = start + length;
            qsizetype placeholderChars = length;
            while (findPlaceholder(kKey, lastEnd, &start, &length))
            {
                lastEnd = start + length;
                placeholderChars += length;
            }
            TemplateRef reference;
            reference.entryIndex = index;
            reference.literalLength = static_cast<quint32>(kKey.size() - placeholderChars);
            reference.prefixLength = static_cast<quint32>(kFirstStart);
            reference.suffixLength = static_cast<quint32>(kKey.size() - lastEnd);
            pack->sourceTemplates.push_back(reference);
        }
        std::stable_sort(
            pack->sourceTemplates.begin(),
            pack->sourceTemplates.end(),
            [](const TemplateRef& left, const TemplateRef& right) {
                return left.literalLength > right.literalLength;
            });
        pack->sourceTemplates.shrink_to_fit();
    }

    // ParsedTemplate description: A source string is split into n+1 literal segments and n placeholders; captures[k] is the text matched by the k-th placeholder.
    struct ParsedTemplate
    {
        std::vector<QStringView> literals;
        std::vector<QStringView> placeholders;
        std::vector<QStringView> captures;
    };

    ParsedTemplate parseTemplate(const QStringView pattern)
    {
        ParsedTemplate parsed;
        qsizetype previousEnd = 0;
        qsizetype cursor = 0;
        qsizetype start = 0;
        qsizetype length = 0;
        while (findPlaceholder(pattern, cursor, &start, &length))
        {
            parsed.literals.push_back(pattern.sliced(previousEnd, start - previousEnd));
            parsed.placeholders.push_back(pattern.sliced(start, length));
            previousEnd = start + length;
            cursor = previousEnd;
        }
        parsed.literals.push_back(pattern.sliced(previousEnd));
        parsed.captures.resize(parsed.placeholders.size());
        return parsed;
    }

    // matchTemplateFrom:
    // - Equivalent to a backtracking match for the regex ^L0([\s\S]*?)L1...([\s\S]*?)Ln$, where placeholders are lazy and match the shortest possible string.
    // - The trailing $ at the end can match either the end of the text or the newline before the end, consistent with default PCRE behavior.
    bool matchTemplateFrom(
        const QStringView text,
        ParsedTemplate& parsed,
        const std::size_t index,
        const qsizetype position)
    {
        const QStringView kNext = parsed.literals[index + 1];
        if (index + 1 == parsed.placeholders.size())
        {
            const qsizetype kSize = text.size();
            const qsizetype kEndings[2] = { kSize - 1, kSize };
            for (int choice = text.endsWith(QChar(u'\n')) ? 0 : 1; choice < 2; ++choice)
            {
                const qsizetype kLiteralStart = kEndings[choice] - kNext.size();
                if (kLiteralStart >= position && text.sliced(kLiteralStart, kNext.size()) == kNext)
                {
                    parsed.captures[index] = text.sliced(position, kLiteralStart - position);
                    return true;
                }
            }
            return false;
        }
        for (qsizetype candidate = position; candidate + kNext.size() <= text.size(); ++candidate)
        {
            if (text.sliced(candidate, kNext.size()) != kNext)
            {
                continue;
            }
            parsed.captures[index] = text.sliced(position, candidate - position);
            if (matchTemplateFrom(text, parsed, index + 1, candidate + kNext.size()))
            {
                return true;
            }
        }
        return false;
    }

    bool matchTemplate(const QStringView text, ParsedTemplate& parsed)
    {
        if (parsed.placeholders.empty() || !text.startsWith(parsed.literals[0]))
        {
            return false;
        }
        return matchTemplateFrom(text, parsed, 0, parsed.literals[0].size());
    }

    // parsePackBytes:
    // - If pack is null: Perform only manifest scanning, skip the three large tables, and retrieve only top-level scalars.
    // - pack is non-null: Fully load, decode the three tables into pack->text, and sort them.
    bool parsePackBytes(
        const QByteArray& bytes,
        LoadedPack* pack,
        PackMetadata* meta,
        QString* errorOut)
    {
        JsonCursor cursor(bytes);
        if (pack != nullptr)
        {
            pack->text.reserve(bytes.size());
        }

        bool seenTranslations = false;
        bool seenContext = false;
        bool seenSource = false;
        const auto kReadOptionalString = [&cursor](QString* target) -> bool {
            if (cursor.peek() == '"')
            {
                QString value;
                quint32 offset = 0;
                quint32 length = 0;
                if (!cursor.scanString(&value, &offset, &length))
                {
                    return false;
                }
                *target = value;
                return true;
            }
            return cursor.skipValue();
        };

        const auto kHandleMember = [&](const QString& key) -> bool {
            if (key == QLatin1String("schema")) return kReadOptionalString(&meta->schema);
            if (key == QLatin1String("id")) return kReadOptionalString(&meta->id);
            if (key == QLatin1String("name")) return kReadOptionalString(&meta->name);
            if (key == QLatin1String("native_name")) return kReadOptionalString(&meta->nativeName);
            if (key == QLatin1String("author")) return kReadOptionalString(&meta->author);
            if (key == QLatin1String("text_direction")) return kReadOptionalString(&meta->textDirection);
            if (key == QLatin1String("fallback")) return kReadOptionalString(&meta->fallback);
            if (key == QLatin1String("format_version"))
            {
                const char kLead = cursor.peek();
                if (kLead == '-' || (kLead >= '0' && kLead <= '9'))
                {
                    double value = 0.0;
                    if (!cursor.readNumber(&value))
                    {
                        return false;
                    }
                    meta->formatVersion = value == static_cast<double>(static_cast<int>(value))
                        ? static_cast<int>(value)
                        : -1;
                    return true;
                }
                return cursor.skipValue();
            }
            if (key == QLatin1String("translations"))
            {
                if (seenTranslations)
                {
                    return cursor.fail("duplicate_translations_section");
                }
                seenTranslations = true;
                if (cursor.peek() != '{')
                {
                    return cursor.skipValue();
                }
                if (pack != nullptr)
                {
                    return parseStringMap(cursor, pack->text, pack->translations);
                }
                meta->hasTranslations = cursor.objectHasMembers();
                return cursor.skipValue();
            }
            if (key == QLatin1String("context_translations"))
            {
                if (seenContext)
                {
                    return cursor.fail("duplicate_context_translations_section");
                }
                seenContext = true;
                if (pack != nullptr && cursor.peek() == '{')
                {
                    return parseStringMap(cursor, pack->text, pack->contextTranslations);
                }
                return cursor.skipValue();
            }
            if (key == QLatin1String("source_translations"))
            {
                if (seenSource)
                {
                    return cursor.fail("duplicate_source_translations_section");
                }
                seenSource = true;
                if (cursor.peek() != '{')
                {
                    return cursor.fail("source_translations_must_be_an_object");
                }
                if (pack != nullptr)
                {
                    return parseStringMap(cursor, pack->text, pack->sourceTranslations);
                }
                return cursor.skipValue();
            }
            return cursor.skipValue();
        };

        bool parsed = cursor.expect('{');
        if (parsed && !cursor.consumeIf('}'))
        {
            for (;;)
            {
                QString key;
                quint32 keyOffset = 0;
                quint32 keyLength = 0;
                if (!cursor.scanString(&key, &keyOffset, &keyLength)
                    || !cursor.expect(':')
                    || !kHandleMember(key))
                {
                    parsed = false;
                    break;
                }
                if (cursor.consumeIf(','))
                {
                    continue;
                }
                parsed = cursor.expect('}');
                break;
            }
        }
        if (parsed && !cursor.atEnd())
        {
            parsed = cursor.fail("unexpected_data_after_the_root_object");
        }
        if (!parsed)
        {
            if (errorOut != nullptr)
            {
                *errorOut = cursor.error();
            }
            return false;
        }

        if (pack != nullptr)
        {
            meta->hasTranslations = !pack->translations.empty();
            finalizeTable(pack->text, pack->translations);
            finalizeTable(pack->text, pack->contextTranslations);
            finalizeTable(pack->text, pack->sourceTranslations);
            const auto kKeysAreValid = [pack](const std::vector<StringEntry>& table, const bool allowBlank) {
                return std::none_of(table.begin(), table.end(), [&](const StringEntry& entry) {
                    const QStringView kKey = pack->keyOf(entry);
                    return allowBlank ? kKey.isEmpty() : kKey.trimmed().isEmpty();
                });
            };
            if (!kKeysAreValid(pack->translations, false)
                || !kKeysAreValid(pack->contextTranslations, false)
                || !kKeysAreValid(pack->sourceTranslations, true))
            {
                if (errorOut != nullptr)
                {
                    // Same category as parser error codes: this is an internal reason for troubleshooting corrupted language packs, not UI text.
                    *errorOut = QStringLiteral("empty_translation_key");
                }
                return false;
            }
            pack->text.squeeze();
            buildSourceTemplates(pack);
        }
        return true;
    }

    bool isValidLanguageIdText(const QString& languageId)
    {
        static const QRegularExpression kLanguageIdExpression(
            QStringLiteral("^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"));
        return kLanguageIdExpression.match(languageId).hasMatch();
    }

    // loadPackFile purpose: reads and validates a language pack file; if pack is null, performs only a manifest scan.
    bool loadPackFile(
        const QString& filePath,
        LoadedPack* pack,
        PackMetadata* meta,
        QString* errorOut)
    {
        const auto kReportError = [errorOut](const QString& message) {
            if (errorOut != nullptr)
            {
                *errorOut = message;
            }
            return false;
        };

        const QFileInfo kFileInfo(filePath);
        if (!kFileInfo.exists() || !kFileInfo.isFile() || kFileInfo.size() <= 0 || kFileInfo.size() > kMaximumLanguagePackBytes)
        {
            return kReportError(QStringLiteral("Invalid language pack size: %1").arg(filePath));
        }
        QFile packFile(filePath);
        if (!packFile.open(QIODevice::ReadOnly))
        {
            return kReportError(QStringLiteral("Cannot open language pack: %1").arg(filePath));
        }
        const QByteArray kBytes = packFile.readAll();
        packFile.close();

        QString parseError;
        if (!parsePackBytes(kBytes, pack, meta, &parseError))
        {
            return kReportError(QStringLiteral("Invalid language pack JSON (%1): %2").arg(filePath, parseError));
        }

        meta->schema = meta->schema;
        meta->id = meta->id.trimmed();
        meta->name = meta->name.trimmed();
        meta->nativeName = meta->nativeName.trimmed();
        meta->author = meta->author.trimmed();
        meta->fallback = meta->fallback.trimmed();
        if (meta->schema != QString::fromLatin1(kLanguagePackSchema)
            || meta->formatVersion != kLanguagePackFormatVersion
            || !isValidLanguageIdText(meta->id)
            || meta->name.isEmpty()
            || meta->nativeName.isEmpty()
            || !meta->hasTranslations)
        {
            return kReportError(QStringLiteral("Language pack metadata is invalid: %1").arg(filePath));
        }
        if (!meta->fallback.isEmpty() && !isValidLanguageIdText(meta->fallback))
        {
            return kReportError(QStringLiteral("Language pack fallback id is invalid: %1").arg(filePath));
        }
        return true;
    }
}

// State:
// - packs: Registered only at startup; an empty data field indicates the language has not been used yet and consumes no translation table memory.
// - The mutex protects the manifest and on-demand loading; query threads receive a shared_ptr snapshot, which remains unchanged after loading.
struct ks::i18n::LanguageManager::State
{
    struct PackEntry
    {
        LanguageInfo info;
        QString fallbackLanguageId;
        std::shared_ptr<const LoadedPack> data;
        bool loadAttempted = false;
        QString loadError;
    };

    mutable QMutex mutex;
    std::vector<PackEntry> packs;
};

struct ks::i18n::LanguageManager::PackRef
{
    bool found = false;
    QString languageId;
    QString fallbackLanguageId;
    QString loadError;
    std::shared_ptr<const LoadedPack> data;
};

ks::i18n::LanguageManager::LanguageManager()
    : state_(std::make_unique<State>())
{
}

ks::i18n::LanguageManager::~LanguageManager() = default;

ks::i18n::LanguageManager& ks::i18n::LanguageManager::instance()
{
    static LanguageManager manager;
    return manager;
}

ks::i18n::LanguageManager::PackRef ks::i18n::LanguageManager::acquirePack(
    const QString& languageId) const
{
    PackRef reference;
    QMutexLocker locker(&state_->mutex);
    const auto kIterator = std::find_if(
        state_->packs.begin(),
        state_->packs.end(),
        [&languageId](const State::PackEntry& entry) {
            return entry.info.id.compare(languageId, Qt::CaseInsensitive) == 0;
        });
    if (kIterator == state_->packs.end())
    {
        return reference;
    }

    if (!kIterator->data && !kIterator->loadAttempted)
    {
        kIterator->loadAttempted = true;
        auto loaded = std::make_shared<LoadedPack>();
        PackMetadata metadata;
        if (loadPackFile(kIterator->info.filePath, loaded.get(), &metadata, &kIterator->loadError))
        {
            kIterator->data = std::move(loaded);
        }
    }

    reference.found = true;
    reference.languageId = kIterator->info.id;
    reference.fallbackLanguageId = kIterator->fallbackLanguageId;
    reference.loadError = kIterator->loadError;
    reference.data = kIterator->data;
    return reference;
}

bool ks::i18n::LanguageManager::initialize(
    const QString& preferredLanguageId,
    QString* errorTextOut)
{
    QStringList warningList;
    if (!hasAnyPack())
    {
        discoverLanguagePacks(&warningList);
    }

    if (!hasAnyPack())
    {
        currentLanguageId_ = QString::fromLatin1(kProductFallbackLanguageId);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("No valid language packs were found. Built-in text will be used.");
        }
        applyApplicationDirection();
        return false;
    }

    const bool kApplied = setLanguage(preferredLanguageId, errorTextOut);
    if (errorTextOut != nullptr && !warningList.isEmpty())
    {
        const QString kWarningText = warningList.join(QStringLiteral("\n"));
        *errorTextOut = errorTextOut->isEmpty()
            ? kWarningText
            : (*errorTextOut + QStringLiteral("\n") + kWarningText);
    }
    return kApplied;
}

bool ks::i18n::LanguageManager::setLanguage(
    const QString& languageId,
    QString* errorTextOut)
{
    const QString kResolvedLanguageId = resolvePreferredLanguageId(languageId);
    // The translation table for the pack is loaded only when switching languages; this is the primary trigger for on-demand loading.
    const PackRef kPack = acquirePack(kResolvedLanguageId);
    if (!kPack.found)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("Language pack not found: %1 (resolved from %2)")
                .arg(kResolvedLanguageId, languageId);
        }
        return false;
    }
    if (!kPack.data)
    {
        if (errorTextOut != nullptr)
        {
            // When loadPackFile fails, loadError is always written (it already contains the registered UI text).
            // This fallback only occurs when the invariant is violated, so use an internal error code instead of adding a new UI string.
            *errorTextOut = kPack.loadError.isEmpty()
                ? QStringLiteral("language_pack_load_failed:") + kPack.languageId
                : kPack.loadError;
        }
        return false;
    }

    const bool kLanguageWillChange = !currentLanguageId_.isEmpty()
        && currentLanguageId_.compare(kPack.languageId, Qt::CaseInsensitive) != 0;
    if (kLanguageWillChange)
    {
        // Capture the canonical source for controls that were constructed from
        // an already-rendered English context translation before changing the
        // active pack. Their runtime metadata then makes the switch reversible.
        QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (application != nullptr)
        {
            const QWidgetList kTopLevelWidgetList = application->topLevelWidgets();
            for (QWidget* widget : kTopLevelWidgetList)
            {
                applyRuntimeTranslations(widget);
            }
        }
    }

    currentLanguageId_ = kPack.languageId;
    ensureApplicationEventFilter();
    applyApplicationDirection();
    retranslateAll();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return true;
}

QString ks::i18n::LanguageManager::resolvePreferredLanguageId(
    const QString& preferredLanguageId) const
{
    QString requestedLanguageId = preferredLanguageId.trimmed();
    if (requestedLanguageId.isEmpty()
        || requestedLanguageId.compare(
            QString::fromLatin1(kSystemLanguagePreferenceId),
            Qt::CaseInsensitive) == 0)
    {
        requestedLanguageId = QLocale::system().name();
    }
    requestedLanguageId.replace('_', '-');

    // Negotiation checks only language IDs in the manifest; no translation tables are loaded.
    QMutexLocker locker(&state_->mutex);
    const auto kFindExactLanguage = [this](const QString& candidateLanguageId) {
        return std::find_if(
            state_->packs.cbegin(),
            state_->packs.cend(),
            [&candidateLanguageId](const State::PackEntry& entry) {
                return entry.info.id.compare(candidateLanguageId, Qt::CaseInsensitive) == 0;
            });
    };

    // Locale negotiation is deterministic:
    // exact region -> base language -> en-US -> KSword's product fallback.
    auto languageMatch = kFindExactLanguage(requestedLanguageId);
    if (languageMatch != state_->packs.cend())
    {
        return languageMatch->info.id;
    }

    const QString kBaseLanguageId = requestedLanguageId.section('-', 0, 0);
    languageMatch = kFindExactLanguage(kBaseLanguageId);
    if (languageMatch == state_->packs.cend() && !kBaseLanguageId.isEmpty())
    {
        languageMatch = std::find_if(
            state_->packs.cbegin(),
            state_->packs.cend(),
            [&kBaseLanguageId](const State::PackEntry& entry) {
                return entry.info.id.section('-', 0, 0).compare(
                    kBaseLanguageId,
                    Qt::CaseInsensitive) == 0;
            });
    }
    if (languageMatch != state_->packs.cend())
    {
        return languageMatch->info.id;
    }

    languageMatch = kFindExactLanguage(QString::fromLatin1(kEnglishFallbackLanguageId));
    if (languageMatch != state_->packs.cend())
    {
        return languageMatch->info.id;
    }

    languageMatch = kFindExactLanguage(QString::fromLatin1(kProductFallbackLanguageId));
    if (languageMatch != state_->packs.cend())
    {
        return languageMatch->info.id;
    }

    // A damaged/custom installation may omit both required fallback packs.
    // Keep the UI usable with the first validated pack; normal builds always
    // stop at the product fallback above.
    return state_->packs.empty()
        ? QString::fromLatin1(kProductFallbackLanguageId)
        : state_->packs.front().info.id;
}

bool ks::i18n::LanguageManager::hasAnyPack() const
{
    QMutexLocker locker(&state_->mutex);
    return !state_->packs.empty();
}

QString ks::i18n::LanguageManager::currentLanguageId() const
{
    return currentLanguageId_;
}

QList<ks::i18n::LanguageInfo> ks::i18n::LanguageManager::availableLanguages() const
{
    // The language selection list requires only metadata from the manifest and does not trigger any translation table loading.
    QMutexLocker locker(&state_->mutex);
    QList<LanguageInfo> languageList;
    languageList.reserve(static_cast<qsizetype>(state_->packs.size()));
    for (const State::PackEntry& entry : state_->packs)
    {
        languageList.append(entry.info);
    }
    return languageList;
}

QString ks::i18n::LanguageManager::text(
    const QString& key,
    const QString& fallbackText) const
{
    QStringList visitedLanguageIds;
    return resolveText(currentLanguageId_, key, fallbackText, &visitedLanguageIds);
}

QString ks::i18n::LanguageManager::contextText(
    const QString& contextKey,
    const QString& sourceText) const
{
    if (contextKey.trimmed().isEmpty() || sourceText.isEmpty())
    {
        return sourceText;
    }

    // Chinese is the historical source language. Returning the call-site
    // fallback makes a language switch incapable of rewriting the old UI.
    if (isHistoricalChineseLanguage(currentLanguageId_))
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveContextText(currentLanguageId_, contextKey, sourceText, &visitedLanguageIds);
}

QString ks::i18n::LanguageManager::sourceText(const QString& sourceText) const
{
    if (sourceText.isEmpty() || isHistoricalChineseLanguage(currentLanguageId_))
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveSourceText(
        currentLanguageId_,
        sourceText,
        &visitedLanguageIds,
        true);
}

QString ks::i18n::LanguageManager::packedSourceText(const QString& sourceText) const
{
    if (sourceText.isEmpty())
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveSourceText(
        currentLanguageId_,
        sourceText,
        &visitedLanguageIds,
        false);
}

QString ks::i18n::LanguageManager::sourceForRenderedText(const QString& renderedText) const
{
    if (renderedText.isEmpty() || containsHanCharacters(renderedText))
    {
        return {};
    }

    // Only traverse the fallback chain of the current language: translations displayed on the UI can only come from the currently
    // active package. Scanning disabled languages would load them all into memory and does not correspond to any displayed text.
    // The reverse lookup index is built only the first time this code path is reached in each package.
    QStringList visitedLanguageIds;
    QString languageId = currentLanguageId_;
    while (!languageId.trimmed().isEmpty())
    {
        const QString kNormalizedLanguageId = languageId.trimmed().toLower();
        if (visitedLanguageIds.contains(kNormalizedLanguageId))
        {
            break;
        }
        visitedLanguageIds.append(kNormalizedLanguageId);

        const PackRef kPack = acquirePack(kNormalizedLanguageId);
        if (!kPack.found)
        {
            break;
        }
        if (kPack.data)
        {
            const QStringView kSource = kPack.data->renderedSource(renderedText);
            if (!kSource.isEmpty())
            {
                return kSource.toString();
            }
        }
        languageId = kPack.fallbackLanguageId;
    }
    return {};
}

QString ks::i18n::LanguageManager::displayText(const QString& renderedOrSourceText) const
{
    if (renderedOrSourceText.isEmpty())
    {
        return renderedOrSourceText;
    }
    if (containsHanCharacters(renderedOrSourceText))
    {
        return sourceText(renderedOrSourceText);
    }

    const QString kCanonicalSource = sourceForRenderedText(renderedOrSourceText);
    return kCanonicalSource.isEmpty() ? renderedOrSourceText : sourceText(kCanonicalSource);
}

void ks::i18n::LanguageManager::bindText(
    QObject* object,
    const QString& key,
    const QString& fallbackText)
{
    if (object == nullptr)
    {
        return;
    }
    object->setProperty(kTextKeyProperty, key);
    object->setProperty(kTextFallbackProperty, fallbackText);
    applyBindings(object);
}

void ks::i18n::LanguageManager::bindToolTip(
    QWidget* widget,
    const QString& key,
    const QString& fallbackText)
{
    if (widget == nullptr)
    {
        return;
    }
    widget->setProperty(kToolTipKeyProperty, key);
    widget->setProperty(kToolTipFallbackProperty, fallbackText);
    applyBindings(widget);
}

void ks::i18n::LanguageManager::bindPlaceholder(
    QLineEdit* lineEdit,
    const QString& key,
    const QString& fallbackText)
{
    if (lineEdit == nullptr)
    {
        return;
    }
    lineEdit->setProperty(kPlaceholderKeyProperty, key);
    lineEdit->setProperty(kPlaceholderFallbackProperty, fallbackText);
    applyBindings(lineEdit);
}

void ks::i18n::LanguageManager::bindSuffix(
    QSpinBox* spinBox,
    const QString& key,
    const QString& fallbackText)
{
    if (spinBox == nullptr)
    {
        return;
    }
    spinBox->setProperty(kSuffixKeyProperty, key);
    spinBox->setProperty(kSuffixFallbackProperty, fallbackText);
    applyBindings(spinBox);
}

void ks::i18n::LanguageManager::bindWindowTitle(
    QWidget* widget,
    const QString& key,
    const QString& fallbackText)
{
    if (widget == nullptr)
    {
        return;
    }
    widget->setProperty(kWindowTitleKeyProperty, key);
    widget->setProperty(kWindowTitleFallbackProperty, fallbackText);
    applyBindings(widget);
}

void ks::i18n::LanguageManager::bindTab(
    QTabWidget* tabWidget,
    QWidget* page,
    const QString& key,
    const QString& fallbackText)
{
    if (tabWidget == nullptr || page == nullptr)
    {
        return;
    }
    page->setProperty(kTabKeyProperty, key);
    page->setProperty(kTabFallbackProperty, fallbackText);
    applyBindings(tabWidget);
}

void ks::i18n::LanguageManager::bindTabToolTip(
    QTabWidget* tabWidget,
    QWidget* page,
    const QString& key,
    const QString& fallbackText)
{
    if (tabWidget == nullptr || page == nullptr || tabWidget->indexOf(page) < 0)
    {
        return;
    }
    page->setProperty(kTabToolTipKeyProperty, key);
    page->setProperty(kTabToolTipFallbackProperty, fallbackText);
    applyBindings(tabWidget);
}

void ks::i18n::LanguageManager::bindComboBoxItem(
    QComboBox* comboBox,
    const int itemIndex,
    const QString& key,
    const QString& fallbackText)
{
    if (comboBox == nullptr || itemIndex < 0 || itemIndex >= comboBox->count())
    {
        return;
    }
    comboBox->setItemData(itemIndex, key, kComboKeyRole);
    comboBox->setItemData(itemIndex, fallbackText, kComboFallbackRole);
    applyBindings(comboBox);
}

void ks::i18n::LanguageManager::retranslateAll()
{
    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }

    const QWidgetList kTopLevelWidgetList = application->topLevelWidgets();
    for (QWidget* widget : kTopLevelWidgetList)
    {
        if (widget == nullptr)
        {
            continue;
        }
        QList<QPointer<QWidget>> widgetList;
        widgetList.append(QPointer<QWidget>(widget));
        const QList<QWidget*> kChildWidgetList = widget->findChildren<QWidget*>();
        widgetList.reserve(widgetList.size() + kChildWidgetList.size());
        for (QWidget* childWidget : kChildWidgetList)
        {
            widgetList.append(QPointer<QWidget>(childWidget));
        }

        // Qt normally delivers LanguageChange to top-level widgets. KSword
        // contains many nested, independently implemented pages, so deliver the
        // event to every live widget as well. This keeps already-created lazy
        // pages, tables, charts, and dialogs in sync without a restart.
        for (const QPointer<QWidget>& targetWidget : widgetList)
        {
            if (targetWidget.isNull())
            {
                continue;
            }
            QEvent languageChangeEvent(QEvent::LanguageChange);
            QCoreApplication::sendEvent(targetWidget.data(), &languageChangeEvent);
        }
        applyBindings(widget);
        applyRuntimeTranslations(widget);
    }
}

void ks::i18n::LanguageManager::discoverLanguagePacks(QStringList* warningListOut)
{
    // Scan manifest only: read only top-level scalar fields per package; skip all three translation tables.
    // The translation table is parsed by acquirePack only when the language is queried for the first time; unused languages do not consume translation table memory.
    QMutexLocker locker(&state_->mutex);
    state_->packs.clear();

    const QStringList kDirectoryList = languageDirectoryCandidates();
    for (const QString& directoryPath : kDirectoryList)
    {
        QDir languageDirectory(directoryPath);
        if (!languageDirectory.exists())
        {
            continue;
        }

        const QFileInfoList kFileInfoList = languageDirectory.entryInfoList(
            QStringList{ QStringLiteral("*.json") },
            QDir::Files | QDir::Readable,
            QDir::Name | QDir::IgnoreCase);
        for (const QFileInfo& fileInfo : kFileInfoList)
        {
            PackMetadata metadata;
            QString loadErrorText;
            if (!loadPackFile(fileInfo.absoluteFilePath(), nullptr, &metadata, &loadErrorText))
            {
                if (warningListOut != nullptr)
                {
                    warningListOut->append(loadErrorText);
                }
                continue;
            }

            const bool kAlreadyLoaded = std::any_of(
                state_->packs.cbegin(),
                state_->packs.cend(),
                [&metadata](const State::PackEntry& entry) {
                    return entry.info.id.compare(metadata.id, Qt::CaseInsensitive) == 0;
                });
            if (kAlreadyLoaded)
            {
                continue;
            }

            State::PackEntry entry;
            entry.info.id = metadata.id;
            entry.info.name = metadata.name;
            entry.info.nativeName = metadata.nativeName;
            entry.info.author = metadata.author;
            entry.info.filePath = QDir::cleanPath(fileInfo.absoluteFilePath());
            entry.info.rightToLeft = metadata.textDirection.compare(
                QStringLiteral("rtl"),
                Qt::CaseInsensitive) == 0;
            entry.fallbackLanguageId = metadata.fallback;
            state_->packs.push_back(std::move(entry));
        }
    }

    std::sort(
        state_->packs.begin(),
        state_->packs.end(),
        [](const State::PackEntry& left, const State::PackEntry& right) {
            return left.info.nativeName.localeAwareCompare(right.info.nativeName) < 0;
        });
}

QString ks::i18n::LanguageManager::resolveText(
    const QString& languageId,
    const QString& key,
    const QString& fallbackText,
    QStringList* visitedLanguageIds) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty())
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }

    const QString kNormalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(kNormalizedLanguageId))
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }
    visitedLanguageIds->append(kNormalizedLanguageId);

    // zh-CN is the source-language baseline. The fallback at the original
    // call site is authoritative so a generated/edited pack cannot alter it.
    if (isHistoricalChineseLanguage(kNormalizedLanguageId) && !fallbackText.isEmpty())
    {
        return fallbackText;
    }

    const PackRef kPack = acquirePack(kNormalizedLanguageId);
    if (!kPack.found || !kPack.data)
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }

    if (const StringEntry* entry = kPack.data->find(kPack.data->translations, key))
    {
        return kPack.data->valueOf(*entry).toString();
    }
    if (const StringEntry* entry = kPack.data->find(kPack.data->contextTranslations, key))
    {
        return kPack.data->valueOf(*entry).toString();
    }
    if (!kPack.fallbackLanguageId.isEmpty())
    {
        return resolveText(
            kPack.fallbackLanguageId,
            key,
            fallbackText,
            visitedLanguageIds);
    }
    return fallbackText.isEmpty() ? key : fallbackText;
}

QString ks::i18n::LanguageManager::resolveContextText(
    const QString& languageId,
    const QString& contextKey,
    const QString& sourceText,
    QStringList* visitedLanguageIds) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty())
    {
        return sourceText;
    }

    const QString kNormalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(kNormalizedLanguageId))
    {
        return sourceText;
    }
    visitedLanguageIds->append(kNormalizedLanguageId);

    // Keep the historical Chinese fallback authoritative even when a third
    // language reaches zh-CN through its fallback chain.
    if (isHistoricalChineseLanguage(kNormalizedLanguageId))
    {
        return sourceText;
    }

    const PackRef kPack = acquirePack(kNormalizedLanguageId);
    if (!kPack.found || !kPack.data)
    {
        return sourceText;
    }

    if (const StringEntry* entry = kPack.data->find(kPack.data->contextTranslations, contextKey))
    {
        return kPack.data->valueOf(*entry).toString();
    }
    if (!kPack.fallbackLanguageId.isEmpty())
    {
        return resolveContextText(
            kPack.fallbackLanguageId,
            contextKey,
            sourceText,
            visitedLanguageIds);
    }
    return sourceText;
}

QString ks::i18n::LanguageManager::resolveSourceText(
    const QString& languageId,
    const QString& sourceText,
    QStringList* visitedLanguageIds,
    const bool preserveHistoricalChineseSource) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty() || sourceText.isEmpty())
    {
        return sourceText;
    }

    const QString kNormalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(kNormalizedLanguageId))
    {
        return sourceText;
    }
    visitedLanguageIds->append(kNormalizedLanguageId);

    if (preserveHistoricalChineseSource
        && isHistoricalChineseLanguage(kNormalizedLanguageId))
    {
        return sourceText;
    }

    const PackRef kPack = acquirePack(kNormalizedLanguageId);
    if (!kPack.found || !kPack.data)
    {
        return sourceText;
    }

    if (const StringEntry* entry = kPack.data->find(kPack.data->sourceTranslations, sourceText))
    {
        return kPack.data->valueOf(*entry).toString();
    }

    if (containsHanCharacters(sourceText))
    {
        for (const TemplateRef& reference : kPack.data->sourceTemplates)
        {
            const StringEntry& entry = kPack.data->sourceTranslations[reference.entryIndex];
            const QStringView kPatternText = kPack.data->keyOf(entry);
            if (reference.prefixLength > 0
                && !sourceText.startsWith(kPatternText.first(reference.prefixLength)))
            {
                continue;
            }
            if (reference.suffixLength > 0
                && !sourceText.endsWith(kPatternText.last(reference.suffixLength)))
            {
                continue;
            }

            ParsedTemplate parsedPattern = parseTemplate(kPatternText);
            if (!matchTemplate(sourceText, parsedPattern))
            {
                continue;
            }

            const QStringView kTranslatedPattern = kPack.data->valueOf(entry);
            QString translatedText;
            qsizetype previousEnd = 0;
            qsizetype placeholderStart = 0;
            qsizetype placeholderLength = 0;
            while (findPlaceholder(kTranslatedPattern, previousEnd, &placeholderStart, &placeholderLength))
            {
                translatedText += kTranslatedPattern.sliced(
                    previousEnd,
                    placeholderStart - previousEnd);
                const QStringView kPlaceholder = kTranslatedPattern.sliced(
                    placeholderStart,
                    placeholderLength);
                // When the same placeholder appears multiple times in the source string, capture the first occurrence, consistent with the registration order of the legacy implementation.
                const auto kPlaceholderIterator = std::find(
                    parsedPattern.placeholders.cbegin(),
                    parsedPattern.placeholders.cend(),
                    kPlaceholder);
                if (kPlaceholderIterator == parsedPattern.placeholders.cend())
                {
                    translatedText.clear();
                    break;
                }
                // Placeholder values can themselves be stable UI phrases (for
                // example a translated status template receiving "Safe Mode".
                // Resolve each captured value independently so an English outer
                // template cannot retain a nested Chinese enum/status string.
                const std::size_t kCaptureIndex = static_cast<std::size_t>(
                    kPlaceholderIterator - parsedPattern.placeholders.cbegin());
                translatedText += this->sourceText(
                    parsedPattern.captures[kCaptureIndex].toString());
                previousEnd = placeholderStart + placeholderLength;
            }
            if (!translatedText.isNull())
            {
                translatedText += kTranslatedPattern.sliced(previousEnd);
                return translatedText;
            }
        }
    }

    if (!kPack.fallbackLanguageId.isEmpty())
    {
        return resolveSourceText(
            kPack.fallbackLanguageId,
            sourceText,
            visitedLanguageIds,
            preserveHistoricalChineseSource);
    }
    return sourceText;
}

void ks::i18n::LanguageManager::ensureApplicationEventFilter()
{
    if (applicationEventFilterInstalled_)
    {
        return;
    }

    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }
    application->installEventFilter(this);
    applicationEventFilterInstalled_ = true;
}

void ks::i18n::LanguageManager::scheduleRuntimeTranslation(QObject* object)
{
    if (object == nullptr || applyingRuntimeTranslations_
        || object->property(kRuntimeRefreshPendingProperty).toBool())
    {
        return;
    }

    object->setProperty(kRuntimeRefreshPendingProperty, true);
    const QPointer<QObject> kGuardedObject(object);
    QTimer::singleShot(0, this, [this, kGuardedObject]() {
        if (kGuardedObject.isNull())
        {
            return;
        }
        kGuardedObject->setProperty(kRuntimeRefreshPendingProperty, false);
        applyRuntimeTranslations(kGuardedObject.data());
    });
}

bool ks::i18n::LanguageManager::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == nullptr || event == nullptr || applyingRuntimeTranslations_
        || isHistoricalChineseLanguage(currentLanguageId_))
    {
        return QObject::eventFilter(watched, event);
    }

    switch (event->type())
    {
    case QEvent::ChildAdded:
    {
        QChildEvent* childEvent = static_cast<QChildEvent*>(event);
        QObject* targetObject = childEvent->child() != nullptr ? childEvent->child() : watched;
        scheduleRuntimeTranslation(runtimeTranslationRoot(targetObject));
        break;
    }
    case QEvent::Show:
    case QEvent::PolishRequest:
    case QEvent::ActionAdded:
    case QEvent::ActionChanged:
        scheduleRuntimeTranslation(runtimeTranslationRoot(watched));
        break;
    case QEvent::LayoutRequest:
    case QEvent::UpdateRequest:
    {
        QObject* targetObject = watched;
        if (qobject_cast<QHeaderView*>(watched) != nullptr)
        {
            QObject* parentObject = watched->parent();
            while (parentObject != nullptr && qobject_cast<QAbstractItemView*>(parentObject) == nullptr)
            {
                parentObject = parentObject->parent();
            }
            if (parentObject != nullptr)
            {
                targetObject = parentObject;
            }
        }
        scheduleRuntimeTranslation(targetObject);
        break;
    }
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void ks::i18n::LanguageManager::applyRuntimeTranslations(QObject* object)
{
    if (object == nullptr || applyingRuntimeTranslations_)
    {
        return;
    }

    QScopedValueRollback<bool> translationGuard(applyingRuntimeTranslations_, true);
    std::function<void(QAbstractItemModel*, const QModelIndex&, int&)> translateModelItems;
    translateModelItems = [this, &translateModelItems](
                              QAbstractItemModel* model,
                              const QModelIndex& parentIndex,
                              int& remainingIndexBudget) {
        if (model == nullptr || remainingIndexBudget <= 0)
        {
            return;
        }

        const int kRowCount = model->rowCount(parentIndex);
        const int kColumnCount = model->columnCount(parentIndex);
        for (int row = 0; row < kRowCount && remainingIndexBudget > 0; ++row)
        {
            for (int column = 0; column < kColumnCount && remainingIndexBudget > 0; ++column)
            {
                const QModelIndex kIndex = model->index(row, column, parentIndex);
                --remainingIndexBudget;
                if (!kIndex.isValid())
                {
                    continue;
                }

                const QVariant kSourceValue = model->data(kIndex, kRuntimeModelSourceRole);
                const QVariant kAppliedValue = model->data(kIndex, kRuntimeModelAppliedRole);
                const ManagedTextResult kResult = resolveManagedText(
                    *this,
                    model->data(kIndex, Qt::DisplayRole).toString(),
                    kSourceValue,
                    kAppliedValue,
                    false);
                if (kResult.clearMetadata)
                {
                    model->setData(kIndex, QVariant(), kRuntimeModelSourceRole);
                    model->setData(kIndex, QVariant(), kRuntimeModelAppliedRole);
                    continue;
                }
                if (!kResult.updateMetadata)
                {
                    continue;
                }

                // Do not mutate read-only/custom models that reject our
                // private roles. This keeps runtime/user data untouched.
                if (!model->setData(kIndex, kResult.sourceText, kRuntimeModelSourceRole))
                {
                    continue;
                }
                if (!model->setData(kIndex, kResult.appliedText, kRuntimeModelAppliedRole))
                {
                    model->setData(kIndex, QVariant(), kRuntimeModelSourceRole);
                    continue;
                }
                if (kResult.setText
                    && !model->setData(kIndex, kResult.appliedText, Qt::DisplayRole))
                {
                    model->setData(kIndex, QVariant(), kRuntimeModelSourceRole);
                    model->setData(kIndex, QVariant(), kRuntimeModelAppliedRole);
                }
            }

            const QModelIndex kChildParent = model->index(row, 0, parentIndex);
            if (kChildParent.isValid() && model->hasChildren(kChildParent))
            {
                translateModelItems(model, kChildParent, remainingIndexBudget);
            }
        }
    };

    std::function<void(QObject*)> visitObject;
    visitObject = [this, &translateModelItems, &visitObject](QObject* currentObject) {
        if (currentObject == nullptr)
        {
            return;
        }

        if (QAction* action = qobject_cast<QAction*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                action,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                action->text(),
                [action](const QString& value) { action->setText(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeToolTipSourceProperty,
                kRuntimeToolTipAppliedProperty,
                action->toolTip(),
                [action](const QString& value) { action->setToolTip(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeStatusTipSourceProperty,
                kRuntimeStatusTipAppliedProperty,
                action->statusTip(),
                [action](const QString& value) { action->setStatusTip(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeWhatsThisSourceProperty,
                kRuntimeWhatsThisAppliedProperty,
                action->whatsThis(),
                [action](const QString& value) { action->setWhatsThis(value); });
        }

        if (QWidget* widget = qobject_cast<QWidget*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeWindowTitleSourceProperty,
                kRuntimeWindowTitleAppliedProperty,
                widget->windowTitle(),
                [widget](const QString& value) { widget->setWindowTitle(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeToolTipSourceProperty,
                kRuntimeToolTipAppliedProperty,
                widget->toolTip(),
                [widget](const QString& value) { widget->setToolTip(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeStatusTipSourceProperty,
                kRuntimeStatusTipAppliedProperty,
                widget->statusTip(),
                [widget](const QString& value) { widget->setStatusTip(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeWhatsThisSourceProperty,
                kRuntimeWhatsThisAppliedProperty,
                widget->whatsThis(),
                [widget](const QString& value) { widget->setWhatsThis(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeAccessibleNameSourceProperty,
                kRuntimeAccessibleNameAppliedProperty,
                widget->accessibleName(),
                [widget](const QString& value) { widget->setAccessibleName(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeAccessibleDescriptionSourceProperty,
                kRuntimeAccessibleDescriptionAppliedProperty,
                widget->accessibleDescription(),
                [widget](const QString& value) { widget->setAccessibleDescription(value); });
        }

        if (QLabel* label = qobject_cast<QLabel*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                label,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                label->text(),
                [label](const QString& value) { label->setText(value); });
        }
        else if (QAbstractButton* button = qobject_cast<QAbstractButton*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                button,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                button->text(),
                [button](const QString& value) { button->setText(value); });
        }

        if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                groupBox,
                kRuntimeTitleSourceProperty,
                kRuntimeTitleAppliedProperty,
                groupBox->title(),
                [groupBox](const QString& value) { groupBox->setTitle(value); });
        }
        if (QMenu* menu = qobject_cast<QMenu*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                menu,
                kRuntimeTitleSourceProperty,
                kRuntimeTitleAppliedProperty,
                menu->title(),
                [menu](const QString& value) { menu->setTitle(value); });
        }
        if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                lineEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                lineEdit->placeholderText(),
                [lineEdit](const QString& value) { lineEdit->setPlaceholderText(value); });
        }
        if (QPlainTextEdit* plainTextEdit = qobject_cast<QPlainTextEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                plainTextEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                plainTextEdit->placeholderText(),
                [plainTextEdit](const QString& value) { plainTextEdit->setPlaceholderText(value); });
        }
        if (QTextEdit* textEdit = qobject_cast<QTextEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                textEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                textEdit->placeholderText(),
                [textEdit](const QString& value) { textEdit->setPlaceholderText(value); });
        }

        const auto kTranslateSpinBox = [this](auto* spinBox) {
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimePrefixSourceProperty,
                kRuntimePrefixAppliedProperty,
                spinBox->prefix(),
                [spinBox](const QString& value) { spinBox->setPrefix(value); });
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimeSuffixSourceProperty,
                kRuntimeSuffixAppliedProperty,
                spinBox->suffix(),
                [spinBox](const QString& value) { spinBox->setSuffix(value); });
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimeSpecialValueSourceProperty,
                kRuntimeSpecialValueAppliedProperty,
                spinBox->specialValueText(),
                [spinBox](const QString& value) { spinBox->setSpecialValueText(value); });
        };
        if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(currentObject))
        {
            kTranslateSpinBox(spinBox);
        }
        else if (QDoubleSpinBox* doubleSpinBox = qobject_cast<QDoubleSpinBox*>(currentObject))
        {
            kTranslateSpinBox(doubleSpinBox);
        }

        if (QComboBox* comboBox = qobject_cast<QComboBox*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                comboBox,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                comboBox->placeholderText(),
                [comboBox](const QString& value) { comboBox->setPlaceholderText(value); });
            for (int itemIndex = 0; itemIndex < comboBox->count(); ++itemIndex)
            {
                const ManagedTextResult kResult = resolveManagedText(
                    *this,
                    comboBox->itemText(itemIndex),
                    comboBox->itemData(itemIndex, kRuntimeComboSourceRole),
                    comboBox->itemData(itemIndex, kRuntimeComboAppliedRole));
                if (kResult.clearMetadata)
                {
                    comboBox->setItemData(itemIndex, QVariant(), kRuntimeComboSourceRole);
                    comboBox->setItemData(itemIndex, QVariant(), kRuntimeComboAppliedRole);
                    continue;
                }
                if (!kResult.updateMetadata)
                {
                    continue;
                }
                if (kResult.setText)
                {
                    comboBox->setItemText(itemIndex, kResult.appliedText);
                }
                comboBox->setItemData(itemIndex, kResult.sourceText, kRuntimeComboSourceRole);
                comboBox->setItemData(itemIndex, kResult.appliedText, kRuntimeComboAppliedRole);
            }
        }

        if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(currentObject))
        {
            for (int tabIndex = 0; tabIndex < tabWidget->count(); ++tabIndex)
            {
                QWidget* page = tabWidget->widget(tabIndex);
                if (page == nullptr)
                {
                    continue;
                }
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabSourceProperty,
                    kRuntimeTabAppliedProperty,
                    tabWidget->tabText(tabIndex),
                    [tabWidget, tabIndex](const QString& value) { tabWidget->setTabText(tabIndex, value); });
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabToolTipSourceProperty,
                    kRuntimeTabToolTipAppliedProperty,
                    tabWidget->tabToolTip(tabIndex),
                    [tabWidget, tabIndex](const QString& value) { tabWidget->setTabToolTip(tabIndex, value); });
            }
        }
        if (QToolBox* toolBox = qobject_cast<QToolBox*>(currentObject))
        {
            for (int itemIndex = 0; itemIndex < toolBox->count(); ++itemIndex)
            {
                QWidget* page = toolBox->widget(itemIndex);
                if (page == nullptr)
                {
                    continue;
                }
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabSourceProperty,
                    kRuntimeTabAppliedProperty,
                    toolBox->itemText(itemIndex),
                    [toolBox, itemIndex](const QString& value) { toolBox->setItemText(itemIndex, value); });
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabToolTipSourceProperty,
                    kRuntimeTabToolTipAppliedProperty,
                    toolBox->itemToolTip(itemIndex),
                    [toolBox, itemIndex](const QString& value) { toolBox->setItemToolTip(itemIndex, value); });
            }
        }

        if (QTableView* tableView = qobject_cast<QTableView*>(currentObject))
        {
            QAbstractItemModel* model = tableView->model();
            if (model != nullptr)
            {
                const int kColumnCount = model->columnCount(tableView->rootIndex());
                for (int section = 0; section < kColumnCount; ++section)
                {
                    const QString kCurrentHeader = model->headerData(
                        section,
                        Qt::Horizontal,
                        Qt::DisplayRole).toString();
                    const ManagedTextResult kResult = resolveManagedText(
                        *this,
                        kCurrentHeader,
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderSourceRole),
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderAppliedRole));
                    if (kResult.clearMetadata)
                    {
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderSourceRole);
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderAppliedRole);
                        continue;
                    }
                    if (!kResult.updateMetadata)
                    {
                        continue;
                    }
                    if (kResult.setText
                        && !model->setHeaderData(section, Qt::Horizontal, kResult.appliedText, Qt::DisplayRole))
                    {
                        continue;
                    }
                    model->setHeaderData(section, Qt::Horizontal, kResult.sourceText, kRuntimeHeaderSourceRole);
                    model->setHeaderData(section, Qt::Horizontal, kResult.appliedText, kRuntimeHeaderAppliedRole);
                }
                int remainingIndexBudget = 50000;
                translateModelItems(model, tableView->rootIndex(), remainingIndexBudget);
            }
        }
        else if (QTreeView* treeView = qobject_cast<QTreeView*>(currentObject))
        {
            QAbstractItemModel* model = treeView->model();
            if (model != nullptr)
            {
                const int kColumnCount = model->columnCount(treeView->rootIndex());
                for (int section = 0; section < kColumnCount; ++section)
                {
                    const QString kCurrentHeader = model->headerData(
                        section,
                        Qt::Horizontal,
                        Qt::DisplayRole).toString();
                    const ManagedTextResult kResult = resolveManagedText(
                        *this,
                        kCurrentHeader,
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderSourceRole),
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderAppliedRole));
                    if (kResult.clearMetadata)
                    {
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderSourceRole);
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderAppliedRole);
                        continue;
                    }
                    if (!kResult.updateMetadata)
                    {
                        continue;
                    }
                    if (kResult.setText
                        && !model->setHeaderData(section, Qt::Horizontal, kResult.appliedText, Qt::DisplayRole))
                    {
                        continue;
                    }
                    model->setHeaderData(section, Qt::Horizontal, kResult.sourceText, kRuntimeHeaderSourceRole);
                    model->setHeaderData(section, Qt::Horizontal, kResult.appliedText, kRuntimeHeaderAppliedRole);
                }
                int remainingIndexBudget = 50000;
                translateModelItems(model, treeView->rootIndex(), remainingIndexBudget);
            }
        }

        const QObjectList kChildList = currentObject->children();
        for (QObject* childObject : kChildList)
        {
            visitObject(childObject);
        }
    };

    visitObject(object);
}

void ks::i18n::LanguageManager::applyBindings(QObject* object) const
{
    if (object == nullptr)
    {
        return;
    }

    const QString kTextKey = object->property(kTextKeyProperty).toString();
    if (!kTextKey.isEmpty())
    {
        const QString kTranslatedText = text(kTextKey, object->property(kTextFallbackProperty).toString());
        if (QAbstractButton* button = qobject_cast<QAbstractButton*>(object))
        {
            button->setText(kTranslatedText);
        }
        else if (QLabel* label = qobject_cast<QLabel*>(object))
        {
            label->setText(kTranslatedText);
        }
        else if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(object))
        {
            groupBox->setTitle(kTranslatedText);
        }
        else if (QAction* action = qobject_cast<QAction*>(object))
        {
            action->setText(kTranslatedText);
        }
    }

    if (QWidget* widget = qobject_cast<QWidget*>(object))
    {
        const QString kToolTipKey = widget->property(kToolTipKeyProperty).toString();
        if (!kToolTipKey.isEmpty())
        {
            widget->setToolTip(text(kToolTipKey, widget->property(kToolTipFallbackProperty).toString()));
        }

        const QString kWindowTitleKey = widget->property(kWindowTitleKeyProperty).toString();
        if (!kWindowTitleKey.isEmpty())
        {
            widget->setWindowTitle(text(
                kWindowTitleKey,
                widget->property(kWindowTitleFallbackProperty).toString()));
        }
    }

    if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(object))
    {
        const QString kPlaceholderKey = lineEdit->property(kPlaceholderKeyProperty).toString();
        if (!kPlaceholderKey.isEmpty())
        {
            lineEdit->setPlaceholderText(text(
                kPlaceholderKey,
                lineEdit->property(kPlaceholderFallbackProperty).toString()));
        }
    }

    if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(object))
    {
        const QString kSuffixKey = spinBox->property(kSuffixKeyProperty).toString();
        if (!kSuffixKey.isEmpty())
        {
            spinBox->setSuffix(text(
                kSuffixKey,
                spinBox->property(kSuffixFallbackProperty).toString()));
        }
    }

    if (QComboBox* comboBox = qobject_cast<QComboBox*>(object))
    {
        for (int index = 0; index < comboBox->count(); ++index)
        {
            const QString kItemKey = comboBox->itemData(index, kComboKeyRole).toString();
            if (!kItemKey.isEmpty())
            {
                comboBox->setItemText(index, text(kItemKey, comboBox->itemData(index, kComboFallbackRole).toString()));
            }
        }
    }

    if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(object))
    {
        for (int index = 0; index < tabWidget->count(); ++index)
        {
            QWidget* page = tabWidget->widget(index);
            if (page == nullptr)
            {
                continue;
            }
            const QString kTabKey = page->property(kTabKeyProperty).toString();
            if (!kTabKey.isEmpty())
            {
                tabWidget->setTabText(index, text(kTabKey, page->property(kTabFallbackProperty).toString()));
            }
            const QString kTabToolTipKey = page->property(kTabToolTipKeyProperty).toString();
            if (!kTabToolTipKey.isEmpty())
            {
                tabWidget->setTabToolTip(
                    index,
                    text(kTabToolTipKey, page->property(kTabToolTipFallbackProperty).toString()));
            }
        }
    }

    const QObjectList kChildList = object->children();
    for (QObject* childObject : kChildList)
    {
        applyBindings(childObject);
    }
}

void ks::i18n::LanguageManager::applyApplicationDirection() const
{
    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }

    // Writing direction comes from metadata in the manifest; no translation table needs to be loaded.
    bool rightToLeft = false;
    {
        QMutexLocker locker(&state_->mutex);
        const auto kPackIterator = std::find_if(
            state_->packs.cbegin(),
            state_->packs.cend(),
            [this](const State::PackEntry& entry) {
                return entry.info.id.compare(currentLanguageId_, Qt::CaseInsensitive) == 0;
            });
        rightToLeft = kPackIterator != state_->packs.cend() && kPackIterator->info.rightToLeft;
    }
    application->setLayoutDirection(rightToLeft ? Qt::RightToLeft : Qt::LeftToRight);
}
