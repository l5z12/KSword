#pragma once

#include <QList>
#include <QHash>
#include <QObject>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include <memory>

class QComboBox;
class QLineEdit;
class QSpinBox;
class QTabWidget;
class QWidget;

namespace ks::i18n
{
    struct LanguageInfo
    {
        QString id;
        QString name;
        QString nativeName;
        QString author;
        QString filePath;
        bool rightToLeft = false;
    };

    class LanguageManager final : public QObject
    {
    public:
        static LanguageManager& instance();

        bool initialize(const QString& preferredLanguageId, QString* errorTextOut = nullptr);
        bool setLanguage(const QString& languageId, QString* errorTextOut = nullptr);

        QString currentLanguageId() const;
        QList<LanguageInfo> availableLanguages() const;
        QString text(const QString& key, const QString& fallbackText = QString()) const;
        QString contextText(const QString& contextKey, const QString& sourceText) const;
        QString sourceText(const QString& sourceText) const;
        // Force a query for the current language pack's source_translations; used for standalone pages where English serves as the canonical source text.
        // Unlike sourceText(), this also checks the package in Chinese mode instead of directly returning the call-site text.
        QString packedSourceText(const QString& sourceText) const;
        QString sourceForRenderedText(const QString& renderedText) const;
        QString displayText(const QString& renderedOrSourceText) const;

        void bindText(QObject* object, const QString& key, const QString& fallbackText);
        void bindToolTip(QWidget* widget, const QString& key, const QString& fallbackText);
        void bindPlaceholder(QLineEdit* lineEdit, const QString& key, const QString& fallbackText);
        void bindSuffix(QSpinBox* spinBox, const QString& key, const QString& fallbackText);
        void bindWindowTitle(QWidget* widget, const QString& key, const QString& fallbackText);
        void bindTab(QTabWidget* tabWidget, QWidget* page, const QString& key, const QString& fallbackText);
        void bindTabToolTip(QTabWidget* tabWidget, QWidget* page, const QString& key, const QString& fallbackText);
        void bindComboBoxItem(
            QComboBox* comboBox,
            int itemIndex,
            const QString& key,
            const QString& fallbackText);
        void retranslateAll();

    private:
        LanguageManager();
        ~LanguageManager() override;
        Q_DISABLE_COPY_MOVE(LanguageManager)

        // Language packs are loaded on demand: only metadata manifests are read at startup; translation tables are parsed only upon first actual use.
        // State holds the list and loaded translation tables; PackRef is a read-only snapshot obtained from a single query.
        struct State;
        struct PackRef;

        void discoverLanguagePacks(QStringList* warningListOut);
        // acquirePack: Retrieve the pack by language ID; resolve it here if not yet loaded. data is null if not found or resolution fails.
        PackRef acquirePack(const QString& languageId) const;
        // hasAnyPack: Whether there are available language packs in the manifest; checks metadata only without triggering loading.
        bool hasAnyPack() const;
        QString resolvePreferredLanguageId(const QString& preferredLanguageId) const;
        QString resolveText(
            const QString& languageId,
            const QString& key,
            const QString& fallbackText,
            QStringList* visitedLanguageIds) const;
        QString resolveContextText(
            const QString& languageId,
            const QString& contextKey,
            const QString& sourceText,
            QStringList* visitedLanguageIds) const;
        QString resolveSourceText(
            const QString& languageId,
            const QString& sourceText,
            QStringList* visitedLanguageIds,
            bool preserveHistoricalChineseSource) const;
        void ensureApplicationEventFilter();
        void scheduleRuntimeTranslation(QObject* object);
        void applyRuntimeTranslations(QObject* object);
        void applyBindings(QObject* object) const;
        void applyApplicationDirection() const;
        bool eventFilter(QObject* watched, QEvent* event) override;

        std::unique_ptr<State> state_;
        QString currentLanguageId_;
        bool applicationEventFilterInstalled_ = false;
        bool applyingRuntimeTranslations_ = false;
    };

    inline QString text(const QString& key, const QString& fallbackText = QString())
    {
        return LanguageManager::instance().text(key, fallbackText);
    }

    inline QString contextText(const QString& contextKey, const QString& sourceText)
    {
        return LanguageManager::instance().contextText(contextKey, sourceText);
    }

    inline QString sourceText(const QString& sourceText)
    {
        return LanguageManager::instance().sourceText(sourceText);
    }

    inline QString packedSourceText(const QString& sourceText)
    {
        return LanguageManager::instance().packedSourceText(sourceText);
    }

    inline QString displayText(const QString& renderedOrSourceText)
    {
        return LanguageManager::instance().displayText(renderedOrSourceText);
    }

}
