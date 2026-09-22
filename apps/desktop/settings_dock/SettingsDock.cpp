#include "SettingsDock.h"

#include "../Framework.h"
#include "../internationalization/LanguageManager.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../Theme.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFileDialog>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QSlider>
#include <QSpinBox>
#include <QStringList>
#include <QTabWidget>
#include <QToolButton>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cmath>
#include <string>
#include <vector>

namespace
{
    // ToolTip and icon constants: Centralize maintenance of settings page button text to avoid scattered hardcoding.
    constexpr const char* kIconThemeFollowSystem = ":/Icon/settings_theme_system.svg";
    constexpr const char* kIconThemeLight = ":/Icon/settings_theme_light.svg";
    constexpr const char* kIconThemeDark = ":/Icon/settings_theme_dark.svg";
    constexpr const char* kIconBrowseBackground = ":/Icon/settings_background_browse.svg";
    constexpr const char* kIconResetBackground = ":/Icon/settings_background_reset.svg";
    constexpr wchar_t kUnlockerKeyName[] = L"Ksword.FileUnlocker";

    // Purpose of windowScalePercentFromFactor / windowScaleFactorFromPercent:
    // - The settings page displays window scaling as a percentage (consistent with Windows display settings), while the configuration file still stores the scale factor.
    // - Traverse both directions through normalizeWindowScaleFactor to ensure the UI selectable range matches the persisted range.
    // Input/Output: conversion between percentage integer (50~200) and scale factor (0.50~2.00).
    int windowScalePercentFromFactor(const double scaleFactor)
    {
        return static_cast<int>(std::lround(
            ks::settings::normalizeWindowScaleFactor(scaleFactor) * 100.0));
    }

    double windowScaleFactorFromPercent(const int scalePercent)
    {
        return ks::settings::normalizeWindowScaleFactor(
            static_cast<double>(scalePercent) / 100.0);
    }

    // selectedThemeUsesDarkBackground: Computes the default main background preview for theme buttons that have not yet been applied.
    // When following the system, reuse the currently active theme state; when forcing a theme, read the button ID directly.
    bool selectedThemeUsesDarkBackground(const QButtonGroup* themeButtonGroup)
    {
        if (themeButtonGroup != nullptr)
        {
            const int kCheckedThemeId = themeButtonGroup->checkedId();
            if (kCheckedThemeId == static_cast<int>(ks::settings::ThemeMode::kDark))
            {
                return true;
            }
            if (kCheckedThemeId == static_cast<int>(ks::settings::ThemeMode::kLight))
            {
                return false;
            }
        }
        return ksword_theme::isDarkModeEnabled();
    }

    std::wstring queryCurrentExecutablePath()
    {
        std::vector<wchar_t> pathBuffer(1024, L'\0');
        while (pathBuffer.size() < 32768)
        {
            ::SetLastError(ERROR_SUCCESS);
            const DWORD kCopiedLength = ::GetModuleFileNameW(
                nullptr,
                pathBuffer.data(),
                static_cast<DWORD>(pathBuffer.size()));
            const DWORD kLastError = ::GetLastError();
            if (kCopiedLength == 0)
            {
                return std::wstring();
            }
            if (kCopiedLength < pathBuffer.size() && kLastError != ERROR_INSUFFICIENT_BUFFER)
            {
                return std::wstring(pathBuffer.data(), kCopiedLength);
            }
            pathBuffer.resize(pathBuffer.size() * 2, L'\0');
        }
        return std::wstring();
    }

    bool writeRegistryString(
        HKEY rootKey,
        const std::wstring& subKeyPath,
        const wchar_t* valueName,
        const std::wstring& valueText)
    {
        HKEY keyHandle = nullptr;
        const LONG kCreateResult = ::RegCreateKeyExW(
            rootKey,
            subKeyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &keyHandle,
            nullptr);
        if (kCreateResult != ERROR_SUCCESS)
        {
            return false;
        }

        const DWORD kValueSizeBytes = static_cast<DWORD>((valueText.size() + 1) * sizeof(wchar_t));
        const LONG kSetResult = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueText.c_str()),
            kValueSizeBytes);
        ::RegCloseKey(keyHandle);
        return kSetResult == ERROR_SUCCESS;
    }

    void deleteRegistryTreeBestEffort(HKEY rootKey, const std::wstring& subKeyPath)
    {
        ::RegDeleteTreeW(rootKey, subKeyPath.c_str());
    }

    bool registerUnlockerContextMenuNow(const std::wstring& executablePath)
    {
        if (executablePath.empty())
        {
            return false;
        }

        const std::wstring kCommandForFile = L"\"" + executablePath + L"\" --unlock \"%1\"";
        const std::wstring kBaseStar = L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kBaseDirectory = L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kBaseDrive = L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kMenuText = ks::i18n::contextText(
            QStringLiteral("main.unlocker.menu"),
            QStringLiteral("使用 Ksword 文件解锁器(R3/R0)")).toStdWString();

        // The unlocker is only meaningful for 'selected files/folders/drives', so Directory\Background registration is no longer performed:
        // This location corresponds to the right-click context menu on the desktop and folder backgrounds when no target is selected; the menu items are purely noise.
        // The old version wrote this key; clear it during registration to prevent it from lingering on the desktop right-click menu after an upgrade.
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));

        return
            writeRegistryString(HKEY_CURRENT_USER, kBaseStar, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseStar, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseStar + L"\\command", nullptr, kCommandForFile)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory + L"\\command", nullptr, kCommandForFile)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDrive, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDrive, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDrive + L"\\command", nullptr, kCommandForFile);
    }

    void unregisterUnlockerContextMenuNow()
    {
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName));
        // Directory\Background is no longer registered, but must still be deleted: users with old versions installed need to be fully cleaned up.
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));
    }
}

SettingsDock::SettingsDock(QWidget* parent)
    : QWidget(parent)
{
    // Constructs a log event to trace the entire call chain for 'Settings page initialization'.
    KLogEvent settingsInitEvent;
    info << settingsInitEvent << "[SettingsDock] 开始初始化设置页 UI。" << eol;

    initializeUi();
    initializeAppearanceTab();
    initializeFeaturesTab();
    initializeOnlineScanTab();
    loadSettingsFromJson();

    info << settingsInitEvent << "[SettingsDock] 设置页初始化完成，界面与启动配置已加载。" << eol;
}

ks::settings::AppearanceSettings SettingsDock::currentAppearanceSettings() const
{
    return currentAppearanceSettings_;
}

void SettingsDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }
    if (event->type() == QEvent::LanguageChange)
    {
        updateSystemDefaultFontItemText();
        refreshBugcheckDiagnosticsStatusText();
        updateApplyButtonState();
    }
    // In system-follow mode, light/dark themes are flipped by the system without going through the 'Apply' button.
    // Trigger a re-send here to prevent the theme button from remaining stuck on the snapshot colors of the old theme.
    if (event->type() == QEvent::ApplicationPaletteChange && themeButtonGroup_ != nullptr)
    {
        updateThemeButtonStyle();
    }
}

void SettingsDock::initializeUi()
{
    // rootLayout role: SettingsDock root layout, carrying only scrollable setting tab content.
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(8);

    // m_tabWidget: Tab container for settings pages, extensible for additional tabs.
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setTabPosition(QTabWidget::North);
    rootLayout->addWidget(tabWidget_);

    setLayout(rootLayout);
}

void SettingsDock::initializeAppearanceTab()
{
    // Split the original 'Appearance, Language, and Startup' long page into three tabs to prevent a single settings page from exceeding available height.
    appearanceTab_ = new QWidget(tabWidget_);
    QVBoxLayout* appearanceRootLayout = new QVBoxLayout(appearanceTab_);
    appearanceRootLayout->setContentsMargins(8, 8, 8, 8);
    appearanceRootLayout->setSpacing(12);

    languageTab_ = new QWidget(tabWidget_);
    QVBoxLayout* languageRootLayout = new QVBoxLayout(languageTab_);
    languageRootLayout->setContentsMargins(8, 8, 8, 8);
    languageRootLayout->setSpacing(12);

    startupTab_ = new QWidget(tabWidget_);
    QVBoxLayout* startupRootLayout = new QVBoxLayout(startupTab_);
    startupRootLayout->setContentsMargins(8, 8, 8, 8);
    startupRootLayout->setSpacing(12);

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    // ===== Interface Language Group =====
    QGroupBox* languageGroupBox = new QGroupBox(QStringLiteral("界面语言"), languageTab_);
    languageManager.bindText(languageGroupBox, QStringLiteral("settings.language.group"), QStringLiteral("界面语言"));
    QVBoxLayout* languageLayout = new QVBoxLayout(languageGroupBox);
    languageLayout->setSpacing(8);

    QHBoxLayout* languageSelectLayout = new QHBoxLayout();
    QLabel* languageLabel = new QLabel(QStringLiteral("显示语言"), languageGroupBox);
    languageManager.bindText(languageLabel, QStringLiteral("settings.language.label"), QStringLiteral("显示语言"));
    languageSelectLayout->addWidget(languageLabel, 0);
    languageCombo_ = new QComboBox(languageGroupBox);
    languageCombo_->addItem(QStringLiteral("跟随系统"), QStringLiteral("system"));
    languageManager.bindComboBoxItem(
        languageCombo_,
        0,
        QStringLiteral("language.name.system"),
        QStringLiteral("跟随系统"));
    const QList<ks::i18n::LanguageInfo> kAvailableLanguages = languageManager.availableLanguages();
    for (const ks::i18n::LanguageInfo& languageInfo : kAvailableLanguages)
    {
        const QString kDisplayName = languageInfo.nativeName.isEmpty()
            ? languageInfo.name
            : languageInfo.nativeName;
        languageCombo_->addItem(kDisplayName, languageInfo.id);
        languageManager.bindComboBoxItem(
            languageCombo_,
            languageCombo_->count() - 1,
            QStringLiteral("language.name.%1").arg(languageInfo.id),
            kDisplayName);
    }
    languageManager.bindToolTip(
        languageCombo_,
        QStringLiteral("settings.language.tooltip"),
        QStringLiteral("选择界面语言；保存后立即切换"));
    languageSelectLayout->addWidget(languageCombo_, 1);
    languageLayout->addLayout(languageSelectLayout);
    languageRootLayout->addWidget(languageGroupBox);
    languageRootLayout->addStretch();

    // ===== Theme Mode Group =====
    QGroupBox* themeGroupBox = new QGroupBox(QStringLiteral("主题模式"), appearanceTab_);
    languageManager.bindText(themeGroupBox, QStringLiteral("settings.theme.group"), QStringLiteral("主题模式"));
    QVBoxLayout* themeLayout = new QVBoxLayout(themeGroupBox);
    themeLayout->setSpacing(8);

    QLabel* themeHintLabel = new QLabel(QStringLiteral("可选择跟随系统、浅色或深色主题。"), themeGroupBox);
    languageManager.bindText(themeHintLabel, QStringLiteral("settings.theme.hint"), QStringLiteral("可选择跟随系统、浅色或深色主题。"));
    themeLayout->addWidget(themeHintLabel);

    QHBoxLayout* themeButtonLayout = new QHBoxLayout();
    themeButtonLayout->setSpacing(10);
    themeButtonGroup_ = new QButtonGroup(themeGroupBox);
    themeButtonGroup_->setExclusive(true);

    // m_followSystemButton: Theme Follow System button (icon + tooltip).
    followSystemButton_ = new QToolButton(themeGroupBox);
    followSystemButton_->setIcon(QIcon(QString::fromUtf8(kIconThemeFollowSystem)));
    followSystemButton_->setCheckable(true);
    ksword_theme::applyStandardIconButtonMetrics(followSystemButton_);
    followSystemButton_->setToolTip(QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));
    languageManager.bindToolTip(followSystemButton_, QStringLiteral("settings.theme.system.tooltip"), QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));

    // m_lightModeButton function: Force light theme button (icon + tooltip).
    lightModeButton_ = new QToolButton(themeGroupBox);
    lightModeButton_->setIcon(QIcon(QString::fromUtf8(kIconThemeLight)));
    lightModeButton_->setCheckable(true);
    ksword_theme::applyStandardIconButtonMetrics(lightModeButton_);
    lightModeButton_->setToolTip(QStringLiteral("强制浅色模式（白底深色字）"));
    languageManager.bindToolTip(lightModeButton_, QStringLiteral("settings.theme.light.tooltip"), QStringLiteral("强制浅色模式（白底深色字）"));

    // m_darkModeButton function: Force dark mode button (icon + hover tooltip).
    darkModeButton_ = new QToolButton(themeGroupBox);
    darkModeButton_->setIcon(QIcon(QString::fromUtf8(kIconThemeDark)));
    darkModeButton_->setCheckable(true);
    ksword_theme::applyStandardIconButtonMetrics(darkModeButton_);
    darkModeButton_->setToolTip(QStringLiteral("强制深色模式（黑底白字）"));
    languageManager.bindToolTip(darkModeButton_, QStringLiteral("settings.theme.dark.tooltip"), QStringLiteral("强制深色模式（黑底白字）"));

    themeButtonGroup_->addButton(followSystemButton_, static_cast<int>(ks::settings::ThemeMode::kFollowSystem));
    themeButtonGroup_->addButton(lightModeButton_, static_cast<int>(ks::settings::ThemeMode::kLight));
    themeButtonGroup_->addButton(darkModeButton_, static_cast<int>(ks::settings::ThemeMode::kDark));

    themeButtonLayout->addWidget(followSystemButton_);
    themeButtonLayout->addWidget(lightModeButton_);
    themeButtonLayout->addWidget(darkModeButton_);
    themeButtonLayout->addStretch();
    themeLayout->addLayout(themeButtonLayout);

    // ===== Custom theme color group =====
    QGroupBox* themeColorGroupBox = new QGroupBox(QStringLiteral("主题色"), themeGroupBox);
    languageManager.bindText(themeColorGroupBox, QStringLiteral("settings.theme.color.group"), QStringLiteral("主题色"));
    QVBoxLayout* themeColorLayout = new QVBoxLayout(themeColorGroupBox);
    themeColorLayout->setSpacing(6);

    QLabel* themeColorHintLabel = new QLabel(
        QStringLiteral("自定义主主题色会保留现有深浅主题偏移；修改前会显示兼容性提示。"),
        themeColorGroupBox);
    themeColorHintLabel->setWordWrap(true);
    languageManager.bindText(
        themeColorHintLabel,
        QStringLiteral("settings.theme.color.hint"),
        QStringLiteral("自定义主主题色会保留现有深浅主题偏移；修改前会显示兼容性提示。"));
    themeColorLayout->addWidget(themeColorHintLabel);

    QHBoxLayout* themeColorActionLayout = new QHBoxLayout();
    themeColorActionLayout->setSpacing(6);
    themeColorPreviewLabel_ = new QLabel(themeColorGroupBox);
    themeColorPreviewLabel_->setMinimumWidth(112);
    themeColorPreviewLabel_->setAlignment(Qt::AlignCenter);
    themeColorActionLayout->addWidget(themeColorPreviewLabel_, 0);

    chooseThemeColorButton_ = new QPushButton(QStringLiteral("自定义主题色"), themeColorGroupBox);
    languageManager.bindText(chooseThemeColorButton_, QStringLiteral("settings.theme.color.choose"), QStringLiteral("自定义主题色"));
    themeColorActionLayout->addWidget(chooseThemeColorButton_, 0);

    resetThemeColorButton_ = new QPushButton(QStringLiteral("一键复原"), themeColorGroupBox);
    languageManager.bindText(resetThemeColorButton_, QStringLiteral("settings.theme.color.reset"), QStringLiteral("一键复原"));
    themeColorActionLayout->addWidget(resetThemeColorButton_, 0);
    themeColorActionLayout->addStretch();
    themeColorLayout->addLayout(themeColorActionLayout);
    themeLayout->addWidget(themeColorGroupBox);

    QHBoxLayout* fontLayout = new QHBoxLayout();
    fontLayout->setSpacing(6);
    QLabel* fontLabel = new QLabel(QStringLiteral("设置字体"), themeGroupBox);
    languageManager.bindText(fontLabel, QStringLiteral("settings.font.label"), QStringLiteral("设置字体"));
    fontLayout->addWidget(fontLabel, 0);
    fontCombo_ = new QComboBox(themeGroupBox);
    // Item 0's itemData is fixed to an empty string; display text is localized via an independent refresh function.
    fontCombo_->addItem(QString(), QString());
    updateSystemDefaultFontItemText();
    // fontFamilies usage: Captures currently installed fonts in the snapshot system and saves stable family data for each entry.
    const QStringList kFontFamilies = QFontDatabase::families();
    for (const QString& fontFamily : kFontFamilies)
    {
        const int kFontIndex = fontCombo_->count();
        fontCombo_->addItem(fontFamily, fontFamily);
        fontCombo_->setItemData(kFontIndex, QFont(fontFamily), Qt::FontRole);
    }
    fontCombo_->setToolTip(QStringLiteral("选择系统中已安装的字体；点击“应用”后立即生效"));
    languageManager.bindToolTip(
        fontCombo_,
        QStringLiteral("settings.font.tooltip"),
        QStringLiteral("选择系统中已安装的字体；点击“应用”后立即生效"));
    fontLayout->addWidget(fontCombo_, 1);
    themeLayout->addLayout(fontLayout);

    textAntialiasingCheckBox_ = new QCheckBox(QStringLiteral("启用文本抗锯齿"), themeGroupBox);
    languageManager.bindText(
        textAntialiasingCheckBox_,
        QStringLiteral("settings.text_antialiasing.enabled"),
        QStringLiteral("启用文本抗锯齿"));
    textAntialiasingCheckBox_->setToolTip(
        QStringLiteral("启用后使用平滑字体渲染；关闭时使用无抗锯齿字体渲染。"));
    languageManager.bindToolTip(
        textAntialiasingCheckBox_,
        QStringLiteral("settings.text_antialiasing.enabled.tooltip"),
        QStringLiteral("启用后使用平滑字体渲染；关闭时使用无抗锯齿字体渲染。"));
    themeLayout->addWidget(textAntialiasingCheckBox_);
    appearanceRootLayout->addWidget(themeGroupBox);

    // ===== Window Background Group =====
    QGroupBox* backgroundGroupBox = new QGroupBox(QStringLiteral("窗口背景"), appearanceTab_);
    languageManager.bindText(backgroundGroupBox, QStringLiteral("settings.background.group"), QStringLiteral("窗口背景"));
    QVBoxLayout* backgroundLayout = new QVBoxLayout(backgroundGroupBox);
    backgroundLayout->setSpacing(8);

    QLabel* mainBackgroundColorHintLabel = new QLabel(
        QStringLiteral("主背景色可独立于主题色自定义；恢复默认后随浅色/深色模式切换。"),
        backgroundGroupBox);
    mainBackgroundColorHintLabel->setWordWrap(true);
    languageManager.bindText(
        mainBackgroundColorHintLabel,
        QStringLiteral("settings.background.color.hint"),
        QStringLiteral("主背景色可独立于主题色自定义；恢复默认后随浅色/深色模式切换。"));
    backgroundLayout->addWidget(mainBackgroundColorHintLabel);

    QHBoxLayout* mainBackgroundColorActionLayout = new QHBoxLayout();
    mainBackgroundColorActionLayout->setSpacing(6);
    mainBackgroundColorPreviewLabel_ = new QLabel(backgroundGroupBox);
    mainBackgroundColorPreviewLabel_->setMinimumWidth(112);
    mainBackgroundColorPreviewLabel_->setAlignment(Qt::AlignCenter);
    mainBackgroundColorActionLayout->addWidget(mainBackgroundColorPreviewLabel_, 0);

    chooseMainBackgroundColorButton_ = new QPushButton(
        QStringLiteral("自定义主背景色"),
        backgroundGroupBox);
    languageManager.bindText(
        chooseMainBackgroundColorButton_,
        QStringLiteral("settings.background.color.choose"),
        QStringLiteral("自定义主背景色"));
    mainBackgroundColorActionLayout->addWidget(chooseMainBackgroundColorButton_, 0);

    resetMainBackgroundColorButton_ = new QPushButton(
        QStringLiteral("恢复默认背景色"),
        backgroundGroupBox);
    languageManager.bindText(
        resetMainBackgroundColorButton_,
        QStringLiteral("settings.background.color.reset"),
        QStringLiteral("恢复默认背景色"));
    mainBackgroundColorActionLayout->addWidget(resetMainBackgroundColorButton_, 0);
    mainBackgroundColorActionLayout->addStretch();
    backgroundLayout->addLayout(mainBackgroundColorActionLayout);

    QLabel* pathHintLabel = new QLabel(
        QStringLiteral("选择一张图片作为窗口背景（支持 PNG/JPG/BMP）。"),
        backgroundGroupBox);
    pathHintLabel->setWordWrap(true);
    languageManager.bindText(pathHintLabel, QStringLiteral("settings.background.path_hint"), QStringLiteral("选择一张图片作为窗口背景（支持 PNG/JPG/BMP）。"));
    backgroundLayout->addWidget(pathHintLabel);

    QHBoxLayout* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);

    // m_backgroundPathEdit: Input field for the user to enter the background image path.
    backgroundPathEdit_ = new QLineEdit(backgroundGroupBox);
    backgroundPathEdit_->setPlaceholderText(QStringLiteral("Style/ksword_background.png"));
    pathLayout->addWidget(backgroundPathEdit_, 1);

    // m_browseBackgroundButton function: opens a file dialog to select a background image.
    browseBackgroundButton_ = new QToolButton(backgroundGroupBox);
    browseBackgroundButton_->setIcon(QIcon(QString::fromUtf8(kIconBrowseBackground)));
    ksword_theme::applyStandardIconButtonMetrics(browseBackgroundButton_);
    browseBackgroundButton_->setToolTip(QStringLiteral("浏览背景图文件"));
    languageManager.bindToolTip(browseBackgroundButton_, QStringLiteral("settings.background.browse.tooltip"), QStringLiteral("浏览背景图文件"));
    pathLayout->addWidget(browseBackgroundButton_);

    // m_resetBackgroundButton function: Restore the default background path.
    resetBackgroundButton_ = new QToolButton(backgroundGroupBox);
    resetBackgroundButton_->setIcon(QIcon(QString::fromUtf8(kIconResetBackground)));
    ksword_theme::applyStandardIconButtonMetrics(resetBackgroundButton_);
    resetBackgroundButton_->setToolTip(QStringLiteral("恢复默认背景路径"));
    languageManager.bindToolTip(resetBackgroundButton_, QStringLiteral("settings.background.reset.tooltip"), QStringLiteral("恢复默认背景路径"));
    pathLayout->addWidget(resetBackgroundButton_);

    backgroundLayout->addLayout(pathLayout);

    QLabel* opacityHintLabel = new QLabel(QStringLiteral("背景图透明度（0% 仅纯色背景，100% 仅背景图）"), backgroundGroupBox);
    languageManager.bindText(opacityHintLabel, QStringLiteral("settings.background.opacity"), QStringLiteral("背景图透明度（0% 仅纯色背景，100% 仅背景图）"));
    backgroundLayout->addWidget(opacityHintLabel);

    QHBoxLayout* opacityLayout = new QHBoxLayout();
    opacityLayout->setSpacing(6);

    // m_backgroundOpacitySlider function: Controls the background image opacity value.
    backgroundOpacitySlider_ = new QSlider(Qt::Horizontal, backgroundGroupBox);
    backgroundOpacitySlider_->setRange(0, 100);
    backgroundOpacitySlider_->setSingleStep(1);
    backgroundOpacitySlider_->setPageStep(5);
    backgroundOpacitySlider_->setToolTip(QStringLiteral("拖动调整背景图透明度"));
    languageManager.bindToolTip(backgroundOpacitySlider_, QStringLiteral("settings.background.opacity.tooltip"), QStringLiteral("拖动调整背景图透明度"));
    opacityLayout->addWidget(backgroundOpacitySlider_, 1);

    // m_backgroundOpacityValueLabel purpose: displays the current opacity percentage.
    backgroundOpacityValueLabel_ = new QLabel(QStringLiteral("35%"), backgroundGroupBox);
    backgroundOpacityValueLabel_->setMinimumWidth(48);
    opacityLayout->addWidget(backgroundOpacityValueLabel_);

    backgroundLayout->addLayout(opacityLayout);

    // m_backgroundTransparencyCheckBox function: Toggle window transparent background (alpha channel transparency / Mica material).
    backgroundTransparencyCheckBox_ = new QCheckBox(QStringLiteral("透明窗口背景（重启后生效）"), backgroundGroupBox);
    languageManager.bindText(backgroundTransparencyCheckBox_, QStringLiteral("settings.background.transparency"), QStringLiteral("透明窗口背景（重启后生效）"));
    backgroundTransparencyCheckBox_->setToolTip(QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    languageManager.bindToolTip(backgroundTransparencyCheckBox_, QStringLiteral("settings.background.transparency.tooltip"), QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    backgroundLayout->addWidget(backgroundTransparencyCheckBox_);

    // Translucency effect selection row: Enabled after checking transparency; material switches immediately at runtime without restart.
    QHBoxLayout* translucencyMaterialLayout = new QHBoxLayout();
    translucencyMaterialLayout->setSpacing(6);
    QLabel* translucencyMaterialLabel = new QLabel(QStringLiteral("透明背景效果"), backgroundGroupBox);
    languageManager.bindText(translucencyMaterialLabel, QStringLiteral("settings.background.translucency_material"), QStringLiteral("透明背景效果"));
    translucencyMaterialLayout->addWidget(translucencyMaterialLabel);

    // m_backgroundTranslucencyMaterialCombo: Selects the rendering mode for the transparent background (auto/matte/direct).
    backgroundTranslucencyMaterialCombo_ = new QComboBox(backgroundGroupBox);
    backgroundTranslucencyMaterialCombo_->addItem(QStringLiteral("自动（有背景图直透，无图磨砂）"), QStringLiteral("auto"));
    backgroundTranslucencyMaterialCombo_->addItem(QStringLiteral("磨砂玻璃"), QStringLiteral("acrylic"));
    backgroundTranslucencyMaterialCombo_->addItem(QStringLiteral("直透桌面（完全透明）"), QStringLiteral("desktop"));
    backgroundTranslucencyMaterialCombo_->setToolTip(QStringLiteral("磨砂玻璃：由系统实时模糊窗口后方内容并叠加主题着色。直透桌面：透明区域清晰地直接看到桌面。自动：设置了背景图时直透，没有背景图时用磨砂玻璃。修改后立即生效。"));
    languageManager.bindToolTip(backgroundTranslucencyMaterialCombo_, QStringLiteral("settings.background.translucency_material.tooltip"), QStringLiteral("磨砂玻璃：由系统实时模糊窗口后方内容并叠加主题着色。直透桌面：透明区域清晰地直接看到桌面。自动：设置了背景图时直透，没有背景图时用磨砂玻璃。修改后立即生效。"));
    languageManager.bindComboBoxItem(backgroundTranslucencyMaterialCombo_, 0, QStringLiteral("settings.background.translucency_material.auto"), QStringLiteral("自动（有背景图直透，无图磨砂）"));
    languageManager.bindComboBoxItem(backgroundTranslucencyMaterialCombo_, 1, QStringLiteral("settings.background.translucency_material.acrylic"), QStringLiteral("磨砂玻璃"));
    languageManager.bindComboBoxItem(backgroundTranslucencyMaterialCombo_, 2, QStringLiteral("settings.background.translucency_material.desktop"), QStringLiteral("直透桌面（完全透明）"));
    translucencyMaterialLayout->addWidget(backgroundTranslucencyMaterialCombo_, 1);
    backgroundLayout->addLayout(translucencyMaterialLayout);

    // ===== Glass Visual Effect Three Sliders ===== Note: Frosted glass is composited by the system. Its
    // blur radius is fixed internally in Windows (the undocumented ACCENT_POLICY has no radius field).
    // Therefore, 'Glass Blur Radius' applies to the blur layer of the application-drawn background image.
    // The two opacity values correspond respectively to frosted shading (system compositing) and direct shading (self-drawn fallback).
    QLabel* blurRadiusHintLabel = new QLabel(
        QStringLiteral("玻璃模糊半径（作用于背景图；0% 不模糊）"),
        backgroundGroupBox);
    blurRadiusHintLabel->setWordWrap(true);
    languageManager.bindText(
        blurRadiusHintLabel,
        QStringLiteral("settings.background.blur_radius"),
        QStringLiteral("玻璃模糊半径（作用于背景图；0% 不模糊）"));
    backgroundLayout->addWidget(blurRadiusHintLabel);

    QHBoxLayout* blurRadiusLayout = new QHBoxLayout();
    blurRadiusLayout->setSpacing(6);

    // m_backgroundBlurRadiusSlider: Controls the radius intensity for custom-drawn background glass blur.
    backgroundBlurRadiusSlider_ = new QSlider(Qt::Horizontal, backgroundGroupBox);
    backgroundBlurRadiusSlider_->setRange(0, 100);
    backgroundBlurRadiusSlider_->setSingleStep(1);
    backgroundBlurRadiusSlider_->setPageStep(5);
    backgroundBlurRadiusSlider_->setToolTip(QStringLiteral("把背景图模糊成毛玻璃质感，数值越大越糊。仅作用于背景图：磨砂玻璃是由 Windows 合成的，它的模糊半径由系统固定，应用无法调整。修改后立即生效。"));
    languageManager.bindToolTip(
        backgroundBlurRadiusSlider_,
        QStringLiteral("settings.background.blur_radius.tooltip"),
        QStringLiteral("把背景图模糊成毛玻璃质感，数值越大越糊。仅作用于背景图：磨砂玻璃是由 Windows 合成的，它的模糊半径由系统固定，应用无法调整。修改后立即生效。"));
    blurRadiusLayout->addWidget(backgroundBlurRadiusSlider_, 1);

    // m_backgroundBlurRadiusValueLabel purpose: Displays the current blur radius intensity.
    backgroundBlurRadiusValueLabel_ = new QLabel(QStringLiteral("0%"), backgroundGroupBox);
    backgroundBlurRadiusValueLabel_->setMinimumWidth(48);
    blurRadiusLayout->addWidget(backgroundBlurRadiusValueLabel_);

    backgroundLayout->addLayout(blurRadiusLayout);

    QLabel* acrylicTintHintLabel = new QLabel(
        QStringLiteral("磨砂着色不透明度（越低越通透，越高文字越清晰）"),
        backgroundGroupBox);
    acrylicTintHintLabel->setWordWrap(true);
    languageManager.bindText(
        acrylicTintHintLabel,
        QStringLiteral("settings.background.acrylic_tint"),
        QStringLiteral("磨砂着色不透明度（越低越通透，越高文字越清晰）"));
    backgroundLayout->addWidget(acrylicTintHintLabel);

    QHBoxLayout* acrylicTintLayout = new QHBoxLayout();
    acrylicTintLayout->setSpacing(6);

    // m_acrylicTintOpacitySlider: Controls the opacity of the frosted glass tint layer.
    acrylicTintOpacitySlider_ = new QSlider(Qt::Horizontal, backgroundGroupBox);
    acrylicTintOpacitySlider_->setRange(0, 100);
    acrylicTintOpacitySlider_->setSingleStep(1);
    acrylicTintOpacitySlider_->setPageStep(5);
    acrylicTintOpacitySlider_->setToolTip(QStringLiteral("“磨砂玻璃”效果上叠加的主题着色浓度。调到 0% 接近纯模糊，调高则更接近实色背景、前景文字更易读。仅在透明背景效果为磨砂玻璃时生效，修改后立即生效。"));
    languageManager.bindToolTip(
        acrylicTintOpacitySlider_,
        QStringLiteral("settings.background.acrylic_tint.tooltip"),
        QStringLiteral("“磨砂玻璃”效果上叠加的主题着色浓度。调到 0% 接近纯模糊，调高则更接近实色背景、前景文字更易读。仅在透明背景效果为磨砂玻璃时生效，修改后立即生效。"));
    acrylicTintLayout->addWidget(acrylicTintOpacitySlider_, 1);

    // m_acrylicTintOpacityValueLabel: Displays the frosted tint opacity value.
    acrylicTintOpacityValueLabel_ = new QLabel(QStringLiteral("75%"), backgroundGroupBox);
    acrylicTintOpacityValueLabel_->setMinimumWidth(48);
    acrylicTintLayout->addWidget(acrylicTintOpacityValueLabel_);

    backgroundLayout->addLayout(acrylicTintLayout);

    QLabel* desktopTintHintLabel = new QLabel(
        QStringLiteral("直透着色不透明度（0% 几乎完全看到桌面）"),
        backgroundGroupBox);
    desktopTintHintLabel->setWordWrap(true);
    languageManager.bindText(
        desktopTintHintLabel,
        QStringLiteral("settings.background.desktop_tint"),
        QStringLiteral("直透着色不透明度（0% 几乎完全看到桌面）"));
    backgroundLayout->addWidget(desktopTintHintLabel);

    QHBoxLayout* desktopTintLayout = new QHBoxLayout();
    desktopTintLayout->setSpacing(6);

    // m_desktopTintOpacitySlider: Controls the opacity of the custom-drawn tint layer in direct desktop mode.
    desktopTintOpacitySlider_ = new QSlider(Qt::Horizontal, backgroundGroupBox);
    desktopTintOpacitySlider_->setRange(0, 100);
    desktopTintOpacitySlider_->setSingleStep(1);
    desktopTintOpacitySlider_->setPageStep(5);
    desktopTintOpacitySlider_->setToolTip(QStringLiteral("“直透桌面”时窗口自绘的主题着色浓度。调到 0% 几乎完全透出桌面（仍保留最低限度的鼠标响应），调高则界面更实、文字更易读。没有背景图时生效，修改后立即生效。"));
    languageManager.bindToolTip(
        desktopTintOpacitySlider_,
        QStringLiteral("settings.background.desktop_tint.tooltip"),
        QStringLiteral("“直透桌面”时窗口自绘的主题着色浓度。调到 0% 几乎完全透出桌面（仍保留最低限度的鼠标响应），调高则界面更实、文字更易读。没有背景图时生效，修改后立即生效。"));
    desktopTintLayout->addWidget(desktopTintOpacitySlider_, 1);

    // m_desktopTintOpacityValueLabel: Displays the translucent tint opacity value.
    desktopTintOpacityValueLabel_ = new QLabel(QStringLiteral("65%"), backgroundGroupBox);
    desktopTintOpacityValueLabel_->setMinimumWidth(48);
    desktopTintLayout->addWidget(desktopTintOpacityValueLabel_);

    backgroundLayout->addLayout(desktopTintLayout);

    // The combo box and the two color sliders' availability follow the transparency master switch; the initial state is synchronized by applySettingsToUi.
    // The blur radius applies to the background image's custom-drawn layer and does not depend on window transparency, so it is always available.
    backgroundTranslucencyMaterialCombo_->setEnabled(backgroundTransparencyCheckBox_->isChecked());
    connect(backgroundTransparencyCheckBox_, &QCheckBox::toggled, backgroundTranslucencyMaterialCombo_, &QWidget::setEnabled);
    acrylicTintOpacitySlider_->setEnabled(backgroundTransparencyCheckBox_->isChecked());
    connect(backgroundTransparencyCheckBox_, &QCheckBox::toggled, acrylicTintOpacitySlider_, &QWidget::setEnabled);
    desktopTintOpacitySlider_->setEnabled(backgroundTransparencyCheckBox_->isChecked());
    connect(backgroundTransparencyCheckBox_, &QCheckBox::toggled, desktopTintOpacitySlider_, &QWidget::setEnabled);
    appearanceRootLayout->addWidget(backgroundGroupBox);

    // ===== Interaction and Scrolling Group =====
    QGroupBox* interactionGroupBox = new QGroupBox(QStringLiteral("交互与滚动"), appearanceTab_);
    languageManager.bindText(interactionGroupBox, QStringLiteral("settings.interaction.group"), QStringLiteral("交互与滚动"));
    QVBoxLayout* interactionLayout = new QVBoxLayout(interactionGroupBox);
    interactionLayout->setSpacing(8);

    QLabel* interactionHintLabel = new QLabel(
        QStringLiteral("调整全局滚动，以及滚轮是否直接调整滑块。"),
        interactionGroupBox);
    interactionHintLabel->setWordWrap(true);
    languageManager.bindText(interactionHintLabel, QStringLiteral("settings.interaction.hint"), QStringLiteral("调整全局滚动，以及滚轮是否直接调整滑块。"));
    interactionLayout->addWidget(interactionHintLabel);

    QHBoxLayout* scrollBarWidthLayout = new QHBoxLayout();
    scrollBarWidthLayout->setSpacing(6);
    QLabel* scrollBarWidthLabel = new QLabel(QStringLiteral("滚动条宽度"), interactionGroupBox);
    languageManager.bindText(scrollBarWidthLabel, QStringLiteral("settings.scrollbar.width"), QStringLiteral("滚动条宽度"));
    scrollBarWidthLayout->addWidget(scrollBarWidthLabel, 0);
    scrollBarWidthCombo_ = new QComboBox(interactionGroupBox);
    scrollBarWidthCombo_->addItem(QStringLiteral("窄版（默认，遮挡更少）"), false);
    scrollBarWidthCombo_->addItem(QStringLiteral("宽版（旧版大小）"), true);
    languageManager.bindComboBoxItem(scrollBarWidthCombo_, 0, QStringLiteral("settings.scrollbar.narrow"), QStringLiteral("窄版（默认，遮挡更少）"));
    languageManager.bindComboBoxItem(scrollBarWidthCombo_, 1, QStringLiteral("settings.scrollbar.wide"), QStringLiteral("宽版（旧版大小）"));
    scrollBarWidthLayout->addWidget(scrollBarWidthCombo_, 1);
    interactionLayout->addLayout(scrollBarWidthLayout);

    scrollBarAutoHideCheckBox_ = new QCheckBox(QStringLiteral("滚动条自动隐藏（悬停时展开）"), interactionGroupBox);
    languageManager.bindText(scrollBarAutoHideCheckBox_, QStringLiteral("settings.scrollbar.auto_hide"), QStringLiteral("滚动条自动隐藏（悬停时展开）"));
    scrollBarAutoHideCheckBox_->setToolTip(QStringLiteral("启用后滚动条默认缩到很窄，鼠标悬停时展开到当前宽度档位"));
    languageManager.bindToolTip(scrollBarAutoHideCheckBox_, QStringLiteral("settings.scrollbar.auto_hide.tooltip"), QStringLiteral("启用后滚动条默认缩到很窄，鼠标悬停时展开到当前宽度档位"));
    interactionLayout->addWidget(scrollBarAutoHideCheckBox_);

    smoothScrollingCheckBox_ = new QCheckBox(
        QStringLiteral("启用全局平滑滚动"),
        interactionGroupBox);
    languageManager.bindText(
        smoothScrollingCheckBox_,
        QStringLiteral("settings.scroll.smooth"),
        QStringLiteral("启用全局平滑滚动"));
    smoothScrollingCheckBox_->setToolTip(
        QStringLiteral("对表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    languageManager.bindToolTip(
        smoothScrollingCheckBox_,
        QStringLiteral("settings.scroll.smooth.tooltip"),
        QStringLiteral("对表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    interactionLayout->addWidget(smoothScrollingCheckBox_);

    sliderWheelAdjustCheckBox_ = new QCheckBox(QStringLiteral("允许滚轮直接调整滑块"), interactionGroupBox);
    languageManager.bindText(sliderWheelAdjustCheckBox_, QStringLiteral("settings.slider.wheel"), QStringLiteral("允许滚轮直接调整滑块"));
    sliderWheelAdjustCheckBox_->setToolTip(QStringLiteral("关闭后，鼠标滚轮经过滑块时优先滚动页面，不再误改滑块值"));
    languageManager.bindToolTip(sliderWheelAdjustCheckBox_, QStringLiteral("settings.slider.wheel.tooltip"), QStringLiteral("关闭后，鼠标滚轮经过滑块时优先滚动页面，不再误改滑块值"));
    interactionLayout->addWidget(sliderWheelAdjustCheckBox_);

    appearanceRootLayout->addWidget(interactionGroupBox);

    // ===== Detail Page Display Scheme Group ===== This setting applies only to strictly
    // matched pages. After selection, clicking 'Apply' immediately reorders existing pages.
    QGroupBox* detailSchemeGroupBox = new QGroupBox(
        QStringLiteral("详情页显示方案"),
        appearanceTab_);
    languageManager.bindText(
        detailSchemeGroupBox,
        QStringLiteral("settings.detail_layout.group"),
        QStringLiteral("详情页显示方案"));
    QVBoxLayout* detailSchemeLayout = new QVBoxLayout(detailSchemeGroupBox);
    detailSchemeLayout->setSpacing(6);

    QLabel* detailSchemeHintLabel = new QLabel(
        QStringLiteral("统一设置表格当前行详情的显示位置；点击应用后立即生效。"),
        detailSchemeGroupBox);
    detailSchemeHintLabel->setWordWrap(true);
    languageManager.bindText(
        detailSchemeHintLabel,
        QStringLiteral("settings.detail_layout.hint"),
        QStringLiteral("统一设置表格当前行详情的显示位置；点击应用后立即生效。"));
    detailSchemeLayout->addWidget(detailSchemeHintLabel);

    detailSchemeButtonGroup_ = new QButtonGroup(detailSchemeGroupBox);
    detailSchemeButtonGroup_->setExclusive(true);
    const auto kAddDetailSchemeRadio = [this, detailSchemeGroupBox, detailSchemeLayout, &languageManager](
        const ks::settings::DetailDisplayScheme scheme,
        const QString& textKey,
        const QString& fallbackText)
        {
            // Use QRadioButton for each item to display explicit text, avoiding ambiguity where four layouts rely solely on indistinguishable icons.
            QRadioButton* radioButton = new QRadioButton(fallbackText, detailSchemeGroupBox);
            languageManager.bindText(radioButton, textKey, fallbackText);
            detailSchemeButtonGroup_->addButton(radioButton, static_cast<int>(scheme));
            detailSchemeLayout->addWidget(radioButton);
        };
    kAddDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::kBottomCollapsed,
        QStringLiteral("settings.detail_layout.bottom_collapsed"),
        QStringLiteral("下方折叠（默认）"));
    kAddDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::kRight,
        QStringLiteral("settings.detail_layout.right"),
        QStringLiteral("表格右侧"));
    kAddDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::kEmbedded,
        QStringLiteral("settings.detail_layout.embedded"),
        QStringLiteral("行内嵌入"));
    kAddDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::kFloating,
        QStringLiteral("settings.detail_layout.floating"),
        QStringLiteral("独立窗口"));
    appearanceRootLayout->addWidget(detailSchemeGroupBox);

    // ===== Startup Behavior Group =====
    QGroupBox* startupGroupBox = new QGroupBox(QStringLiteral("启动行为"), startupTab_);
    languageManager.bindText(startupGroupBox, QStringLiteral("settings.startup.group"), QStringLiteral("启动行为"));
    QVBoxLayout* startupLayout = new QVBoxLayout(startupGroupBox);
    startupLayout->setSpacing(8);

    QLabel* startupHintLabel = new QLabel(
        QStringLiteral("设置应用下次启动时的窗口显示方式与权限申请行为。"),
        startupGroupBox);
    startupHintLabel->setWordWrap(true);
    languageManager.bindText(startupHintLabel, QStringLiteral("settings.startup.hint"), QStringLiteral("设置应用下次启动时的窗口显示方式与权限申请行为。"));
    startupLayout->addWidget(startupHintLabel);

    // m_startupMaximizedCheckBox function: Controls whether to maximize directly upon the next startup.
    startupMaximizedCheckBox_ = new QCheckBox(QStringLiteral("启动时最大化"), startupGroupBox);
    languageManager.bindText(startupMaximizedCheckBox_, QStringLiteral("settings.startup.maximized"), QStringLiteral("启动时最大化"));
    startupMaximizedCheckBox_->setToolTip(QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    languageManager.bindToolTip(startupMaximizedCheckBox_, QStringLiteral("settings.startup.maximized.tooltip"), QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    startupLayout->addWidget(startupMaximizedCheckBox_);

    // m_startupTopMostCheckBox function: Controls whether to automatically set the HWND_TOPMOST highest-level z-order on startup.
    startupTopMostCheckBox_ = new QCheckBox(QStringLiteral("启动后默认最高级置顶"), startupGroupBox);
    languageManager.bindText(startupTopMostCheckBox_, QStringLiteral("settings.startup.topmost"), QStringLiteral("启动后默认最高级置顶"));
    startupTopMostCheckBox_->setToolTip(
        QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    languageManager.bindToolTip(startupTopMostCheckBox_, QStringLiteral("settings.startup.topmost.tooltip"), QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    startupLayout->addWidget(startupTopMostCheckBox_);

    // m_startupAutoAdminCheckBox function: Controls whether to attempt UAC elevation before the startup window appears.
    startupAutoAdminCheckBox_ = new QCheckBox(QStringLiteral("启动时自动请求管理员权限"), startupGroupBox);
    languageManager.bindText(startupAutoAdminCheckBox_, QStringLiteral("settings.startup.admin"), QStringLiteral("启动时自动请求管理员权限"));
    startupAutoAdminCheckBox_->setToolTip(
        QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    languageManager.bindToolTip(startupAutoAdminCheckBox_, QStringLiteral("settings.startup.admin.tooltip"), QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    startupLayout->addWidget(startupAutoAdminCheckBox_);

    // m_startupAutoInstallR0DriverCheckBox function: Controls whether to automatically install and start the KswordARK driver after the main window is displayed for the first time.
    startupAutoInstallR0DriverCheckBox_ = new QCheckBox(QStringLiteral("启动时自动安装驱动"), startupGroupBox);
    languageManager.bindText(startupAutoInstallR0DriverCheckBox_, QStringLiteral("settings.startup.auto_install_r0"), QStringLiteral("启动时自动安装驱动"));
    startupAutoInstallR0DriverCheckBox_->setToolTip(
        QStringLiteral("下次启动时自动尝试安装并启动 KswordARK 驱动；权限不足时会显示错误，但不会额外请求管理员重启"));
    languageManager.bindToolTip(startupAutoInstallR0DriverCheckBox_, QStringLiteral("settings.startup.auto_install_r0.tooltip"), QStringLiteral("下次启动时自动尝试安装并启动 KswordARK 驱动；权限不足时会显示错误，但不会额外请求管理员重启"));
    startupLayout->addWidget(startupAutoInstallR0DriverCheckBox_);

    // m_preventMultipleInstancesCheckBox purpose: Controls whether normal startup activates an existing window and exits the new process.
    preventMultipleInstancesCheckBox_ = new QCheckBox(QStringLiteral("防止多开"), startupGroupBox);
    languageManager.bindText(preventMultipleInstancesCheckBox_, QStringLiteral("settings.startup.prevent_multiple_instances"), QStringLiteral("防止多开"));
    preventMultipleInstancesCheckBox_->setToolTip(
        QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    languageManager.bindToolTip(preventMultipleInstancesCheckBox_, QStringLiteral("settings.startup.prevent_multiple_instances.tooltip"), QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    startupLayout->addWidget(preventMultipleInstancesCheckBox_);

    // m_unlockerShellContextMenuCheckBox: Controls whether to enable the system right-click 'File Unlocker' menu.
    unlockerShellContextMenuCheckBox_ = new QCheckBox(QStringLiteral("启用系统右键“文件解锁器”菜单"), startupGroupBox);
    languageManager.bindText(unlockerShellContextMenuCheckBox_, QStringLiteral("settings.startup.unlocker"), QStringLiteral("启用系统右键“文件解锁器”菜单"));
    unlockerShellContextMenuCheckBox_->setToolTip(
        QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    languageManager.bindToolTip(unlockerShellContextMenuCheckBox_, QStringLiteral("settings.startup.unlocker.tooltip"), QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    startupLayout->addWidget(unlockerShellContextMenuCheckBox_);

    QLabel* taskmgrHijackHintLabel = new QLabel(
        QStringLiteral("将系统任务管理器入口切换到 Ksword。此操作需要管理员权限。"),
        startupGroupBox);
    taskmgrHijackHintLabel->setWordWrap(true);
    languageManager.bindText(taskmgrHijackHintLabel, QStringLiteral("settings.startup.taskmgr_hint"), QStringLiteral("将系统任务管理器入口切换到 Ksword。此操作需要管理员权限。"));
    startupLayout->addWidget(taskmgrHijackHintLabel);

    QHBoxLayout* taskmgrHijackButtonLayout = new QHBoxLayout();
    taskmgrHijackButtonLayout->setSpacing(8);

    // m_installTaskmgrHijackButton function: Points the taskmgr.exe IFEO Debugger to the current Ksword5.1.exe.
    installTaskmgrHijackButton_ = new QPushButton(QStringLiteral("用 Ksword 替代任务管理器"), startupGroupBox);
    languageManager.bindText(installTaskmgrHijackButton_, QStringLiteral("settings.startup.taskmgr_install"), QStringLiteral("用 Ksword 替代任务管理器"));
    installTaskmgrHijackButton_->setMinimumWidth(146);
    installTaskmgrHijackButton_->setFixedHeight(30);
    installTaskmgrHijackButton_->setToolTip(
        QStringLiteral("打开任务管理器时改为启动 Ksword"));
    languageManager.bindToolTip(installTaskmgrHijackButton_, QStringLiteral("settings.startup.taskmgr_install.tooltip"), QStringLiteral("打开任务管理器时改为启动 Ksword"));
    taskmgrHijackButtonLayout->addWidget(installTaskmgrHijackButton_, 0);

    // m_uninstallTaskmgrHijackButton function: Remove taskmgr.exe IFEO Debugger and restore the system Task Manager.
    uninstallTaskmgrHijackButton_ = new QPushButton(QStringLiteral("恢复系统任务管理器"), startupGroupBox);
    languageManager.bindText(uninstallTaskmgrHijackButton_, QStringLiteral("settings.startup.taskmgr_uninstall"), QStringLiteral("恢复系统任务管理器"));
    uninstallTaskmgrHijackButton_->setMinimumWidth(126);
    uninstallTaskmgrHijackButton_->setFixedHeight(30);
    uninstallTaskmgrHijackButton_->setToolTip(
        QStringLiteral("恢复任务管理器的默认启动方式"));
    languageManager.bindToolTip(uninstallTaskmgrHijackButton_, QStringLiteral("settings.startup.taskmgr_uninstall.tooltip"), QStringLiteral("恢复任务管理器的默认启动方式"));
    taskmgrHijackButtonLayout->addWidget(uninstallTaskmgrHijackButton_, 0);
    taskmgrHijackButtonLayout->addStretch(1);
    startupLayout->addLayout(taskmgrHijackButtonLayout);

    // Startup window scaling settings: take effect after restart to uniformly control main window UI scaling.
    QHBoxLayout* startupScaleLayout = new QHBoxLayout();
    startupScaleLayout->setSpacing(6);
    QLabel* startupScaleLabel = new QLabel(QStringLiteral("窗口缩放"), startupGroupBox);
    languageManager.bindText(startupScaleLabel, QStringLiteral("settings.startup.scale"), QStringLiteral("窗口缩放"));
    startupScaleLayout->addWidget(startupScaleLabel, 0);

    // m_startupWindowScaleSpin purpose: Sets the main window scale percentage for the next startup.
    // Deliberately avoiding a multiplier input box like 'scale factor 1.00': multipliers are an internal
    // representation; users think in percentages (consistent with Windows display settings). The old plain text box
    // lacked validators and range display, so entering 150 (as a percentage) would be silently clamped to 2.00.
    // The spin box displays the range, step size, and unit on the interface, preventing out-of-range input.
    startupWindowScaleSpin_ = new QSpinBox(startupGroupBox);
    startupWindowScaleSpin_->setRange(
        windowScalePercentFromFactor(ks::settings::kMinimumWindowScaleFactor),
        windowScalePercentFromFactor(ks::settings::kMaximumWindowScaleFactor));
    startupWindowScaleSpin_->setSingleStep(5);
    startupWindowScaleSpin_->setSuffix(QStringLiteral(" %"));
    startupWindowScaleSpin_->setValue(100);
    startupWindowScaleSpin_->setKeyboardTracking(false);
    startupWindowScaleSpin_->setToolTip(
        QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    languageManager.bindToolTip(startupWindowScaleSpin_, QStringLiteral("settings.startup.scale.tooltip"), QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    startupScaleLayout->addWidget(startupWindowScaleSpin_, 0);
    startupScaleLayout->addStretch(1);
    startupLayout->addLayout(startupScaleLayout);

    // m_startupWindowScaleHintLabel: Indicates when the setting takes effect and its relationship with system scaling.
    // The specific percentage is already displayed by the spin box itself, so no need to repeat it here.
    startupWindowScaleHintLabel_ = new QLabel(
        QStringLiteral("重启后生效；最终大小是系统显示缩放与此处设置相乘的结果。"),
        startupGroupBox);
    startupWindowScaleHintLabel_->setWordWrap(true);
    languageManager.bindText(
        startupWindowScaleHintLabel_,
        QStringLiteral("settings.startup.scale_hint"),
        QStringLiteral("重启后生效；最终大小是系统显示缩放与此处设置相乘的结果。"));
    startupLayout->addWidget(startupWindowScaleHintLabel_);

    startupRootLayout->addWidget(startupGroupBox);
    startupRootLayout->addStretch();

    // ===== privilege Button Group =====
    QGroupBox* privilegeGroupBox = new QGroupBox(QStringLiteral("权限状态按钮"), appearanceTab_);
    languageManager.bindText(
        privilegeGroupBox,
        QStringLiteral("settings.privilege_buttons.group"),
        QStringLiteral("权限状态按钮"));
    QVBoxLayout* privilegeLayout = new QVBoxLayout(privilegeGroupBox);
    privilegeLayout->setSpacing(8);

    QLabel* privilegeHintLabel = new QLabel(
        QStringLiteral("选择右上角显示哪些权限等级。取消勾选只是不再显示，不会改变任何能力。"),
        privilegeGroupBox);
    privilegeHintLabel->setWordWrap(true);
    languageManager.bindText(
        privilegeHintLabel,
        QStringLiteral("settings.privilege_buttons.hint"),
        QStringLiteral("选择右上角显示哪些权限等级。取消勾选只是不再显示，不会改变任何能力。"));
    privilegeLayout->addWidget(privilegeHintLabel);

    privilegeUiAccessCheckBox_ = new QCheckBox(QStringLiteral("UIAccess（跨权限窗口置顶）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeUiAccessCheckBox_,
        QStringLiteral("settings.privilege_buttons.uiaccess"),
        QStringLiteral("UIAccess（跨权限窗口置顶）"));
    privilegeLayout->addWidget(privilegeUiAccessCheckBox_);

    privilegeAdminCheckBox_ = new QCheckBox(QStringLiteral("Admin（管理员）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeAdminCheckBox_,
        QStringLiteral("settings.privilege_buttons.admin"),
        QStringLiteral("Admin（管理员）"));
    privilegeLayout->addWidget(privilegeAdminCheckBox_);

    privilegeDebugCheckBox_ = new QCheckBox(QStringLiteral("Debug（调试特权）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeDebugCheckBox_,
        QStringLiteral("settings.privilege_buttons.debug"),
        QStringLiteral("Debug（调试特权）"));
    privilegeLayout->addWidget(privilegeDebugCheckBox_);

    privilegeSystemCheckBox_ = new QCheckBox(QStringLiteral("System（系统账户）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeSystemCheckBox_,
        QStringLiteral("settings.privilege_buttons.system"),
        QStringLiteral("System（系统账户）"));
    privilegeLayout->addWidget(privilegeSystemCheckBox_);

    privilegeR0CheckBox_ = new QCheckBox(QStringLiteral("R0（内核驱动）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeR0CheckBox_,
        QStringLiteral("settings.privilege_buttons.r0"),
        QStringLiteral("R0（内核驱动）"));
    privilegeLayout->addWidget(privilegeR0CheckBox_);

    privilegeHvmCheckBox_ = new QCheckBox(QStringLiteral("R-1（硬件虚拟化）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeHvmCheckBox_,
        QStringLiteral("settings.privilege_buttons.hvm"),
        QStringLiteral("R-1（硬件虚拟化）"));
    privilegeLayout->addWidget(privilegeHvmCheckBox_);

    privilegeDdmaCheckBox_ = new QCheckBox(QStringLiteral("DDMA（磁盘直接内存访问）"), privilegeGroupBox);
    languageManager.bindText(
        privilegeDdmaCheckBox_,
        QStringLiteral("settings.privilege_buttons.ddma"),
        QStringLiteral("DDMA（磁盘直接内存访问）"));
    // Keep the string on a single line: line breaks cause i18n audits to treat it as multiple independent source strings, requiring a translation entry for each segment.
    privilegeDdmaCheckBox_->setToolTip(QStringLiteral("显示 DDMA 常驻虚扇区指示灯。亮起代表磁盘上有一块扇区正被当作 DMA 中转站占用。"));
    privilegeLayout->addWidget(privilegeDdmaCheckBox_);

    QHBoxLayout* hvmNameLayout = new QHBoxLayout();
    hvmNameLayout->setSpacing(6);
    QLabel* hvmNameLabel = new QLabel(QStringLiteral("虚拟化按钮显示为"), privilegeGroupBox);
    languageManager.bindText(
        hvmNameLabel,
        QStringLiteral("settings.privilege_buttons.hvm_name"),
        QStringLiteral("虚拟化按钮显示为"));
    hvmNameLayout->addWidget(hvmNameLabel, 0);
    hvmDisplayNameCombo_ = new QComboBox(privilegeGroupBox);
    // All three are product names or architecture terms, so they do not change with the interface language; thus, the item text is not bound to a translation resource.
    hvmDisplayNameCombo_->addItem(
        QStringLiteral("KVM"),
        static_cast<int>(ks::settings::HvmDisplayName::kKvm));
    hvmDisplayNameCombo_->addItem(
        QStringLiteral("HVM"),
        static_cast<int>(ks::settings::HvmDisplayName::kHvm));
    hvmDisplayNameCombo_->addItem(
        QStringLiteral("R-1"),
        static_cast<int>(ks::settings::HvmDisplayName::kRingMinusOne));
    // Keep the string on a single line: line breaks cause i18n audits to treat it as multiple independent source strings, requiring a translation entry for each segment.
    hvmDisplayNameCombo_->setToolTip(
        QStringLiteral("同一个能力的三种叫法：KVM 是产品内部名，HVM 是硬件术语，R-1 是按权限分层的称呼。只影响右上角按钮。"));
    hvmNameLayout->addWidget(hvmDisplayNameCombo_, 1);
    privilegeLayout->addLayout(hvmNameLayout);

    appearanceRootLayout->addWidget(privilegeGroupBox);

    // ===== Log Notification Group =====
    QGroupBox* notificationGroupBox = new QGroupBox(QStringLiteral("日志通知"), appearanceTab_);
    languageManager.bindText(notificationGroupBox, QStringLiteral("settings.notification.group"), QStringLiteral("日志通知"));
    QVBoxLayout* notificationLayout = new QVBoxLayout(notificationGroupBox);
    notificationLayout->setSpacing(8);

    QLabel* notificationHintLabel = new QLabel(
        QStringLiteral("在右侧以不抢焦点的卡片显示日志和运行中任务。"),
        notificationGroupBox);
    notificationHintLabel->setWordWrap(true);
    languageManager.bindText(notificationHintLabel, QStringLiteral("settings.notification.hint"), QStringLiteral("在右侧以不抢焦点的卡片显示日志和运行中任务。"));
    notificationLayout->addWidget(notificationHintLabel);

    notificationCardsEnabledCheckBox_ = new QCheckBox(QStringLiteral("启用右侧通知卡片"), notificationGroupBox);
    languageManager.bindText(notificationCardsEnabledCheckBox_, QStringLiteral("settings.notification.enabled"), QStringLiteral("启用右侧通知卡片"));
    notificationLayout->addWidget(notificationCardsEnabledCheckBox_);

    QHBoxLayout* notificationLevelLayout = new QHBoxLayout();
    QLabel* notificationLevelLabel = new QLabel(QStringLiteral("最低日志级别"), notificationGroupBox);
    languageManager.bindText(notificationLevelLabel, QStringLiteral("settings.notification.minimum_level"), QStringLiteral("最低日志级别"));
    notificationLevelLayout->addWidget(notificationLevelLabel, 0);
    notificationMinimumLevelCombo_ = new QComboBox(notificationGroupBox);
    notificationMinimumLevelCombo_->addItem(QStringLiteral("调试 Debug"), 0);
    notificationMinimumLevelCombo_->addItem(QStringLiteral("信息 Info"), 1);
    notificationMinimumLevelCombo_->addItem(QStringLiteral("警告 Warn"), 2);
    notificationMinimumLevelCombo_->addItem(QStringLiteral("错误 Error"), 3);
    notificationMinimumLevelCombo_->addItem(QStringLiteral("致命 Fatal"), 4);
    languageManager.bindComboBoxItem(notificationMinimumLevelCombo_, 0, QStringLiteral("settings.notification.level.debug"), QStringLiteral("调试 Debug"));
    languageManager.bindComboBoxItem(notificationMinimumLevelCombo_, 1, QStringLiteral("settings.notification.level.info"), QStringLiteral("信息 Info"));
    languageManager.bindComboBoxItem(notificationMinimumLevelCombo_, 2, QStringLiteral("settings.notification.level.warn"), QStringLiteral("警告 Warn"));
    languageManager.bindComboBoxItem(notificationMinimumLevelCombo_, 3, QStringLiteral("settings.notification.level.error"), QStringLiteral("错误 Error"));
    languageManager.bindComboBoxItem(notificationMinimumLevelCombo_, 4, QStringLiteral("settings.notification.level.fatal"), QStringLiteral("致命 Fatal"));
    notificationLevelLayout->addWidget(notificationMinimumLevelCombo_, 1);
    notificationLayout->addLayout(notificationLevelLayout);

    QHBoxLayout* notificationDurationLayout = new QHBoxLayout();
    QLabel* notificationDurationLabel = new QLabel(QStringLiteral("日志展示秒数"), notificationGroupBox);
    languageManager.bindText(notificationDurationLabel, QStringLiteral("settings.notification.duration"), QStringLiteral("日志展示秒数"));
    notificationDurationLayout->addWidget(notificationDurationLabel, 0);
    notificationLogDisplaySecondsSpin_ = new QSpinBox(notificationGroupBox);
    notificationLogDisplaySecondsSpin_->setRange(0, 60);
    notificationLogDisplaySecondsSpin_->setSuffix(QStringLiteral(" 秒"));
    notificationLogDisplaySecondsSpin_->setToolTip(QStringLiteral("0 表示日志卡片常驻，直到因空间不足被替换。"));
    languageManager.bindToolTip(notificationLogDisplaySecondsSpin_, QStringLiteral("settings.notification.duration.tooltip"), QStringLiteral("0 表示日志卡片常驻，直到因空间不足被替换。"));
    notificationDurationLayout->addWidget(notificationLogDisplaySecondsSpin_, 1);
    notificationLayout->addLayout(notificationDurationLayout);

    QHBoxLayout* notificationMaximumCountLayout = new QHBoxLayout();
    QLabel* notificationMaximumCountLabel = new QLabel(QStringLiteral("同时显示最多日志条数"), notificationGroupBox);
    languageManager.bindText(notificationMaximumCountLabel, QStringLiteral("settings.notification.maximum_count"), QStringLiteral("同时显示最多日志条数"));
    notificationMaximumCountLayout->addWidget(notificationMaximumCountLabel, 0);
    notificationMaximumVisibleLogCardsSpin_ = new QSpinBox(notificationGroupBox);
    notificationMaximumVisibleLogCardsSpin_->setRange(0, 100);
    notificationMaximumVisibleLogCardsSpin_->setToolTip(QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    languageManager.bindToolTip(notificationMaximumVisibleLogCardsSpin_, QStringLiteral("settings.notification.maximum_count.tooltip"), QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    notificationMaximumCountLayout->addWidget(notificationMaximumVisibleLogCardsSpin_, 1);
    notificationLayout->addLayout(notificationMaximumCountLayout);

    notificationLogHeightLimitCheckBox_ = new QCheckBox(QStringLiteral("限制单条日志卡片高度"), notificationGroupBox);
    languageManager.bindText(notificationLogHeightLimitCheckBox_, QStringLiteral("settings.notification.height_limit.enabled"), QStringLiteral("限制单条日志卡片高度"));
    notificationLayout->addWidget(notificationLogHeightLimitCheckBox_);

    QHBoxLayout* notificationMaximumLinesLayout = new QHBoxLayout();
    QLabel* notificationMaximumLinesLabel = new QLabel(QStringLiteral("最高文字行数"), notificationGroupBox);
    languageManager.bindText(notificationMaximumLinesLabel, QStringLiteral("settings.notification.height_limit.lines"), QStringLiteral("最高文字行数"));
    notificationMaximumLinesLayout->addWidget(notificationMaximumLinesLabel, 0);
    notificationLogMaximumLinesSpin_ = new QSpinBox(notificationGroupBox);
    notificationLogMaximumLinesSpin_->setRange(1, 50);
    notificationLogMaximumLinesSpin_->setSuffix(QStringLiteral(" 行"));
    languageManager.bindSuffix(notificationLogMaximumLinesSpin_, QStringLiteral("settings.notification.height_limit.lines.suffix"), QStringLiteral(" 行"));
    notificationLogMaximumLinesSpin_->setToolTip(QStringLiteral("超出时可通过卡片标题栏的小箭头展开完整日志。"));
    languageManager.bindToolTip(notificationLogMaximumLinesSpin_, QStringLiteral("settings.notification.height_limit.lines.tooltip"), QStringLiteral("超出时可通过卡片标题栏的小箭头展开完整日志。"));
    notificationMaximumLinesLayout->addWidget(notificationLogMaximumLinesSpin_, 1);
    notificationLayout->addLayout(notificationMaximumLinesLayout);

    QHBoxLayout* notificationPlacementLayout = new QHBoxLayout();
    QLabel* notificationPlacementLabel = new QLabel(QStringLiteral("显示位置"), notificationGroupBox);
    languageManager.bindText(notificationPlacementLabel, QStringLiteral("settings.notification.placement"), QStringLiteral("显示位置"));
    notificationPlacementLayout->addWidget(notificationPlacementLabel, 0);
    notificationDisplayPlacementCombo_ = new QComboBox(notificationGroupBox);
    notificationDisplayPlacementCombo_->addItem(QStringLiteral("屏幕右侧"), static_cast<int>(ks::settings::NotificationDisplayPlacement::kScreen));
    notificationDisplayPlacementCombo_->addItem(QStringLiteral("Ksword 主窗口内"), static_cast<int>(ks::settings::NotificationDisplayPlacement::kMainWindow));
    languageManager.bindComboBoxItem(notificationDisplayPlacementCombo_, 0, QStringLiteral("settings.notification.placement.screen"), QStringLiteral("屏幕右侧"));
    languageManager.bindComboBoxItem(notificationDisplayPlacementCombo_, 1, QStringLiteral("settings.notification.placement.window"), QStringLiteral("Ksword 主窗口内"));
    notificationPlacementLayout->addWidget(notificationDisplayPlacementCombo_, 1);
    notificationLayout->addLayout(notificationPlacementLayout);

    QHBoxLayout* notificationStackLayout = new QHBoxLayout();
    QLabel* notificationStackLabel = new QLabel(QStringLiteral("堆叠方向"), notificationGroupBox);
    languageManager.bindText(notificationStackLabel, QStringLiteral("settings.notification.stack_direction"), QStringLiteral("堆叠方向"));
    notificationStackLayout->addWidget(notificationStackLabel, 0);
    notificationStackDirectionCombo_ = new QComboBox(notificationGroupBox);
    notificationStackDirectionCombo_->addItem(QStringLiteral("右下向右上"), static_cast<int>(ks::settings::NotificationStackDirection::kBottomUp));
    notificationStackDirectionCombo_->addItem(QStringLiteral("右上向右下"), static_cast<int>(ks::settings::NotificationStackDirection::kTopDown));
    languageManager.bindComboBoxItem(notificationStackDirectionCombo_, 0, QStringLiteral("settings.notification.stack.bottom_up"), QStringLiteral("右下向右上"));
    languageManager.bindComboBoxItem(notificationStackDirectionCombo_, 1, QStringLiteral("settings.notification.stack.top_down"), QStringLiteral("右上向右下"));
    notificationStackLayout->addWidget(notificationStackDirectionCombo_, 1);
    notificationLayout->addLayout(notificationStackLayout);

    appearanceRootLayout->addWidget(notificationGroupBox);

    appearanceRootLayout->addStretch();
    tabWidget_->addTab(appearanceTab_, QStringLiteral("外观"));
    languageManager.bindTab(tabWidget_, appearanceTab_, QStringLiteral("settings.tab.appearance"), QStringLiteral("外观"));
    tabWidget_->addTab(languageTab_, QStringLiteral("语言"));
    languageManager.bindTab(tabWidget_, languageTab_, QStringLiteral("settings.tab.language"), QStringLiteral("语言"));
    tabWidget_->addTab(startupTab_, QStringLiteral("启动"));
    languageManager.bindTab(tabWidget_, startupTab_, QStringLiteral("settings.tab.startup"), QStringLiteral("启动"));

    bindAppearanceSignals();
    updateThemeButtonStyle();
    updateApplyButtonState();
}

void SettingsDock::showLanguageSettingsTab()
{
    if (tabWidget_ != nullptr && languageTab_ != nullptr)
    {
        tabWidget_->setCurrentWidget(languageTab_);
    }
}

void SettingsDock::initializeFeaturesTab()
{
    featuresTab_ = new QWidget(tabWidget_);
    QVBoxLayout* featuresRootLayout = new QVBoxLayout(featuresTab_);
    featuresRootLayout->setContentsMargins(8, 8, 8, 8);
    featuresRootLayout->setSpacing(12);

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    QGroupBox* r0PromptGroupBox = new QGroupBox(QStringLiteral("R0 功能提示"), featuresTab_);
    languageManager.bindText(
        r0PromptGroupBox,
        QStringLiteral("settings.features.r0.group"),
        QStringLiteral("R0 功能提示"));
    QVBoxLayout* r0PromptLayout = new QVBoxLayout(r0PromptGroupBox);
    r0PromptLayout->setSpacing(8);

    QLabel* r0PromptHintLabel = new QLabel(
        QStringLiteral("勾选后，R0 驱动未启用或当前权限不足时不再自动弹出提示；仍可通过标题栏 R0 按钮手动管理驱动。"),
        r0PromptGroupBox);
    r0PromptHintLabel->setWordWrap(true);
    languageManager.bindText(
        r0PromptHintLabel,
        QStringLiteral("settings.features.r0.hint"),
        QStringLiteral("勾选后，R0 驱动未启用或当前权限不足时不再自动弹出提示；仍可通过标题栏 R0 按钮手动管理驱动。"));
    r0PromptLayout->addWidget(r0PromptHintLabel);

    suppressR0FeaturePromptsCheckBox_ = new QCheckBox(
        QStringLiteral("永远不提示 R0 功能"),
        r0PromptGroupBox);
    languageManager.bindText(
        suppressR0FeaturePromptsCheckBox_,
        QStringLiteral("settings.features.r0.suppress_prompts"),
        QStringLiteral("永远不提示 R0 功能"));
    suppressR0FeaturePromptsCheckBox_->setToolTip(
        QStringLiteral("关闭 R0 驱动未启用和权限不足时的自动提示"));
    languageManager.bindToolTip(
        suppressR0FeaturePromptsCheckBox_,
        QStringLiteral("settings.features.r0.suppress_prompts.tooltip"),
        QStringLiteral("关闭 R0 驱动未启用和权限不足时的自动提示"));
    r0PromptLayout->addWidget(suppressR0FeaturePromptsCheckBox_);

    featuresRootLayout->addWidget(r0PromptGroupBox);

    // ---- Automatic crash dump check ----
    QGroupBox* dumpCheckGroupBox = new QGroupBox(QStringLiteral("崩溃转储检查"), featuresTab_);
    languageManager.bindText(
        dumpCheckGroupBox,
        QStringLiteral("settings.features.dump.group"),
        QStringLiteral("崩溃转储检查"));
    QVBoxLayout* dumpCheckLayout = new QVBoxLayout(dumpCheckGroupBox);
    dumpCheckLayout->setSpacing(8);

    QLabel* dumpCheckHintLabel = new QLabel(
        QStringLiteral("启动后检查系统近 24 小时内是否产生过新的崩溃转储，有则询问是否立即解析。"
            "检查只读取文件名与时间，不会打开转储内容；同一个转储只会询问一次。"),
        dumpCheckGroupBox);
    dumpCheckHintLabel->setWordWrap(true);
    languageManager.bindText(
        dumpCheckHintLabel,
        QStringLiteral("settings.features.dump.hint"),
        QStringLiteral("启动后检查系统近 24 小时内是否产生过新的崩溃转储，有则询问是否立即解析。"
            "检查只读取文件名与时间，不会打开转储内容；同一个转储只会询问一次。"));
    dumpCheckLayout->addWidget(dumpCheckHintLabel);

    dumpAutoCheckCheckBox_ = new QCheckBox(
        QStringLiteral("启动时检查新的崩溃转储"),
        dumpCheckGroupBox);
    languageManager.bindText(
        dumpAutoCheckCheckBox_,
        QStringLiteral("settings.features.dump.auto_check"),
        QStringLiteral("启动时检查新的崩溃转储"));
    dumpAutoCheckCheckBox_->setToolTip(
        QStringLiteral("关闭后不再自动检查，仍可随时在“转储分析”页手动打开转储文件"));
    languageManager.bindToolTip(
        dumpAutoCheckCheckBox_,
        QStringLiteral("settings.features.dump.auto_check.tooltip"),
        QStringLiteral("关闭后不再自动检查，仍可随时在“转储分析”页手动打开转储文件"));
    dumpCheckLayout->addWidget(dumpAutoCheckCheckBox_);

    featuresRootLayout->addWidget(dumpCheckGroupBox);
    initializeBugcheckDiagnosticsControls(featuresRootLayout);
    featuresRootLayout->addStretch();
    tabWidget_->addTab(featuresTab_, QStringLiteral("功能"));
    languageManager.bindTab(
        tabWidget_,
        featuresTab_,
        QStringLiteral("settings.tab.features"),
        QStringLiteral("功能"));

    connect(
        suppressR0FeaturePromptsCheckBox_,
        &QCheckBox::toggled,
        this,
        [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
        });

    connect(
        dumpAutoCheckCheckBox_,
        &QCheckBox::toggled,
        this,
        [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
        });
}

void SettingsDock::bindAppearanceSignals()
{
    if (languageCombo_ != nullptr)
    {
        connect(languageCombo_, &QComboBox::currentIndexChanged, this, [this](const int /*index*/) {
            markPendingChanges(QStringLiteral("界面语言变化"));
        });
    }

    connect(themeButtonGroup_, &QButtonGroup::idClicked, this, [this](int /*clickedId*/) {
        updateThemeButtonStyle();
        updateMainBackgroundColorPreview();
        markPendingChanges(QStringLiteral("主题按钮切换"));
        });

    connect(chooseThemeColorButton_, &QPushButton::clicked, this, [this]() {
        chooseCustomThemeColor();
        });

    connect(resetThemeColorButton_, &QPushButton::clicked, this, [this]() {
        resetThemeColorToDefault();
        });

    connect(chooseMainBackgroundColorButton_, &QPushButton::clicked, this, [this]() {
        chooseCustomMainBackgroundColor();
        });

    connect(resetMainBackgroundColorButton_, &QPushButton::clicked, this, [this]() {
        resetMainBackgroundColorToDefault();
        });

    connect(fontCombo_, &QComboBox::currentIndexChanged, this, [this](const int /*fontIndex*/) {
        markPendingChanges(QString());
        });

    connect(textAntialiasingCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QString());
        });

    // Permission button row: seven switches and one name dropdown; any change triggers the same 'pending application' flag.
    for (QCheckBox* privilegeCheckBox : {
             privilegeUiAccessCheckBox_,
             privilegeAdminCheckBox_,
             privilegeDebugCheckBox_,
             privilegeSystemCheckBox_,
             privilegeR0CheckBox_,
             privilegeHvmCheckBox_,
             privilegeDdmaCheckBox_})
    {
        if (privilegeCheckBox == nullptr)
        {
            continue;
        }
        connect(privilegeCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
            });
    }
    if (hvmDisplayNameCombo_ != nullptr)
    {
        connect(hvmDisplayNameCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
            markPendingChanges(QString());
            });
    }

    connect(backgroundPathEdit_, &QLineEdit::editingFinished, this, [this]() {
        markPendingChanges(QStringLiteral("背景路径编辑完成"));
        });

    connect(backgroundOpacitySlider_, &QSlider::valueChanged, this, [this](const int value) {
        updateOpacityValueLabel(value);
        if (!isApplyingUiState_)
        {
            markPendingChanges(QStringLiteral("背景透明度变化"));
        }
        });

    connect(backgroundTransparencyCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QString());
        });

    connect(backgroundTranslucencyMaterialCombo_, &QComboBox::currentIndexChanged, this, [this](const int /*itemIndex*/) {
        markPendingChanges(QString());
        });

    connect(backgroundBlurRadiusSlider_, &QSlider::valueChanged, this, [this](const int value) {
        backgroundBlurRadiusValueLabel_->setText(QStringLiteral("%1%").arg(value));
        if (!isApplyingUiState_)
        {
            markPendingChanges(QStringLiteral("玻璃模糊半径变化"));
        }
        });

    connect(acrylicTintOpacitySlider_, &QSlider::valueChanged, this, [this](const int value) {
        acrylicTintOpacityValueLabel_->setText(QStringLiteral("%1%").arg(value));
        if (!isApplyingUiState_)
        {
            markPendingChanges(QStringLiteral("磨砂着色不透明度变化"));
        }
        });

    connect(desktopTintOpacitySlider_, &QSlider::valueChanged, this, [this](const int value) {
        desktopTintOpacityValueLabel_->setText(QStringLiteral("%1%").arg(value));
        if (!isApplyingUiState_)
        {
            markPendingChanges(QStringLiteral("直透着色不透明度变化"));
        }
        });

    connect(browseBackgroundButton_, &QToolButton::clicked, this, [this]() {
        openBackgroundFileDialog();
        });

    connect(resetBackgroundButton_, &QToolButton::clicked, this, [this]() {
        resetBackgroundPathToDefault();
        });

    connect(startupMaximizedCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时最大化开关切换"));
        });

    connect(startupTopMostCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动后默认最高级置顶开关切换"));
        });

    connect(startupAutoAdminCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时自动请求管理员权限开关切换"));
        });

    connect(startupAutoInstallR0DriverCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时自动安装驱动开关切换"));
        });

    connect(preventMultipleInstancesCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("防止多开开关切换"));
        });

    connect(unlockerShellContextMenuCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("系统右键文件解锁器开关切换"));
        });

    connect(installTaskmgrHijackButton_, &QPushButton::clicked, this, [this]() {
        launchTaskmgrHijackScript(true);
        });

    connect(uninstallTaskmgrHijackButton_, &QPushButton::clicked, this, [this]() {
        launchTaskmgrHijackScript(false);
        });

    connect(scrollBarWidthCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("滚动条宽度切换"));
        });

    connect(scrollBarAutoHideCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("滚动条自动隐藏开关切换"));
        });

    connect(smoothScrollingCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("全局平滑滚动开关切换"));
        });

    connect(sliderWheelAdjustCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("滑块滚轮调节开关切换"));
        });

    connect(detailSchemeButtonGroup_, &QButtonGroup::idClicked, this, [this](const int) {
        markPendingChanges(QStringLiteral("详情页显示方案切换"));
        });

    connect(notificationCardsEnabledCheckBox_, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("通知卡片开关切换"));
        });
    connect(notificationMinimumLevelCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知最低日志级别切换"));
        });
    connect(notificationLogDisplaySecondsSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知日志展示秒数切换"));
        });
    connect(notificationMaximumVisibleLogCardsSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知同时显示日志条数切换"));
        });
    connect(notificationLogHeightLimitCheckBox_, &QCheckBox::toggled, this, [this](const bool checked) {
        if (notificationLogMaximumLinesSpin_ != nullptr)
        {
            notificationLogMaximumLinesSpin_->setEnabled(checked);
        }
        markPendingChanges(QStringLiteral("通知日志卡片高度限制切换"));
        });
    connect(notificationLogMaximumLinesSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知日志卡片最高文字行数切换"));
        });
    connect(notificationDisplayPlacementCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知显示位置切换"));
        });
    connect(notificationStackDirectionCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知堆叠方向切换"));
        });

    connect(startupWindowScaleSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        if (!isApplyingUiState_)
        {
            markPendingChanges(QStringLiteral("启动窗口缩放变化"));
        }
        });

}

void SettingsDock::applySettings()
{
    saveAndEmitFromUi(QStringLiteral("点击应用按钮"));
}

void SettingsDock::loadSettingsFromJson()
{
    currentAppearanceSettings_ = ks::settings::loadAppearanceSettings();
    applySettingsToUi(currentAppearanceSettings_);
    hasPendingChanges_ = false;
    updateApplyButtonState();
    emit appearanceSettingsChanged(currentAppearanceSettings_);
}

void SettingsDock::applySettingsToUi(const ks::settings::AppearanceSettings& settings)
{
    isApplyingUiState_ = true;

    if (languageCombo_ != nullptr)
    {
        const int kLanguageIndex = languageCombo_->findData(settings.uiLanguage, Qt::UserRole, Qt::MatchFixedString);
        if (kLanguageIndex >= 0)
        {
            languageCombo_->setCurrentIndex(kLanguageIndex);
        }
    }

    // selectedButton purpose: Find the button corresponding to the theme mode and set it as selected.
    QAbstractButton* selectedButton = themeButtonGroup_->button(static_cast<int>(settings.themeMode));
    if (selectedButton != nullptr)
    {
        selectedButton->setChecked(true);
    }
    else if (followSystemButton_ != nullptr)
    {
        followSystemButton_->setChecked(true);
    }

    if (fontCombo_ != nullptr)
    {
        // configuredFontFamily purpose: map null values stably to item 0, 'System Default'.
        const QString kConfiguredFontFamily = settings.fontFamily.trimmed();
        int fontIndex = fontCombo_->findData(
            kConfiguredFontFamily,
            Qt::UserRole,
            Qt::MatchFixedString);
        if (fontIndex < 0 && !kConfiguredFontFamily.isEmpty())
        {
            // When the configured font is not yet installed, retain the family to avoid silently overwriting user configuration upon the first application.
            fontCombo_->addItem(kConfiguredFontFamily, kConfiguredFontFamily);
            fontIndex = fontCombo_->count() - 1;
            fontCombo_->setItemData(fontIndex, QFont(kConfiguredFontFamily), Qt::FontRole);
        }
        fontCombo_->setCurrentIndex(fontIndex >= 0 ? fontIndex : 0);
    }

    pendingCustomThemeColor_ = settings.customThemeColor;
    updateThemeColorPreview();
    pendingCustomMainBackgroundColor_ = settings.customMainBackgroundColor;
    updateMainBackgroundColorPreview();

    backgroundPathEdit_->setText(settings.backgroundImagePath);
    backgroundOpacitySlider_->setValue(settings.backgroundOpacityPercent);
    if (backgroundTransparencyCheckBox_ != nullptr)
    {
        backgroundTransparencyCheckBox_->setChecked(settings.backgroundTransparencyEnabled);
    }
    if (backgroundTranslucencyMaterialCombo_ != nullptr)
    {
        // Historical values 'mica'/'blur' no longer have direct mappings: both represent 'frosted',
        // so they are echoed back as 'acrylic' to stay consistent with migration rules in material
        // decision logic; otherwise, findData returning -1 would silently change old users to 'Auto'.
        QString materialKey = settings.backgroundTranslucencyMaterial.trimmed().toLower();
        if (materialKey == QStringLiteral("mica") || materialKey == QStringLiteral("blur"))
        {
            materialKey = QStringLiteral("acrylic");
        }
        const int kMaterialIndex = backgroundTranslucencyMaterialCombo_->findData(materialKey);
        backgroundTranslucencyMaterialCombo_->setCurrentIndex(kMaterialIndex >= 0 ? kMaterialIndex : 0);
        backgroundTranslucencyMaterialCombo_->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (backgroundBlurRadiusSlider_ != nullptr)
    {
        // The blur radius applies to the background image's custom-drawn layer and is independent of window transparency, so it is not disabled when the transparency toggle is off.
        backgroundBlurRadiusSlider_->setValue(settings.backgroundBlurRadiusPercent);
    }
    if (acrylicTintOpacitySlider_ != nullptr)
    {
        acrylicTintOpacitySlider_->setValue(settings.acrylicTintOpacityPercent);
        acrylicTintOpacitySlider_->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (desktopTintOpacitySlider_ != nullptr)
    {
        desktopTintOpacitySlider_->setValue(settings.desktopTintOpacityPercent);
        desktopTintOpacitySlider_->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (textAntialiasingCheckBox_ != nullptr)
    {
        textAntialiasingCheckBox_->setChecked(settings.textAntialiasingEnabled);
    }
    if (privilegeUiAccessCheckBox_ != nullptr)
    {
        privilegeUiAccessCheckBox_->setChecked(settings.privilegeButtonUiAccessVisible);
    }
    if (privilegeAdminCheckBox_ != nullptr)
    {
        privilegeAdminCheckBox_->setChecked(settings.privilegeButtonAdminVisible);
    }
    if (privilegeDebugCheckBox_ != nullptr)
    {
        privilegeDebugCheckBox_->setChecked(settings.privilegeButtonDebugVisible);
    }
    if (privilegeSystemCheckBox_ != nullptr)
    {
        privilegeSystemCheckBox_->setChecked(settings.privilegeButtonSystemVisible);
    }
    if (privilegeR0CheckBox_ != nullptr)
    {
        privilegeR0CheckBox_->setChecked(settings.privilegeButtonR0Visible);
    }
    if (privilegeHvmCheckBox_ != nullptr)
    {
        privilegeHvmCheckBox_->setChecked(settings.privilegeButtonHvmVisible);
    }
    if (privilegeDdmaCheckBox_ != nullptr)
    {
        privilegeDdmaCheckBox_->setChecked(settings.privilegeButtonDdmaVisible);
    }
    if (hvmDisplayNameCombo_ != nullptr)
    {
        const int kHvmNameIndex = hvmDisplayNameCombo_->findData(
            static_cast<int>(settings.hvmDisplayName));
        hvmDisplayNameCombo_->setCurrentIndex(kHvmNameIndex >= 0 ? kHvmNameIndex : 0);
    }

    if (startupMaximizedCheckBox_ != nullptr)
    {
        startupMaximizedCheckBox_->setChecked(settings.launchMaximizedOnStartup);
    }

    if (startupTopMostCheckBox_ != nullptr)
    {
        startupTopMostCheckBox_->setChecked(settings.startupTopMostEnabled);
    }

    if (startupAutoAdminCheckBox_ != nullptr)
    {
        startupAutoAdminCheckBox_->setChecked(settings.autoRequestAdminOnStartup);
    }
    if (startupAutoInstallR0DriverCheckBox_ != nullptr)
    {
        startupAutoInstallR0DriverCheckBox_->setChecked(settings.startupAutoInstallR0Driver);
    }
    if (preventMultipleInstancesCheckBox_ != nullptr)
    {
        preventMultipleInstancesCheckBox_->setChecked(settings.preventMultipleInstances);
    }
    if (unlockerShellContextMenuCheckBox_ != nullptr)
    {
        unlockerShellContextMenuCheckBox_->setChecked(settings.unlockerShellContextMenuEnabled);
    }
    if (suppressR0FeaturePromptsCheckBox_ != nullptr)
    {
        suppressR0FeaturePromptsCheckBox_->setChecked(settings.suppressR0FeaturePrompts);
    }
    if (dumpAutoCheckCheckBox_ != nullptr)
    {
        dumpAutoCheckCheckBox_->setChecked(settings.dumpAutoCheckEnabled);
    }
    if (dumpAutoCheckCheckBox_ != nullptr)
    {
        dumpAutoCheckCheckBox_->setChecked(settings.dumpAutoCheckEnabled);
    }

    if (scrollBarWidthCombo_ != nullptr)
    {
        const int kScrollBarWidthIndex = scrollBarWidthCombo_->findData(settings.useWideScrollBars);
        scrollBarWidthCombo_->setCurrentIndex(kScrollBarWidthIndex >= 0 ? kScrollBarWidthIndex : 0);
    }
    if (scrollBarAutoHideCheckBox_ != nullptr)
    {
        scrollBarAutoHideCheckBox_->setChecked(settings.scrollBarAutoHideEnabled);
    }
    if (smoothScrollingCheckBox_ != nullptr)
    {
        smoothScrollingCheckBox_->setChecked(settings.smoothScrollingEnabled);
    }
    if (sliderWheelAdjustCheckBox_ != nullptr)
    {
        sliderWheelAdjustCheckBox_->setChecked(settings.sliderWheelAdjustEnabled);
    }

    if (notificationCardsEnabledCheckBox_ != nullptr)
    {
        notificationCardsEnabledCheckBox_->setChecked(settings.notificationCardsEnabled);
    }
    if (notificationMinimumLevelCombo_ != nullptr)
    {
        const int kIndex = notificationMinimumLevelCombo_->findData(settings.notificationMinimumLevel);
        notificationMinimumLevelCombo_->setCurrentIndex(kIndex >= 0 ? kIndex : 2);
    }
    if (notificationLogDisplaySecondsSpin_ != nullptr)
    {
        notificationLogDisplaySecondsSpin_->setValue(settings.notificationLogDisplaySeconds);
    }
    if (notificationMaximumVisibleLogCardsSpin_ != nullptr)
    {
        notificationMaximumVisibleLogCardsSpin_->setValue(settings.notificationMaximumVisibleLogCards);
    }
    if (notificationLogHeightLimitCheckBox_ != nullptr)
    {
        notificationLogHeightLimitCheckBox_->setChecked(settings.notificationLogHeightLimitEnabled);
    }
    if (notificationLogMaximumLinesSpin_ != nullptr)
    {
        notificationLogMaximumLinesSpin_->setValue(settings.notificationLogMaximumLines);
        notificationLogMaximumLinesSpin_->setEnabled(
            notificationLogHeightLimitCheckBox_ != nullptr
            && notificationLogHeightLimitCheckBox_->isChecked());
    }
    if (notificationDisplayPlacementCombo_ != nullptr)
    {
        const int kIndex = notificationDisplayPlacementCombo_->findData(
            static_cast<int>(settings.notificationDisplayPlacement));
        notificationDisplayPlacementCombo_->setCurrentIndex(kIndex >= 0 ? kIndex : 0);
    }
    if (notificationStackDirectionCombo_ != nullptr)
    {
        const int kIndex = notificationStackDirectionCombo_->findData(
            static_cast<int>(settings.notificationStackDirection));
        notificationStackDirectionCombo_->setCurrentIndex(kIndex >= 0 ? kIndex : 0);
    }

    if (startupWindowScaleSpin_ != nullptr)
    {
        startupWindowScaleSpin_->setValue(
            windowScalePercentFromFactor(settings.startupWindowScaleFactor));
    }

    if (detailSchemeButtonGroup_ != nullptr)
    {
        QAbstractButton* detailSchemeButton = detailSchemeButtonGroup_->button(
            static_cast<int>(settings.detailDisplayScheme));
        if (detailSchemeButton == nullptr)
        {
            detailSchemeButton = detailSchemeButtonGroup_->button(
                static_cast<int>(ks::settings::DetailDisplayScheme::kBottomCollapsed));
        }
        if (detailSchemeButton != nullptr)
        {
            detailSchemeButton->setChecked(true);
        }
    }

    // Populating the online scanning API Key:
    // - The settings page displays only the Key saved by the user;
    // - PasswordEchoOnEdit hides text when not being edited to prevent shoulder-surfing leaks.
    if (virusTotalApiKeyEdit_ != nullptr)
    {
        virusTotalApiKeyEdit_->setText(settings.virusTotalApiKey);
    }
    if (threatBookApiKeyEdit_ != nullptr)
    {
        threatBookApiKeyEdit_->setText(settings.threatBookApiKey);
    }

    updateOpacityValueLabel(settings.backgroundOpacityPercent);
    // Explicitly fill in the three glass-effect labels: setValue does not emit valueChanged when the value is unchanged; relying solely
    // on signals leaves the placeholder text from construction when the configured value exactly matches the slider's initial value.
    if (backgroundBlurRadiusValueLabel_ != nullptr)
    {
        backgroundBlurRadiusValueLabel_->setText(
            QStringLiteral("%1%").arg(settings.backgroundBlurRadiusPercent));
    }
    if (acrylicTintOpacityValueLabel_ != nullptr)
    {
        acrylicTintOpacityValueLabel_->setText(
            QStringLiteral("%1%").arg(settings.acrylicTintOpacityPercent));
    }
    if (desktopTintOpacityValueLabel_ != nullptr)
    {
        desktopTintOpacityValueLabel_->setText(
            QStringLiteral("%1%").arg(settings.desktopTintOpacityPercent));
    }
    updateThemeButtonStyle();

    isApplyingUiState_ = false;
    hasPendingChanges_ = false;
    updateApplyButtonState();
}

ks::settings::AppearanceSettings SettingsDock::collectSettingsFromUi() const
{
    ks::settings::AppearanceSettings collectedSettings = currentAppearanceSettings_;

    // Dangerous action confirmation policy is maintained by deep feature menus; retain the latest values from disk when saving other settings.
    collectedSettings.suppressDangerousActionConfirmations =
        ks::settings::dangerousActionConfirmationsSuppressed();

    collectedSettings.uiLanguage = (languageCombo_ != nullptr && languageCombo_->currentIndex() >= 0)
        ? languageCombo_->currentData().toString()
        : currentAppearanceSettings_.uiLanguage;
    collectedSettings.customThemeColor = pendingCustomThemeColor_;
    collectedSettings.customMainBackgroundColor = pendingCustomMainBackgroundColor_;

    // checkedThemeId purpose: Read the ID of the currently selected theme button.
    const int kCheckedThemeId = themeButtonGroup_->checkedId();
    if (kCheckedThemeId == static_cast<int>(ks::settings::ThemeMode::kLight))
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::kLight;
    }
    else if (kCheckedThemeId == static_cast<int>(ks::settings::ThemeMode::kDark))
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::kDark;
    }
    else
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::kFollowSystem;
    }

    const QString kRawPathText = backgroundPathEdit_->text().trimmed();
    collectedSettings.backgroundImagePath = kRawPathText.isEmpty()
        ? QStringLiteral("Style/ksword_background.png")
        : kRawPathText;

    collectedSettings.backgroundOpacityPercent = backgroundOpacitySlider_->value();
    collectedSettings.backgroundTransparencyEnabled = backgroundTransparencyCheckBox_ != nullptr
        && backgroundTransparencyCheckBox_->isChecked();
    collectedSettings.backgroundTranslucencyMaterial = backgroundTranslucencyMaterialCombo_ != nullptr
        ? backgroundTranslucencyMaterialCombo_->currentData().toString()
        : currentAppearanceSettings_.backgroundTranslucencyMaterial;
    collectedSettings.backgroundBlurRadiusPercent = backgroundBlurRadiusSlider_ != nullptr
        ? backgroundBlurRadiusSlider_->value()
        : currentAppearanceSettings_.backgroundBlurRadiusPercent;
    collectedSettings.acrylicTintOpacityPercent = acrylicTintOpacitySlider_ != nullptr
        ? acrylicTintOpacitySlider_->value()
        : currentAppearanceSettings_.acrylicTintOpacityPercent;
    collectedSettings.desktopTintOpacityPercent = desktopTintOpacitySlider_ != nullptr
        ? desktopTintOpacitySlider_->value()
        : currentAppearanceSettings_.desktopTintOpacityPercent;
    // The startup page field is no longer edited via the settings page; preserve the current in-memory value when saving other settings to avoid accidentally overwriting the old configuration.
    collectedSettings.startupDefaultTabKey = currentAppearanceSettings_.startupDefaultTabKey;
    collectedSettings.launchMaximizedOnStartup =
        (startupMaximizedCheckBox_ != nullptr) && startupMaximizedCheckBox_->isChecked();
    collectedSettings.startupTopMostEnabled =
        (startupTopMostCheckBox_ != nullptr) && startupTopMostCheckBox_->isChecked();
    collectedSettings.autoRequestAdminOnStartup =
        (startupAutoAdminCheckBox_ != nullptr) && startupAutoAdminCheckBox_->isChecked();
    collectedSettings.startupAutoInstallR0Driver =
        (startupAutoInstallR0DriverCheckBox_ != nullptr)
        && startupAutoInstallR0DriverCheckBox_->isChecked();
    collectedSettings.preventMultipleInstances =
        (preventMultipleInstancesCheckBox_ == nullptr) || preventMultipleInstancesCheckBox_->isChecked();
    collectedSettings.startupWindowScaleFactor = parseWindowScaleFactorFromUi();
    // This switch originates from a pre-launch popup, not the settings page; retain the memory value here to prevent it from being overwritten during save.
    collectedSettings.startupScaleRecommendPromptDisabled =
        currentAppearanceSettings_.startupScaleRecommendPromptDisabled;
    collectedSettings.unlockerShellContextMenuEnabled =
        (unlockerShellContextMenuCheckBox_ != nullptr) && unlockerShellContextMenuCheckBox_->isChecked();
    collectedSettings.suppressR0FeaturePrompts =
        (suppressR0FeaturePromptsCheckBox_ != nullptr)
        && suppressR0FeaturePromptsCheckBox_->isChecked();
    collectedSettings.dumpAutoCheckEnabled =
        (dumpAutoCheckCheckBox_ == nullptr) || dumpAutoCheckCheckBox_->isChecked();
    // Records that have been prompted for dump are written by the startup check process; the settings page only passes them through to avoid clearing them during save.
    collectedSettings.dumpAutoCheckPromptedPath =
        currentAppearanceSettings_.dumpAutoCheckPromptedPath;
    collectedSettings.dumpAutoCheckPromptedTimeMsec =
        currentAppearanceSettings_.dumpAutoCheckPromptedTimeMsec;
    collectedSettings.useWideScrollBars =
        (scrollBarWidthCombo_ != nullptr) && scrollBarWidthCombo_->currentData().toBool();
    collectedSettings.scrollBarAutoHideEnabled =
        (scrollBarAutoHideCheckBox_ != nullptr) && scrollBarAutoHideCheckBox_->isChecked();
    collectedSettings.smoothScrollingEnabled =
        (smoothScrollingCheckBox_ != nullptr) && smoothScrollingCheckBox_->isChecked();
    collectedSettings.sliderWheelAdjustEnabled =
        (sliderWheelAdjustCheckBox_ != nullptr) && sliderWheelAdjustCheckBox_->isChecked();
    const int kDetailSchemeId = detailSchemeButtonGroup_ != nullptr
        ? detailSchemeButtonGroup_->checkedId()
        : static_cast<int>(currentAppearanceSettings_.detailDisplayScheme);
    if (kDetailSchemeId >= static_cast<int>(ks::settings::DetailDisplayScheme::kBottomCollapsed) &&
        kDetailSchemeId <= static_cast<int>(ks::settings::DetailDisplayScheme::kFloating))
    {
        collectedSettings.detailDisplayScheme =
            static_cast<ks::settings::DetailDisplayScheme>(kDetailSchemeId);
    }
    collectedSettings.fontFamily = fontCombo_ != nullptr
        ? fontCombo_->currentData(Qt::UserRole).toString().trimmed()
        : currentAppearanceSettings_.fontFamily;
    collectedSettings.textAntialiasingEnabled =
        (textAntialiasingCheckBox_ != nullptr) && textAntialiasingCheckBox_->isChecked();
    /*
     * Permission button visibility: retain current value if the control is missing, rather than treating it as unchecked.
     *
     * Other checkboxes use `(ptr != nullptr) && isChecked()`, yielding false if the control is absent.
     * That writing style here would equate to "Settings page not constructed = hide the entire row of buttons," which is a behavior that
     * modifies user configuration based on a UI fault. Since the default is to show all, the default value must revert to the current value.
     */
    collectedSettings.privilegeButtonUiAccessVisible =
        (privilegeUiAccessCheckBox_ != nullptr)
            ? privilegeUiAccessCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonUiAccessVisible;
    collectedSettings.privilegeButtonAdminVisible =
        (privilegeAdminCheckBox_ != nullptr)
            ? privilegeAdminCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonAdminVisible;
    collectedSettings.privilegeButtonDebugVisible =
        (privilegeDebugCheckBox_ != nullptr)
            ? privilegeDebugCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonDebugVisible;
    collectedSettings.privilegeButtonSystemVisible =
        (privilegeSystemCheckBox_ != nullptr)
            ? privilegeSystemCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonSystemVisible;
    collectedSettings.privilegeButtonR0Visible =
        (privilegeR0CheckBox_ != nullptr)
            ? privilegeR0CheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonR0Visible;
    collectedSettings.privilegeButtonHvmVisible =
        (privilegeHvmCheckBox_ != nullptr)
            ? privilegeHvmCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonHvmVisible;
    collectedSettings.privilegeButtonDdmaVisible =
        (privilegeDdmaCheckBox_ != nullptr)
            ? privilegeDdmaCheckBox_->isChecked()
            : currentAppearanceSettings_.privilegeButtonDdmaVisible;
    collectedSettings.hvmDisplayName =
        (hvmDisplayNameCombo_ != nullptr)
            ? static_cast<ks::settings::HvmDisplayName>(
                  hvmDisplayNameCombo_->currentData().toInt())
            : currentAppearanceSettings_.hvmDisplayName;
    collectedSettings.notificationCardsEnabled =
        (notificationCardsEnabledCheckBox_ != nullptr) && notificationCardsEnabledCheckBox_->isChecked();
    collectedSettings.notificationMinimumLevel =
        notificationMinimumLevelCombo_ != nullptr
        ? notificationMinimumLevelCombo_->currentData().toInt()
        : currentAppearanceSettings_.notificationMinimumLevel;
    collectedSettings.notificationLogDisplaySeconds =
        notificationLogDisplaySecondsSpin_ != nullptr
        ? notificationLogDisplaySecondsSpin_->value()
        : currentAppearanceSettings_.notificationLogDisplaySeconds;
    collectedSettings.notificationMaximumVisibleLogCards =
        notificationMaximumVisibleLogCardsSpin_ != nullptr
        ? notificationMaximumVisibleLogCardsSpin_->value()
        : currentAppearanceSettings_.notificationMaximumVisibleLogCards;
    collectedSettings.notificationLogHeightLimitEnabled =
        (notificationLogHeightLimitCheckBox_ != nullptr)
        && notificationLogHeightLimitCheckBox_->isChecked();
    collectedSettings.notificationLogMaximumLines =
        notificationLogMaximumLinesSpin_ != nullptr
        ? notificationLogMaximumLinesSpin_->value()
        : currentAppearanceSettings_.notificationLogMaximumLines;
    collectedSettings.notificationDisplayPlacement =
        notificationDisplayPlacementCombo_ != nullptr
        ? static_cast<ks::settings::NotificationDisplayPlacement>(notificationDisplayPlacementCombo_->currentData().toInt())
        : currentAppearanceSettings_.notificationDisplayPlacement;
    collectedSettings.notificationStackDirection =
        notificationStackDirectionCombo_ != nullptr
        ? static_cast<ks::settings::NotificationStackDirection>(notificationStackDirectionCombo_->currentData().toInt())
        : currentAppearanceSettings_.notificationStackDirection;
    // Online scanning API Key:
    // - Read from the Online Scanning tab;
    // - Trim uniformly on save; OnlineScan reads only from config during runtime, never hardcodes keys.
    collectedSettings.virusTotalApiKey = (virusTotalApiKeyEdit_ != nullptr)
        ? virusTotalApiKeyEdit_->text().trimmed()
        : currentAppearanceSettings_.virusTotalApiKey;
    collectedSettings.threatBookApiKey = (threatBookApiKeyEdit_ != nullptr)
        ? threatBookApiKeyEdit_->text().trimmed()
        : currentAppearanceSettings_.threatBookApiKey;

    return collectedSettings;
}

void SettingsDock::markPendingChanges(const QString& triggerReason)
{
    Q_UNUSED(triggerReason);
    if (isApplyingUiState_)
    {
        return;
    }

    hasPendingChanges_ = true;
    updateApplyButtonState();
}

void SettingsDock::updateSystemDefaultFontItemText()
{
    if (fontCombo_ == nullptr || fontCombo_->count() <= 0)
    {
        return;
    }

    // systemDefaultData usage: Verify that the 0th item remains a stable empty family semantics.
    const QString kSystemDefaultData =
        fontCombo_->itemData(0, Qt::UserRole).toString();
    if (!kSystemDefaultData.isEmpty())
    {
        return;
    }
    fontCombo_->setItemText(
        0,
        ks::i18n::text(
            QStringLiteral("settings.font.system_default"),
            QStringLiteral("系统默认")));
}

void SettingsDock::updateApplyButtonState()
{
    emit pendingChangesChanged(hasPendingChanges_);

    // The Save button on the Online Scan page and the Apply button on the Appearance page share the same
    // pending-changes state, ensuring that clicking Save from any settings page persists the complete configuration.
    if (saveOnlineScanKeysButton_ != nullptr)
    {
        saveOnlineScanKeysButton_->setEnabled(hasPendingChanges_);
        saveOnlineScanKeysButton_->setToolTip(
            hasPendingChanges_
            ? ks::i18n::text(QStringLiteral("settings.online.save.pending"), QStringLiteral("保存当前 API Key 与其它待提交设置"))
            : ks::i18n::text(QStringLiteral("settings.online.save.clean"), QStringLiteral("当前 API Key 已保存，无待提交改动")));
    }
}

void SettingsDock::updateThemeColorPreview()
{
    if (themeColorPreviewLabel_ == nullptr)
    {
        return;
    }

    const QColor kPreviewColor = pendingCustomThemeColor_.isEmpty()
        ? ksword_theme::defaultPrimaryAccentColor()
        : QColor(pendingCustomThemeColor_);
    const QColor kReadableTextColor = ksword_theme::ensureTextContrast(
        ksword_theme::whiteColor(),
        kPreviewColor);
    const QString kColorText = kPreviewColor.name(QColor::HexRgb).toUpper();
    themeColorPreviewLabel_->setText(kColorText);
    themeColorPreviewLabel_->setStyleSheet(
        QStringLiteral("QLabel{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px;font-weight:600;}")
        .arg(kColorText)
        .arg(ksword_theme::themeColorName(kReadableTextColor))
        .arg(ksword_theme::borderHex()));

    if (resetThemeColorButton_ != nullptr)
    {
        resetThemeColorButton_->setEnabled(!pendingCustomThemeColor_.isEmpty());
    }
}

void SettingsDock::chooseCustomThemeColor()
{
    const QMessageBox::StandardButton kWarningResult = QMessageBox::warning(
        this,
        ks::i18n::text(
            QStringLiteral("settings.theme.color.warning.title"),
            QStringLiteral("自定义主题色提示")),
        ks::i18n::text(
            QStringLiteral("settings.theme.color.warning.message"),
            QStringLiteral("当前界面所有颜色均基于偏移量设计，便于修改主题色；但尚未覆盖测试所有颜色组合。若选择过于极端的颜色，部分界面仍可能无法正常显示。是否继续？")),
        QMessageBox::Ok | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (kWarningResult != QMessageBox::Ok)
    {
        return;
    }

    const QColor kInitialColor = pendingCustomThemeColor_.isEmpty()
        ? ksword_theme::defaultPrimaryAccentColor()
        : QColor(pendingCustomThemeColor_);
    const QColor kSelectedColor = QColorDialog::getColor(
        kInitialColor,
        this,
        ks::i18n::text(
            QStringLiteral("settings.theme.color.dialog.title"),
            QStringLiteral("选择主题色")),
        QColorDialog::ShowAlphaChannel);
    if (!kSelectedColor.isValid())
    {
        return;
    }

    pendingCustomThemeColor_ = kSelectedColor.name(QColor::HexRgb).toUpper();
    updateThemeColorPreview();
    markPendingChanges(QStringLiteral("custom theme color selected"));
}

void SettingsDock::resetThemeColorToDefault()
{
    if (pendingCustomThemeColor_.isEmpty())
    {
        return;
    }

    pendingCustomThemeColor_.clear();
    updateThemeColorPreview();
    markPendingChanges(QStringLiteral("custom theme color restored"));
}

void SettingsDock::updateMainBackgroundColorPreview()
{
    if (mainBackgroundColorPreviewLabel_ == nullptr)
    {
        return;
    }

    const QColor kPreviewColor = pendingCustomMainBackgroundColor_.isEmpty()
        ? ksword_theme::defaultMainBackgroundColor(
            selectedThemeUsesDarkBackground(themeButtonGroup_))
        : QColor(pendingCustomMainBackgroundColor_);
    const QColor kReadableTextColor = ksword_theme::ensureTextContrast(
        ksword_theme::textPrimaryColor(),
        kPreviewColor);
    const QString kColorText = kPreviewColor.name(QColor::HexRgb).toUpper();
    mainBackgroundColorPreviewLabel_->setText(kColorText);
    mainBackgroundColorPreviewLabel_->setStyleSheet(
        QStringLiteral("QLabel{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px;font-weight:600;}")
        .arg(kColorText)
        .arg(ksword_theme::themeColorName(kReadableTextColor))
        .arg(ksword_theme::borderHex()));

    if (resetMainBackgroundColorButton_ != nullptr)
    {
        resetMainBackgroundColorButton_->setEnabled(
            !pendingCustomMainBackgroundColor_.isEmpty());
    }
}

void SettingsDock::chooseCustomMainBackgroundColor()
{
    const QColor kInitialColor = pendingCustomMainBackgroundColor_.isEmpty()
        ? ksword_theme::defaultMainBackgroundColor(
            selectedThemeUsesDarkBackground(themeButtonGroup_))
        : QColor(pendingCustomMainBackgroundColor_);
    const QColor kSelectedColor = QColorDialog::getColor(
        kInitialColor,
        this,
        ks::i18n::text(
            QStringLiteral("settings.background.color.dialog.title"),
            QStringLiteral("选择主背景色")));
    if (!kSelectedColor.isValid())
    {
        return;
    }

    pendingCustomMainBackgroundColor_ = kSelectedColor.name(QColor::HexRgb).toUpper();
    updateMainBackgroundColorPreview();
    markPendingChanges(QStringLiteral("custom main background color selected"));
}

void SettingsDock::resetMainBackgroundColorToDefault()
{
    if (pendingCustomMainBackgroundColor_.isEmpty())
    {
        return;
    }

    pendingCustomMainBackgroundColor_.clear();
    updateMainBackgroundColorPreview();
    markPendingChanges(QStringLiteral("custom main background color restored"));
}

void SettingsDock::saveAndEmitFromUi(const QString& triggerReason)
{
    if (isApplyingUiState_)
    {
        return;
    }

    // settingsEvent: Unified log event object for the current 'settings change' call chain.
    KLogEvent settingsEvent;
    const ks::settings::AppearanceSettings kNextSettings = collectSettingsFromUi();
    const bool kUnlockerShellContextMenuChanged =
        kNextSettings.unlockerShellContextMenuEnabled != currentAppearanceSettings_.unlockerShellContextMenuEnabled;
    const bool kSameScaleFactor =
        std::fabs(kNextSettings.startupWindowScaleFactor - currentAppearanceSettings_.startupWindowScaleFactor) < 0.0001;

    if (kNextSettings.themeMode == currentAppearanceSettings_.themeMode
        && kNextSettings.customThemeColor.compare(currentAppearanceSettings_.customThemeColor, Qt::CaseInsensitive) == 0
        && kNextSettings.customMainBackgroundColor.compare(
            currentAppearanceSettings_.customMainBackgroundColor,
            Qt::CaseInsensitive) == 0
        && kNextSettings.uiLanguage.compare(currentAppearanceSettings_.uiLanguage, Qt::CaseInsensitive) == 0
        && kNextSettings.backgroundImagePath == currentAppearanceSettings_.backgroundImagePath
        && kNextSettings.backgroundOpacityPercent == currentAppearanceSettings_.backgroundOpacityPercent
        && kNextSettings.backgroundTransparencyEnabled == currentAppearanceSettings_.backgroundTransparencyEnabled
        && kNextSettings.backgroundTranslucencyMaterial == currentAppearanceSettings_.backgroundTranslucencyMaterial
        && kNextSettings.backgroundBlurRadiusPercent == currentAppearanceSettings_.backgroundBlurRadiusPercent
        && kNextSettings.acrylicTintOpacityPercent == currentAppearanceSettings_.acrylicTintOpacityPercent
        && kNextSettings.desktopTintOpacityPercent == currentAppearanceSettings_.desktopTintOpacityPercent
        && kNextSettings.launchMaximizedOnStartup == currentAppearanceSettings_.launchMaximizedOnStartup
        && kNextSettings.startupTopMostEnabled == currentAppearanceSettings_.startupTopMostEnabled
        && kNextSettings.autoRequestAdminOnStartup == currentAppearanceSettings_.autoRequestAdminOnStartup
        && kNextSettings.startupAutoInstallR0Driver == currentAppearanceSettings_.startupAutoInstallR0Driver
        && kNextSettings.preventMultipleInstances == currentAppearanceSettings_.preventMultipleInstances
        && kSameScaleFactor
        && kNextSettings.startupScaleRecommendPromptDisabled == currentAppearanceSettings_.startupScaleRecommendPromptDisabled
        && kNextSettings.unlockerShellContextMenuEnabled == currentAppearanceSettings_.unlockerShellContextMenuEnabled
        && kNextSettings.suppressR0FeaturePrompts == currentAppearanceSettings_.suppressR0FeaturePrompts
        && kNextSettings.useWideScrollBars == currentAppearanceSettings_.useWideScrollBars
        && kNextSettings.scrollBarAutoHideEnabled == currentAppearanceSettings_.scrollBarAutoHideEnabled
        && kNextSettings.smoothScrollingEnabled == currentAppearanceSettings_.smoothScrollingEnabled
        && kNextSettings.sliderWheelAdjustEnabled == currentAppearanceSettings_.sliderWheelAdjustEnabled
        && kNextSettings.detailDisplayScheme == currentAppearanceSettings_.detailDisplayScheme
        && kNextSettings.fontFamily.compare(currentAppearanceSettings_.fontFamily, Qt::CaseInsensitive) == 0
        && kNextSettings.textAntialiasingEnabled == currentAppearanceSettings_.textAntialiasingEnabled
        && kNextSettings.privilegeButtonUiAccessVisible == currentAppearanceSettings_.privilegeButtonUiAccessVisible
        && kNextSettings.privilegeButtonAdminVisible == currentAppearanceSettings_.privilegeButtonAdminVisible
        && kNextSettings.privilegeButtonDebugVisible == currentAppearanceSettings_.privilegeButtonDebugVisible
        && kNextSettings.privilegeButtonSystemVisible == currentAppearanceSettings_.privilegeButtonSystemVisible
        && kNextSettings.privilegeButtonR0Visible == currentAppearanceSettings_.privilegeButtonR0Visible
        && kNextSettings.privilegeButtonHvmVisible == currentAppearanceSettings_.privilegeButtonHvmVisible
        && kNextSettings.privilegeButtonDdmaVisible == currentAppearanceSettings_.privilegeButtonDdmaVisible
        && kNextSettings.hvmDisplayName == currentAppearanceSettings_.hvmDisplayName
        && kNextSettings.notificationCardsEnabled == currentAppearanceSettings_.notificationCardsEnabled
        && kNextSettings.notificationMinimumLevel == currentAppearanceSettings_.notificationMinimumLevel
        && kNextSettings.notificationLogDisplaySeconds == currentAppearanceSettings_.notificationLogDisplaySeconds
        && kNextSettings.notificationMaximumVisibleLogCards == currentAppearanceSettings_.notificationMaximumVisibleLogCards
        && kNextSettings.notificationLogHeightLimitEnabled == currentAppearanceSettings_.notificationLogHeightLimitEnabled
        && kNextSettings.notificationLogMaximumLines == currentAppearanceSettings_.notificationLogMaximumLines
        && kNextSettings.notificationDisplayPlacement == currentAppearanceSettings_.notificationDisplayPlacement
        && kNextSettings.notificationStackDirection == currentAppearanceSettings_.notificationStackDirection
        && kNextSettings.virusTotalApiKey == currentAppearanceSettings_.virusTotalApiKey
        && kNextSettings.threatBookApiKey == currentAppearanceSettings_.threatBookApiKey)
    {
        hasPendingChanges_ = false;
        updateApplyButtonState();
        return;
    }

    QString saveErrorText;
    const bool kSaveOk = ks::settings::saveAppearanceSettings(kNextSettings, &saveErrorText);
    if (!kSaveOk)
    {
        err << settingsEvent
            << "[SettingsDock] 保存外观设置失败，触发来源="
            << triggerReason.toStdString()
            << "，错误="
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    if (kUnlockerShellContextMenuChanged)
    {
        if (kNextSettings.unlockerShellContextMenuEnabled)
        {
            const std::wstring kExecutablePath = queryCurrentExecutablePath();
            const bool kRegisterOk = registerUnlockerContextMenuNow(kExecutablePath);
            if (!kRegisterOk)
            {
                warn << settingsEvent
                    << "[SettingsDock] 系统右键文件解锁器菜单即时注册失败，将保留配置并在下次启动重试。"
                    << eol;
            }
            else
            {
                info << settingsEvent
                    << "[SettingsDock] 系统右键文件解锁器菜单已即时注册。"
                    << eol;
            }
        }
        else
        {
            // Unchecking must immediately remove all shell menus under HKCU\Software\Classes (including legacy items); writing only
            // configuration to wait for the next startup is insufficient, as users would still see the right-click menu lingering.
            unregisterUnlockerContextMenuNow();
            info << settingsEvent
                << "[SettingsDock] 系统右键文件解锁器菜单已即时移除。"
                << eol;
        }
    }

    const bool kLanguageChanged =
        kNextSettings.uiLanguage.compare(currentAppearanceSettings_.uiLanguage, Qt::CaseInsensitive) != 0;
    currentAppearanceSettings_ = kNextSettings;
    if (kLanguageChanged)
    {
        QString languageErrorText;
        if (!ks::i18n::LanguageManager::instance().setLanguage(
            currentAppearanceSettings_.uiLanguage,
            &languageErrorText))
        {
            warn << settingsEvent
                << "[SettingsDock] Failed to apply language pack: "
                << languageErrorText
                << eol;
        }
    }
    isApplyingUiState_ = true;
    if (startupWindowScaleSpin_ != nullptr)
    {
        startupWindowScaleSpin_->setValue(
            windowScalePercentFromFactor(currentAppearanceSettings_.startupWindowScaleFactor));
    }
    if (virusTotalApiKeyEdit_ != nullptr)
    {
        virusTotalApiKeyEdit_->setText(currentAppearanceSettings_.virusTotalApiKey);
    }
    if (threatBookApiKeyEdit_ != nullptr)
    {
        threatBookApiKeyEdit_->setText(currentAppearanceSettings_.threatBookApiKey);
    }
    isApplyingUiState_ = false;
    hasPendingChanges_ = false;
    updateApplyButtonState();

    info << settingsEvent
        << "[SettingsDock] 外观设置已保存，触发来源="
        << triggerReason.toStdString()
        << "，主题模式="
        << ks::settings::themeModeToJsonText(currentAppearanceSettings_.themeMode).toStdString()
        << ", customThemeColor="
        << (currentAppearanceSettings_.customThemeColor.isEmpty()
            ? "default"
            : currentAppearanceSettings_.customThemeColor.toStdString())
        << ", customMainBackgroundColor="
        << (currentAppearanceSettings_.customMainBackgroundColor.isEmpty()
            ? "default"
            : currentAppearanceSettings_.customMainBackgroundColor.toStdString())
        << "，界面语言="
        << currentAppearanceSettings_.uiLanguage.toStdString()
        << "，背景路径="
        << currentAppearanceSettings_.backgroundImagePath.toStdString()
        << "，透明度="
        << currentAppearanceSettings_.backgroundOpacityPercent
        << "%，启动时最大化="
        << (currentAppearanceSettings_.launchMaximizedOnStartup ? "true" : "false")
        << "，启动后默认最高级置顶="
        << (currentAppearanceSettings_.startupTopMostEnabled ? "true" : "false")
        << "，启动时自动请求管理员权限="
        << (currentAppearanceSettings_.autoRequestAdminOnStartup ? "true" : "false")
        << "，启动时自动安装驱动="
        << (currentAppearanceSettings_.startupAutoInstallR0Driver ? "true" : "false")
        << "，防止多开="
        << (currentAppearanceSettings_.preventMultipleInstances ? "true" : "false")
        << "，启动窗口缩放因子="
        << currentAppearanceSettings_.startupWindowScaleFactor
        << "，小屏缩放提示不再弹出="
        << (currentAppearanceSettings_.startupScaleRecommendPromptDisabled ? "true" : "false")
        << "，系统右键文件解锁器菜单="
        << (currentAppearanceSettings_.unlockerShellContextMenuEnabled ? "true" : "false")
        << "，宽滚动条="
        << (currentAppearanceSettings_.useWideScrollBars ? "true" : "false")
        << "，滚动条自动隐藏="
        << (currentAppearanceSettings_.scrollBarAutoHideEnabled ? "true" : "false")
        << "，全局平滑滚动="
        << (currentAppearanceSettings_.smoothScrollingEnabled ? "true" : "false")
        << "，滚轮调整滑块="
        << (currentAppearanceSettings_.sliderWheelAdjustEnabled ? "true" : "false")
        << "，详情页显示方案="
        << ks::settings::detailDisplaySchemeToJsonText(
            currentAppearanceSettings_.detailDisplayScheme).toStdString()
        << "，VirusTotal API Key已配置="
        << (!currentAppearanceSettings_.virusTotalApiKey.trimmed().isEmpty() ? "true" : "false")
        << "，ThreatBook API Key已配置="
        << (!currentAppearanceSettings_.threatBookApiKey.trimmed().isEmpty() ? "true" : "false")
        << eol;

    emit appearanceSettingsChanged(currentAppearanceSettings_);

    // appearanceSettingsChanged is a direct connection signal; the global theme switch is complete upon return.
    // SurfaceMuted and PrimaryBlueSubtle have no equivalents in the palette, so a snapshot must be taken
    // and re-applied here; otherwise, this row of theme buttons will remain stuck on the pre-switch colors.
    updateThemeButtonStyle();

    QMessageBox::information(
        this,
        ks::i18n::text(
            QStringLiteral("settings.apply.success.title"),
            QStringLiteral("应用")),
        ks::i18n::text(
            QStringLiteral("settings.apply.success.message"),
            QStringLiteral("当前设置已应用，无待提交改动")));
}

void SettingsDock::updateThemeButtonStyle()
{
    const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
    const QString kNormalStyle = kDarkModeEnabled
        ? QStringLiteral(
            "QToolButton{"
            "  border:1px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}"
            "QToolButton:hover{"
            "  background:%3;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::surfaceMutedColorHex())
        : QStringLiteral(
            "QToolButton{"
            "  border:1px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}"
            "QToolButton:hover{"
            "  background:%3;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::primaryBlueSubtleHex())
            .arg(ksword_theme::primaryBlueSubtleHex());

    const QString kCheckedStyle = kDarkModeEnabled
        ? QStringLiteral(
            "QToolButton{"
            "  border:2px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::primaryBlueSubtleHex())
        : QStringLiteral(
            "QToolButton{"
            "  border:2px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::primaryBlueSubtleHex());

    const QList<QAbstractButton*> kThemeButtons = themeButtonGroup_->buttons();
    for (QAbstractButton* themeButton : kThemeButtons)
    {
        QToolButton* themedToolButton = qobject_cast<QToolButton*>(themeButton);
        if (themedToolButton == nullptr)
        {
            continue;
        }
        themedToolButton->setStyleSheet(themedToolButton->isChecked() ? kCheckedStyle : kNormalStyle);
    }
}

void SettingsDock::updateOpacityValueLabel(const int opacityPercent)
{
    backgroundOpacityValueLabel_->setText(QStringLiteral("%1%").arg(opacityPercent));
}

void SettingsDock::launchTaskmgrHijackScript(const bool install)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("任务管理器映像劫持"));
        return;
    }

    // scriptPath:
    // - Fixed lookup of TaskmgrHijack.ps1 from the application's current directory, matching the deployment method where scripts are copied into the Release package.
    // - Do not revert to the repository path to avoid behavioral inconsistencies between release packages and development directories.
    const QString kApplicationDirectoryPath = QCoreApplication::applicationDirPath();
    const QString kScriptPath = QDir(kApplicationDirectoryPath).absoluteFilePath(QStringLiteral("TaskmgrHijack.ps1"));
    const QFileInfo kScriptFileInfo(kScriptPath);
    if (!kScriptFileInfo.exists() || !kScriptFileInfo.isFile())
    {
        const QString kErrorText = QStringLiteral("未找到任务管理器映像劫持脚本。\n\n路径：%1").arg(kScriptPath);
        KLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] TaskmgrHijack.ps1 不存在，无法执行任务管理器映像劫持动作: "
            << kScriptPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("任务管理器映像劫持"), kErrorText);
        return;
    }

    // targetExePath:
    // - Explicitly pass the current Ksword main executable path during installation to prevent the script from failing to locate Ksword5.1.exe due to PowerShell working directory changes;
    // - TargetExe is not needed during uninstallation; keep script argument semantics minimal.
    const QString kTargetExePath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    QStringList argumentList;
    argumentList
        << QStringLiteral("-NoProfile")
        << QStringLiteral("-ExecutionPolicy")
        << QStringLiteral("Bypass")
        << QStringLiteral("-File")
        << QDir::toNativeSeparators(kScriptPath)
        << (install ? QStringLiteral("-Install") : QStringLiteral("-Uninstall"));
    if (install)
    {
        argumentList << QStringLiteral("-TargetExe") << kTargetExePath;
    }

    // powershellProcess:
    // - Asynchronously start the script to avoid blocking the settings dialog.
    // - The script's Ensure-Administrator re-runs with RunAs when needed and continues execution in the elevated window.
    QProcess* powershellProcess = new QProcess(this);
    powershellProcess->setProgram(QStringLiteral("powershell.exe"));
    powershellProcess->setArguments(argumentList);
    powershellProcess->setWorkingDirectory(kApplicationDirectoryPath);

    connect(powershellProcess, &QProcess::errorOccurred, this,
        [this, powershellProcess, install](const QProcess::ProcessError processError) {
            const QString kErrorText = powershellProcess->errorString();
            KLogEvent settingsEvent;
            err << settingsEvent
                << "[SettingsDock] 启动 TaskmgrHijack.ps1 失败, action="
                << (install ? "install" : "uninstall")
                << ", processError="
                << static_cast<int>(processError)
                << ", error="
                << kErrorText.toStdString()
                << eol;
            QMessageBox::warning(
                this,
                QStringLiteral("任务管理器映像劫持"),
                QStringLiteral("启动 PowerShell 脚本失败。\n\n%1").arg(kErrorText));
        });
    connect(powershellProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
        [powershellProcess, install](const int exitCode, const QProcess::ExitStatus exitStatus) {
            KLogEvent settingsEvent;
            info << settingsEvent
                << "[SettingsDock] TaskmgrHijack.ps1 进程结束, action="
                << (install ? "install" : "uninstall")
                << ", exitCode="
                << exitCode
                << ", exitStatus="
                << static_cast<int>(exitStatus)
                << eol;
            powershellProcess->deleteLater();
        });

    powershellProcess->start();
    if (!powershellProcess->waitForStarted(3000))
    {
        const QString kErrorText = powershellProcess->errorString();
        KLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] TaskmgrHijack.ps1 未能启动, action="
            << (install ? "install" : "uninstall")
            << ", error="
            << kErrorText.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("任务管理器映像劫持"),
            QStringLiteral("启动 PowerShell 脚本失败。\n\n%1").arg(kErrorText));
        powershellProcess->deleteLater();
        return;
    }

    KLogEvent settingsEvent;
    info << settingsEvent
        << "[SettingsDock] 已启动 TaskmgrHijack.ps1, action="
        << (install ? "install" : "uninstall")
        << ", script="
        << kScriptPath.toStdString()
        << ", targetExe="
        << kTargetExePath.toStdString()
        << eol;
}

double SettingsDock::parseWindowScaleFactorFromUi() const
{
    if (startupWindowScaleSpin_ == nullptr)
    {
        return ks::settings::normalizeWindowScaleFactor(
            currentAppearanceSettings_.startupWindowScaleFactor);
    }

    // The spin box only produces valid percentages, so no text parsing or fallback handling is needed.
    return windowScaleFactorFromPercent(startupWindowScaleSpin_->value());
}

void SettingsDock::openBackgroundFileDialog()
{
    const QString kSelectedFilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择背景图片"),
        backgroundPathEdit_->text(),
        QStringLiteral("图片文件 (*.png *.jpg *.jpeg *.bmp *.webp);;所有文件 (*.*)"));

    if (kSelectedFilePath.isEmpty())
    {
        return;
    }

    backgroundPathEdit_->setText(kSelectedFilePath);
    markPendingChanges(QStringLiteral("浏览按钮选择背景图"));
}

void SettingsDock::resetBackgroundPathToDefault()
{
    backgroundPathEdit_->setText(QStringLiteral("Style/ksword_background.png"));
    markPendingChanges(QStringLiteral("恢复默认背景路径"));
}
