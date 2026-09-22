#include "SettingsDock.h"

#include "../Framework.h"
#include "../internationalization/LanguageManager.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

void SettingsDock::initializeOnlineScanTab()
{
    // m_onlineScanTab role: Container for the API Key configuration controls of the online scan service.
    onlineScanTab_ = new QWidget(tabWidget_);
    QVBoxLayout* rootLayout = new QVBoxLayout(onlineScanTab_);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(12);

    QLabel* hintLabel = new QLabel(
        QStringLiteral("在线扫描模块会在运行时从本设置读取 API Key。当前右键“上传到沙箱”仅接入 VirusTotal；ThreatBook 暂不显示入口。"),
        onlineScanTab_);
    hintLabel->setWordWrap(true);
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(hintLabel, QStringLiteral("settings.online.hint"), QStringLiteral("在线扫描模块会在运行时从本设置读取 API Key。当前右键“上传到沙箱”仅接入 VirusTotal；ThreatBook 暂不显示入口。"));
    rootLayout->addWidget(hintLabel, 0);

    // keyGroupBox purpose: Groups the two online scan service key input fields.
    QGroupBox* keyGroupBox = new QGroupBox(QStringLiteral("在线扫描 API Key"), onlineScanTab_);
    languageManager.bindText(keyGroupBox, QStringLiteral("settings.online.group"), QStringLiteral("在线扫描 API Key"));
    QFormLayout* formLayout = new QFormLayout(keyGroupBox);
    formLayout->setContentsMargins(10, 10, 10, 10);
    formLayout->setSpacing(8);
    formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

    virusTotalApiKeyEdit_ = new QLineEdit(keyGroupBox);
    virusTotalApiKeyEdit_->setPlaceholderText(QStringLiteral("VirusTotal API Key"));
    virusTotalApiKeyEdit_->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    virusTotalApiKeyEdit_->setClearButtonEnabled(true);
    virusTotalApiKeyEdit_->setToolTip(QStringLiteral("用于 VirusTotal v3 API 的 x-apikey 请求头；留空时上传会提示先配置 Key"));
    languageManager.bindToolTip(virusTotalApiKeyEdit_, QStringLiteral("settings.online.virustotal.tooltip"), QStringLiteral("用于 VirusTotal v3 API 的 x-apikey 请求头；留空时上传会提示先配置 Key"));
    QLabel* virusTotalLabel = new QLabel(QStringLiteral("VirusTotal"), keyGroupBox);
    formLayout->addRow(virusTotalLabel, virusTotalApiKeyEdit_);

    // m_threatBookApiKeyEdit: Stores the API key parameter used for ThreatBook file/upload and file/report operations.
    threatBookApiKeyEdit_ = new QLineEdit(keyGroupBox);
    threatBookApiKeyEdit_->setPlaceholderText(QStringLiteral("ThreatBook / 微步在线 API Key"));
    languageManager.bindPlaceholder(threatBookApiKeyEdit_, QStringLiteral("settings.online.threatbook.placeholder"), QStringLiteral("ThreatBook / 微步在线 API Key"));
    threatBookApiKeyEdit_->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    threatBookApiKeyEdit_->setClearButtonEnabled(true);
    threatBookApiKeyEdit_->setToolTip(QStringLiteral("用于 ThreatBook v3 API 的 apikey 参数；留空时上传会提示先配置 Key"));
    languageManager.bindToolTip(threatBookApiKeyEdit_, QStringLiteral("settings.online.threatbook.tooltip"), QStringLiteral("用于 ThreatBook v3 API 的 apikey 参数；留空时上传会提示先配置 Key"));
    QLabel* threatBookLabel = new QLabel(QStringLiteral("ThreatBook"), keyGroupBox);
    formLayout->addRow(threatBookLabel, threatBookApiKeyEdit_);

    rootLayout->addWidget(keyGroupBox, 0);

    QLabel* storageHintLabel = new QLabel(
        QStringLiteral("提示：API Key 会保存到当前设置 JSON 中，路径与外观设置一致；若不希望保留密钥，可清空后保存。"),
        onlineScanTab_);
    storageHintLabel->setWordWrap(true);
    languageManager.bindText(storageHintLabel, QStringLiteral("settings.online.storage_hint"), QStringLiteral("提示：API Key 会保存到当前设置 JSON 中，路径与外观设置一致；若不希望保留密钥，可清空后保存。"));
    rootLayout->addWidget(storageHintLabel, 0);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->addStretch(1);
    saveOnlineScanKeysButton_ = new QPushButton(QStringLiteral("保存 API Key"), onlineScanTab_);
    languageManager.bindText(saveOnlineScanKeysButton_, QStringLiteral("settings.online.save"), QStringLiteral("保存 API Key"));
    saveOnlineScanKeysButton_->setMinimumWidth(112);
    saveOnlineScanKeysButton_->setFixedHeight(30);
    saveOnlineScanKeysButton_->setToolTip(QStringLiteral("保存 VirusTotal 与 ThreatBook API Key 到设置 JSON"));
    languageManager.bindToolTip(saveOnlineScanKeysButton_, QStringLiteral("settings.online.save.tooltip"), QStringLiteral("保存 VirusTotal 与 ThreatBook API Key 到设置 JSON"));
    saveOnlineScanKeysButton_->setEnabled(false);
    actionLayout->addWidget(saveOnlineScanKeysButton_, 0);
    rootLayout->addLayout(actionLayout);

    rootLayout->addStretch(1);
    tabWidget_->addTab(onlineScanTab_, QStringLiteral("在线扫描"));
    languageManager.bindTab(tabWidget_, onlineScanTab_, QStringLiteral("settings.tab.online_scan"), QStringLiteral("在线扫描"));

    bindOnlineScanSignals();
}

void SettingsDock::bindOnlineScanSignals()
{
    if (virusTotalApiKeyEdit_ != nullptr)
    {
        connect(virusTotalApiKeyEdit_, &QLineEdit::textEdited, this, [this](const QString& /*text*/) {
            markPendingChanges(QStringLiteral("VirusTotal API Key 变化"));
            });
    }

    // Mark as pending save only when the ThreatBook input changes, without writing to disk immediately, to maintain consistency with the application model of the Appearance page.
    if (threatBookApiKeyEdit_ != nullptr)
    {
        connect(threatBookApiKeyEdit_, &QLineEdit::textEdited, this, [this](const QString& /*text*/) {
            markPendingChanges(QStringLiteral("ThreatBook API Key 变化"));
            });
    }

    if (saveOnlineScanKeysButton_ != nullptr)
    {
        connect(saveOnlineScanKeysButton_, &QPushButton::clicked, this, [this]() {
            saveAndEmitFromUi(QStringLiteral("点击在线扫描 API Key 保存按钮"));
            });
    }
}
