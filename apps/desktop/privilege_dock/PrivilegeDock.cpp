#include "PrivilegeDock.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../internationalization/LanguageManager.h"
#include "../framework/PrivilegeElevationPrompt.h"

// ============================================================
// PrivilegeDock.cpp
// Purpose:
// 1) Implement local account management (create users, reset passwords);
// 2) enumerate user/group/current process permissions for audit purposes.
// 3) All sensitive operations require secondary confirmation and are logged.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QEvent>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPushButton>
#include <QPointer>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Lm.h>

#pragma comment(lib, "Netapi32.lib")

namespace
{
    QString privilegeText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    std::string privilegeLogText(const char* const key, const QString& sourceText)
    {
        return privilegeText(key, sourceText).toStdString();
    }

    // blueButtonStyle:
    // - Unify button styles to ensure the privilege page's visual appearance matches other Dock panels.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // blueInputStyle:
    // - Unify the border and focus highlight style of input fields.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // tableHeaderStyle:
    // - Unified account table header style to ensure readability in both light and dark modes.
    QString tableHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // boolText:
    // - Convert boolean states uniformly to Chinese text 'Yes/No'.
    QString boolText(const bool value)
    {
        return value
            ? privilegeText("privilege.bool.yes", QStringLiteral("是"))
            : privilegeText("privilege.bool.no", QStringLiteral("否"));
    }

    QString privilegeTableMenuStyle()
    {
        // Inputs: None.
        // Processing: Generate opaque menu styles to ensure account/privilege table right-click menus remain readable in both light and dark themes.
        // Returns: QMenu stylesheet text.
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:%6;}"
            "QMenu::item:disabled{color:%5;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::textSecondaryHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    void copyPrivilegeTableCurrentRow(QTableWidget* table)
    {
        // Input: Account table or privilege table.
        // Processing: Read all columns of the currently displayed row and copy to clipboard as TSV.
        // Return: No return value; no action if table/clipboard unavailable or no current row.
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join(QChar('\t')));
    }

    void installPrivilegeTableCopyMenu(QTableWidget* table)
    {
        // Input: The account/privilege table containing the capabilities of the current row to be copied.
        // Handling: Install a read-only right-click menu; select the corresponding cell when right-clicking a row.
        // Returns: void; does not trigger account creation, password reset, or privilege adjustment.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition) {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(privilegeTableMenuStyle());
            QAction* copyRowAction = menu.addAction(privilegeText(
                "privilege.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyPrivilegeTableCurrentRow(table);
            }
        });
    }
}

PrivilegeDock::PrivilegeDock(QWidget* parent)
    : QWidget(parent)
{
    KLogEvent event;
    info << event
        << privilegeLogText("privilege.log.construct.start", QStringLiteral("[PrivilegeDock] 构造开始。"))
        << eol;

    initializeUi();
    initializeConnections();

    info << event
        << privilegeLogText("privilege.log.construct.completed", QStringLiteral("[PrivilegeDock] 构造完成。"))
        << eol;
}

void PrivilegeDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (initialRefreshDone_)
    {
        return;
    }

    initialRefreshDone_ = true;
    if (accountStatusLabel_ != nullptr)
    {
        accountStatusLabel_->setText(privilegeText(
            "privilege.account.status.first_load",
            QStringLiteral("状态：首次打开，正在加载账号列表...")));
    }
    if (permissionStatusLabel_ != nullptr)
    {
        permissionStatusLabel_->setText(privilegeText(
            "privilege.permission.status.first_load",
            QStringLiteral("状态：首次打开，正在加载权限快照...")));
    }

    QTimer::singleShot(0, this, [this]()
        {
            refreshLocalUserList();
            refreshPermissionSnapshot();
        });
}

void PrivilegeDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    applyTranslatedHeaders();
    refreshLocalUserTable();
    refreshPermissionSnapshot();
}

void PrivilegeDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    tabWidget_ = new QTabWidget(this);
    tabWidget_->setTabPosition(QTabWidget::West);
    rootLayout_->addWidget(tabWidget_, 1);

    initializeAccountTab();
    initializePermissionTab();
}

void PrivilegeDock::initializeAccountTab()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    accountPage_ = new QWidget(tabWidget_);
    accountLayout_ = new QVBoxLayout(accountPage_);
    accountLayout_->setContentsMargins(4, 4, 4, 4);
    accountLayout_->setSpacing(6);

    accountToolbarLayout_ = new QHBoxLayout();
    accountToolbarLayout_->setContentsMargins(0, 0, 0, 0);
    accountToolbarLayout_->setSpacing(6);

    accountRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), accountPage_);
    languageManager.bindToolTip(
        accountRefreshButton_,
        QStringLiteral("privilege.account.refresh.tooltip"),
        QStringLiteral("刷新本地账号列表"));
    accountRefreshButton_->setStyleSheet(blueButtonStyle());
    accountRefreshButton_->setFixedWidth(34);

    accountStatusLabel_ = new QLabel(privilegeText(
        "privilege.account.status.pending", QStringLiteral("状态：待刷新")), accountPage_);
    accountToolbarLayout_->addWidget(accountRefreshButton_, 0);
    accountToolbarLayout_->addWidget(accountStatusLabel_, 1);
    accountLayout_->addLayout(accountToolbarLayout_, 0);

    accountTable_ = new ks::ui::VisibleTableWidget(accountPage_);
    accountTable_->setColumnCount(4);
    applyTranslatedHeaders();
    accountTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    accountTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    accountTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    accountTable_->horizontalHeader()->setStyleSheet(tableHeaderStyle());
    accountTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    accountTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    accountTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    accountTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    installPrivilegeTableCopyMenu(accountTable_);
    accountLayout_->addWidget(accountTable_, 1);

    // New user input area: includes username, password, and password confirmation.
    QFormLayout* createLayout = new QFormLayout();
    createUserNameEdit_ = new QLineEdit(accountPage_);
    createPasswordEdit_ = new QLineEdit(accountPage_);
    createPasswordConfirmEdit_ = new QLineEdit(accountPage_);
    createPasswordEdit_->setEchoMode(QLineEdit::Password);
    createPasswordConfirmEdit_->setEchoMode(QLineEdit::Password);
    languageManager.bindPlaceholder(
        createUserNameEdit_,
        QStringLiteral("privilege.account.create.username.placeholder"),
        QStringLiteral("输入新用户名"));
    languageManager.bindPlaceholder(
        createPasswordEdit_,
        QStringLiteral("privilege.account.create.password.placeholder"),
        QStringLiteral("输入密码"));
    languageManager.bindPlaceholder(
        createPasswordConfirmEdit_,
        QStringLiteral("privilege.account.create.confirm_password.placeholder"),
        QStringLiteral("再次输入密码"));
    createUserNameEdit_->setStyleSheet(blueInputStyle());
    createPasswordEdit_->setStyleSheet(blueInputStyle());
    createPasswordConfirmEdit_->setStyleSheet(blueInputStyle());
    QLabel* createUserLabel = new QLabel(QStringLiteral("新用户"), accountPage_);
    QLabel* createPasswordLabel = new QLabel(QStringLiteral("密码"), accountPage_);
    QLabel* createConfirmPasswordLabel = new QLabel(QStringLiteral("确认密码"), accountPage_);
    languageManager.bindText(createUserLabel, QStringLiteral("privilege.account.create.username.label"), QStringLiteral("新用户"));
    languageManager.bindText(createPasswordLabel, QStringLiteral("privilege.account.create.password.label"), QStringLiteral("密码"));
    languageManager.bindText(createConfirmPasswordLabel, QStringLiteral("privilege.account.create.confirm_password.label"), QStringLiteral("确认密码"));
    createLayout->addRow(createUserLabel, createUserNameEdit_);
    createLayout->addRow(createPasswordLabel, createPasswordEdit_);
    createLayout->addRow(createConfirmPasswordLabel, createPasswordConfirmEdit_);
    accountLayout_->addLayout(createLayout, 0);

    createUserButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), accountPage_);
    languageManager.bindToolTip(
        createUserButton_,
        QStringLiteral("privilege.account.create.tooltip"),
        QStringLiteral("创建本地用户（会弹出二次确认）"));
    createUserButton_->setStyleSheet(blueButtonStyle());
    createUserButton_->setFixedWidth(34);
    accountLayout_->addWidget(createUserButton_, 0, Qt::AlignLeft);

    // Password reset input area: supports specifying an account and confirming the password.
    QFormLayout* resetLayout = new QFormLayout();
    resetUserNameEdit_ = new QLineEdit(accountPage_);
    resetPasswordEdit_ = new QLineEdit(accountPage_);
    resetPasswordConfirmEdit_ = new QLineEdit(accountPage_);
    resetPasswordEdit_->setEchoMode(QLineEdit::Password);
    resetPasswordConfirmEdit_->setEchoMode(QLineEdit::Password);
    languageManager.bindPlaceholder(
        resetUserNameEdit_,
        QStringLiteral("privilege.account.reset.username.placeholder"),
        QStringLiteral("输入要重置密码的用户名"));
    languageManager.bindPlaceholder(
        resetPasswordEdit_,
        QStringLiteral("privilege.account.reset.password.placeholder"),
        QStringLiteral("输入新密码"));
    languageManager.bindPlaceholder(
        resetPasswordConfirmEdit_,
        QStringLiteral("privilege.account.reset.confirm_password.placeholder"),
        QStringLiteral("再次输入新密码"));
    resetUserNameEdit_->setStyleSheet(blueInputStyle());
    resetPasswordEdit_->setStyleSheet(blueInputStyle());
    resetPasswordConfirmEdit_->setStyleSheet(blueInputStyle());
    QLabel* resetUserLabel = new QLabel(QStringLiteral("目标用户"), accountPage_);
    QLabel* resetPasswordLabel = new QLabel(QStringLiteral("新密码"), accountPage_);
    QLabel* resetConfirmPasswordLabel = new QLabel(QStringLiteral("确认新密码"), accountPage_);
    languageManager.bindText(resetUserLabel, QStringLiteral("privilege.account.reset.username.label"), QStringLiteral("目标用户"));
    languageManager.bindText(resetPasswordLabel, QStringLiteral("privilege.account.reset.password.label"), QStringLiteral("新密码"));
    languageManager.bindText(resetConfirmPasswordLabel, QStringLiteral("privilege.account.reset.confirm_password.label"), QStringLiteral("确认新密码"));
    resetLayout->addRow(resetUserLabel, resetUserNameEdit_);
    resetLayout->addRow(resetPasswordLabel, resetPasswordEdit_);
    resetLayout->addRow(resetConfirmPasswordLabel, resetPasswordConfirmEdit_);
    accountLayout_->addLayout(resetLayout, 0);

    resetPasswordButton_ = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), accountPage_);
    languageManager.bindToolTip(
        resetPasswordButton_,
        QStringLiteral("privilege.account.reset.tooltip"),
        QStringLiteral("重置用户密码（会弹出二次确认）"));
    resetPasswordButton_->setStyleSheet(blueButtonStyle());
    resetPasswordButton_->setFixedWidth(34);
    accountLayout_->addWidget(resetPasswordButton_, 0, Qt::AlignLeft);

    tabWidget_->addTab(accountPage_, QStringLiteral("账号"));
    languageManager.bindTab(
        tabWidget_,
        accountPage_,
        QStringLiteral("privilege.tab.accounts"),
        QStringLiteral("账号"));
}

void PrivilegeDock::initializePermissionTab()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    permissionPage_ = new QWidget(tabWidget_);
    permissionLayout_ = new QVBoxLayout(permissionPage_);
    permissionLayout_->setContentsMargins(4, 4, 4, 4);
    permissionLayout_->setSpacing(6);

    permissionToolbarLayout_ = new QHBoxLayout();
    permissionToolbarLayout_->setContentsMargins(0, 0, 0, 0);
    permissionToolbarLayout_->setSpacing(6);

    permissionRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), permissionPage_);
    languageManager.bindToolTip(
        permissionRefreshButton_,
        QStringLiteral("privilege.permission.refresh.tooltip"),
        QStringLiteral("刷新用户/组/权限快照"));
    permissionRefreshButton_->setStyleSheet(blueButtonStyle());
    permissionRefreshButton_->setFixedWidth(34);

    permissionStatusLabel_ = new QLabel(privilegeText(
        "privilege.permission.status.pending", QStringLiteral("状态：待刷新")), permissionPage_);
    permissionToolbarLayout_->addWidget(permissionRefreshButton_, 0);
    permissionToolbarLayout_->addWidget(permissionStatusLabel_, 1);
    permissionLayout_->addLayout(permissionToolbarLayout_, 0);

    permissionTable_ = new ks::ui::VisibleTableWidget(permissionPage_);
    permissionTable_->setColumnCount(4);
    applyTranslatedHeaders();
    permissionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    permissionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    permissionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    permissionTable_->setWordWrap(false);
    permissionTable_->horizontalHeader()->setStyleSheet(tableHeaderStyle());
    permissionTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    permissionTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    permissionTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    permissionTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    installPrivilegeTableCopyMenu(permissionTable_);
    permissionLayout_->addWidget(permissionTable_, 1);

    tabWidget_->addTab(permissionPage_, QStringLiteral("权限"));
    languageManager.bindTab(
        tabWidget_,
        permissionPage_,
        QStringLiteral("privilege.tab.permissions"),
        QStringLiteral("权限"));
}

void PrivilegeDock::applyTranslatedHeaders()
{
    if (accountTable_ != nullptr)
    {
        accountTable_->setHorizontalHeaderLabels({
            privilegeText("privilege.account.header.username", QStringLiteral("用户名")),
            privilegeText("privilege.account.header.full_name", QStringLiteral("全名")),
            privilegeText("privilege.account.header.disabled", QStringLiteral("已禁用")),
            privilegeText("privilege.account.header.last_logon", QStringLiteral("最后登录"))
            });
    }
    if (permissionTable_ != nullptr)
    {
        permissionTable_->setHorizontalHeaderLabels({
            privilegeText("privilege.permission.header.type", QStringLiteral("类型")),
            privilegeText("privilege.permission.header.name", QStringLiteral("名称")),
            privilegeText("privilege.permission.header.status", QStringLiteral("状态")),
            privilegeText("privilege.permission.header.detail", QStringLiteral("详情"))
            });
    }
}

void PrivilegeDock::initializeConnections()
{
    connect(accountRefreshButton_, &QPushButton::clicked, this, [this]() {
        refreshLocalUserList();
    });
    connect(permissionRefreshButton_, &QPushButton::clicked, this, [this]() {
        refreshPermissionSnapshot();
    });
    connect(createUserButton_, &QPushButton::clicked, this, [this]() {
        createUserByInputs();
    });
    connect(resetPasswordButton_, &QPushButton::clicked, this, [this]() {
        resetPasswordByInputs();
    });
    connect(accountTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const int kRow = accountTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(localUserList_.size()))
        {
            return;
        }
        resetUserNameEdit_->setText(localUserList_[static_cast<std::size_t>(kRow)].name);
    });
}

void PrivilegeDock::refreshLocalUserList()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-local-user-refresh"),
            {accountTable_, permissionTable_},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshLocalUserList();
                }
            }))
    {
        return;
    }

    // accountEvent reuses the entire refresh log chain.
    KLogEvent accountEvent;
    info << accountEvent
        << privilegeLogText(
            "privilege.log.refresh_users.start",
            QStringLiteral("[PrivilegeDock] 开始刷新本地用户列表。"))
        << eol;

    localUserList_.clear();

    DWORD level = 2;
    DWORD preferedLength = MAX_PREFERRED_LENGTH;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    LPUSER_INFO_2 userInfo = nullptr;

    const NET_API_STATUS kEnumStatus = ::NetUserEnum(
        nullptr,
        level,
        FILTER_NORMAL_ACCOUNT,
        reinterpret_cast<LPBYTE*>(&userInfo),
        preferedLength,
        &entriesRead,
        &totalEntries,
        &resumeHandle);
    if (kEnumStatus != NERR_Success && kEnumStatus != ERROR_MORE_DATA)
    {
        const QString kErrorText = winErrorText(kEnumStatus);
        err << accountEvent
            << privilegeLogText(
                "privilege.log.refresh_users.failed",
                QStringLiteral("[PrivilegeDock] 刷新用户失败, status="))
            << kEnumStatus
            << ", error="
            << kErrorText.toStdString()
            << eol;
        accountStatusLabel_->setText(privilegeText(
            "privilege.account.status.refresh_failed",
            QStringLiteral("状态：刷新失败 - %1")).arg(kErrorText));
        if (userInfo != nullptr)
        {
            ::NetApiBufferFree(userInfo);
        }
        refreshLocalUserTable();
        return;
    }

    for (DWORD index = 0; index < entriesRead; ++index)
    {
        const USER_INFO_2& infoData = userInfo[index];
        LocalUserEntry entry;
        entry.name = infoData.usri2_name != nullptr
            ? QString::fromWCharArray(infoData.usri2_name)
            : QStringLiteral("<null>");
        entry.fullName = infoData.usri2_full_name != nullptr
            ? QString::fromWCharArray(infoData.usri2_full_name)
            : QString();
        entry.disabled = (infoData.usri2_flags & UF_ACCOUNTDISABLE) != 0;
        entry.lastLogonText = fileTimeToDateTimeText(infoData.usri2_last_logon);
        localUserList_.push_back(entry);
    }

    if (userInfo != nullptr)
    {
        ::NetApiBufferFree(userInfo);
    }

    refreshLocalUserTable();
    accountStatusLabel_->setText(privilegeText(
        "privilege.account.status.loaded",
        QStringLiteral("状态：已加载 %1 / %2 个账号"))
        .arg(entriesRead)
        .arg(totalEntries));

    info << accountEvent
        << privilegeLogText(
            "privilege.log.refresh_users.completed",
            QStringLiteral("[PrivilegeDock] 用户列表刷新完成, entriesRead="))
        << entriesRead
        << ", totalEntries="
        << totalEntries
        << eol;
}

void PrivilegeDock::refreshLocalUserTable()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-local-user-table-rebuild"),
            {accountTable_},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshLocalUserTable();
                }
            }))
    {
        return;
    }

    accountTable_->setRowCount(static_cast<int>(localUserList_.size()));
    for (int row = 0; row < static_cast<int>(localUserList_.size()); ++row)
    {
        const LocalUserEntry& entry = localUserList_[static_cast<std::size_t>(row)];
        accountTable_->setItem(row, 0, new QTableWidgetItem(entry.name));
        accountTable_->setItem(row, 1, new QTableWidgetItem(entry.fullName));
        accountTable_->setItem(row, 2, new QTableWidgetItem(boolText(entry.disabled)));
        accountTable_->setItem(row, 3, new QTableWidgetItem(entry.lastLogonText));
    }
}

bool PrivilegeDock::createLocalUser(
    const QString& userName,
    const QString& passwordText,
    QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::wstring userNameW = userName.toStdWString();
    std::wstring passwordW = passwordText.toStdWString();

    USER_INFO_1 userInfo{};
    userInfo.usri1_name = const_cast<wchar_t*>(userNameW.c_str());
    userInfo.usri1_password = const_cast<wchar_t*>(passwordW.c_str());
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_flags = UF_SCRIPT;

    DWORD paramError = 0;
    const NET_API_STATUS kStatus = ::NetUserAdd(
        nullptr,
        1,
        reinterpret_cast<LPBYTE>(&userInfo),
        &paramError);
    if (kStatus != NERR_Success)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = privilegeText(
                "privilege.error.net_user_add",
                QStringLiteral("NetUserAdd失败: %1, 参数索引=%2"))
                .arg(winErrorText(kStatus))
                .arg(paramError);
        }
        return false;
    }
    return true;
}

bool PrivilegeDock::resetLocalUserPassword(
    const QString& userName,
    const QString& newPassword,
    QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::wstring passwordW = newPassword.toStdWString();
    USER_INFO_1003 userInfo{};
    userInfo.usri1003_password = const_cast<wchar_t*>(passwordW.c_str());

    const NET_API_STATUS kStatus = ::NetUserSetInfo(
        nullptr,
        reinterpret_cast<LPCWSTR>(userName.utf16()),
        1003,
        reinterpret_cast<LPBYTE>(&userInfo),
        nullptr);
    if (kStatus != NERR_Success)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = privilegeText(
                "privilege.error.net_user_set_info",
                QStringLiteral("NetUserSetInfo失败: %1")).arg(winErrorText(kStatus));
        }
        return false;
    }
    return true;
}

void PrivilegeDock::createUserByInputs()
{
    const QString kUserName = createUserNameEdit_->text().trimmed();
    const QString kPassword = createPasswordEdit_->text();
    const QString kConfirmPassword = createPasswordConfirmEdit_->text();

    if (kUserName.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.username_empty", QStringLiteral("用户名不能为空。")));
        return;
    }
    if (kPassword.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.password_empty", QStringLiteral("密码不能为空。")));
        return;
    }
    if (kPassword != kConfirmPassword)
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.password_mismatch", QStringLiteral("两次密码输入不一致。")));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("创建本地用户"));
        return;
    }

    // Secondary confirmation: prevent accidental system account creation.
    const int kConfirm = QMessageBox::question(
        this,
        privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
        privilegeText(
            "privilege.dialog.create.confirm",
            QStringLiteral("确定创建本地用户“%1”吗？")).arg(kUserName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirm != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    info << actionEvent
        << privilegeLogText(
            "privilege.log.create_user.request",
            QStringLiteral("[PrivilegeDock] 创建用户请求, user="))
        << kUserName.toStdString()
        << eol;

    QString errorText;
    if (!createLocalUser(kUserName, kPassword, &errorText))
    {
        err << actionEvent
            << privilegeLogText(
                "privilege.log.create_user.failed",
                QStringLiteral("[PrivilegeDock] 创建用户失败, user="))
            << kUserName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        // privilegePromptHandled: Skips the old creation failure popup if the privilege recovery prompt has already been shown.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("创建本地用户"),
            errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
                errorText);
        }
        return;
    }

    info << actionEvent
        << privilegeLogText(
            "privilege.log.create_user.succeeded",
            QStringLiteral("[PrivilegeDock] 创建用户成功, user="))
        << kUserName.toStdString()
        << eol;
    QMessageBox::information(
        this,
        privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
        privilegeText("privilege.dialog.create.succeeded", QStringLiteral("创建成功。")));
    refreshLocalUserList();
    refreshPermissionSnapshot();
}

void PrivilegeDock::resetPasswordByInputs()
{
    const QString kUserName = resetUserNameEdit_->text().trimmed();
    const QString kPassword = resetPasswordEdit_->text();
    const QString kConfirmPassword = resetPasswordConfirmEdit_->text();

    if (kUserName.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.username_empty", QStringLiteral("目标用户名不能为空。")));
        return;
    }
    if (kPassword.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.password_empty", QStringLiteral("新密码不能为空。")));
        return;
    }
    if (kPassword != kConfirmPassword)
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.password_mismatch", QStringLiteral("两次密码输入不一致。")));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("重置本地用户密码"));
        return;
    }

    const int kConfirm = QMessageBox::question(
        this,
        privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
        privilegeText(
            "privilege.dialog.reset.confirm",
            QStringLiteral("确定为“%1”重置密码吗？")).arg(kUserName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirm != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    info << actionEvent
        << privilegeLogText(
            "privilege.log.reset_password.request",
            QStringLiteral("[PrivilegeDock] 重置密码请求, user="))
        << kUserName.toStdString()
        << eol;

    QString errorText;
    if (!resetLocalUserPassword(kUserName, kPassword, &errorText))
    {
        err << actionEvent
            << privilegeLogText(
                "privilege.log.reset_password.failed",
                QStringLiteral("[PrivilegeDock] 重置密码失败, user="))
            << kUserName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        // privilegePromptHandled: Skips the old reset failure popup if the privilege recovery prompt has already been shown.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("重置本地用户密码"),
            errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
                errorText);
        }
        return;
    }

    info << actionEvent
        << privilegeLogText(
            "privilege.log.reset_password.succeeded",
            QStringLiteral("[PrivilegeDock] 重置密码成功, user="))
        << kUserName.toStdString()
        << eol;
    QMessageBox::information(
        this,
        privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
        privilegeText("privilege.dialog.reset.succeeded", QStringLiteral("重置成功。")));
}

void PrivilegeDock::refreshPermissionSnapshot()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-permission-snapshot-refresh"),
            {accountTable_, permissionTable_},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshPermissionSnapshot();
                }
            }))
    {
        return;
    }

    KLogEvent event;
    info << event
        << privilegeLogText(
            "privilege.log.refresh_privileges.start",
            QStringLiteral("[PrivilegeDock] 开始刷新权限快照。"))
        << eol;

    std::vector<PermissionSnapshotRow> rowList;
    appendLocalUserAndGroupRows(&rowList);
    appendCurrentProcessPrivilegeRows(&rowList);
    refreshPermissionTable(rowList);

    permissionStatusLabel_->setText(privilegeText(
        "privilege.permission.status.completed",
        QStringLiteral("状态：%1 刷新完成，共 %2 项"))
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(static_cast<int>(rowList.size())));

    info << event
        << privilegeLogText(
            "privilege.log.refresh_privileges.completed",
            QStringLiteral("[PrivilegeDock] 权限快照刷新完成, rows="))
        << rowList.size()
        << eol;
}

void PrivilegeDock::appendLocalUserAndGroupRows(std::vector<PermissionSnapshotRow>* rowsOut) const
{
    if (rowsOut == nullptr)
    {
        return;
    }

    // Write to the local user cache first.
    for (const LocalUserEntry& entry : localUserList_)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.user", QStringLiteral("用户"));
        row.name = entry.name;
        row.status = privilegeText(
            "privilege.row.user.status",
            QStringLiteral("禁用:%1  最后登录:%2"))
            .arg(boolText(entry.disabled))
            .arg(entry.lastLogonText);
        row.detail = entry.fullName.isEmpty()
            ? privilegeText("privilege.row.no_full_name", QStringLiteral("<无全名>"))
            : privilegeText("privilege.row.full_name", QStringLiteral("全名:%1")).arg(entry.fullName);
        rowsOut->push_back(row);
    }

    // enumerate local groups again.
    LPLOCALGROUP_INFO_1 groupInfo = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0; // totalEntries: Reserved for future pagination expansion.
    DWORD_PTR resumeHandle = 0;
    const NET_API_STATUS kStatus = ::NetLocalGroupEnum(
        nullptr,
        1,
        reinterpret_cast<LPBYTE*>(&groupInfo),
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resumeHandle);
    if (kStatus == NERR_Success || kStatus == ERROR_MORE_DATA)
    {
        for (DWORD index = 0; index < entriesRead; ++index)
        {
            const LOCALGROUP_INFO_1& group = groupInfo[index];
            const QString kGroupName = group.lgrpi1_name != nullptr
                ? QString::fromWCharArray(group.lgrpi1_name)
                : QStringLiteral("<null>");
            const QString kGroupComment = group.lgrpi1_comment != nullptr
                ? QString::fromWCharArray(group.lgrpi1_comment)
                : QString();
            PermissionSnapshotRow row;
            row.type = privilegeText("privilege.row.type.group", QStringLiteral("组"));
            row.name = kGroupName;
            row.status = privilegeText("privilege.row.group.local", QStringLiteral("本地组"));
            row.detail = kGroupComment.isEmpty()
                ? privilegeText("privilege.row.no_description", QStringLiteral("<无说明>"))
                : kGroupComment;
            rowsOut->push_back(row);
        }
    }
    else
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.group", QStringLiteral("组"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = winErrorText(kStatus);
        rowsOut->push_back(row);
    }

    if (groupInfo != nullptr)
    {
        ::NetApiBufferFree(groupInfo);
    }
}

void PrivilegeDock::appendCurrentProcessPrivilegeRows(std::vector<PermissionSnapshotRow>* rowsOut) const
{
    if (rowsOut == nullptr)
    {
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.open_process_token",
            QStringLiteral("OpenProcessToken失败: %1")).arg(winErrorText(::GetLastError()));
        rowsOut->push_back(row);
        return;
    }

    DWORD bytesNeeded = 0;
    ::GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.get_token_information",
            QStringLiteral("GetTokenInformation失败: %1")).arg(winErrorText(::GetLastError()));
        rowsOut->push_back(row);
        ::CloseHandle(tokenHandle);
        return;
    }

    std::vector<unsigned char> tokenBuffer(bytesNeeded, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenPrivileges,
        tokenBuffer.data(),
        bytesNeeded,
        &bytesNeeded) == FALSE)
    {
        const QString kErrorText = winErrorText(::GetLastError());
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.get_token_information",
            QStringLiteral("GetTokenInformation失败: %1")).arg(kErrorText);
        rowsOut->push_back(row);
        ::CloseHandle(tokenHandle);
        return;
    }

    TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenBuffer.data());
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
    {
        const LUID_AND_ATTRIBUTES& privilege = privileges->Privileges[index];
        wchar_t nameBuffer[256] = {};
        DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
        QString privilegeName = privilegeText(
            "privilege.row.lookup_privilege_name_failed",
            QStringLiteral("<LookupPrivilegeName失败>"));
        if (::LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&privilege.Luid), nameBuffer, &nameLength) != FALSE)
        {
            privilegeName = QString::fromWCharArray(nameBuffer, static_cast<int>(nameLength));
        }

        wchar_t displayNameBuffer[512] = {};
        DWORD displayNameLength = static_cast<DWORD>(std::size(displayNameBuffer));
        DWORD languageId = 0;
        QString displayName = privilegeText("privilege.row.no_display_name", QStringLiteral("<无显示名>"));
        if (::LookupPrivilegeDisplayNameW(
            nullptr,
            reinterpret_cast<LPCWSTR>(privilegeName.utf16()),
            displayNameBuffer,
            &displayNameLength,
            &languageId) != FALSE)
        {
            Q_UNUSED(languageId);
            displayName = QString::fromWCharArray(displayNameBuffer, static_cast<int>(displayNameLength));
        }

        const bool kEnabled = (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        const bool kEnabledByDefault = (privilege.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        const bool kRemoved = (privilege.Attributes & SE_PRIVILEGE_REMOVED) != 0;

        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeName;
        row.status = privilegeText(
            "privilege.row.process_privilege.status",
            QStringLiteral("启用:%1 默认:%2 移除:%3"))
            .arg(boolText(kEnabled))
            .arg(boolText(kEnabledByDefault))
            .arg(boolText(kRemoved));
        row.detail = QStringLiteral("%1, Attributes=0x%2")
            .arg(displayName)
            .arg(QString::number(privilege.Attributes, 16).toUpper());
        rowsOut->push_back(row);
    }

    if (privileges->PrivilegeCount == 0)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.empty", QStringLiteral("<空>"));
        row.status = privilegeText("privilege.row.no_privileges", QStringLiteral("无权限项"));
        row.detail = privilegeText(
            "privilege.row.no_privileges.detail",
            QStringLiteral("当前进程令牌未返回任何权限条目。"));
        rowsOut->push_back(row);
    }

    ::CloseHandle(tokenHandle);
}

void PrivilegeDock::refreshPermissionTable(const std::vector<PermissionSnapshotRow>& rowList)
{
    if (permissionTable_ == nullptr)
    {
        return;
    }

    permissionTable_->setRowCount(static_cast<int>(rowList.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(rowList.size()); ++rowIndex)
    {
        const PermissionSnapshotRow& rowData = rowList[static_cast<std::size_t>(rowIndex)];
        permissionTable_->setItem(rowIndex, 0, new QTableWidgetItem(rowData.type));
        permissionTable_->setItem(rowIndex, 1, new QTableWidgetItem(rowData.name));
        permissionTable_->setItem(rowIndex, 2, new QTableWidgetItem(rowData.status));
        permissionTable_->setItem(rowIndex, 3, new QTableWidgetItem(rowData.detail));
    }
}

QString PrivilegeDock::fileTimeToDateTimeText(const std::uint32_t secondsSince1970) const
{
    if (secondsSince1970 == 0)
    {
        return privilegeText("privilege.time.never", QStringLiteral("从未"));
    }
    return QDateTime::fromSecsSinceEpoch(secondsSince1970).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString PrivilegeDock::winErrorText(const DWORD code) const
{
    wchar_t* messageBuffer = nullptr;
    const DWORD kMessageLength = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        0,
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        nullptr);
    QString messageText;
    if (kMessageLength > 0 && messageBuffer != nullptr)
    {
        messageText = QString::fromWCharArray(messageBuffer).trimmed();
        ::LocalFree(messageBuffer);
    }
    if (messageText.isEmpty())
    {
        return privilegeText("privilege.error.code", QStringLiteral("错误码 %1")).arg(code);
    }
    return QStringLiteral("%1 (code=%2)").arg(messageText).arg(code);
}
