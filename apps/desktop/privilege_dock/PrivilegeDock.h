#pragma once

// ============================================================
// PrivilegeDock.h
// Purpose:
// 1) Provide 'Account/privilege' tabs;
// 2) The account page supports local user creation and password reset (including double confirmation);
// 3) The permissions page displays user, group, and current process permission details.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <vector>  // std::vector: Cache for local accounts and permission snapshots.

class QHBoxLayout;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;

class PrivilegeDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent control;
    // - Purpose: initialize the account and permissions page and trigger the first data load.
    explicit PrivilegeDock(QWidget* parent = nullptr);

protected:
    // showEvent：
    // - Refresh account and permission snapshots only upon first display.
    // - Avoid synchronous access to local accounts and privilege information during main window startup.
    void showEvent(QShowEvent* event) override;
    void changeEvent(QEvent* event) override;

private:
    // LocalUserEntry：
    // - Purpose: Cache display fields for the local user table.
    // - name is used for subsequent password reset operations.
    struct LocalUserEntry
    {
        QString name;         // name: Local user name.
        QString fullName;     // fullName: Full name / remark.
        bool disabled = false; // disabled: Whether disabled.
        QString lastLogonText; // lastLogonText: Last logon time text.
    };

    // PermissionSnapshotRow：
    // - Purpose: One row of data in the permissions page list;
    // - type/name/status/detail correspond to the four columns of the list.
    struct PermissionSnapshotRow
    {
        QString type;
        QString name;
        QString status;
        QString detail;
    };

private:
    // ===================== UI Initialization =====================
    void initializeUi();
    void initializeAccountTab();
    void initializePermissionTab();
    void initializeConnections();
    void applyTranslatedHeaders();

    // ===================== Account Functions =====================
    void refreshLocalUserList();
    void refreshLocalUserTable();
    bool createLocalUser(
        const QString& userName,
        const QString& passwordText,
        QString* errorTextOut);
    bool resetLocalUserPassword(
        const QString& userName,
        const QString& newPassword,
        QString* errorTextOut);
    void createUserByInputs();
    void resetPasswordByInputs();

    // ===================== Permission Page Functions =====================
    void refreshPermissionSnapshot();
    void appendLocalUserAndGroupRows(std::vector<PermissionSnapshotRow>* rowsOut) const;
    void appendCurrentProcessPrivilegeRows(std::vector<PermissionSnapshotRow>* rowsOut) const;
    void refreshPermissionTable(const std::vector<PermissionSnapshotRow>& rowList);
    QString fileTimeToDateTimeText(std::uint32_t secondsSince1970) const;
    QString winErrorText(DWORD code) const;

private:
    // Top-level control.
    QVBoxLayout* rootLayout_ = nullptr;  // m_rootLayout: Root layout.
    QTabWidget* tabWidget_ = nullptr;    // m_tabWidget: Account/privilege tab.

    // Account tab.
    QWidget* accountPage_ = nullptr;                // m_accountPage: Account page container.
    QVBoxLayout* accountLayout_ = nullptr;          // m_accountLayout: Account page layout.
    QHBoxLayout* accountToolbarLayout_ = nullptr;   // m_accountToolbarLayout: Account page toolbar layout.
    QPushButton* accountRefreshButton_ = nullptr;   // m_accountRefreshButton: Refresh account button.
    QLabel* accountStatusLabel_ = nullptr;          // m_accountStatusLabel: Account status label.
    QTableWidget* accountTable_ = nullptr;          // m_accountTable: Local user list.
    QLineEdit* createUserNameEdit_ = nullptr;       // m_createUserNameEdit: Input box for creating a new username.
    QLineEdit* createPasswordEdit_ = nullptr;       // m_createPasswordEdit: New password input field.
    QLineEdit* createPasswordConfirmEdit_ = nullptr; // m_createPasswordConfirmEdit: New password confirmation input field.
    QPushButton* createUserButton_ = nullptr;       // m_createUserButton: create user execution button.
    QLineEdit* resetUserNameEdit_ = nullptr;        // m_resetUserNameEdit: Input box for the target user to reset the password.
    QLineEdit* resetPasswordEdit_ = nullptr;        // m_resetPasswordEdit: Password input box after reset.
    QLineEdit* resetPasswordConfirmEdit_ = nullptr; // m_resetPasswordConfirmEdit: Password reset confirmation input field.
    QPushButton* resetPasswordButton_ = nullptr;    // m_resetPasswordButton: Button to execute the reset.

    // privilege page.
    QWidget* permissionPage_ = nullptr;            // m_permissionPage: Permission page container.
    QVBoxLayout* permissionLayout_ = nullptr;      // m_permissionLayout: Permission page layout.
    QHBoxLayout* permissionToolbarLayout_ = nullptr; // m_permissionToolbarLayout: Toolbar layout for the permissions page.
    QPushButton* permissionRefreshButton_ = nullptr; // m_permissionRefreshButton: Button to refresh permissions.
    QLabel* permissionStatusLabel_ = nullptr;      // m_permissionStatusLabel: Status label on the permissions page.
    QTableWidget* permissionTable_ = nullptr;      // m_permissionTable: Permission snapshot list.

    // Cache.
    std::vector<LocalUserEntry> localUserList_;    // m_localUserList: Local user cache.
    bool initialRefreshDone_ = false;              // Whether the first refresh was completed upon initial display.
};
