#pragma once

#include <QCoreApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <windows.h>
#include <shellapi.h>

#include "../internationalization/LanguageManager.h"

namespace ks::ui
{
    inline bool isPrivilegeRequiredError(const unsigned long errorCode)
    {
        return errorCode == ERROR_ACCESS_DENIED ||
            errorCode == ERROR_PRIVILEGE_NOT_HELD ||
            errorCode == ERROR_ELEVATION_REQUIRED ||
            errorCode == ERROR_NOT_ALL_ASSIGNED;
    }

    inline bool isCurrentProcessElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        TOKEN_ELEVATION elevation{};
        DWORD returnedBytes = 0;
        const BOOL kQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &returnedBytes);
        ::CloseHandle(tokenHandle);
        return kQueryOk != FALSE && elevation.TokenIsElevated != 0;
    }

    inline QString quoteWindowsArgument(const QString& argument)
    {
        QString quoted = argument;
        quoted.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(quoted);
    }

    // requestAdministratorRestartForFeature：
    // - Call when a feature explicitly requires administrator privileges but the current instance has not yet been elevated.
    // - Explains to the user the current feature and restart impact; upon confirmation, restarts the entire KSword application with runas.
    // - Returns false; the caller should immediately stop the current feature, allowing the user to retry in an administrator instance.
    inline bool requestAdministratorRestartForFeature(
        QWidget* const parent,
        const QString& featureName)
    {
        if (isCurrentProcessElevated())
        {
            return true;
        }

        QMessageBox prompt(parent);
        prompt.setIcon(QMessageBox::Information);
        prompt.setWindowTitle(ks::i18n::text(
            QStringLiteral("privilege.admin_required.title"),
            QStringLiteral("需要管理员权限")));
        prompt.setText(ks::i18n::text(
            QStringLiteral("privilege.admin_required.message"),
            QStringLiteral("“%1”需要管理员权限。\n\n是否以管理员身份重新启动 Ksword？")).arg(featureName));
        prompt.setInformativeText(ks::i18n::text(
            QStringLiteral("privilege.admin_required.hint"),
            QStringLiteral("确认 Windows UAC 后，当前实例会退出；请在新实例中重试该功能。")));
        QPushButton* const kElevateButton = prompt.addButton(
            ks::i18n::text(
                QStringLiteral("privilege.admin_required.elevate"),
                QStringLiteral("以管理员身份重启")),
            QMessageBox::AcceptRole);
        prompt.addButton(
            ks::i18n::text(QStringLiteral("privilege.admin_required.cancel"), QStringLiteral("取消")),
            QMessageBox::RejectRole);
        prompt.exec();
        if (prompt.clickedButton() != kElevateButton)
        {
            return false;
        }

        const QStringList kArgumentList = QCoreApplication::arguments();
        QStringList parameterList;
        for (int index = 1; index < kArgumentList.size(); ++index)
        {
            parameterList.push_back(quoteWindowsArgument(kArgumentList.at(index)));
        }
        if (!parameterList.contains(QStringLiteral("\"--ksword-privilege-restart\""), Qt::CaseInsensitive))
        {
            parameterList.push_back(QStringLiteral("--ksword-privilege-restart"));
        }

        const std::wstring kExecutablePath = QCoreApplication::applicationFilePath().toStdWString();
        const std::wstring kParameterText = parameterList.join(QLatin1Char(' ')).toStdWString();
        const HINSTANCE kResult = ::ShellExecuteW(
            parent != nullptr ? reinterpret_cast<HWND>(parent->winId()) : nullptr,
            L"runas",
            kExecutablePath.c_str(),
            kParameterText.empty() ? nullptr : kParameterText.c_str(),
            nullptr,
            SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(kResult) <= 32)
        {
            QMessageBox::warning(
                parent,
                ks::i18n::text(
                    QStringLiteral("privilege.admin_required.restart_failed.title"),
                    QStringLiteral("管理员重启失败")),
                ks::i18n::text(
                    QStringLiteral("privilege.admin_required.restart_failed.message"),
                    QStringLiteral("管理员重启未启动，可能被取消或被系统策略阻止。")));
            return false;
        }

        QCoreApplication::quit();
        return false;
    }

    // promptForPrivilegeFailure：
    // - Unifies errors indicating 'insufficient privileges discovered after feature execution' into feature-level privilege elevation prompts.
    // - Returns false if already an administrator, allowing the caller to continue displaying the original error without masking driver/object-specific denials.
    inline bool promptForPrivilegeFailure(
        QWidget* const parent,
        const QString& featureName,
        const unsigned long errorCode)
    {
        if (!isPrivilegeRequiredError(errorCode) || isCurrentProcessElevated())
        {
            return false;
        }
        (void)requestAdministratorRestartForFeature(parent, featureName);
        return true;
    }

    inline bool promptForPrivilegeFailure(
        QWidget* const parent,
        const QString& featureName,
        const QString& errorText)
    {
        const QString kNormalized = errorText.trimmed();
        if (isCurrentProcessElevated() ||
            !(kNormalized.contains(QStringLiteral("access is denied"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("拒绝访问"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("权限不足"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("error=5"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("win32=5"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("0x80070005"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("0x80320005"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("0x00000005"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("code=5"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("错误码=5"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("错误码：5"), Qt::CaseInsensitive) ||
                kNormalized.contains(QStringLiteral("错误码 5"), Qt::CaseInsensitive)))
        {
            return false;
        }
        (void)requestAdministratorRestartForFeature(parent, featureName);
        return true;
    }

    inline bool promptForPrivilegeNtStatus(
        QWidget* const parent,
        const QString& featureName,
        const long statusValue)
    {
        const unsigned long kStatus = static_cast<unsigned long>(statusValue);
        if (isCurrentProcessElevated() ||
            (kStatus != 0xC0000022UL && // STATUS_ACCESS_DENIED
                kStatus != 0xC0000061UL && // STATUS_PRIVILEGE_NOT_HELD
                kStatus != 0xC000042CUL)) // STATUS_INVALID_IMAGE_HASH/elevation policy denial
        {
            return false;
        }
        (void)requestAdministratorRestartForFeature(parent, featureName);
        return true;
    }
}
