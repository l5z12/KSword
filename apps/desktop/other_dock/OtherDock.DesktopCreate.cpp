#include "OtherDock.h"
#include "../ui/CodeEditorWidget.h"
#include "../Theme.h"

// ============================================================
// OtherDock.DesktopCreate.cpp
// Purpose:
// 1) Hosts the new desktop dialog and CreateDesktop/CreateDesktopEx calls for the "Desktop Management" page.
// 2) Consolidate detailed parameters such as name, heap size, access mask, inheritance handle, and security descriptor into a dialog for centralized configuration;
// 3) 'Other processes cannot access' is implemented via private DACL + reserved/inherited handle creation to prevent other processes from opening by name.
// ============================================================

#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStringList>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

#ifndef DF_ALLOWOTHERACCOUNTHOOK
#define DF_ALLOWOTHERACCOUNTHOOK 0x0001
#endif

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace
{
    // CreateDesktopExWProc：
    // - Purpose: Dynamically bind CreateDesktopExW to avoid missing declarations caused by old SDK macro conditions.
    // - Returns: A new desktop handle on success; nullptr on failure with GetLastError set.
    using CreateDesktopExWProc = HDESK(WINAPI*)(
        LPCWSTR,
        LPCWSTR,
        DEVMODEW*,
        DWORD,
        ACCESS_MASK,
        LPSECURITY_ATTRIBUTES,
        ULONG,
        PVOID);

    // AccessFlagControl：
    // - Purpose: Bind an access mask bit to a checkbox in the dialog.
    // - Input: mask is DESKTOP_* or standard access rights;
    // - Output: collectDesiredAccess synthesizes the final dwDesiredAccess based on the checked state.
    struct AccessFlagControl
    {
        QCheckBox* checkBox = nullptr;      // checkBox: parameter switch in the popup dialog.
        ACCESS_MASK mask = 0;               // mask: Corresponding Win32 access mask.
        QString nameText;                   // nameText: Permission name displayed in the summary.
    };

    // SecurityDescriptorHolder：
    // - Purpose: Ensure that SECURITY_DESCRIPTOR, ACL, and LocalFree remain valid during the CreateDesktop call.
    // - Input: Populated by buildSecurityDescriptorHolder in default/private/SDDL modes;
    // - Output: descriptor() returns a pointer suitable for passing to SECURITY_ATTRIBUTES.
    struct SecurityDescriptorHolder
    {
        SECURITY_DESCRIPTOR descriptorStorage{}; // descriptorStorage: Absolute security descriptor in private DACL mode.
        bool descriptorInitialized = false;       // descriptorInitialized: Indicates whether descriptorStorage has been initialized.
        std::vector<BYTE> aclBuffer;              // aclBuffer: private DACL memory.
        PSECURITY_DESCRIPTOR localDescriptor = nullptr; // localDescriptor: descriptor allocated by SDDL API.

        ~SecurityDescriptorHolder()
        {
            if (localDescriptor != nullptr)
            {
                ::LocalFree(localDescriptor);
            }
        }

        PSECURITY_DESCRIPTOR descriptor() const
        {
            if (localDescriptor != nullptr)
            {
                return localDescriptor;
            }
            if (descriptorInitialized)
            {
                return const_cast<SECURITY_DESCRIPTOR*>(&descriptorStorage);
            }
            return nullptr;
        }
    };

    // queryUserObjectNameForCreateDialog：
    // - Purpose: Read the current window station name for displaying the 'Create Target' dialog.
    // - Input: Win32 user object handle;
    // - Output: returns the object name on success, or an empty string on failure.
    QString queryUserObjectNameForCreateDialog(HANDLE userObjectHandle)
    {
        if (userObjectHandle == nullptr)
        {
            return QString();
        }

        DWORD requiredBytes = 0;
        ::GetUserObjectInformationW(userObjectHandle, UOI_NAME, nullptr, 0, &requiredBytes);
        if (requiredBytes < sizeof(wchar_t))
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(requiredBytes / sizeof(wchar_t) + 1, L'\0');
        const BOOL kQueryOk = ::GetUserObjectInformationW(
            userObjectHandle,
            UOI_NAME,
            nameBuffer.data(),
            static_cast<DWORD>(nameBuffer.size() * sizeof(wchar_t)),
            &requiredBytes);
        return kQueryOk != FALSE
            ? QString::fromWCharArray(nameBuffer.data()).trimmed()
            : QString();
    }

    // desktopCreateInputStyle：
    // - Purpose: Apply the same blue border style used in the main interface to the popup input box.
    // - Inputs: None;
    // - Output: Qt stylesheet string.
    QString desktopCreateInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox,QPlainTextEdit{"
            "  border:1px solid %1;"
            "  border-radius:3px;"
            "  background:%2;"
            "  color:%3;"
            "  padding:3px 6px;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // desktopCreateDefaultAccess：
    // - Purpose: Provide the default desktop access mask suitable for UI creation, switching, and querying.
    // - Inputs: None;
    // - Output: combination of DESKTOP_* and standard access rights.
    ACCESS_MASK desktopCreateDefaultAccess()
    {
        return DESKTOP_CREATEWINDOW
            | DESKTOP_CREATEMENU
            | DESKTOP_ENUMERATE
            | DESKTOP_HOOKCONTROL
            | DESKTOP_READOBJECTS
            | DESKTOP_SWITCHDESKTOP
            | DESKTOP_WRITEOBJECTS
            | READ_CONTROL
            | WRITE_DAC;
    }

    // collectDesiredAccess：
    // - Purpose: Collect dwDesiredAccess from permission checkboxes.
    // - Input: accessControls contains all permission items from the dialog.
    // - Output: Final access mask, automatically supplemented with READOBJECTS/WRITEOBJECTS if necessary.
    ACCESS_MASK collectDesiredAccess(const std::vector<AccessFlagControl>& accessControls)
    {
        ACCESS_MASK desiredAccess = 0;
        for (const AccessFlagControl& control : accessControls)
        {
            if (control.checkBox != nullptr && control.checkBox->isChecked())
            {
                desiredAccess |= control.mask;
            }
        }

        const bool kStandardSecurityRequested =
            (desiredAccess & (READ_CONTROL | WRITE_DAC | WRITE_OWNER)) != 0;
        if (kStandardSecurityRequested)
        {
            desiredAccess |= DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS;
        }
        return desiredAccess;
    }

    // accessMaskToText：
    // - Purpose: Convert the access mask to a hexadecimal value and a list of permission names.
    // - Input: accessControls used to reverse-lookup checked names;
    // - Output: Human-readable text for the popup summary and logs.
    QString accessMaskToText(
        const ACCESS_MASK desiredAccess,
        const std::vector<AccessFlagControl>& accessControls)
    {
        QStringList nameList;
        for (const AccessFlagControl& control : accessControls)
        {
            if ((desiredAccess & control.mask) != 0)
            {
                nameList << control.nameText;
            }
        }
        return QStringLiteral("0x%1 (%2)")
            .arg(static_cast<qulonglong>(desiredAccess), 8, 16, QChar('0'))
            .arg(nameList.isEmpty() ? QStringLiteral("无") : nameList.join(QStringLiteral(" | ")))
            .toUpper();
    }

    // buildPrivateDenyAllDescriptor：
    // - Purpose: Construct an 'empty DACL' security descriptor to prevent other processes from reopening the desktop by name via OpenDesktopW.
    // - Input: holder is used to store SECURITY_DESCRIPTOR and ACL memory;
    // - Output: Returns true on success; returns false on failure and populates errorText.
    bool buildPrivateDenyAllDescriptor(SecurityDescriptorHolder& holder, QString& errorText)
    {
        holder.aclBuffer.resize(sizeof(ACL));

        PSECURITY_DESCRIPTOR descriptor = &holder.descriptorStorage;
        PACL privateAcl = reinterpret_cast<PACL>(holder.aclBuffer.data());
        if (::InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) == FALSE)
        {
            errorText = QStringLiteral("InitializeSecurityDescriptor 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        holder.descriptorInitialized = true;
        if (::InitializeAcl(privateAcl, static_cast<DWORD>(holder.aclBuffer.size()), ACL_REVISION) == FALSE)
        {
            errorText = QStringLiteral("InitializeAcl 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        if (::SetSecurityDescriptorDacl(descriptor, TRUE, privateAcl, FALSE) == FALSE)
        {
            errorText = QStringLiteral("SetSecurityDescriptorDacl 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        return true;
    }

    // buildSddlDescriptor：
    // - Purpose: Convert user-provided SDDL to a SECURITY_DESCRIPTOR;
    // - Input: sddlText is the custom security descriptor from the dialog;
    // - Output: Returns true on success; holder.localDescriptor is responsible for LocalFree.
    bool buildSddlDescriptor(
        const QString& sddlText,
        SecurityDescriptorHolder& holder,
        QString& errorText)
    {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const BOOL kConvertOk = ::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            reinterpret_cast<LPCWSTR>(sddlText.utf16()),
            SDDL_REVISION_1,
            &descriptor,
            nullptr);
        if (kConvertOk == FALSE || descriptor == nullptr)
        {
            errorText = QStringLiteral("SDDL 转换失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        holder.localDescriptor = descriptor;
        return true;
    }

    // loadCreateDesktopExW：
    // - Purpose: Dynamically retrieve CreateDesktopExW from user32.dll;
    // - Inputs: None;
    // - Output: Function pointer; returns nullptr if the system does not support it.
    CreateDesktopExWProc loadCreateDesktopExW()
    {
        HMODULE user32Module = ::GetModuleHandleW(L"user32.dll");
        if (user32Module == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<CreateDesktopExWProc>(
            ::GetProcAddress(user32Module, "CreateDesktopExW"));
    }

    // createDesktopWithParameters：
    // - Purpose: Call CreateDesktopW or CreateDesktopExW based on dialog parameters;
    // - Input: desktopName, flags, access, securityAttributes, heapSizeKb.
    // - Output: Returns HDESK on success; returns nullptr on failure and populates errorCodeOut.
    HDESK createDesktopWithParameters(
        const QString& desktopName,
        const DWORD flags,
        const ACCESS_MASK desiredAccess,
        SECURITY_ATTRIBUTES* securityAttributes,
        const DWORD heapSizeKb,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (heapSizeKb > 0)
        {
            CreateDesktopExWProc createDesktopExW = loadCreateDesktopExW();
            if (createDesktopExW == nullptr)
            {
                errorCodeOut = ERROR_PROC_NOT_FOUND;
                return nullptr;
            }
            HDESK desktopHandle = createDesktopExW(
                reinterpret_cast<LPCWSTR>(desktopName.utf16()),
                nullptr,
                nullptr,
                flags,
                desiredAccess,
                securityAttributes,
                heapSizeKb,
                nullptr);
            errorCodeOut = desktopHandle != nullptr ? ERROR_SUCCESS : ::GetLastError();
            return desktopHandle;
        }

        HDESK desktopHandle = ::CreateDesktopW(
            reinterpret_cast<LPCWSTR>(desktopName.utf16()),
            nullptr,
            nullptr,
            flags,
            desiredAccess,
            securityAttributes);
        errorCodeOut = desktopHandle != nullptr ? ERROR_SUCCESS : ::GetLastError();
        return desktopHandle;
    }
}

void OtherDock::showCreateDesktopDialog()
{
    KLogEvent dialogEvent;
    info << dialogEvent << "[OtherDock] 打开新建桌面参数弹窗。" << eol;

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("新建桌面 - 参数设置"));
    dialog.setMinimumWidth(760);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
    QLabel* introLabel = new QLabel(
        QStringLiteral("创建目标为当前进程窗口站；详细参数会直接传入 CreateDesktopW/CreateDesktopExW。"),
        &dialog);
    introLabel->setWordWrap(true);
    rootLayout->addWidget(introLabel);

    QGroupBox* basicGroup = new QGroupBox(QStringLiteral("基础参数"), &dialog);
    QFormLayout* basicLayout = new QFormLayout(basicGroup);
    QLineEdit* desktopNameEdit = new QLineEdit(
        QStringLiteral("KswordDesktop_%1").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        basicGroup);
    QLineEdit* windowStationEdit = new QLineEdit(
        queryUserObjectNameForCreateDialog(::GetProcessWindowStation()),
        basicGroup);
    QSpinBox* heapSizeSpin = new QSpinBox(basicGroup);
    QCheckBox* allowOtherAccountHookCheck = new QCheckBox(QStringLiteral("DF_ALLOWOTHERACCOUNTHOOK"), basicGroup);
    desktopNameEdit->setStyleSheet(desktopCreateInputStyle());
    windowStationEdit->setReadOnly(true);
    windowStationEdit->setStyleSheet(desktopCreateInputStyle());
    heapSizeSpin->setRange(0, 262144);
    heapSizeSpin->setSuffix(QStringLiteral(" KB"));
    heapSizeSpin->setSpecialValueText(QStringLiteral("默认"));
    heapSizeSpin->setToolTip(QStringLiteral("该桌面可用的界面内存上限，窗口很多时可调大；填 0 表示使用系统默认值"));
    allowOtherAccountHookCheck->setToolTip(QStringLiteral("允许其它用户帐户的程序在该桌面上设置钩子；出于安全考虑通常不勾选"));
    heapSizeSpin->setStyleSheet(desktopCreateInputStyle());
    basicLayout->addRow(QStringLiteral("桌面名称"), desktopNameEdit);
    basicLayout->addRow(QStringLiteral("目标窗口站"), windowStationEdit);
    basicLayout->addRow(QStringLiteral("桌面堆大小"), heapSizeSpin);
    basicLayout->addRow(QStringLiteral("创建标志"), allowOtherAccountHookCheck);
    rootLayout->addWidget(basicGroup);

    QGroupBox* accessGroup = new QGroupBox(QStringLiteral("访问掩码（dwDesiredAccess）"), &dialog);
    QGridLayout* accessLayout = new QGridLayout(accessGroup);
    std::vector<AccessFlagControl> accessControls;
    const std::array<std::pair<const char*, ACCESS_MASK>, 12> kAccessDefinitions = { {
        { "DESKTOP_CREATEWINDOW", DESKTOP_CREATEWINDOW },
        { "DESKTOP_CREATEMENU", DESKTOP_CREATEMENU },
        { "DESKTOP_ENUMERATE", DESKTOP_ENUMERATE },
        { "DESKTOP_HOOKCONTROL", DESKTOP_HOOKCONTROL },
        { "DESKTOP_JOURNALPLAYBACK", DESKTOP_JOURNALPLAYBACK },
        { "DESKTOP_JOURNALRECORD", DESKTOP_JOURNALRECORD },
        { "DESKTOP_READOBJECTS", DESKTOP_READOBJECTS },
        { "DESKTOP_SWITCHDESKTOP", DESKTOP_SWITCHDESKTOP },
        { "DESKTOP_WRITEOBJECTS", DESKTOP_WRITEOBJECTS },
        { "READ_CONTROL", READ_CONTROL },
        { "WRITE_DAC", WRITE_DAC },
        { "WRITE_OWNER", WRITE_OWNER }
    } };
    const ACCESS_MASK kDefaultAccess = desktopCreateDefaultAccess();
    for (int i = 0; i < static_cast<int>(kAccessDefinitions.size()); ++i)
    {
        QCheckBox* checkBox = new QCheckBox(QString::fromLatin1(kAccessDefinitions[i].first), accessGroup);
        checkBox->setChecked((kDefaultAccess & kAccessDefinitions[i].second) != 0);
        accessLayout->addWidget(checkBox, i / 3, i % 3);
        accessControls.push_back(AccessFlagControl{ checkBox, kAccessDefinitions[i].second, checkBox->text() });
    }
    rootLayout->addWidget(accessGroup);

    QGroupBox* securityGroup = new QGroupBox(QStringLiteral("安全与继承"), &dialog);
    QVBoxLayout* securityLayout = new QVBoxLayout(securityGroup);
    QCheckBox* privateAccessCheck = new QCheckBox(QStringLiteral("其他进程不可访问（仅当前进程和继承句柄的子进程可访问）"), securityGroup);
    QCheckBox* inheritableHandleCheck = new QCheckBox(QStringLiteral("返回句柄可继承"), securityGroup);
    QCheckBox* keepHandleCheck = new QCheckBox(QStringLiteral("创建后在本进程保留桌面句柄"), securityGroup);
    QCheckBox* switchAfterCreateCheck = new QCheckBox(QStringLiteral("创建成功后立即切换到该桌面"), securityGroup);
    QCheckBox* customSddlCheck = new QCheckBox(QStringLiteral("使用自定义 SDDL 安全描述符"), securityGroup);
    privateAccessCheck->setToolTip(QStringLiteral("限制只有本程序及其子进程能使用该桌面，其它程序无法访问"));
    inheritableHandleCheck->setToolTip(QStringLiteral("允许本程序启动的子进程继承这个桌面句柄"));
    keepHandleCheck->setToolTip(QStringLiteral("创建后不关闭句柄，保持桌面存在；取消勾选则桌面可能在无人使用时被系统回收"));
    switchAfterCreateCheck->setToolTip(QStringLiteral("创建完成后立刻切换过去（切换后原桌面窗口会暂时看不到）"));
    customSddlCheck->setToolTip(QStringLiteral("改用下方手写的 SDDL 字符串精确指定谁能访问该桌面，而不使用上面的勾选项"));
    QPlainTextEdit* sddlEdit = new QPlainTextEdit(securityGroup);
    privateAccessCheck->setToolTip(QStringLiteral("使用空 DACL 阻止其它进程按名称打开；当前进程使用创建返回句柄，子进程需要继承该句柄。"));
    inheritableHandleCheck->setChecked(true);
    keepHandleCheck->setChecked(true);
    sddlEdit->setPlaceholderText(QStringLiteral("示例：D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"));
    sddlEdit->setEnabled(false);
    sddlEdit->setFixedHeight(58);
    sddlEdit->setStyleSheet(desktopCreateInputStyle());
    securityLayout->addWidget(privateAccessCheck);
    securityLayout->addWidget(inheritableHandleCheck);
    securityLayout->addWidget(keepHandleCheck);
    securityLayout->addWidget(switchAfterCreateCheck);
    securityLayout->addWidget(customSddlCheck);
    securityLayout->addWidget(sddlEdit);
    rootLayout->addWidget(securityGroup);

    // Parameter summary is generated by this page based on control state; using a unified editor to support immediate repainting in English mode.
    CodeEditorWidget* summaryEdit = new CodeEditorWidget(&dialog);
    summaryEdit->setReadOnly(true);
    summaryEdit->setFixedHeight(164);
    rootLayout->addWidget(summaryEdit);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("创建"));
    buttonBox->button(QDialogButtonBox::Ok)->setIcon(QIcon(":/Icon/desktop_create.svg"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    rootLayout->addWidget(buttonBox);

    std::function<void()> updateSummary = [&]() {
        const ACCESS_MASK kDesiredAccess = collectDesiredAccess(accessControls);
        const DWORD kFlags = allowOtherAccountHookCheck->isChecked() ? DF_ALLOWOTHERACCOUNTHOOK : 0;
        QStringList lines;
        lines << QStringLiteral("桌面：%1\\%2").arg(windowStationEdit->text(), desktopNameEdit->text().trimmed());
        lines << QStringLiteral("堆大小：%1").arg(heapSizeSpin->value() == 0 ? QStringLiteral("系统默认") : heapSizeSpin->text());
        lines << QStringLiteral("创建标志：0x%1").arg(static_cast<qulonglong>(kFlags), 8, 16, QChar('0')).toUpper();
        lines << QStringLiteral("访问掩码：%1").arg(accessMaskToText(kDesiredAccess, accessControls));
        lines << QStringLiteral("安全模式：%1").arg(privateAccessCheck->isChecked()
            ? QStringLiteral("私有空 DACL，外部进程不能按名称 OpenDesktopW")
            : (customSddlCheck->isChecked() ? QStringLiteral("自定义 SDDL") : QStringLiteral("默认 Token DACL")));
        lines << QStringLiteral("句柄策略：继承=%1；保留=%2；创建后切换=%3")
            .arg(inheritableHandleCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(keepHandleCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(switchAfterCreateCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"));
        summaryEdit->setLocalizedText(lines.join('\n'));
    };

    auto syncSecurityOptions = [&]() {
        const bool kPrivateMode = privateAccessCheck->isChecked();
        inheritableHandleCheck->setChecked(kPrivateMode ? true : inheritableHandleCheck->isChecked());
        keepHandleCheck->setChecked(kPrivateMode ? true : keepHandleCheck->isChecked());
        inheritableHandleCheck->setEnabled(!kPrivateMode);
        keepHandleCheck->setEnabled(!kPrivateMode);
        customSddlCheck->setEnabled(!kPrivateMode);
        sddlEdit->setEnabled(!kPrivateMode && customSddlCheck->isChecked());
        updateSummary();
    };

    for (const AccessFlagControl& control : accessControls)
    {
        QObject::connect(control.checkBox, &QCheckBox::toggled, &dialog, [&](bool) {
            updateSummary();
        });
    }
    QObject::connect(desktopNameEdit, &QLineEdit::textChanged, &dialog, [&](const QString&) {
        updateSummary();
    });
    QObject::connect(heapSizeSpin, QOverload<int>::of(&QSpinBox::valueChanged), &dialog, [&](int) {
        updateSummary();
    });
    QObject::connect(allowOtherAccountHookCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(privateAccessCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        syncSecurityOptions();
    });
    QObject::connect(inheritableHandleCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(keepHandleCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(switchAfterCreateCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(customSddlCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        syncSecurityOptions();
    });
    QObject::connect(sddlEdit, &QPlainTextEdit::textChanged, &dialog, [&]() {
        updateSummary();
    });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dialog, [&]() {
        const QString kDesktopName = desktopNameEdit->text().trimmed();
        if (kDesktopName.isEmpty() || kDesktopName.contains(QChar('\\')) || kDesktopName.contains(QChar('/')))
        {
            QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), QStringLiteral("桌面名称不能为空，也不能包含路径分隔符。"));
            return;
        }

        SecurityDescriptorHolder securityHolder;
        QString securityErrorText;
        if (privateAccessCheck->isChecked())
        {
            if (!buildPrivateDenyAllDescriptor(securityHolder, securityErrorText))
            {
                QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), securityErrorText);
                return;
            }
        }
        else if (customSddlCheck->isChecked())
        {
            if (!buildSddlDescriptor(sddlEdit->toPlainText().trimmed(), securityHolder, securityErrorText))
            {
                QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), securityErrorText);
                return;
            }
        }

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = privateAccessCheck->isChecked() || inheritableHandleCheck->isChecked();
        securityAttributes.lpSecurityDescriptor = securityHolder.descriptor();

        const DWORD kCreateFlags = allowOtherAccountHookCheck->isChecked() ? DF_ALLOWOTHERACCOUNTHOOK : 0;
        const ACCESS_MASK kDesiredAccess = collectDesiredAccess(accessControls);
        DWORD createErrorCode = ERROR_SUCCESS;
        HDESK desktopHandle = createDesktopWithParameters(
            kDesktopName,
            kCreateFlags,
            kDesiredAccess,
            &securityAttributes,
            static_cast<DWORD>(heapSizeSpin->value()),
            createErrorCode);
        if (desktopHandle == nullptr)
        {
            err << dialogEvent
                << "[OtherDock] 新建桌面失败, desktop="
                << kDesktopName.toStdString()
                << ", code="
                << createErrorCode
                << eol;
            QMessageBox::warning(
                &dialog,
                QStringLiteral("新建桌面"),
                QStringLiteral("CreateDesktop 失败，错误码=%1。").arg(createErrorCode));
            return;
        }

        // Explicitly synchronize the handle inheritance flag to the returned handle again to avoid differences in how different API paths handle SECURITY_ATTRIBUTES.
        const BOOL kInheritHandleFlag = privateAccessCheck->isChecked() || inheritableHandleCheck->isChecked();
        if (::SetHandleInformation(
            desktopHandle,
            HANDLE_FLAG_INHERIT,
            kInheritHandleFlag ? HANDLE_FLAG_INHERIT : 0) == FALSE)
        {
            warn << dialogEvent
                << "[OtherDock] 新建桌面后设置句柄继承位失败, desktop="
                << kDesktopName.toStdString()
                << ", code="
                << ::GetLastError()
                << eol;
        }

        const bool kShouldKeepHandle = privateAccessCheck->isChecked() || keepHandleCheck->isChecked();
        if (kShouldKeepHandle)
        {
            CreatedDesktopRecord record;
            record.windowStationName = windowStationEdit->text().trimmed();
            record.desktopName = kDesktopName;
            record.desktopHandle = desktopHandle;
            record.desiredAccess = kDesiredAccess;
            record.privateAccess = privateAccessCheck->isChecked();
            record.inheritableHandle = kInheritHandleFlag != FALSE;
            createdDesktopHandles_.push_back(record);
        }

        bool switched = false;
        DWORD switchErrorCode = ERROR_SUCCESS;
        if (switchAfterCreateCheck->isChecked())
        {
            switched = ::SwitchDesktop(desktopHandle) != FALSE;
            switchErrorCode = switched ? ERROR_SUCCESS : ::GetLastError();
        }
        if (!kShouldKeepHandle)
        {
            ::CloseDesktop(desktopHandle);
        }

        const QString kStatusText = QStringLiteral("新建桌面成功：%1\\%2；私有=%3；保留句柄=%4%5")
            .arg(windowStationEdit->text().trimmed(), kDesktopName)
            .arg(privateAccessCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(kShouldKeepHandle ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(switchAfterCreateCheck->isChecked()
                ? QStringLiteral("；切换=%1").arg(switched ? QStringLiteral("成功") : QStringLiteral("失败:%1").arg(switchErrorCode))
                : QString());
        if (desktopStatusLabel_ != nullptr)
        {
            desktopStatusLabel_->setText(kStatusText);
        }

        info << dialogEvent
            << "[OtherDock] 新建桌面成功, desktop="
            << kDesktopName.toStdString()
            << ", desiredAccess="
            << static_cast<unsigned long>(kDesiredAccess)
            << ", privateAccess="
            << (privateAccessCheck->isChecked() ? 1 : 0)
            << ", keepHandle="
            << (kShouldKeepHandle ? 1 : 0)
            << eol;
        refreshDesktopList();
        dialog.accept();
    });

    syncSecurityOptions();
    dialog.exec();
}
