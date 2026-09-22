#include "MainWindow.h"
#include "framework/PrivilegeElevationPrompt.h"
#include "internationalization/LanguageManager.h"
#include "memory_dock/MemoryAccessBackend.h"

#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QCheckBox>
#include <QWidget>
#include <QHBoxLayout>
#include <QPushButton>
#include <QMessageBox>
#include <QStringList>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "include/ads/DockAreaTitleBar.h"
#include "include/ads/DockAreaWidget.h"
#include "ui/DockTabInteraction.h"
#include "Theme.h"
#include "../../shared/platform/process/Process.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>
#include <TlHelp32.h>

#include "MainWindow.NativeFrameSupport.h"
#include "MainWindow.Win32PrivilegesSupport.h"

namespace ksword::ui::main_window
{
    // buildPrivilegeButtonStyle:
    // - Generate button style based on whether privileges are currently held;
    // - true -> blue background with white text
    // - false -> white background with blue text.
    QString buildPrivilegeButtonStyle(const bool activeState)
    {
        const QString kBackgroundColor = activeState
            ? ksword_theme::kPrimaryBlueHex
            : ksword_theme::surfaceHex();
        // In the inactive state, use a neutral background with accent-colored text. PrimaryBlueHex cannot be used directly here:
        // When users set the accent color to bright yellow or bright green, it becomes nearly invisible on light-colored surfaces.
        // accentTextColor preserves hue and adjusts brightness until it meets Surface contrast requirements.
        const QString kTextColor = activeState
            ? ksword_theme::onAccentHex()
            : (ksword_theme::isDarkModeEnabled()
                ? ksword_theme::textPrimaryHex()
                : ksword_theme::accentButtonTextHex());
        const QString kHoverColor = activeState
            ? ksword_theme::primaryBlueSolidHoverHex()
            : ksword_theme::primaryBlueSolidHoverHex();
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%6;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%5;"
            "  color:%6;"
            "}")
            .arg(kBackgroundColor)
            .arg(kTextColor)
            .arg(ksword_theme::kPrimaryBlueBorderHex)
            .arg(kHoverColor)
            .arg(ksword_theme::kPrimaryBluePressedHex)
            .arg(ksword_theme::onAccentHex());
    }

    // buildR0ButtonStyle:
    // - R0-specific style;
    // - true -> Blue background, font color automatically black/white based on light/dark theme;
    // - false -> blue text on black/white background.
    QString buildR0ButtonStyle(const bool activeState)
    {
        const QString kAdaptiveTextColor = ksword_theme::onAccentHex();
        const QString kBackgroundColor = activeState
            ? ksword_theme::kPrimaryBlueHex
            : ksword_theme::surfaceHex();
        // Same as above: non-active state accent text must be calibrated against the Surface first; otherwise, high-brightness accent text will blur over the background.
        const QString kTextColor = activeState
            ? kAdaptiveTextColor
            : ksword_theme::accentButtonTextHex();
        const QString kHoverColor = activeState
            ? ksword_theme::primaryBlueSolidHoverHex()
            : ksword_theme::primaryBlueSubtleHex();
        const QString kPressedColor = activeState
            ? ksword_theme::kPrimaryBluePressedHex
            : ksword_theme::themeColorName(ksword_theme::primaryBlueSurfacePressedColor());
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%5;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%6;"
            "  color:%5;"
            "}")
            .arg(kBackgroundColor)
            .arg(kTextColor)
            .arg(ksword_theme::kPrimaryBlueBorderHex)
            .arg(kHoverColor)
            .arg(activeState ? kAdaptiveTextColor : ksword_theme::textPrimaryColorHex())
            .arg(kPressedColor);
    }
}

using namespace ksword::ui::main_window;

void MainWindow::initPrivilegeStatusButtons()
{
    // Prevent duplicate initialization: If the container already exists, refresh its status only once.
    if (privilegeButtonContainer_ != nullptr)
    {
        refreshPrivilegeStatusButtons();
        return;
    }

    // The privilege status group is attached to the right side of the main function tab bar after the dock layout is restored; during initialization, it is managed by the main window.
    privilegeButtonContainer_ = new QWidget(this);
    QHBoxLayout* buttonLayout = new QHBoxLayout(privilegeButtonContainer_);
    buttonLayout->setContentsMargins(0, 0, 4, 0);
    buttonLayout->setSpacing(6);

    // Button text uses plain characters to meet user requirements; UIAccess is placed on the far left to toggle TokenUIAccess fallback.
    uiAccessStatusButton_ = new QPushButton("UIAccess", privilegeButtonContainer_);
    adminStatusButton_ = new QPushButton("Admin", privilegeButtonContainer_);
    debugStatusButton_ = new QPushButton("Debug", privilegeButtonContainer_);
    systemStatusButton_ = new QPushButton("System", privilegeButtonContainer_);
    r0StatusButton_ = new QPushButton("R0", privilegeButtonContainer_);
    // KVM is positioned to the right of R0: it is one layer lower (hypervisor / R-1) and depends on R0.
    kvmStatusButton_ = new QPushButton("KVM", privilegeButtonContainer_);
    // DDMA is placed to the right of R-1. It is not a lower privilege ring but another access path bypassing the
    // CPU (device-side DMA). Placing it at the end of this row signifies 'less constrained by the CPU than R-1'.
    ddmaStatusButton_ = new QPushButton("DDMA", privilegeButtonContainer_);

    // Unify button sizes to ensure a neat top-right layout.
    const std::array<QPushButton*, 7> kStatusButtons{
        uiAccessStatusButton_,
        adminStatusButton_,
        debugStatusButton_,
        systemStatusButton_,
        r0StatusButton_,
        kvmStatusButton_,
        ddmaStatusButton_
    };
    for (QPushButton* statusButton : kStatusButtons)
    {
        if (statusButton == nullptr)
        {
            continue;
        }
        statusButton->setFixedHeight(22);
        statusButton->setMinimumWidth(56);
        buttonLayout->addWidget(statusButton);
    }
    if (uiAccessStatusButton_ != nullptr)
    {
        uiAccessStatusButton_->setMinimumWidth(74);
    }

    // Tooltip for the privilege status button: These buttons serve as both 'status indicators' and 'quick actions'; each explains its meaning and click behavior.
    uiAccessStatusButton_->setToolTip(QStringLiteral("UIAccess：跨权限窗口置顶能力状态。点击后重启程序并尝试启用/关闭该能力。"));
    adminStatusButton_->setToolTip(QStringLiteral("Admin：当前是否以管理员权限运行。非管理员时点击会以管理员身份重启程序。"));
    debugStatusButton_->setToolTip(QStringLiteral("Debug：调试特权（SeDebugPrivilege）状态，用于访问受保护进程。点击申请该特权（需要管理员）。"));
    systemStatusButton_->setToolTip(QStringLiteral("System：当前是否以 LocalSystem 系统账户运行。点击查看当前身份说明。"));
    r0StatusButton_->setToolTip(QStringLiteral("R0：KswordARK 内核驱动服务状态。点击启动或停止驱动（内核功能都依赖它）。"));
    kvmStatusButton_->setToolTip(QStringLiteral("KVM：KSwordVM 硬件虚拟化（R-1）常驻状态。左键启动或停止常驻，右键打开 R-1 能力菜单。"));
    // The right-click menu carries capabilities unsuitable for single-click, such as write permission toggles and maintaining self-checks.
    kvmStatusButton_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(kvmStatusButton_, &QPushButton::customContextMenuRequested,
        this, [this](const QPoint& position) {
            if (kvmStatusButton_ != nullptr)
            {
                showKvmMenu(kvmStatusButton_->mapToGlobal(position));
            }
        });
    connect(kvmStatusButton_, &QPushButton::clicked, this, [this]() {
        handleKvmStatusButtonClicked();
    });

    // DDMA indicator light: lit means a resident virtual sector is registered. Clicking navigates to the DDMA sub-page of the memory page because
    // registering a resident sector requires selecting a disk, filling a temporary LBA, and confirming overwrite, which cannot be done in a single click.
    ddmaStatusButton_->setToolTip(QStringLiteral(
        "DDMA：磁盘直接内存访问的常驻虚扇区状态。亮起代表磁盘上有一块扇区正被登记为 DMA 中转站。点击打开内存页的 DDMA 子页进行配置或解除。"));
    connect(ddmaStatusButton_, &QPushButton::clicked, this, [this]() {
        handleDdmaStatusButtonClicked();
    });

    // UIAccess button:
    // - If the current instance already has UIAccess, downgrade to a standard user instance.
    // - If UIAccess is absent, elevate as needed and try starting with the SYSTEM TokenUIAccess fallback.
    connect(uiAccessStatusButton_, &QPushButton::clicked, this, [this]() {
        handleUiAccessButtonClicked();
    });

    // Admin button:
    // - Already has admin privileges: only display the current status.
    // - If not an administrator, immediately trigger a runas restart to elevate privileges.
    connect(adminStatusButton_, &QPushButton::clicked, this, [this]() {
        if (hasAdminPrivilege())
        {
            QMessageBox::information(this, "Admin", "当前已是管理员权限。");
            refreshPrivilegeStatusButtons();
            return;
        }

        KLogEvent logEvent;
        warn << logEvent << "[MainWindow] Admin 按钮触发提权重启。" << eol;
        requestAdminElevationRestart();
    });

    // Debug button:
    // - If not an administrator: perform the Admin privilege elevation action as needed first;
    // - If administrator: request SeDebugPrivilege.
    connect(debugStatusButton_, &QPushButton::clicked, this, [this]() {
        if (!hasAdminPrivilege())
        {
            KLogEvent logEvent;
            warn << logEvent << "[MainWindow] Debug 按钮检测到非管理员，转为执行 Admin 提权。" << eol;
            requestAdminElevationRestart();
            return;
        }

        std::string errorText;
        const bool kEnableOk = enableSeDebugPrivilege(errorText);
        if (kEnableOk)
        {
            KLogEvent logEvent;
            info << logEvent << "[MainWindow] SeDebugPrivilege 申请成功。" << eol;
            QMessageBox::information(this, "Debug", "SeDebugPrivilege 已启用。");
        }
        else
        {
            KLogEvent logEvent;
            err << logEvent << "[MainWindow] SeDebugPrivilege 申请失败: " << errorText << eol;
            // privilegePromptHandled: Suppress the old Debug failure dialog when the privilege recovery prompt has been displayed.
            const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("启用 SeDebugPrivilege"),
                QString::fromStdString(errorText));
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    "Debug",
                    QString("SeDebugPrivilege 启用失败。\n%1").arg(QString::fromStdString(errorText)));
            }
        }
        refreshPrivilegeStatusButtons();
    });

    // The System button only displays status; clicking it shows a prompt (user-mode processes cannot directly switch to SYSTEM).
    connect(systemStatusButton_, &QPushButton::clicked, this, [this]() {
        if (hasSystemPrivilege())
        {
            QMessageBox::information(this, "System", "当前进程已经是 LocalSystem 身份。");
        }
        else
        {
            HANDLE hToken = NULL;          // Current process token handle.
            LUID luid;                     // privilege locally unique identifier.
            TOKEN_PRIVILEGES tp;           // Token privileges structure.

            // Open the current process token, requiring privilege adjustment and permission query.
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            {
                KLogEvent logEvent;
                err << logEvent << "OpenProcessToken failed, error: " << GetLastError() << eol;
                return 1;
            }

            // Looks up the LUID for the SE_DEBUG_NAME privilege.
            if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
            {
                KLogEvent logEvent;
                err << logEvent << "LookupPrivilegeValue failed, error: " << GetLastError() << eol;
                CloseHandle(hToken);
                return 1;
            }

            // Set the privilege attribute to enabled.
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // Adjust token privileges.
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            {
                KLogEvent logEvent;
                err << logEvent << "AdjustTokenPrivileges failed, error: " << GetLastError() << eol;
                CloseHandle(hToken);
                return 1;
            }
            // Verify that privileges are truly enabled (AdjustTokenPrivileges may succeed without fully assigning them).
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                KLogEvent logEvent;
                err << logEvent << "AdjustTokenPrivileges: SeDebugPrivilege not assigned" << eol;
                CloseHandle(hToken);
                return 1;
            }
            CloseHandle(hToken);  // Privileges enabled; close temporary handle.

            // ========== Step 2: enumerate processes to retrieve the PIDs of lsass.exe and winlogon.exe ==========
            DWORD idL = 0;                     // Store the process ID of lsass.exe.
            DWORD idW = 0;                     // Stores the process ID of winlogon.exe.
            PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };  // Process snapshot entry (wide character).
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // Process snapshot handle
            if (hSnapshot == INVALID_HANDLE_VALUE)
            {
                KLogEvent logEvent;
                err << logEvent << "CreateToolhelp32Snapshot failed, error: " << GetLastError() << eol;
                return 1;
            }

            // Iterate through the process snapshot to match the target process name.
            if (Process32FirstW(hSnapshot, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0)
                    {
                        idL = pe.th32ProcessID;
                        KLogEvent logEvent;
                        info << logEvent << "Found lsass.exe with PID: " << idL << eol;
                    }
                    else if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0)
                    {
                        idW = pe.th32ProcessID;
                        KLogEvent logEvent;
                        info << logEvent << "Found winlogon.exe with PID: " << idW << eol;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);

            // ========== Step 3: Open target process (prefer lsass, then winlogon) ==========
            HANDLE hProcess = NULL;          // Target process handle
            if (idL != 0)
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
            if (!hProcess && idW != 0)
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
            if (!hProcess)
            {
                KLogEvent logEvent;
                err << logEvent << "Failed to open target process (lsass/winlogon), error: " << GetLastError() << eol;
                return 1;
            }
            {
                KLogEvent logEvent;
                info << logEvent << "Opened target process" << eol;
            }

            // ========== Step 4: Open the token handle of the target process ==========
            HANDLE hTokenx = NULL;           // Token handle of the target process.
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx))
            {
                KLogEvent logEvent;
                err << logEvent << "OpenProcessToken on target process failed, error: " << GetLastError() << eol;
                CloseHandle(hProcess);
                return 1;
            }

            // ========== Step 5: Duplicate token to obtain a usable primary token ==========
            HANDLE hNewToken = NULL;         // Copy the obtained new token handle.
            if (!DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNewToken))
            {
                KLogEvent logEvent;
                err << logEvent << "DuplicateTokenEx failed, error: " << GetLastError() << eol;
                CloseHandle(hTokenx);
                CloseHandle(hProcess);
                return 1;
            }
            CloseHandle(hTokenx);
            CloseHandle(hProcess);

            // ========== Step 6: Get the current program's own path ==========
            std::wstring selfPath = ks::process::getCurrentProcessPath();
            if (selfPath.empty())
            {
                KLogEvent logEvent;
                err << logEvent <<"Failed to get current process path" << eol;
                CloseHandle(hNewToken);
                return 1;
            }
            {
                KLogEvent logEvent;
                // pathUtf8 usage: Converts the UTF-16 path to UTF-8 to avoid compilation errors caused by directly outputting std::wstring to the log stream (std::ostringstream).
                const std::string kPathUtf8 = ks::str::utf16ToUtf8(selfPath);
                info << logEvent << "Current process path: " << kPathUtf8 << eol;
            }

            // ========== Step 7: Launch self using the copied token ==========
            STARTUPINFOW si = { sizeof(STARTUPINFOW) };
            PROCESS_INFORMATION pi = { 0 };
            // Use a writable buffer for lpDesktop to avoid a compilation error assigning const wchar_t* to LPWSTR.
            wchar_t desktop[] = L"winsta0\\default";
            si.lpDesktop = desktop;          // Displayed on the interactive desktop.

            // SYSTEM privilege switching must carry the internal restart flag; otherwise, the default anti-multi-instance protection will cause the new instance to exit immediately.
            const QStringList kLaunchArgumentList = argumentsWithPrivilegeRestartTakeover(
                QCoreApplication::arguments(),
                ::GetCurrentProcessId());
            QString commandLineText = quoteQStringCommandLineArgument(QString::fromStdWString(selfPath));
            for (int index = 1; index < kLaunchArgumentList.size(); ++index)
            {
                commandLineText += QLatin1Char(' ');
                commandLineText += quoteQStringCommandLineArgument(kLaunchArgumentList.at(index));
            }
            std::wstring commandLineWide = commandLineText.toStdWString();

            if (!CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, selfPath.c_str(), commandLineWide.data(),
                NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
            {
                KLogEvent logEvent;
                err << logEvent << "CreateProcessWithTokenW failed, error: " << GetLastError() << eol;
                CloseHandle(hNewToken);
                return 1;
            }

            {
                KLogEvent logEvent;
                info << logEvent << "Successfully started new instance of the program. New PID: " << pi.dwProcessId << eol;
            }

            // Clean up resources
            CloseHandle(hNewToken);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            close();
        }

        // Qt ignores the slot return value, but early failure paths in this
        // lambda return an int for legacy flow control. Return a final success
        // value so every compiler-visible path is explicit and warning-free.
        return 0;
    });

    // R0 button:
    // - Query service status before starting.
    // - Stop and unload the service if it is running.
    // - If not running, loads KswordARK.sys from the current exe directory.
    connect(r0StatusButton_, &QPushButton::clicked, this, [this]() {
        handleR0StatusButtonClicked();
    });

    // Periodically refresh privilege status to ensure button colors match actual privileges.
    privilegeStatusTimer_ = new QTimer(this);
    privilegeStatusTimer_->setInterval(1500);
    connect(privilegeStatusTimer_, &QTimer::timeout, this, [this]() {
        refreshPrivilegeStatusButtons();
    });
    privilegeStatusTimer_->start();

    // Query R0 service status once at startup to serve as the source for button initial states.
    queryR0DriverServiceRunning(r0DriverServiceRunning_, true);
    refreshPrivilegeStatusButtons();
}

void MainWindow::attachPrivilegeStatusButtonsToPrimaryDockTabBar()
{
    // The Dock Area belonging to the Welcome page is the main functional Tab bar; the privilege button group moves/follows it.
    if (privilegeButtonContainer_ == nullptr || dockWelcome_ == nullptr)
    {
        return;
    }

    ads::CDockAreaWidget* const kMainDockArea = dockWelcome_->dockAreaWidget();
    if (kMainDockArea == nullptr || kMainDockArea->titleBar() == nullptr)
    {
        return;
    }

    ads::CDockAreaTitleBar* const kTitleBar = kMainDockArea->titleBar();
    if (privilegeButtonContainer_->parentWidget() == kTitleBar
        && kTitleBar->indexOf(privilegeButtonContainer_) >= 0)
    {
        return;
    }

    // Append to the end of the ADS title bar layout: TabBar occupies the center expandable space, while the privilege button group is fixed to the right.
    kTitleBar->insertWidget(-1, privilegeButtonContainer_);
    privilegeButtonContainer_->show();
}

void MainWindow::handleR0DriverUnavailable(const unsigned long win32Error)
{
    // All ArkDriverClient calls converge here. Only prompt when the window is interactive, and merge failures from multiple pages/background
    // tasks within a short time into a single choice to avoid interrupting the user repeatedly just after opening an R0 page.
    if (!r0UnavailablePromptArmed_ || r0UnavailablePromptShowing_)
    {
        return;
    }

    bool serviceRunning = false;
    if (!queryR0DriverServiceRunning(serviceRunning, false))
    {
        return;
    }
    if (serviceRunning)
    {
        r0DriverServiceRunning_ = true;
        refreshPrivilegeStatusButtons();
        return;
    }

    r0DriverServiceRunning_ = false;
    if (suppressR0PromptsForSession_ || currentAppearanceSettings_.suppressR0FeaturePrompts)
    {
        refreshPrivilegeStatusButtons();
        return;
    }
    r0UnavailablePromptShowing_ = true;

    const bool kIsAdmin = hasAdminPrivilege();
    QMessageBox prompt(this);
    prompt.setIcon(QMessageBox::Warning);
    prompt.setWindowTitle(ks::i18n::text(
        QStringLiteral("r0.enable_required.title"),
        QStringLiteral("需要启用 R0")));
    prompt.setText(ks::i18n::text(
        QStringLiteral("r0.enable_required.message"),
        QStringLiteral("当前操作需要 R0 驱动，但 KswordARK 驱动服务尚未启用。\n\n是否现在启用 R0？")));
    prompt.setInformativeText(ks::i18n::text(
        QStringLiteral("r0.enable_required.hint"),
        QStringLiteral("启用后可继续使用依赖内核权限的功能；R0 状态按钮会显示为已启用。")));
    QCheckBox* const kSuppressForSessionCheckBox = new QCheckBox(
        ks::i18n::text(
            QStringLiteral("r0.enable_required.suppress_session"),
            QStringLiteral("本次不再提醒")));
    prompt.setCheckBox(kSuppressForSessionCheckBox);
    QPushButton* const kEnableButton = prompt.addButton(
        ks::i18n::text(
            kIsAdmin
            ? QStringLiteral("r0.enable_required.enable_now")
            : QStringLiteral("r0.enable_required.elevate_and_enable"),
            kIsAdmin ? QStringLiteral("启用 R0") : QStringLiteral("以管理员身份重启并启用 R0")),
        QMessageBox::AcceptRole);
    prompt.addButton(
        ks::i18n::text(QStringLiteral("r0.enable_required.cancel"), QStringLiteral("暂不启用")),
        QMessageBox::RejectRole);
    prompt.exec();

    r0UnavailablePromptShowing_ = false;
    if (kSuppressForSessionCheckBox->isChecked())
    {
        suppressR0PromptsForSession_ = true;
    }
    if (prompt.clickedButton() != kEnableButton)
    {
        refreshPrivilegeStatusButtons();
        return;
    }

    if (!kIsAdmin)
    {
        requestAdminElevationRestart(true);
        return;
    }

    enableR0ForUserRequest();
    Q_UNUSED(win32Error);
}

void MainWindow::handleR0PermissionRequired(const unsigned long win32Error)
{
    if (!r0UnavailablePromptArmed_
        || r0PermissionPromptShowing_
        || hasAdminPrivilege()
        || suppressR0PromptsForSession_
        || currentAppearanceSettings_.suppressR0FeaturePrompts)
    {
        return;
    }
    r0PermissionPromptShowing_ = true;
    (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("当前内核功能"));
    r0PermissionPromptShowing_ = false;
    Q_UNUSED(win32Error);
}

void MainWindow::enableR0ForUserRequest()
{
    // Purpose:
    // - Inputs: None;
    // - Handling: R0 startup is now executed in the background; this function only dispatches. Status synchronization after success,
    //         failure notifications, and button availability are all handled uniformly by the callback invoked internally by startR0DriverService.
    // - Returns: Nothing.
    if (!startR0DriverService())
    {
        refreshPrivilegeStatusButtons();
    }
}

void MainWindow::applyDdmaButtonState()
{
    if (ddmaStatusButton_ == nullptr)
    {
        return;
    }

    // Do not redraw if the generation hasn't changed: this path is repeatedly called by the periodic refresh of the privilege button, while the
    // DDMA configuration remains completely static between two configurations. The first frame must be allowed via m_ddmaButtonPainted—initializing
    // both generation and the member to 0 would cause the first frame to be misjudged as 'no change' if only the generation were checked.
    const std::uint64_t kGeneration = ksword::memory_backend::ddmaSessionGeneration();
    if (ddmaButtonPainted_ && kGeneration == ddmaSessionGeneration_)
    {
        return;
    }
    ddmaSessionGeneration_ = kGeneration;
    ddmaButtonPainted_ = true;

    const ksword::memory_backend::DdmaSession& session =
        ksword::memory_backend::currentDdmaSession();
    QString reason;
    // Note: The criterion for lighting up is "this channel is actually usable now," consistent with other permission indicators: do not
    // render a partially configured channel as lit, as that would make the indicator overly optimistic compared to actual capability.
    const bool kResident = ksword::memory_backend::isDdmaUsable(session, &reason);

    ddmaStatusButton_->setStyleSheet(buildR0ButtonStyle(kResident));
    if (kResident)
    {
        ddmaStatusButton_->setToolTip(
            ks::i18n::sourceText(QStringLiteral(
                "DDMA：常驻虚扇区已登记（磁盘 #%1，暂存 LBA %2）。该扇区会在每次 DMA 读写时被临时覆盖并立即还原。点击打开内存页的 DDMA 子页。"))
                .arg(session.diskIndex)
                .arg(session.scratchLba));
        return;
    }
    ddmaStatusButton_->setToolTip(
        ks::i18n::sourceText(QStringLiteral("DDMA：未常驻虚扇区。%1点击打开内存页的 DDMA 子页进行配置。"))
            .arg(reason.isEmpty() ? QString() : (reason + QStringLiteral(" "))));
}

void MainWindow::handleDdmaStatusButtonClicked()
{
    // This button does not directly toggle the resident mode: registering a temporary sector requires selecting a disk, entering an LBA, and confirming
    // overwrite—all three steps need user input. Thus, the click only navigates the user to the location where these steps can be performed.
    focusMemoryDockDdmaPage();
}

void MainWindow::applyPrivilegeButtonVisibility()
{
    // Nothing to do if the container is not yet established; the function is immediately called back during establishment.
    if (privilegeButtonContainer_ == nullptr)
    {
        return;
    }

    const ks::settings::AppearanceSettings& settings = currentAppearanceSettings_;
    const std::array<std::pair<QPushButton*, bool>, 7> kVisibility{{
        {uiAccessStatusButton_, settings.privilegeButtonUiAccessVisible},
        {adminStatusButton_, settings.privilegeButtonAdminVisible},
        {debugStatusButton_, settings.privilegeButtonDebugVisible},
        {systemStatusButton_, settings.privilegeButtonSystemVisible},
        {r0StatusButton_, settings.privilegeButtonR0Visible},
        {kvmStatusButton_, settings.privilegeButtonHvmVisible},
        {ddmaStatusButton_, settings.privilegeButtonDdmaVisible}
    }};
    int visibleCount = 0;
    for (const std::pair<QPushButton*, bool>& entry : kVisibility)
    {
        if (entry.first == nullptr)
        {
            continue;
        }
        entry.first->setVisible(entry.second);
        if (entry.second)
        {
            ++visibleCount;
        }
    }

    // When none are displayed, hide the entire row to avoid leaving a blank space on the
    // right side of the Tab bar that looks like a layout bug rather than "I turned them off".
    privilegeButtonContainer_->setVisible(visibleCount > 0);

    // The label applies only to this button's title and tooltip prefix; in-page explanatory text does not switch with it.
    if (kvmStatusButton_ != nullptr)
    {
        const QString kDisplayName =
            ks::settings::hvmDisplayNameLabel(settings.hvmDisplayName);
        kvmStatusButton_->setText(kDisplayName);
        // Keep the string on a single line: line breaks cause i18n audits to treat it as multiple independent source strings, requiring a translation entry for each segment.
        kvmStatusButton_->setToolTip(
            QStringLiteral("%1：KSwordVM 硬件虚拟化（R-1）常驻状态。左键启动或停止常驻，右键打开 R-1 能力菜单。")
                .arg(kDisplayName));
    }
}

void MainWindow::refreshPrivilegeStatusButtons()
{
    // Apply visibility and labels first: since both only affect the rendering of this button row and are unrelated to status
    // queries, placing them at the front ensures hidden buttons do not participate in subsequent style and tooltip updates.
    applyPrivilegeButtonVisibility();

    // Read current privilege status.
    const bool kAdminEnabled = hasAdminPrivilege();
    const bool kDebugEnabled = hasDebugPrivilege();
    const bool kSystemEnabled = hasSystemPrivilege();
    const bool kUiAccessEnabled = hasUiAccessPrivilege();
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordProcessUiAccessPropertyName, kUiAccessEnabled);
    }

    // R0 status flag:
    // - R0: Check if the KswordARK driver service is running.
    const bool kR0Enabled = r0DriverServiceRunning_;

    // Update button styles and tooltips based on status.
    applyPrivilegeButtonStyle(uiAccessStatusButton_, kUiAccessEnabled);
    applyPrivilegeButtonStyle(adminStatusButton_, kAdminEnabled);
    applyPrivilegeButtonStyle(debugStatusButton_, kDebugEnabled);
    applyPrivilegeButtonStyle(systemStatusButton_, kSystemEnabled);
    if (r0StatusButton_ != nullptr)
    {
        r0StatusButton_->setStyleSheet(buildR0ButtonStyle(kR0Enabled));
    }
    // KVM only refreshes the UI using cached values: status queries are blocking IOCTLs and must run in the background.
    applyKvmButtonState();
    // Whether DDMA is resident is entirely a configuration within this process; reading it
    // requires no IOCTL, so it can be placed directly in this synchronous refresh path.
    applyDdmaButtonState();
    // Do not query when the driver is not running to avoid hitting a non-existent device on every refresh cycle.
    if (kR0Enabled)
    {
        refreshKvmStatusAsync();
    }
    else if (kvmAvailable_ || kvmResidentActive_)
    {
        // Immediately mark KVM as unavailable when the driver is stopped, without retaining the optimistic state from the previous round.
        kvmAvailable_ = false;
        kvmResidentActive_ = false;
        kvmFaulted_ = false;
        kvmGeneration_ = 0;
        kvmTooltip_.clear();
        applyKvmButtonState();
    }

    if (uiAccessStatusButton_ != nullptr)
    {
        if (kUiAccessEnabled)
        {
            uiAccessStatusButton_->setToolTip("UIAccess 已启用");
        }
        else
        {
            uiAccessStatusButton_->setToolTip("UIAccess：点击重新启动并尝试启用跨权限界面访问");
        }
    }
    if (adminStatusButton_ != nullptr)
    {
        adminStatusButton_->setToolTip(kAdminEnabled ? "管理员权限已启用" : "点击提权到管理员（重启当前程序）");
    }
    if (debugStatusButton_ != nullptr)
    {
        debugStatusButton_->setToolTip(kDebugEnabled ? "SeDebugPrivilege 已启用" : "点击启用 SeDebugPrivilege");
    }
    if (systemStatusButton_ != nullptr)
    {
        systemStatusButton_->setToolTip(kSystemEnabled ? "当前运行身份：LocalSystem" : "当前运行身份：非 LocalSystem");
    }
    if (r0StatusButton_ != nullptr)
    {
        r0StatusButton_->setToolTip(kR0Enabled
            ? "R0 已启用：KswordARK 驱动服务正在运行（点击卸载）"
            : "R0 未启用：点击创建并启动 KswordARK 驱动服务");
    }

    // Log only on state changes to avoid log flooding from the timer.
    static bool hasPreviousState = false;
    static bool previousUiAccessToken = false;
    static bool previousAdmin = false;
    static bool previousDebug = false;
    static bool previousSystem = false;
    static bool previousR0 = false;
    if (!hasPreviousState ||
        previousAdmin != kAdminEnabled ||
        previousUiAccessToken != kUiAccessEnabled ||
        previousDebug != kDebugEnabled ||
        previousSystem != kSystemEnabled ||
        previousR0 != kR0Enabled)
    {
        hasPreviousState = true;
        previousUiAccessToken = kUiAccessEnabled;
        previousAdmin = kAdminEnabled;
        previousDebug = kDebugEnabled;
        previousSystem = kSystemEnabled;
        previousR0 = kR0Enabled;

        KLogEvent logEvent;
        info << logEvent
            << "[MainWindow] 权限状态刷新, uiAccessToken=" << (kUiAccessEnabled ? "true" : "false")
            << ", admin=" << (kAdminEnabled ? "true" : "false")
            << ", debug=" << (kDebugEnabled ? "true" : "false")
            << ", system=" << (kSystemEnabled ? "true" : "false")
            << ", r0=" << (kR0Enabled ? "true" : "false")
            << eol;
    }
}

void MainWindow::applyPrivilegeButtonStyle(QPushButton* button, const bool activeState)
{
    if (button == nullptr)
    {
        return;
    }
    button->setStyleSheet(buildPrivilegeButtonStyle(activeState));
}

bool MainWindow::hasUiAccessPrivilege() const
{
    // tokenHandle usage: queries the TokenUIAccess flag in the current process token.
    ScopedHandle tokenHandle;
    HANDLE rawTokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawTokenHandle) == FALSE)
    {
        if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
        {
            appInstance->setProperty(kKswordProcessUiAccessPropertyName, false);
        }
        return false;
    }
    tokenHandle.reset(rawTokenHandle);

    DWORD returnLength = 0;
    DWORD uiAccessValue = 0;
    const BOOL kQueryOk = ::GetTokenInformation(
        tokenHandle.get(),
        TokenUIAccess,
        &uiAccessValue,
        sizeof(uiAccessValue),
        &returnLength);
    const bool kUiAccessEnabled = kQueryOk != FALSE && uiAccessValue != 0;
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordProcessUiAccessPropertyName, kUiAccessEnabled);
    }
    return kUiAccessEnabled;
}

bool MainWindow::launchSelfWithSystemUiAccessToken(QString* detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }

    // detailLineList purpose: Record each critical step so both success and failure can be displayed to the user.
    QStringList detailLineList;
    auto failWithDetail = [&](const QString& failureText) {
        detailLineList << failureText;
        if (detailTextOut != nullptr)
        {
            *detailTextOut = detailLineList.join(QStringLiteral("\n"));
        }
        return false;
    };

    if (!hasAdminPrivilege())
    {
        detailLineList << QStringLiteral("当前进程不是提升管理员，无法可靠打开 SYSTEM 进程令牌。");
        if (detailTextOut != nullptr)
        {
            *detailTextOut = detailLineList.join(QStringLiteral("\n"));
        }
        return false;
    }

    // First, attempt to enable all privileges required by the call chain; some privileges may be missing from a standard administrator token, so record them without interrupting.
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_DEBUG_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_ASSIGNPRIMARYTOKEN_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_INCREASE_QUOTA_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_TCB_NAME);

    DWORD currentSessionId = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("ProcessIdToSessionId(GetCurrentProcessId)"), kErrorCode));
    }
    detailLineList << QStringLiteral("当前进程 SessionId：%1").arg(currentSessionId);

    DWORD sourceProcessId = 0;
    DWORD sourceSessionId = 0;
    QString sourceProcessName;
    QString findDetailText;
    if (!findSystemProcessTokenCandidate(
        currentSessionId,
        &sourceProcessId,
        &sourceProcessName,
        &sourceSessionId,
        &findDetailText))
    {
        return failWithDetail(findDetailText);
    }
    detailLineList << QStringLiteral("选定 SYSTEM 令牌源：%1，PID=%2，SessionId=%3")
        .arg(sourceProcessName)
        .arg(sourceProcessId)
        .arg(sourceSessionId);

    // sourceProcessHandle: Opens the SYSTEM process to subsequently read and copy its token only.
    ScopedHandle sourceProcessHandle(::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        sourceProcessId));
    if (!sourceProcessHandle.isValid())
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("OpenProcess(%1)").arg(sourceProcessName), kErrorCode));
    }

    // sourceTokenHandle purpose: Holds the raw token from the SYSTEM process to maintain minimal privileges and reduce the probability of OpenProcessToken failure.
    HANDLE rawSourceTokenHandle = nullptr;
    const DWORD kSourceTokenAccess = TOKEN_DUPLICATE | TOKEN_QUERY;
    if (::OpenProcessToken(sourceProcessHandle.get(), kSourceTokenAccess, &rawSourceTokenHandle) == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("OpenProcessToken(%1)").arg(sourceProcessName), kErrorCode));
    }
    ScopedHandle sourceTokenHandle(rawSourceTokenHandle);

    DWORD tokenUserError = ERROR_SUCCESS;
    if (!tokenBelongsToLocalSystem(sourceTokenHandle.get(), &tokenUserError))
    {
        return failWithDetail(QStringLiteral("令牌源不是 LocalSystem，或无法验证令牌用户：%1，%2")
            .arg(tokenUserError)
            .arg(formatWin32ErrorText(tokenUserError)));
    }

    DWORD sourceTokenSessionId = 0;
    DWORD sourceTokenSessionError = ERROR_SUCCESS;
    if (queryTokenSessionId(sourceTokenHandle.get(), &sourceTokenSessionId, &sourceTokenSessionError))
    {
        detailLineList << QStringLiteral("源令牌 SessionId：%1").arg(sourceTokenSessionId);
    }
    else
    {
        detailLineList << QStringLiteral("源令牌 SessionId 查询失败：%1，%2")
            .arg(sourceTokenSessionError)
            .arg(formatWin32ErrorText(sourceTokenSessionError));
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);

    // Purpose of systemImpersonationTokenHandle:
    // - Copies the SYSTEM source token into an impersonation token.
    // - Subsequently, the current thread temporarily enters the SYSTEM context to improve the success rate of SetTokenInformation/CreateProcessAsUserW.
    HANDLE rawSystemImpersonationTokenHandle = nullptr;
    if (::DuplicateTokenEx(
        sourceTokenHandle.get(),
        MAXIMUM_ALLOWED,
        &securityAttributes,
        SecurityImpersonation,
        TokenImpersonation,
        &rawSystemImpersonationTokenHandle) == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(TokenImpersonation)"), kErrorCode));
    }
    ScopedHandle systemImpersonationTokenHandle(rawSystemImpersonationTokenHandle);

    ScopedThreadImpersonation systemImpersonation;
    DWORD impersonationError = ERROR_SUCCESS;
    if (!systemImpersonation.impersonate(systemImpersonationTokenHandle.get(), &impersonationError))
    {
        return failWithDetail(formatWin32StepFailure(QStringLiteral("ImpersonateLoggedOnUser(SYSTEM)"), impersonationError));
    }
    detailLineList << QStringLiteral("ImpersonateLoggedOnUser：当前线程已临时模拟 SYSTEM。");

    for (const wchar_t* const kPrivilegeName : { SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME })
    {
        DWORD enableError = ERROR_SUCCESS;
        const bool kEnableOk = enableTokenPrivilege(systemImpersonationTokenHandle.get(), kPrivilegeName, &enableError);
        detailLineList << QStringLiteral("SYSTEM 模拟令牌 %1：%2")
            .arg(privilegeNameToDisplayText(kPrivilegeName))
            .arg(kEnableOk
                ? QStringLiteral("已启用")
                : QStringLiteral("未启用（%1，%2）").arg(enableError).arg(formatWin32ErrorText(enableError)));
    }

    // duplicatedTokenHandle usage: The copied primary token will be used to set SessionId and TokenUIAccess subsequently.
    HANDLE rawDuplicatedTokenHandle = nullptr;
    if (::DuplicateTokenEx(
        sourceTokenHandle.get(),
        MAXIMUM_ALLOWED,
        &securityAttributes,
        SecurityImpersonation,
        TokenPrimary,
        &rawDuplicatedTokenHandle) == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(TokenPrimary)"), kErrorCode));
    }
    ScopedHandle duplicatedTokenHandle(rawDuplicatedTokenHandle);
    detailLineList << QStringLiteral("DuplicateTokenEx：已获得 SYSTEM 主令牌。");

    // Enable common privileges for token duplication; do not abort on failure as the token may still be usable for process creation.
    for (const wchar_t* const kPrivilegeName : { SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME })
    {
        DWORD enableError = ERROR_SUCCESS;
        const bool kEnableOk = enableTokenPrivilege(duplicatedTokenHandle.get(), kPrivilegeName, &enableError);
        detailLineList << QStringLiteral("复制令牌 %1：%2")
            .arg(privilegeNameToDisplayText(kPrivilegeName))
            .arg(kEnableOk
                ? QStringLiteral("已启用")
                : QStringLiteral("未启用（%1，%2）").arg(enableError).arg(formatWin32ErrorText(enableError)));
    }

    if (sourceSessionId != currentSessionId)
    {
        // TokenSessionId usage: Attempt to restore the SYSTEM token to the current interactive session to prevent new instances from launching in invisible sessions.
        DWORD sessionIdForToken = currentSessionId;
        if (::SetTokenInformation(
            duplicatedTokenHandle.get(),
            TokenSessionId,
            &sessionIdForToken,
            sizeof(sessionIdForToken)) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            return failWithDetail(formatWin32StepFailure(QStringLiteral("SetTokenInformation(TokenSessionId)"), kErrorCode));
        }
        else
        {
            detailLineList << QStringLiteral("SetTokenInformation(TokenSessionId)：已设置为当前 Session %1。")
                .arg(currentSessionId);
        }
    }

    // Purpose of uiAccessValue: Directly set the TokenUIAccess flag on the copied SYSTEM primary token according to the user-specified scheme.
    DWORD uiAccessValue = 1;
    if (::SetTokenInformation(
        duplicatedTokenHandle.get(),
        TokenUIAccess,
        &uiAccessValue,
        sizeof(uiAccessValue)) == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("SetTokenInformation(TokenUIAccess)"), kErrorCode));
    }
    detailLineList << QStringLiteral("SetTokenInformation(TokenUIAccess)：已请求启用。");

    DWORD verifiedUiAccessValue = 0;
    DWORD verifiedLength = 0;
    if (::GetTokenInformation(
        duplicatedTokenHandle.get(),
        TokenUIAccess,
        &verifiedUiAccessValue,
        sizeof(verifiedUiAccessValue),
        &verifiedLength) == FALSE ||
        verifiedUiAccessValue == 0)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(QStringLiteral("TokenUIAccess 设置后校验失败：%1，%2")
            .arg(kErrorCode)
            .arg(formatWin32ErrorText(kErrorCode)));
    }
    detailLineList << QStringLiteral("TokenUIAccess 校验：复制令牌已带 UIAccess 位。");

    const std::wstring kSelfPath = ks::process::getCurrentProcessPath();
    if (kSelfPath.empty())
    {
        return failWithDetail(QStringLiteral("无法获取当前程序路径。"));
    }

    QString commandLineText = quoteWin32CommandLineArgument(kSelfPath);
    commandLineText += QLatin1Char(' ');
    commandLineText += QString::fromWCharArray(kKswordPrivilegeRestartArgument);
    std::wstring commandLineWide = commandLineText.toStdWString();
    std::wstring applicationPathWide = kSelfPath;

    // startupInfo usage: Specifies the interactive desktop to ensure new process windows appear on the default desktop.
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    wchar_t desktopName[] = L"winsta0\\default";
    startupInfo.lpDesktop = desktopName;
    PROCESS_INFORMATION processInformation{};
    const DWORD kCreationFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
    const BOOL kCreateOk = ::CreateProcessAsUserW(
        duplicatedTokenHandle.get(),
        applicationPathWide.c_str(),
        commandLineWide.data(),
        nullptr,
        nullptr,
        FALSE,
        kCreationFlags,
        nullptr,
        nullptr,
        &startupInfo,
        &processInformation);
    if (kCreateOk == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("CreateProcessAsUserW"), kErrorCode));
    }

    ScopedHandle newProcessHandle(processInformation.hProcess);
    ScopedHandle newThreadHandle(processInformation.hThread);
    detailLineList << QStringLiteral("CreateProcessAsUserW：成功启动新实例，PID=%1。")
        .arg(processInformation.dwProcessId);

    // Explicitly revert impersonation to ensure subsequent UI prompts and the Qt exit flow return to the current process's original identity.
    systemImpersonation.reset();
    detailLineList << QStringLiteral("RevertToSelf：已撤销当前线程 SYSTEM 模拟。");

    if (detailTextOut != nullptr)
    {
        *detailTextOut = detailLineList.join(QStringLiteral("\n"));
    }
    return true;
}

void MainWindow::handleUiAccessButtonClicked()
{
    // When the current instance already has UIAccess, the button semantics revert to the standard user instance; this path does not depend on any signature certificate.
    if (hasUiAccessPrivilege())
    {
        QString launchDetailText;
        const bool kLaunchOk = launchSelfAsUnelevatedFromExplorer(QCoreApplication::arguments(), &launchDetailText);
        if (!kLaunchOk)
        {
            KLogEvent logEvent;
            err << logEvent
                << "[MainWindow][UIAccess] 从 UIAccess 降级重启普通实例失败: "
                << launchDetailText.toStdString()
                << eol;
            QMessageBox::warning(
                this,
                QStringLiteral("UIAccess"),
                QStringLiteral("普通权限重启失败，当前实例保持运行。\n\n%1").arg(launchDetailText));
            refreshPrivilegeStatusButtons();
            return;
        }

        KLogEvent logEvent;
        info << logEvent
            << "[MainWindow][UIAccess] 当前实例已带 UIAccess，已启动普通权限实例并准备正常退出: "
            << launchDetailText.toStdString()
            << eol;
        close();
        return;
    }

    if (!hasAdminPrivilege())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("UIAccess"),
            QStringLiteral(
                "启用 UIAccess 需要管理员权限。\n\n"
                "程序将先以管理员身份重新启动；重启后请再次点击 UIAccess。"));
        requestAdminElevationRestart();
        return;
    }

    QString launchDetailText;
    const bool kLaunchOk = launchSelfWithSystemUiAccessToken(&launchDetailText);
    if (!kLaunchOk)
    {
        KLogEvent logEvent;
        err << logEvent
            << "[MainWindow][UIAccess] SYSTEM TokenUIAccess fallback 启动失败: "
            << launchDetailText.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("UIAccess 启动失败"),
            launchDetailText);
        refreshPrivilegeStatusButtons();
        return;
    }

    {
        KLogEvent logEvent;
        info << logEvent
            << "[MainWindow][UIAccess] SYSTEM TokenUIAccess fallback 启动成功: "
            << launchDetailText.toStdString()
            << eol;
    }
    // No dialog is shown on the success path to avoid repeated interruptions; detailed steps are logged.
    refreshPrivilegeStatusButtons();
    QApplication::quit();
}

void MainWindow::requestAdminElevationRestart(const bool enableR0AfterRestart)
{
    // Get the current executable path to use as the target for runas restart.
    wchar_t exePathBuffer[MAX_PATH] = {};
    const DWORD kPathLength = ::GetModuleFileNameW(nullptr, exePathBuffer, static_cast<DWORD>(std::size(exePathBuffer)));
    if (kPathLength == 0 || kPathLength >= std::size(exePathBuffer))
    {
        const DWORD kLastError = ::GetLastError();
        QMessageBox::warning(this, "Admin", QString("读取当前程序路径失败，错误码: %1").arg(kLastError));
        return;
    }

    QString elevationParameters = QString::fromWCharArray(kKswordPrivilegeRestartArgument);
    if (enableR0AfterRestart)
    {
        elevationParameters += QLatin1Char(' ');
        elevationParameters += QString::fromWCharArray(kKswordEnableR0AfterElevationArgument);
    }
    const std::wstring kElevationParametersWide = elevationParameters.toStdWString();

    // Trigger UAC elevation via ShellExecute("runas"); R0 requests carry internal parameters so the elevated
    // instance directly executes the user-confirmed enable action instead of requiring a restart and re-click.
    HINSTANCE shellResult = ::ShellExecuteW(
        nullptr,
        L"runas",
        exePathBuffer,
        kElevationParametersWide.c_str(),
        nullptr,
        SW_SHOWNORMAL);
    if (reinterpret_cast<std::intptr_t>(shellResult) <= 32)
    {
        QMessageBox::warning(this, "Admin", "提权启动失败，可能被用户取消或系统策略阻止。");
        return;
    }

    // After the new process starts successfully, the current instance exits.
    KLogEvent logEvent;
    info << logEvent << "[MainWindow] 已触发管理员重启，当前实例即将退出。" << eol;
    QApplication::quit();
}

bool MainWindow::hasAdminPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    TOKEN_ELEVATION tokenElevation{};
    DWORD returnLength = 0;
    const BOOL kQueryOk = ::GetTokenInformation(
        tokenHandle,
        TokenElevation,
        &tokenElevation,
        sizeof(tokenElevation),
        &returnLength);
    ::CloseHandle(tokenHandle);
    return kQueryOk != FALSE && tokenElevation.TokenIsElevated != 0;
}

bool MainWindow::hasDebugPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    DWORD requiredLength = 0;
    ::GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &requiredLength);
    if (requiredLength == 0)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    std::vector<BYTE> privilegeBuffer(requiredLength, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenPrivileges,
        privilegeBuffer.data(),
        requiredLength,
        &requiredLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    LUID debugLuid{};
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugLuid) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    const TOKEN_PRIVILEGES* tokenPrivileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(privilegeBuffer.data());
    for (DWORD privilegeIndex = 0; privilegeIndex < tokenPrivileges->PrivilegeCount; ++privilegeIndex)
    {
        const LUID_AND_ATTRIBUTES& privilegeItem = tokenPrivileges->Privileges[privilegeIndex];
        if (privilegeItem.Luid.LowPart == debugLuid.LowPart &&
            privilegeItem.Luid.HighPart == debugLuid.HighPart)
        {
            const bool kEnabled = (privilegeItem.Attributes & SE_PRIVILEGE_ENABLED) != 0;
            ::CloseHandle(tokenHandle);
            return kEnabled;
        }
    }

    ::CloseHandle(tokenHandle);
    return false;
}

bool MainWindow::hasSystemPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    DWORD requiredLength = 0;
    ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredLength);
    if (requiredLength == 0)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    std::vector<BYTE> userBuffer(requiredLength, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenUser,
        userBuffer.data(),
        requiredLength,
        &requiredLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSidLength = static_cast<DWORD>(std::size(systemSidBuffer));
    if (::CreateWellKnownSid(
        WinLocalSystemSid,
        nullptr,
        systemSidBuffer,
        &systemSidLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    const bool kIsSystem = (::EqualSid(tokenUser->User.Sid, systemSidBuffer) != FALSE);
    ::CloseHandle(tokenHandle);
    return kIsSystem;
}

bool MainWindow::enableSeDebugPrivilege(std::string& errorTextOut) const
{
    errorTextOut.clear();

    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(
        ::GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle) == FALSE)
    {
        errorTextOut = "OpenProcessToken failed, error=" + std::to_string(::GetLastError());
        return false;
    }

    LUID debugLuid{};
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugLuid) == FALSE)
    {
        errorTextOut = "LookupPrivilegeValue(SE_DEBUG_NAME) failed, error=" + std::to_string(::GetLastError());
        ::CloseHandle(tokenHandle);
        return false;
    }

    TOKEN_PRIVILEGES tokenPrivileges{};
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = debugLuid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (::AdjustTokenPrivileges(
        tokenHandle,
        FALSE,
        &tokenPrivileges,
        sizeof(tokenPrivileges),
        nullptr,
        nullptr) == FALSE)
    {
        errorTextOut = "AdjustTokenPrivileges failed, error=" + std::to_string(::GetLastError());
        ::CloseHandle(tokenHandle);
        return false;
    }

    const DWORD kAdjustError = ::GetLastError();
    ::CloseHandle(tokenHandle);
    if (kAdjustError != ERROR_SUCCESS)
    {
        errorTextOut = "AdjustTokenPrivileges returned error=" + std::to_string(kAdjustError);
        return false;
    }
    return true;
}
