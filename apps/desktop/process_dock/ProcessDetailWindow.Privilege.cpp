#include "ProcessDetailWindow.InternalCommon.h"

#include <QSignalBlocker>

using namespace process_detail_window_internal;

namespace
{
    // ScopedPrivilegeIdentityHandle: Holds the target process object during token query/adjustment to prevent PID reuse.
    class ScopedPrivilegeIdentityHandle final
    {
    public:
        explicit ScopedPrivilegeIdentityHandle(const HANDLE handleValue)
            : handle_(handleValue)
        {
        }

        ~ScopedPrivilegeIdentityHandle()
        {
            if (handle_ != nullptr)
            {
                ::CloseHandle(handle_);
            }
        }

        ScopedPrivilegeIdentityHandle(const ScopedPrivilegeIdentityHandle&) = delete;
        ScopedPrivilegeIdentityHandle& operator=(const ScopedPrivilegeIdentityHandle&) = delete;

    private:
        HANDLE handle_ = nullptr;
    };

    // invokePrivilegeActionForIdentity: Validates the PID creation time and holds the process handle until the action completes.
    bool invokePrivilegeActionForIdentity(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime100ns,
        const std::function<bool(HANDLE, std::string*)>& actionInvoker,
        std::string* const detailTextOut)
    {
        if (!actionInvoker)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::action invoker is unavailable";
            }
            return false;
        }
        if (processId == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::process identity is unavailable";
            }
            return false;
        }

        HANDLE rawProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            processId);
        if (rawProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::OpenProcess failed, error="
                    + std::to_string(::GetLastError());
            }
            return false;
        }
        ScopedPrivilegeIdentityHandle processHandle(rawProcessHandle);

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(
            rawProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::GetProcessTimes failed, error="
                    + std::to_string(::GetLastError());
            }
            return false;
        }

        const std::uint64_t kActualCreationTime100ns =
            (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U)
            | static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        if (kActualCreationTime100ns == 0U
            || kActualCreationTime100ns != expectedCreationTime100ns)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "ProcessPrivilege::process identity changed";
            }
            return false;
        }

        return actionInvoker(rawProcessHandle, detailTextOut);
    }

    bool queryTokenPrivilegesWithR0Fallback(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime100ns,
        const HANDLE processHandle,
        std::vector<ks::process::TokenPrivilegeInfo>* const privilegesOut,
        bool* const usedR0Out,
        std::string* const detailTextOut)
    {
        if (usedR0Out != nullptr)
        {
            *usedR0Out = false;
        }

        std::string r3DetailText;
        if (ks::process::queryTokenPrivilegesByProcessHandle(
            processHandle,
            privilegesOut,
            &r3DetailText))
        {
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }

        ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessTokenPrivilegeResult kR0Result =
            driverClient.queryProcessTokenPrivileges(
                processId,
                expectedCreationTime100ns);
        if (kR0Result.io.ok
            && (kR0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                || kR0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL))
        {
            std::vector<ks::process::TokenPrivilegeLuidEntry> r0Entries;
            r0Entries.reserve(kR0Result.entries.size());
            for (const ksword::ark::ProcessTokenPrivilegeEntry& r0Entry : kR0Result.entries)
            {
                ks::process::TokenPrivilegeLuidEntry entry{};
                entry.luidLowPart = r0Entry.luidLowPart;
                entry.luidHighPart = r0Entry.luidHighPart;
                entry.attributes = r0Entry.attributes;
                r0Entries.push_back(entry);
            }
            if (ks::process::buildKnownTokenPrivilegeSnapshot(
                r0Entries,
                privilegesOut,
                detailTextOut))
            {
                if (usedR0Out != nullptr)
                {
                    *usedR0Out = true;
                }
                return true;
            }
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = r3DetailText;
            if (!kR0Result.io.message.empty())
            {
                *detailTextOut += " | ";
                *detailTextOut += kR0Result.io.message;
            }
        }
        return false;
    }
}

void ProcessDetailWindow::requestAsyncActionPrivilegeRefresh()
{
    if (actionPrivilegeStatusLabel_ == nullptr || actionPrivilegeRefreshing_)
    {
        return;
    }

    actionPrivilegeInitialRefreshStarted_ = true;
    actionPrivilegeRefreshing_ = true;
    actionPrivilegeReadable_ = false;
    const std::uint64_t kRefreshTicket = ++actionPrivilegeRefreshTicket_;
    actionPrivilegeStatusLabel_->setText(
        ks::i18n::text(QStringLiteral("process.detail.privileges.status.querying"), QString()));
    actionPrivilegeStatusLabel_->setStyleSheet(
        buildStateLabelStyle(statusSecondaryColor(), 600));
    if (actionPrivilegeRefreshButton_ != nullptr)
    {
        actionPrivilegeRefreshButton_->setEnabled(false);
    }
    if (applyActionPrivilegeR3Button_ != nullptr)
    {
        applyActionPrivilegeR3Button_->setEnabled(false);
    }
    if (applyActionPrivilegeR0Button_ != nullptr)
    {
        applyActionPrivilegeR0Button_->setEnabled(false);
    }
    for (QCheckBox* privilegeCheckBox : actionPrivilegeCheckBoxes_)
    {
        if (privilegeCheckBox != nullptr)
        {
            privilegeCheckBox->setEnabled(false);
        }
    }

    const std::uint32_t kProcessId = baseRecord_.pid;
    const std::uint64_t kCreationTime100ns = baseRecord_.creationTime100ns;
    const std::string kExpectedIdentityKey = identityKey();
    const QPointer<ProcessDetailWindow> kGuard(this);
    QRunnable* backgroundTask = QRunnable::create([
        kGuard,
        kProcessId,
        kCreationTime100ns,
        kExpectedIdentityKey,
        kRefreshTicket]()
    {
        ActionPrivilegeRefreshResult refreshResult;
        refreshResult.identityKey = kExpectedIdentityKey;
        refreshResult.ticket = kRefreshTicket;
        std::string detailText;
        refreshResult.queryOk = invokePrivilegeActionForIdentity(
            kProcessId,
            kCreationTime100ns,
            [kProcessId, kCreationTime100ns, &refreshResult](
                const HANDLE processHandle,
                std::string* const actionDetailText)
            {
                return queryTokenPrivilegesWithR0Fallback(
                    kProcessId,
                    kCreationTime100ns,
                    processHandle,
                    &refreshResult.privileges,
                    &refreshResult.usedR0,
                    actionDetailText);
            },
            &detailText);
        refreshResult.diagnosticText = QString::fromStdString(detailText);

        if (kGuard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(kGuard, [kGuard, refreshResult = std::move(refreshResult)]() mutable
        {
            if (kGuard == nullptr)
            {
                return;
            }
            kGuard->applyActionPrivilegeRefreshResult(refreshResult);
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDetailWindow::applyActionPrivilegeRefreshResult(
    const ActionPrivilegeRefreshResult& refreshResult)
{
    if (refreshResult.ticket != actionPrivilegeRefreshTicket_
        || refreshResult.identityKey != identityKey())
    {
        return;
    }

    actionPrivilegeRefreshing_ = false;
    actionPrivilegeReadable_ = refreshResult.queryOk;
    actionPrivilegeSnapshot_ = refreshResult.privileges;
    if (actionPrivilegeRefreshButton_ != nullptr)
    {
        actionPrivilegeRefreshButton_->setEnabled(true);
    }

    std::size_t adjustableCount = 0U;
    std::size_t enabledCount = 0U;
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < actionPrivilegeCheckBoxes_.size();
         ++privilegeIndex)
    {
        QCheckBox* const kPrivilegeCheckBox = actionPrivilegeCheckBoxes_[privilegeIndex];
        if (kPrivilegeCheckBox == nullptr)
        {
            continue;
        }

        const QSignalBlocker kSignalBlocker(kPrivilegeCheckBox);
        kPrivilegeCheckBox->setChecked(false);
        kPrivilegeCheckBox->setEnabled(false);
        if (!refreshResult.queryOk || privilegeIndex >= refreshResult.privileges.size())
        {
            kPrivilegeCheckBox->setToolTip(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.unknown"),
                    QString()));
            continue;
        }

        const ks::process::TokenPrivilegeInfo& privilegeInfo =
            refreshResult.privileges[privilegeIndex];
        if (privilegeInfo.state == ks::process::TokenPrivilegeState::kEnabled
            || privilegeInfo.state == ks::process::TokenPrivilegeState::kDisabled)
        {
            const bool kEnabled =
                privilegeInfo.state == ks::process::TokenPrivilegeState::kEnabled;
            kPrivilegeCheckBox->setChecked(kEnabled);
            kPrivilegeCheckBox->setEnabled(true);
            kPrivilegeCheckBox->setToolTip(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.adjustable"),
                    QString()));
            ++adjustableCount;
            if (kEnabled)
            {
                ++enabledCount;
            }
            continue;
        }

        kPrivilegeCheckBox->setToolTip(
            privilegeInfo.state == ks::process::TokenPrivilegeState::kNotPresent
                ? ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.not_present"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral("process.detail.privileges.state.unknown"),
                    QString()));
    }

    if (applyActionPrivilegeR3Button_ != nullptr)
    {
        applyActionPrivilegeR3Button_->setEnabled(refreshResult.queryOk && adjustableCount > 0U);
    }
    if (applyActionPrivilegeR0Button_ != nullptr)
    {
        applyActionPrivilegeR0Button_->setEnabled(refreshResult.queryOk && adjustableCount > 0U);
    }

    if (actionPrivilegeStatusLabel_ == nullptr)
    {
        return;
    }
    if (!refreshResult.queryOk)
    {
        KLogEvent queryEvent;
        warn << queryEvent
            << "[ProcessDetailWindow] token privilege query failed, pid="
            << baseRecord_.pid
            << ", detail="
            << (refreshResult.diagnosticText.isEmpty()
                ? "none"
                : refreshResult.diagnosticText.toStdString())
            << eol;
        actionPrivilegeStatusLabel_->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.privileges.status.unavailable"),
                QString()));
        actionPrivilegeStatusLabel_->setStyleSheet(
            buildStateLabelStyle(statusWarningColor(), 700));
        return;
    }

    actionPrivilegeStatusLabel_->setText(
        ks::i18n::text(
            QStringLiteral("process.detail.privileges.status.current"),
            QString())
            .arg(enabledCount)
            .arg(adjustableCount)
            .arg(refreshResult.usedR0
                ? ks::i18n::text(
                    QStringLiteral("process.detail.privileges.source.r0"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral("process.detail.privileges.source.r3"),
                    QString())));
    actionPrivilegeStatusLabel_->setStyleSheet(
        buildStateLabelStyle(statusIdleColor(), 600));
}

void ProcessDetailWindow::executeApplyActionPrivileges(const bool useR0)
{
    if (actionPrivilegeRefreshing_ || !actionPrivilegeReadable_)
    {
        return;
    }

    struct PendingPrivilegeEdit
    {
        ks::process::TokenPrivilegeEdit edit;
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        bool luidKnown = false;
    };

    std::vector<PendingPrivilegeEdit> privilegeEdits;
    const std::size_t kComparableCount = std::min(
        actionPrivilegeSnapshot_.size(),
        actionPrivilegeCheckBoxes_.size());
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < kComparableCount;
         ++privilegeIndex)
    {
        const ks::process::TokenPrivilegeInfo& privilegeInfo =
            actionPrivilegeSnapshot_[privilegeIndex];
        QCheckBox* const kPrivilegeCheckBox = actionPrivilegeCheckBoxes_[privilegeIndex];
        if (kPrivilegeCheckBox == nullptr
            || !kPrivilegeCheckBox->isEnabled()
            || (privilegeInfo.state != ks::process::TokenPrivilegeState::kEnabled
                && privilegeInfo.state != ks::process::TokenPrivilegeState::kDisabled))
        {
            continue;
        }

        const bool kCurrentlyEnabled =
            privilegeInfo.state == ks::process::TokenPrivilegeState::kEnabled;
        const bool kRequestedEnabled = kPrivilegeCheckBox->isChecked();
        if (kCurrentlyEnabled == kRequestedEnabled)
        {
            continue;
        }

        PendingPrivilegeEdit privilegeEdit;
        privilegeEdit.edit.privilegeName = privilegeInfo.privilegeName;
        privilegeEdit.edit.action = kRequestedEnabled
            ? ks::process::TokenPrivilegeAction::kEnable
            : ks::process::TokenPrivilegeAction::kDisable;
        privilegeEdit.luidLowPart = privilegeInfo.luidLowPart;
        privilegeEdit.luidHighPart = privilegeInfo.luidHighPart;
        privilegeEdit.luidKnown = privilegeInfo.luidKnown;
        privilegeEdits.push_back(std::move(privilegeEdit));
    }

    if (privilegeEdits.empty())
    {
        if (actionPrivilegeStatusLabel_ != nullptr)
        {
            actionPrivilegeStatusLabel_->setText(
                ks::i18n::text(
                    QStringLiteral("process.detail.privileges.status.no_changes"),
                    QString()));
            actionPrivilegeStatusLabel_->setStyleSheet(
                buildStateLabelStyle(statusSecondaryColor(), 600));
        }
        return;
    }

    actionPrivilegeRefreshing_ = true;
    const std::uint64_t kApplyTicket = ++actionPrivilegeRefreshTicket_;
    if (actionPrivilegeStatusLabel_ != nullptr)
    {
        actionPrivilegeStatusLabel_->setText(
            ks::i18n::text(
                useR0
                    ? QStringLiteral("process.detail.privileges.status.applying_r0")
                    : QStringLiteral("process.detail.privileges.status.applying_r3"),
                QString()).arg(privilegeEdits.size()));
        actionPrivilegeStatusLabel_->setStyleSheet(
            buildStateLabelStyle(statusSecondaryColor(), 600));
    }
    if (actionPrivilegeRefreshButton_ != nullptr)
    {
        actionPrivilegeRefreshButton_->setEnabled(false);
    }
    if (applyActionPrivilegeR3Button_ != nullptr)
    {
        applyActionPrivilegeR3Button_->setEnabled(false);
    }
    if (applyActionPrivilegeR0Button_ != nullptr)
    {
        applyActionPrivilegeR0Button_->setEnabled(false);
    }
    for (QCheckBox* privilegeCheckBox : actionPrivilegeCheckBoxes_)
    {
        if (privilegeCheckBox != nullptr)
        {
            privilegeCheckBox->setEnabled(false);
        }
    }

    struct ApplyTaskResult
    {
        ActionPrivilegeRefreshResult refreshResult;
        QString failureDetails;
        std::size_t editCount = 0U;
        bool allSucceeded = false;
    };

    const std::uint32_t kProcessId = baseRecord_.pid;
    const std::uint64_t kCreationTime100ns = baseRecord_.creationTime100ns;
    const std::string kExpectedIdentityKey = identityKey();
    const QPointer<ProcessDetailWindow> kGuard(this);
    QRunnable* backgroundTask = QRunnable::create([
        kGuard,
        kProcessId,
        kCreationTime100ns,
        kExpectedIdentityKey,
        kApplyTicket,
        useR0,
        privilegeEdits = std::move(privilegeEdits)]() mutable
    {
        ApplyTaskResult taskResult;
        taskResult.editCount = privilegeEdits.size();
        taskResult.refreshResult.identityKey = kExpectedIdentityKey;
        taskResult.refreshResult.ticket = kApplyTicket;
        QStringList failureLines;
        std::string identityDetailText;
        const bool kIdentityActionOk = invokePrivilegeActionForIdentity(
            kProcessId,
            kCreationTime100ns,
            [
                kProcessId,
                kCreationTime100ns,
                useR0,
                &privilegeEdits,
                &taskResult,
                &failureLines](
                    const HANDLE processHandle,
                    std::string* const actionDetailText)
            {
                std::string privilegeDetailText;
                if (useR0)
                {
                    std::vector<ksword::ark::ProcessTokenPrivilegeEntry> r0Edits;
                    r0Edits.reserve(privilegeEdits.size());
                    for (const PendingPrivilegeEdit& privilegeEdit : privilegeEdits)
                    {
                        if (!privilegeEdit.luidKnown)
                        {
                            failureLines.push_back(
                                QStringLiteral("%1: privilege LUID is unavailable")
                                    .arg(QString::fromStdString(
                                        privilegeEdit.edit.privilegeName)));
                            continue;
                        }

                        ksword::ark::ProcessTokenPrivilegeEntry r0Edit{};
                        r0Edit.luidLowPart = privilegeEdit.luidLowPart;
                        r0Edit.luidHighPart = privilegeEdit.luidHighPart;
                        r0Edit.action = privilegeEdit.edit.action ==
                                ks::process::TokenPrivilegeAction::kEnable
                            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
                            : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
                        r0Edits.push_back(r0Edit);
                    }

                    if (r0Edits.size() == privilegeEdits.size())
                    {
                        ksword::ark::DriverClient driverClient;
                        const ksword::ark::ProcessTokenPrivilegeResult kR0Result =
                            driverClient.adjustProcessTokenPrivileges(
                                kProcessId,
                                kCreationTime100ns,
                                r0Edits,
                                false);
                        taskResult.allSucceeded = kR0Result.io.ok
                            && kR0Result.status ==
                                KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                            && kR0Result.appliedCount == r0Edits.size();
                        privilegeDetailText = kR0Result.io.message;
                    }
                    else
                    {
                        taskResult.allSucceeded = false;
                    }
                }
                else
                {
                    std::vector<ks::process::TokenPrivilegeEdit> r3Edits;
                    r3Edits.reserve(privilegeEdits.size());
                    for (const PendingPrivilegeEdit& privilegeEdit : privilegeEdits)
                    {
                        r3Edits.push_back(privilegeEdit.edit);
                    }
                    taskResult.allSucceeded =
                        ks::process::applyTokenPrivilegeEditsByProcessHandle(
                            processHandle,
                            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                            false,
                            r3Edits,
                            &privilegeDetailText);
                }

                if (!taskResult.allSucceeded && !privilegeDetailText.empty())
                {
                    failureLines.push_back(QString::fromStdString(privilegeDetailText));
                }

                taskResult.refreshResult.queryOk = queryTokenPrivilegesWithR0Fallback(
                    kProcessId,
                    kCreationTime100ns,
                    processHandle,
                    &taskResult.refreshResult.privileges,
                    &taskResult.refreshResult.usedR0,
                    actionDetailText);
                return taskResult.refreshResult.queryOk;
            },
            &identityDetailText);
        if (!kIdentityActionOk)
        {
            taskResult.allSucceeded = false;
            taskResult.refreshResult.queryOk = false;
            taskResult.refreshResult.diagnosticText = QString::fromStdString(identityDetailText);
        }
        taskResult.failureDetails = failureLines.join(QStringLiteral("\n"));

        if (kGuard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(kGuard, [kGuard, useR0, taskResult = std::move(taskResult)]() mutable
        {
            if (kGuard == nullptr)
            {
                return;
            }

            kGuard->applyActionPrivilegeRefreshResult(taskResult.refreshResult);
            if (taskResult.refreshResult.ticket != kGuard->actionPrivilegeRefreshTicket_
                || taskResult.refreshResult.identityKey != kGuard->identityKey()
                || kGuard->actionPrivilegeStatusLabel_ == nullptr)
            {
                return;
            }

            kGuard->actionPrivilegeStatusLabel_->setText(
                ks::i18n::text(
                    taskResult.allSucceeded
                        ? (useR0
                            ? QStringLiteral("process.detail.privileges.status.applied_r0")
                            : QStringLiteral("process.detail.privileges.status.applied_r3"))
                        : QStringLiteral("process.detail.privileges.status.apply_failed"),
                    QString())
                    .arg(taskResult.editCount));
            kGuard->actionPrivilegeStatusLabel_->setStyleSheet(
                buildStateLabelStyle(
                    taskResult.allSucceeded ? statusIdleColor() : statusWarningColor(),
                    taskResult.allSucceeded ? 600 : 700));

            KLogEvent actionEvent;
            (taskResult.allSucceeded ? info : warn) << actionEvent
                << "[ProcessDetailWindow]::token privilege apply, path="
                << (useR0 ? "R0" : "R3")
                << ", pid="
                << kGuard->baseRecord_.pid
                << "::editCount=" << taskResult.editCount
                << "::allSucceeded=" << (taskResult.allSucceeded ? "true" : "false")
                << "::detail=" << taskResult.failureDetails.toStdString()
                << eol;
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}
