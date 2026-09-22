#include "TaskbarRestartCoordinator.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QString>
#include <QStringList>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    constexpr auto kRestartAfterPidArgument = "--restart-after-pid";

    QStringList successorArguments()
    {
        const QString kRestartArgument = QString::fromLatin1(kRestartAfterPidArgument);
        const QStringList kCurrentArguments = QCoreApplication::arguments();
        QStringList arguments;
        for (qsizetype argumentIndex = 1; argumentIndex < kCurrentArguments.size(); ++argumentIndex)
        {
            if (kCurrentArguments.at(argumentIndex) == kRestartArgument)
            {
                // Do not pass old replacement arguments to the next generation; discard any subsequent PID (if present) as well.
                if (argumentIndex + 1 < kCurrentArguments.size())
                {
                    ++argumentIndex;
                }
                continue;
            }
            arguments.append(kCurrentArguments.at(argumentIndex));
        }

        arguments.append(kRestartArgument);
        arguments.append(QString::number(::GetCurrentProcessId()));
        return arguments;
    }

    bool requestedPredecessorPid(DWORD* predecessorPid)
    {
        if (predecessorPid == nullptr)
        {
            return false;
        }

        const QString kRestartArgument = QString::fromLatin1(kRestartAfterPidArgument);
        const QStringList kArguments = QCoreApplication::arguments();
        const qsizetype kMarkerIndex = kArguments.indexOf(kRestartArgument);
        if (kMarkerIndex < 0)
        {
            *predecessorPid = 0;
            return true;
        }
        if (kMarkerIndex + 1 >= kArguments.size())
        {
            return false;
        }

        bool parsed = false;
        const qulonglong kParsedPid = kArguments.at(kMarkerIndex + 1).toULongLong(&parsed, 10);
        if (!parsed || kParsedPid == 0 || kParsedPid > MAXDWORD ||
            kParsedPid == ::GetCurrentProcessId())
        {
            return false;
        }

        *predecessorPid = static_cast<DWORD>(kParsedPid);
        return true;
    }
}

bool taskbar_restart_coordinator::scheduleAfterCurrentProcessExit()
{
    const QString kProgramPath = QCoreApplication::applicationFilePath();
    const QFileInfo kProgramFileInfo(kProgramPath);
    if (kProgramPath.isEmpty() || !kProgramFileInfo.isFile())
    {
        return false;
    }

    return QProcess::startDetached(
        kProgramPath,
        successorArguments(),
        kProgramFileInfo.absolutePath());
}

bool taskbar_restart_coordinator::waitForPredecessorIfRequested()
{
    DWORD predecessorPid = 0;
    if (!requestedPredecessorPid(&predecessorPid))
    {
        return false;
    }
    if (predecessorPid == 0)
    {
        return true;
    }

    HANDLE predecessorProcess = ::OpenProcess(SYNCHRONIZE, FALSE, predecessorPid);
    if (predecessorProcess == nullptr)
    {
        // Between startDetached and OpenProcess, the old process may have fully exited; it is safe to proceed at this point.
        return ::GetLastError() == ERROR_INVALID_PARAMETER;
    }

    const DWORD kWaitResult = ::WaitForSingleObject(predecessorProcess, INFINITE);
    ::CloseHandle(predecessorProcess);
    return kWaitResult == WAIT_OBJECT_0;
}
