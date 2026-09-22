#pragma once

// ============================================================
// ThreadAffinityMenu.h
// Purpose:
// - Reuse the interaction of the Ksword5.1 process CPU affinity right-click matrix to provide a single-thread CPU Set menu.
// - Menu writes go only through the Win32 R3 API in shared/ThreadAffinityR3.h and do not touch the driver.
// ============================================================

#include <Windows.h>

#include <cstdint>
#include <functional>

#include <QIcon>
#include <QString>

class QMenu;

namespace ks::process
{
    using ThreadAffinityMenuResultHandler = std::function<void(bool, const QString&)>;

    // addThreadAffinitySubMenu: Appends the 'Thread Affinity' CPU Set matrix to the existing context menu.
    // When targetThreadCreationTime100ns is zero, the menu remains visible but disabled to prevent accidental writes due to TID reuse.
    QMenu* addThreadAffinitySubMenu(
        QMenu* parentMenu,
        const QIcon& icon,
        DWORD targetProcessId,
        DWORD targetThreadId,
        std::uint64_t targetThreadCreationTime100ns,
        const QString& menuStyle,
        ThreadAffinityMenuResultHandler resultHandler);
}
