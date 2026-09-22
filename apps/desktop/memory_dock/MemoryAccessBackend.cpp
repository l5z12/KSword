#include "MemoryAccessBackend.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
// Slice length and access control order both use a shared pure function; this
// is the same implementation used by R0 and the one covered by unit tests.
#include "../../../shared/driver/KswordArkDdmaPlan.h"

#include <algorithm>
#include <vector>

// ============================================================
// MemoryAccessBackend.cpp
// Purpose:
// - Implements a unified read/write facade for the standard driver channel and DDMA channel.
// - All criteria for "whether DDMA can be used", "how to slice", and "how to handle failure" exist only in this file.
// ============================================================

namespace ksword::memory_backend
{
    namespace
    {
        // One DDMA DMA transfer length, consistent with R0 protocol constants.
        constexpr std::uint64_t kDdmaPageBytes =
            static_cast<std::uint64_t>(KSWORD_ARK_DDMA_TRANSFER_BYTES);

        // Single-transaction limit for the standard channel: directly use the protocol constant to avoid hardcoding magic numbers in the UI.
        constexpr std::uint64_t kStandardPhysicalReadMax =
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES);
        constexpr std::uint64_t kStandardPhysicalWriteMax =
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES);
        constexpr std::uint64_t kStandardVirtualReadMax =
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_READ_MAX_BYTES);
        constexpr std::uint64_t kStandardVirtualWriteMax =
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_WRITE_MAX_BYTES);

        // Start of the x64 kernel high half. Canonical addresses are either below 0x0000800000000000
        // or not below 0xFFFF800000000000; the middle region is an unusable hole.
        constexpr std::uint64_t kKernelSpaceStart = 0xFFFF800000000000ULL;

        // ddmaFlagsForRead / ddmaFlagsForWrite：
        // Translate "Session Confirmed" to protocol flags. Both LBA_VALID and ACKNOWLEDGED must be set;
        // missing either causes R0 to return independent status codes instead of a general rejection.
        unsigned long ddmaFlagsForRead()
        {
            return KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
        }

        unsigned long ddmaFlagsForWrite(const bool forceApproved)
        {
            unsigned long flags = ddmaFlagsForRead();
            if (forceApproved)
            {
                flags |= KSWORD_ARK_DDMA_FLAG_FORCE;
            }
            return flags;
        }

        // describeDdmaReadFailure: Translate the R0 read status into user-actionable text.
        QString describeDdmaReadFailure(const ksword::ark::DdmaReadResult& result)
        {
            switch (result.readStatus)
            {
            case KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED:
                return QStringLiteral("驱动拒绝：必须显式指定暂存扇区 LBA。");
            case KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED:
                return QStringLiteral("驱动拒绝：尚未确认暂存扇区可被临时覆盖。");
            case KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND:
                return QStringLiteral("目标磁盘已不在设备列表中，请重新探测 DDMA 通道。");
            case KSWORD_ARK_DDMA_READ_STATUS_RANGE_REJECTED:
                return QStringLiteral("物理区间被驱动拒绝：长度为 0、超过一页或跨页。");
            case KSWORD_ARK_DDMA_READ_STATUS_MAP_FAILED:
                return QStringLiteral("映射目标物理页失败，该物理地址可能不存在。");
            case KSWORD_ARK_DDMA_READ_STATUS_BACKUP_FAILED:
                return QStringLiteral(
                    "备份暂存扇区失败，本次未对磁盘做任何写入。请确认该 LBA 在磁盘容量范围内。");
            case KSWORD_ARK_DDMA_READ_STATUS_STAGE_OUT_FAILED:
                return QStringLiteral("把目标物理页 DMA 写到暂存扇区失败。");
            case KSWORD_ARK_DDMA_READ_STATUS_STAGE_IN_FAILED:
                return QStringLiteral("从暂存扇区 DMA 读回失败。");
            case KSWORD_ARK_DDMA_READ_STATUS_IRQL_REJECTED:
                return QStringLiteral("驱动在非 PASSIVE_LEVEL 下拒绝了本次请求。");
            case KSWORD_ARK_DDMA_READ_STATUS_BUFFER_TOO_SMALL:
                return QStringLiteral("响应缓冲不足，这是客户端缺陷，请上报。");
            default:
                break;
            }
            return QStringLiteral("DDMA 读取失败，readStatus=%1。").arg(result.readStatus);
        }

        // describeDdmaWriteFailure provides status messages for the write path. It is separated from the read path because
        // FORCE_REQUIRED only occurs in the write path and requires prompting the user to confirm rather than modify configuration.
        QString describeDdmaWriteFailure(const ksword::ark::DdmaWriteResult& result)
        {
            switch (result.writeStatus)
            {
            case KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_LBA_REQUIRED:
                return QStringLiteral("驱动拒绝：必须显式指定暂存扇区 LBA。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_NOT_ACKNOWLEDGED:
                return QStringLiteral("驱动拒绝：尚未确认暂存扇区可被临时覆盖。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED:
                return QStringLiteral("驱动要求对 DDMA 写入附加强制标志。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_DISK_NOT_FOUND:
                return QStringLiteral("目标磁盘已不在设备列表中，请重新探测 DDMA 通道。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_RANGE_REJECTED:
                return QStringLiteral("物理区间被驱动拒绝：长度为 0、超过一页或跨页。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_MAP_FAILED:
                return QStringLiteral("映射目标物理页失败，该物理地址可能不存在。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_BACKUP_FAILED:
                return QStringLiteral(
                    "备份暂存扇区失败，本次未对磁盘或物理内存做任何写入。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_READBACK_FAILED:
                return QStringLiteral(
                    "读-改-写的读回阶段失败，目标物理页未被修改。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_OUT_FAILED:
                return QStringLiteral("把数据 DMA 写到暂存扇区失败，目标物理页未被修改。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_STAGE_IN_FAILED:
                return QStringLiteral(
                    "从暂存扇区 DMA 写入目标物理页失败，该页可能处于半写状态。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_ACCESS_DENIED:
                return QStringLiteral("驱动安全策略拒绝了本次 DDMA 写入。");
            case KSWORD_ARK_DDMA_WRITE_STATUS_IRQL_REJECTED:
                return QStringLiteral("驱动在非 PASSIVE_LEVEL 下拒绝了本次请求。");
            default:
                break;
            }
            return QStringLiteral("DDMA 写入失败，writeStatus=%1。").arg(result.writeStatus);
        }

        // formatHex: unified 0x hexadecimal formatting to avoid inconsistencies in case and bit width across locations.
        QString formatHex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 0, 16).toUpper().replace(
                QStringLiteral("0X"), QStringLiteral("0x"));
        }

        // ddmaReadOnePage：
        // - Read a segment within a single physical page (caller guarantees no page crossing).
        // - Compress R0's multi-segment status into a few boolean flags of AccessOutcome.
        AccessOutcome ddmaReadOnePage(
            const ksword::ark::DriverClient& client,
            const DdmaSession& session,
            const std::uint64_t physicalAddress,
            const std::uint32_t lengthBytes)
        {
            AccessOutcome outcome;
            const ksword::ark::DdmaReadResult kResult = client.ddmaReadPhysicalMemory(
                session.diskIndex,
                physicalAddress,
                lengthBytes,
                session.scratchLba,
                ddmaFlagsForRead());

            // Determine if scratch sectors are restored first: even if the read itself fails, dirty sectors must still be reported.
            outcome.scratchDirty = !kResult.scratchRestored() &&
                (kResult.readStatus != KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED) &&
                (kResult.readStatus != KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED) &&
                (kResult.readStatus != KSWORD_ARK_DDMA_READ_STATUS_BACKUP_FAILED) &&
                (kResult.readStatus != KSWORD_ARK_DDMA_READ_STATUS_UNAVAILABLE);

            if (!kResult.io.ok)
            {
                outcome.failureText = kResult.unsupported
                    ? QStringLiteral("当前驱动不支持 DDMA，请更新 KswordARK 驱动。")
                    : QStringLiteral("DDMA 读取通信失败：%1")
                          .arg(QString::fromStdString(kResult.io.message));
                return outcome;
            }
            if (kResult.readStatus != KSWORD_ARK_DDMA_READ_STATUS_OK ||
                kResult.data.size() != static_cast<std::size_t>(lengthBytes))
            {
                outcome.failureText = describeDdmaReadFailure(kResult);
                return outcome;
            }

            outcome.ok = true;
            outcome.bytesDone = lengthBytes;
            outcome.data = QByteArray(
                reinterpret_cast<const char*>(kResult.data.data()),
                static_cast<qsizetype>(kResult.data.size()));
            return outcome;
        }

        // ddmaWriteOnePage: Writes a segment within a single physical page (caller guarantees no page crossing).
        AccessOutcome ddmaWriteOnePage(
            const ksword::ark::DriverClient& client,
            const DdmaSession& session,
            const std::uint64_t physicalAddress,
            const QByteArray& chunk,
            const bool forceApproved)
        {
            AccessOutcome outcome;
            const std::vector<std::uint8_t> kPayload(
                reinterpret_cast<const std::uint8_t*>(chunk.constData()),
                reinterpret_cast<const std::uint8_t*>(chunk.constData()) + chunk.size());

            const ksword::ark::DdmaWriteResult kResult = client.ddmaWritePhysicalMemory(
                session.diskIndex,
                physicalAddress,
                kPayload,
                session.scratchLba,
                ddmaFlagsForWrite(forceApproved));

            outcome.scratchDirty = !kResult.scratchRestored() &&
                (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_LBA_REQUIRED) &&
                (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_NOT_ACKNOWLEDGED) &&
                (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED) &&
                (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_BACKUP_FAILED) &&
                (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_UNAVAILABLE);
            outcome.lostUpdateWindow = kResult.readModifyWriteUsed();

            if (!kResult.io.ok)
            {
                outcome.failureText = kResult.unsupported
                    ? QStringLiteral("当前驱动不支持 DDMA，请更新 KswordARK 驱动。")
                    : QStringLiteral("DDMA 写入通信失败：%1")
                          .arg(QString::fromStdString(kResult.io.message));
                return outcome;
            }
            if (kResult.writeStatus == KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED)
            {
                // Distinguish this from other failures: the caller should prompt for confirmation
                // and retry with force, rather than asking the user to modify DDMA configuration.
                outcome.forceRequired = true;
                outcome.failureText = describeDdmaWriteFailure(kResult);
                return outcome;
            }
            if (kResult.writeStatus != KSWORD_ARK_DDMA_WRITE_STATUS_OK ||
                kResult.bytesWritten != static_cast<std::uint32_t>(chunk.size()))
            {
                outcome.failureText = describeDdmaWriteFailure(kResult);
                return outcome;
            }

            outcome.ok = true;
            outcome.bytesDone = static_cast<std::uint64_t>(chunk.size());
            return outcome;
        }

        // mergeChunkOutcome: Merge warning bits from per-page results into the total result.
        // The alert bit follows a 'retain once set' semantics and must not be overwritten by subsequent successful pages.
        void mergeChunkOutcome(AccessOutcome& total, const AccessOutcome& chunk)
        {
            total.scratchDirty = total.scratchDirty || chunk.scratchDirty;
            total.lostUpdateWindow = total.lostUpdateWindow || chunk.lostUpdateWindow;
            total.partial = total.partial || chunk.partial;
        }
    }

    namespace
    {
        // Process-level DDMA session. Writes occur only on the UI thread (DDMA sub-page), and reads also occur
        // exclusively on the UI thread. The sole exception is the background worker for memory search, but it copies
        // the session by value before starting (see MemoryDock.SearchFlow.cpp), so it never reads the live object here.
        DdmaSession& mutableCurrentDdmaSession()
        {
            static DdmaSession session;
            return session;
        }

        std::uint64_t& mutableDdmaSessionGeneration()
        {
            static std::uint64_t generation = 0ULL;
            return generation;
        }
    }

    const DdmaSession& currentDdmaSession()
    {
        return mutableCurrentDdmaSession();
    }

    void setCurrentDdmaSession(const DdmaSession& session)
    {
        mutableCurrentDdmaSession() = session;
        ++mutableDdmaSessionGeneration();
    }

    std::uint64_t ddmaSessionGeneration()
    {
        return mutableDdmaSessionGeneration();
    }

    std::uint32_t ddmaTransferBytes()
    {
        return static_cast<std::uint32_t>(KSWORD_ARK_DDMA_TRANSFER_BYTES);
    }

    QString backendDisplayName(const MemoryAccessBackend backend)
    {
        if (backend == MemoryAccessBackend::kDdma)
        {
            return QStringLiteral("DDMA（磁盘 DMA）");
        }
        if (backend == MemoryAccessBackend::kUserMode)
        {
            return QStringLiteral("R3（ReadProcessMemory）");
        }
        if (backend == MemoryAccessBackend::kHvm)
        {
            return QStringLiteral("HVM（私有页表窗口）");
        }
        return QStringLiteral("R0（驱动通道）");
    }

    namespace
    {
        // userModeReadVirtual: R3 channel. We open our own handle instead of borrowing the caller's because this
        // ensures consistent permissions for the same PID across all four pages. If we borrowed the handle, readability
        // would depend on what the caller requested in OpenProcess, causing different failure modes for the same
        // channel across different pages. These failure modes are the criteria used to distinguish the three channels.
        AccessOutcome userModeReadVirtual(
            const std::uint32_t processId,
            const std::uint64_t virtualAddress,
            const std::uint64_t lengthBytes)
        {
            AccessOutcome outcome;
            if (virtualAddress >= kKernelSpaceStart)
            {
                outcome.failureText = QStringLiteral("R3 通道读不了内核地址：ReadProcessMemory 只能访问目标进程的用户态地址空间，请改用 R0 驱动通道。");
                return outcome;
            }
            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE,
                static_cast<DWORD>(processId));
            if (kProcessHandle == nullptr)
            {
                outcome.failureText = QStringLiteral("R3 通道打开进程失败，win32=%1。")
                    .arg(::GetLastError());
                return outcome;
            }

            QByteArray buffer(static_cast<qsizetype>(lengthBytes), '\0');
            SIZE_T bytesRead = 0;
            const BOOL kReadOk = ::ReadProcessMemory(
                kProcessHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(virtualAddress)),
                buffer.data(),
                static_cast<SIZE_T>(lengthBytes),
                &bytesRead);
            // The error code must be retrieved immediately after the call: subsequent
            // CloseHandle or QString concatenation may overwrite the thread's last error.
            const DWORD kReadError = (kReadOk == FALSE) ? ::GetLastError() : ERROR_SUCCESS;
            ::CloseHandle(kProcessHandle);

            if (bytesRead == 0)
            {
                outcome.failureText = QStringLiteral("R3 通道读取失败，win32=%1。")
                    .arg(kReadError);
                return outcome;
            }
            outcome.ok = true;
            outcome.bytesDone = static_cast<std::uint64_t>(bytesRead);
            outcome.partial = (bytesRead < lengthBytes);
            outcome.data = buffer.left(static_cast<qsizetype>(bytesRead));
            return outcome;
        }

        // userModeWriteVirtual: R3 write.
        AccessOutcome userModeWriteVirtual(
            const std::uint32_t processId,
            const std::uint64_t virtualAddress,
            const QByteArray& payload)
        {
            AccessOutcome outcome;
            if (virtualAddress >= kKernelSpaceStart)
            {
                outcome.failureText = QStringLiteral(
                    "R3 通道写不了内核地址，请改用 R0 驱动通道。");
                return outcome;
            }
            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,
                static_cast<DWORD>(processId));
            if (kProcessHandle == nullptr)
            {
                outcome.failureText = QStringLiteral("R3 通道打开进程失败，win32=%1。")
                    .arg(::GetLastError());
                return outcome;
            }
            SIZE_T bytesWritten = 0;
            const BOOL kWriteOk = ::WriteProcessMemory(
                kProcessHandle,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(virtualAddress)),
                payload.constData(),
                static_cast<SIZE_T>(payload.size()),
                &bytesWritten);
            const DWORD kWriteError = (kWriteOk == FALSE) ? ::GetLastError() : ERROR_SUCCESS;
            ::CloseHandle(kProcessHandle);

            if (bytesWritten == 0)
            {
                outcome.failureText = QStringLiteral("R3 通道写入失败，win32=%1。")
                    .arg(kWriteError);
                return outcome;
            }
            outcome.ok = true;
            outcome.bytesDone = static_cast<std::uint64_t>(bytesWritten);
            outcome.partial = (static_cast<qsizetype>(bytesWritten) < payload.size());
            return outcome;
        }

        // userModeRejectPhysical: R3 has no means to access physical addresses. This cleanly rejects the request
        // rather than silently falling back to another channel. Falling back would make the user believe they are
        // using R3 while reading R0 results, making the difference between the two channels indistinguishable.
        AccessOutcome userModeRejectPhysical()
        {
            AccessOutcome outcome;
            outcome.failureText = QStringLiteral("R3 通道没有访问物理地址的手段，物理内存读写请选 R0 驱动通道或 DDMA。");
            return outcome;
        }

        // describeHvmMemoryStatus: Converts R-1 memory status into actionable text.
        QString describeHvmMemoryStatus(const unsigned long status)
        {
            switch (status)
            {
            case KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST:
                return QStringLiteral("驱动拒绝：请求字段无效。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED:
                return QStringLiteral("驱动拒绝：缺少界面确认令牌。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE:
                return QStringLiteral(
                    "私有页表窗口不可用：自映射基址没有标定出来（窗口可能落在大页映射里）。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID:
                return QStringLiteral("地址无效。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED:
                return QStringLiteral("虚拟地址翻译失败，该页可能未驻留。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED:
                return QStringLiteral("访问目标页失败。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_BUSY:
                return QStringLiteral("私有窗口正被另一次访问占用，请重试。");
            case KSWORD_ARK_HVM_MEMORY_STATUS_PROCESS_LOOKUP_FAILED:
                return QStringLiteral("目标进程查找失败或已退出。");
            default:
                break;
            }
            return QStringLiteral("R-1 内存访问失败，status=%1。").arg(status);
        }

        // hvmTransfer: Performs a single R-1 read or write operation in 1024-byte chunks.
        //
        // The slice size is a protocol requirement (KSWORD_ARK_HVM_MEMORY_MAX_BYTES), not a tuning parameter: requests use
        // METHOD_BUFFERED, requiring the entire request structure to be snapshotted into system buffers, so each request must be small.
        //
        // usedDirectWindow aggregates via logical AND across all fragments, not by taking the last one. If any fragment
        // falls back to MmCopyMemory, the entire access is no longer considered 'bypassing the memory manager'. Taking
        // only the last fragment would make an access with 50% fallback appear as if no fallback occurred.
        AccessOutcome hvmTransfer(
            const ksword::ark::DriverClient& client,
            const unsigned long readOperation,
            const unsigned long writeOperation,
            const std::uint32_t processId,
            const std::uint64_t baseAddress,
            const QByteArray* payload,
            const std::uint64_t lengthBytes)
        {
            AccessOutcome outcome;
            const bool kIsWrite = (payload != nullptr);
            const std::uint64_t kTotalBytes =
                kIsWrite ? static_cast<std::uint64_t>(payload->size()) : lengthBytes;

            QByteArray collected;
            bool allDirectWindow = true;
            bool anyTransferred = false;

            for (std::uint64_t offset = 0ULL; offset < kTotalBytes;)
            {
                const std::uint64_t kRemaining = kTotalBytes - offset;
                const unsigned long kChunk = static_cast<unsigned long>(
                    (std::min)(kRemaining,
                        static_cast<std::uint64_t>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES)));

                const ksword::ark::HvmMemoryResult kResult = client.hvmMemory(
                    kIsWrite ? writeOperation : readOperation,
                    baseAddress + offset,
                    0ULL,
                    kChunk,
                    kIsWrite
                        ? reinterpret_cast<const unsigned char*>(payload->constData() + offset)
                        : nullptr,
                    /*requireWindow*/ false,
                    /*uiConfirmed*/ true,
                    processId);

                if (!kResult.io.ok)
                {
                    outcome.failureText = kResult.unsupported
                        ? QStringLiteral("当前驱动不支持 R-1 内存访问，请更新 KswordARK 驱动。")
                        : QStringLiteral("R-1 内存访问通信失败：%1")
                              .arg(QString::fromStdString(kResult.io.message));
                    outcome.bytesDone = offset;
                    outcome.data = collected;
                    return outcome;
                }
                const unsigned long kStatus = kResult.response.status;
                if (kStatus != KSWORD_ARK_HVM_MEMORY_STATUS_OK
                    && kStatus != KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL)
                {
                    outcome.failureText = describeHvmMemoryStatus(kStatus);
                    outcome.bytesDone = offset;
                    outcome.data = collected;
                    return outcome;
                }

                anyTransferred = true;
                if (kResult.response.usedDirectWindow == 0U)
                {
                    allDirectWindow = false;
                }
                const unsigned long kDone = kResult.response.bytesTransferred;
                if (!kIsWrite && kDone != 0UL)
                {
                    collected.append(
                        reinterpret_cast<const char*>(kResult.response.data),
                        static_cast<qsizetype>((std::min)(kDone,
                            static_cast<unsigned long>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES))));
                }
                offset += kDone;
                // Stop when the driver reports 0 bytes completed without failure; otherwise, this will spin.
                if (kDone == 0UL)
                {
                    outcome.partial = true;
                    break;
                }
                if (kStatus == KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL)
                {
                    outcome.partial = true;
                    break;
                }
            }

            if (!anyTransferred)
            {
                outcome.failureText = QStringLiteral("R-1 内存访问未完成任何分片。");
                return outcome;
            }
            outcome.ok = true;
            outcome.bytesDone = kIsWrite
                ? static_cast<std::uint64_t>(kTotalBytes)
                : static_cast<std::uint64_t>(collected.size());
            outcome.data = collected;
            if (!kIsWrite && static_cast<std::uint64_t>(collected.size()) < kTotalBytes)
            {
                outcome.partial = true;
            }
            // When the private window path is not taken, **success cannot be silent**: the read operation just performed
            // is exactly the MmCopyMemory we intended to avoid. Comparing it with the R0 channel proves nothing, yet the
            // UI displays them as identical. Since no suitable field exists outside of lostUpdateWindow, we write to
            // failureText while keeping ok=true—the data is valid, but its independence has not been established.
            if (!allDirectWindow)
            {
                outcome.failureText = QStringLiteral("注意：本次访问回退到了 MmCopyMemory（私有页表窗口未标定），因此它与 R0 通道不再是两条独立的路径，两者一致不能用来排除内存管理器被挂钩。");
            }
            return outcome;
        }
    }

    bool isHvmMemoryUsable(QString* const reasonOut)
    {
        const auto kSetReason = [reasonOut](const QString& text) {
            if (reasonOut != nullptr)
            {
                *reasonOut = text;
            }
        };

        const ksword::ark::DriverClient kClient;
        const ksword::ark::HvmMemoryResult kResult = kClient.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
            0ULL, 0ULL, 0UL, nullptr,
            /*requireWindow*/ false,
            /*uiConfirmed*/ true);
        if (!kResult.io.ok)
        {
            kSetReason(kResult.unsupported
                ? QStringLiteral("当前驱动不支持 R-1 内存访问。")
                : QStringLiteral("查询 R-1 内存窗口失败：%1")
                      .arg(QString::fromStdString(kResult.io.message)));
            return false;
        }
        if (kResult.response.windowReady == 0U)
        {
            // When the window is not marked, this channel **can still return data** (falling back to MmCopyMemory),
            // but it is no longer independent of R0. Here we mark it as unavailable to prevent users from seeing
            // consistent results across two channels and mistakenly believing hooks have been ruled out.
            kSetReason(QStringLiteral("私有页表窗口未标定：自映射基址没有找到（窗口可能落在大页映射里）。此时访问会回退到 MmCopyMemory，与 R0 不再是独立的两条路径。"));
            return false;
        }
        kSetReason(QString());
        return true;
    }

    bool isKernelVirtualAddress(const std::uint64_t virtualAddress)
    {
        return virtualAddress >= kKernelSpaceStart;
    }

    bool isDdmaUsable(const DdmaSession& session, QString* const reasonOut)
    {
        // The evaluation order itself is part of the criteria (kernel debugging must precede 'not yet configured'), so the
        // order is determined by the shared pure function; this function only converts the conclusion into displayable text.
        const int kGate = KswordArkDdmaEvaluateGate(
            session.configured ? 1 : 0,
            session.kernelDebuggerEnabled ? 1 : 0,
            session.scratchLbaValid ? 1 : 0,
            session.scratchAcknowledged ? 1 : 0);

        QString reason;
        switch (kGate)
        {
        case KSWORD_ARK_DDMA_GATE_ALLOWED:
            if (reasonOut != nullptr)
            {
                reasonOut->clear();
            }
            return true;
        case KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED:
            reason = QStringLiteral(
                "尚未配置 DDMA 通道。请先到“内存 → DDMA”页探测磁盘并指定暂存扇区。");
            break;
        case KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER:
            // This is not "unavailable" but "will cause a BSOD if used": DDMA uses MmMapIoSpace to
            // map regular RAM, which triggers MiShowBadMapper when kernel debugging is enabled.
            reason = QStringLiteral(
                "本机启用了内核调试。DDMA 需要映射普通物理页，这种机器上会命中 "
                "MiShowBadMapper 直接蓝屏，因此禁止使用。请关闭内核调试后重试。");
            break;
        case KSWORD_ARK_DDMA_GATE_SCRATCH_LBA_MISSING:
            reason = QStringLiteral(
                "尚未指定暂存扇区 LBA。DDMA 必须借用磁盘扇区中转，本工具不提供默认值。");
            break;
        case KSWORD_ARK_DDMA_GATE_SCRATCH_NOT_ACKNOWLEDGED:
        default:
            reason = QStringLiteral(
                "尚未确认暂存扇区可被临时覆盖。请在 DDMA 页勾选确认后再使用。");
            break;
        }

        if (reasonOut != nullptr)
        {
            *reasonOut = reason;
        }
        return false;
    }

    AccessOutcome readPhysical(
        const MemoryAccessBackend backend,
        const DdmaSession& session,
        const std::uint64_t physicalAddress,
        const std::uint64_t lengthBytes)
    {
        AccessOutcome outcome;
        if (lengthBytes == 0ULL)
        {
            outcome.failureText = QStringLiteral("读取长度为 0。");
            return outcome;
        }

        if (backend == MemoryAccessBackend::kUserMode)
        {
            return userModeRejectPhysical();
        }

        const ksword::ark::DriverClient kClient;

        if (backend == MemoryAccessBackend::kHvm)
        {
            return hvmTransfer(
                kClient,
                KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL,
                KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL,
                0U, physicalAddress, nullptr, lengthBytes);
        }

        if (backend == MemoryAccessBackend::kStandardDriver)
        {
            if (lengthBytes > kStandardPhysicalReadMax)
            {
                outcome.failureText = QStringLiteral(
                    "标准通道单次物理读上限 %1 字节，请缩小范围。")
                    .arg(kStandardPhysicalReadMax);
                return outcome;
            }
            const ksword::ark::PhysicalMemoryReadResult kResult = kClient.readPhysicalMemory(
                physicalAddress,
                static_cast<std::uint32_t>(lengthBytes),
                0UL);
            if (!kResult.io.ok)
            {
                outcome.failureText = QStringLiteral("物理内存读取失败：%1")
                    .arg(QString::fromStdString(kResult.io.message));
                return outcome;
            }
            const bool kUsable =
                (kResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK ||
                 kResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL);
            if (!kUsable || kResult.data.empty())
            {
                outcome.failureText = QStringLiteral(
                    "物理内存读取未返回可用数据，readStatus=%1。").arg(kResult.readStatus);
                return outcome;
            }
            outcome.ok = true;
            outcome.partial =
                (kResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL);
            outcome.bytesDone = static_cast<std::uint64_t>(kResult.data.size());
            outcome.data = QByteArray(
                reinterpret_cast<const char*>(kResult.data.data()),
                static_cast<qsizetype>(kResult.data.size()));
            return outcome;
        }

        QString unusableReason;
        if (!isDdmaUsable(session, &unusableReason))
        {
            outcome.failureText = unusableReason;
            return outcome;
        }

        // DDMA transfer granularity is one page; read page-by-page by slicing at page boundaries.
        outcome.data.reserve(static_cast<qsizetype>(lengthBytes));
        std::uint64_t cursor = physicalAddress;
        std::uint64_t remaining = lengthBytes;
        while (remaining > 0ULL)
        {
            // Calculate the chunk length using a shared pure function; all four loops share the same criterion.
            const std::uint64_t kChunkLength =
                static_cast<std::uint64_t>(KswordArkDdmaChunkLength(cursor, remaining));

            const AccessOutcome kChunk = ddmaReadOnePage(
                kClient, session, cursor, static_cast<std::uint32_t>(kChunkLength));
            mergeChunkOutcome(outcome, kChunk);
            if (!kChunk.ok)
            {
                outcome.failureText = QStringLiteral("物理地址 %1：%2")
                    .arg(formatHex(cursor))
                    .arg(kChunk.failureText);
                outcome.bytesDone = static_cast<std::uint64_t>(outcome.data.size());
                return outcome;
            }
            outcome.data.append(kChunk.data);
            cursor += kChunkLength;
            remaining -= kChunkLength;
        }

        outcome.ok = true;
        outcome.bytesDone = static_cast<std::uint64_t>(outcome.data.size());
        return outcome;
    }

    AccessOutcome writePhysical(
        const MemoryAccessBackend backend,
        const DdmaSession& session,
        const std::uint64_t physicalAddress,
        const QByteArray& bytes,
        const bool forceApproved)
    {
        AccessOutcome outcome;
        if (bytes.isEmpty())
        {
            outcome.failureText = QStringLiteral("写入长度为 0。");
            return outcome;
        }

        if (backend == MemoryAccessBackend::kUserMode)
        {
            return userModeRejectPhysical();
        }

        const ksword::ark::DriverClient kClient;

        if (backend == MemoryAccessBackend::kHvm)
        {
            return hvmTransfer(
                kClient,
                KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL,
                KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL,
                0U, physicalAddress, &bytes, 0ULL);
        }

        if (backend == MemoryAccessBackend::kStandardDriver)
        {
            // Standard physical write single-operation limit is 4KB; if exceeded, slice and submit in chunks up to the limit.
            qsizetype offset = 0;
            while (offset < bytes.size())
            {
                const qsizetype kChunkSize = std::min<qsizetype>(
                    static_cast<qsizetype>(kStandardPhysicalWriteMax),
                    bytes.size() - offset);
                const QByteArray kChunk = bytes.mid(offset, kChunkSize);
                const std::vector<std::uint8_t> kPayload(
                    reinterpret_cast<const std::uint8_t*>(kChunk.constData()),
                    reinterpret_cast<const std::uint8_t*>(kChunk.constData()) + kChunk.size());

                unsigned long writeFlags = KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED;
                if (forceApproved)
                {
                    writeFlags |= KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
                }
                const ksword::ark::PhysicalMemoryWriteResult kResult =
                    kClient.writePhysicalMemory(
                        physicalAddress + static_cast<std::uint64_t>(offset),
                        kPayload,
                        writeFlags);

                if (kResult.io.ok &&
                    kResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED)
                {
                    outcome.forceRequired = true;
                    outcome.failureText = QStringLiteral("驱动要求对物理内存写入附加强制标志。");
                    outcome.bytesDone = static_cast<std::uint64_t>(offset);
                    return outcome;
                }
                const bool kChunkOk = kResult.io.ok &&
                    kResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_OK &&
                    kResult.bytesWritten == static_cast<std::uint32_t>(kChunk.size());
                if (!kChunkOk)
                {
                    outcome.failureText = QStringLiteral(
                        "物理内存写入失败。地址 %1，writeStatus=%2；本轮已写入 %3 字节，"
                        "失败前的改动不会自动回滚。")
                        .arg(formatHex(physicalAddress + static_cast<std::uint64_t>(offset)))
                        .arg(kResult.writeStatus)
                        .arg(offset);
                    outcome.bytesDone = static_cast<std::uint64_t>(offset);
                    return outcome;
                }
                offset += kChunkSize;
            }
            outcome.ok = true;
            outcome.bytesDone = static_cast<std::uint64_t>(bytes.size());
            return outcome;
        }

        QString unusableReason;
        if (!isDdmaUsable(session, &unusableReason))
        {
            outcome.failureText = unusableReason;
            return outcome;
        }

        qsizetype offset = 0;
        while (offset < bytes.size())
        {
            const std::uint64_t kCursor = physicalAddress + static_cast<std::uint64_t>(offset);
            // Calculate the chunk length using a shared pure function; all four loops share the same criterion.
            const qsizetype kChunkSize = static_cast<qsizetype>(KswordArkDdmaChunkLength(
                kCursor,
                static_cast<std::uint64_t>(bytes.size() - offset)));
            const QByteArray kChunk = bytes.mid(offset, kChunkSize);

            const AccessOutcome kChunkOutcome =
                ddmaWriteOnePage(kClient, session, kCursor, kChunk, forceApproved);
            mergeChunkOutcome(outcome, kChunkOutcome);
            if (!kChunkOutcome.ok)
            {
                outcome.forceRequired = kChunkOutcome.forceRequired;
                outcome.failureText = QStringLiteral("物理地址 %1：%2 本轮已写入 %3 字节。")
                    .arg(formatHex(kCursor))
                    .arg(kChunkOutcome.failureText)
                    .arg(offset);
                outcome.bytesDone = static_cast<std::uint64_t>(offset);
                return outcome;
            }
            offset += kChunkSize;
        }

        outcome.ok = true;
        outcome.bytesDone = static_cast<std::uint64_t>(bytes.size());
        return outcome;
    }

    AccessOutcome readVirtual(
        const MemoryAccessBackend backend,
        const DdmaSession& session,
        const std::uint32_t processId,
        const std::uint64_t virtualAddress,
        const std::uint64_t lengthBytes)
    {
        AccessOutcome outcome;
        if (lengthBytes == 0ULL)
        {
            outcome.failureText = QStringLiteral("读取长度为 0。");
            return outcome;
        }

        if (backend == MemoryAccessBackend::kUserMode)
        {
            return userModeReadVirtual(processId, virtualAddress, lengthBytes);
        }

        const ksword::ark::DriverClient kClient;

        if (backend == MemoryAccessBackend::kHvm)
        {
            return hvmTransfer(
                kClient,
                KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
                KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL,
                processId, virtualAddress, nullptr, lengthBytes);
        }

        if (backend == MemoryAccessBackend::kStandardDriver)
        {
            if (lengthBytes > kStandardVirtualReadMax)
            {
                outcome.failureText = QStringLiteral(
                    "标准通道单次虚拟读上限 %1 字节，请缩小范围。")
                    .arg(kStandardVirtualReadMax);
                return outcome;
            }
            unsigned long readFlags = KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE;
            if (isKernelVirtualAddress(virtualAddress))
            {
                readFlags |= KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS;
            }
            const ksword::ark::VirtualMemoryReadResult kResult = kClient.readVirtualMemory(
                processId,
                virtualAddress,
                static_cast<std::uint32_t>(lengthBytes),
                readFlags);
            if (!kResult.io.ok)
            {
                outcome.failureText = QStringLiteral("虚拟内存读取失败：%1")
                    .arg(QString::fromStdString(kResult.io.message));
                return outcome;
            }
            if (kResult.data.empty())
            {
                outcome.failureText = QStringLiteral(
                    "虚拟内存读取未返回数据，readStatus=%1。").arg(kResult.readStatus);
                return outcome;
            }
            // Status must be validated against a whitelist, maintaining the same pattern as the physical read check above. Previously,
            // only 'data non-empty' was checked, causing ZERO_FILLED to be treated as a clean success—yet its literal meaning is
            // **The entire segment is unreadable, returning only padded zeros.** The caller receives a block of zero
            // bytes, which is indistinguishable from actually reading a page of zeros. This is the same category of false
            // positive as "both backends read all zeros, so report consistency": a read failure is disguised as data.
            if (kResult.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK &&
                kResult.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY)
            {
                outcome.failureText =
                    (kResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED)
                    ? QStringLiteral("该范围整段都不可读，驱动返回的全部是补零数据。")
                    : QStringLiteral("虚拟内存读取未返回可用数据，readStatus=%1。")
                        .arg(kResult.readStatus);
                return outcome;
            }
            outcome.ok = true;
            outcome.partial =
                (kResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY);
            outcome.bytesDone = static_cast<std::uint64_t>(kResult.data.size());
            outcome.data = QByteArray(
                reinterpret_cast<const char*>(kResult.data.data()),
                static_cast<qsizetype>(kResult.data.size()));
            return outcome;
        }

        QString unusableReason;
        if (!isDdmaUsable(session, &unusableReason))
        {
            outcome.failureText = unusableReason;
            return outcome;
        }

        // DDMA only recognizes physical addresses; virtual addresses must be translated page-by-page. This translation
        // uses the existing R0 read-only page table walker backend, so no page table parsing is re-implemented here.
        outcome.data.reserve(static_cast<qsizetype>(lengthBytes));
        std::uint64_t cursor = virtualAddress;
        std::uint64_t remaining = lengthBytes;
        while (remaining > 0ULL)
        {
            // Calculate the chunk length using a shared pure function; all four loops share the same criterion.
            const std::uint64_t kChunkLength =
                static_cast<std::uint64_t>(KswordArkDdmaChunkLength(cursor, remaining));

            const ksword::ark::VirtualAddressTranslateResult kTranslation =
                kClient.translateVirtualAddress(processId, cursor);
            if (!kTranslation.io.ok || !kTranslation.resolved)
            {
                // This page cannot translate physical addresses: treat as unreadable, zero-fill, and mark as partial results.
                // Do not silently skip or fail entirely—the memory viewer needs to continue displaying subsequent pages.
                outcome.data.append(static_cast<qsizetype>(kChunkLength), '\0');
                outcome.partial = true;
                cursor += kChunkLength;
                remaining -= kChunkLength;
                continue;
            }

            // translateVirtualAddress returns the full physical base address plus the page offset. In
            // large-page scenarios, pageSize exceeds 4KB, but the physical address already includes
            // the offset, so it can be used directly; a single DDMA transfer still covers only 4KB.
            const AccessOutcome kChunk = ddmaReadOnePage(
                kClient,
                session,
                kTranslation.physicalAddress,
                static_cast<std::uint32_t>(kChunkLength));
            mergeChunkOutcome(outcome, kChunk);
            if (!kChunk.ok)
            {
                outcome.failureText = QStringLiteral("虚拟地址 %1（物理 %2）：%3")
                    .arg(formatHex(cursor))
                    .arg(formatHex(kTranslation.physicalAddress))
                    .arg(kChunk.failureText);
                outcome.bytesDone = static_cast<std::uint64_t>(outcome.data.size());
                return outcome;
            }
            outcome.data.append(kChunk.data);
            cursor += kChunkLength;
            remaining -= kChunkLength;
        }

        outcome.ok = true;
        outcome.bytesDone = static_cast<std::uint64_t>(outcome.data.size());
        return outcome;
    }

    AccessOutcome writeVirtual(
        const MemoryAccessBackend backend,
        const DdmaSession& session,
        const std::uint32_t processId,
        const std::uint64_t virtualAddress,
        const QByteArray& bytes,
        const bool forceApproved)
    {
        AccessOutcome outcome;
        if (bytes.isEmpty())
        {
            outcome.failureText = QStringLiteral("写入长度为 0。");
            return outcome;
        }

        if (backend == MemoryAccessBackend::kUserMode)
        {
            return userModeWriteVirtual(processId, virtualAddress, bytes);
        }

        const ksword::ark::DriverClient kClient;

        if (backend == MemoryAccessBackend::kHvm)
        {
            return hvmTransfer(
                kClient,
                KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
                KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL,
                processId, virtualAddress, &bytes, 0ULL);
        }

        if (backend == MemoryAccessBackend::kStandardDriver)
        {
            qsizetype offset = 0;
            while (offset < bytes.size())
            {
                const qsizetype kChunkSize = std::min<qsizetype>(
                    static_cast<qsizetype>(kStandardVirtualWriteMax),
                    bytes.size() - offset);
                const QByteArray kChunk = bytes.mid(offset, kChunkSize);
                const std::vector<std::uint8_t> kPayload(
                    reinterpret_cast<const std::uint8_t*>(kChunk.constData()),
                    reinterpret_cast<const std::uint8_t*>(kChunk.constData()) + kChunk.size());
                const std::uint64_t kTarget =
                    virtualAddress + static_cast<std::uint64_t>(offset);

                unsigned long writeFlags = KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED;
                if (isKernelVirtualAddress(kTarget))
                {
                    writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS;
                }
                if (forceApproved)
                {
                    writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
                }
                const ksword::ark::VirtualMemoryWriteResult kResult =
                    kClient.writeVirtualMemory(processId, kTarget, kPayload, writeFlags);

                if (kResult.io.ok &&
                    kResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED)
                {
                    outcome.forceRequired = true;
                    outcome.failureText = QStringLiteral("驱动要求对本次写入附加强制标志。");
                    outcome.bytesDone = static_cast<std::uint64_t>(offset);
                    return outcome;
                }
                const bool kChunkOk = kResult.io.ok &&
                    kResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_OK &&
                    kResult.bytesWritten == static_cast<std::uint32_t>(kChunk.size());
                if (!kChunkOk)
                {
                    outcome.failureText = QStringLiteral(
                        "虚拟内存写入失败。地址 %1，writeStatus=%2；本轮已写入 %3 字节。")
                        .arg(formatHex(kTarget))
                        .arg(kResult.writeStatus)
                        .arg(offset);
                    outcome.bytesDone = static_cast<std::uint64_t>(offset);
                    return outcome;
                }
                offset += kChunkSize;
            }
            outcome.ok = true;
            outcome.bytesDone = static_cast<std::uint64_t>(bytes.size());
            return outcome;
        }

        QString unusableReason;
        if (!isDdmaUsable(session, &unusableReason))
        {
            outcome.failureText = unusableReason;
            return outcome;
        }

        qsizetype offset = 0;
        while (offset < bytes.size())
        {
            const std::uint64_t kCursor = virtualAddress + static_cast<std::uint64_t>(offset);
            // Calculate the chunk length using a shared pure function; all four loops share the same criterion.
            const qsizetype kChunkSize = static_cast<qsizetype>(KswordArkDdmaChunkLength(
                kCursor,
                static_cast<std::uint64_t>(bytes.size() - offset)));
            const QByteArray kChunk = bytes.mid(offset, kChunkSize);

            const ksword::ark::VirtualAddressTranslateResult kTranslation =
                kClient.translateVirtualAddress(processId, kCursor);
            if (!kTranslation.io.ok || !kTranslation.resolved)
            {
                // Translation failure on the write path must halt the entire operation. Skipping a page to continue
                // writing causes silent corruption where it appears successful but a segment was not written.
                outcome.failureText = QStringLiteral(
                    "虚拟地址 %1 无法翻译成物理地址，DDMA 写入已停止；本轮已写入 %2 字节。")
                    .arg(formatHex(kCursor))
                    .arg(offset);
                outcome.bytesDone = static_cast<std::uint64_t>(offset);
                return outcome;
            }

            const AccessOutcome kChunkOutcome = ddmaWriteOnePage(
                kClient, session, kTranslation.physicalAddress, kChunk, forceApproved);
            mergeChunkOutcome(outcome, kChunkOutcome);
            if (!kChunkOutcome.ok)
            {
                outcome.forceRequired = kChunkOutcome.forceRequired;
                outcome.failureText = QStringLiteral("虚拟地址 %1（物理 %2）：%3 本轮已写入 %4 字节。")
                    .arg(formatHex(kCursor))
                    .arg(formatHex(kTranslation.physicalAddress))
                    .arg(kChunkOutcome.failureText)
                    .arg(offset);
                outcome.bytesDone = static_cast<std::uint64_t>(offset);
                return outcome;
            }
            offset += kChunkSize;
        }

        outcome.ok = true;
        outcome.bytesDone = static_cast<std::uint64_t>(bytes.size());
        return outcome;
    }
}
