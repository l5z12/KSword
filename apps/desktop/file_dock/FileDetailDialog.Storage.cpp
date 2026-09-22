#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QWidget* FileDetailDialog::buildFileObjectTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // File object details are an audit output in 'group + name: value' format:
            // - Displays data in a property tree with copyable fields per line and explanatory sentences spanning columns.
            // - Read-only display; no close handle, unlock, or delete actions provided.

            const QString kNativePath = QDir::toNativeSeparators(filePath_);
            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(kNativePath);
            content += QStringLiteral("说明: 这里只做只读对象/句柄视图，不提供解锁、删除或绕过动作。\n\n");

            const QFileInfo kInfo(filePath_);
            const bool kDirectoryHint = kInfo.isDir();
            HANDLE fileHandle = openReadOnlyFileHandle(filePath_, kDirectoryHint);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                content += QStringLiteral("打开失败: %1\n").arg(::GetLastError());
                layout->addWidget(buildReportView(page, content), 1);
                return page;
            }

            QString standardInfoText;
            QString standardStatusText;
            const bool kStandardOk = queryFileStandardInfoText(fileHandle, standardInfoText, standardStatusText);
            content += QStringLiteral("[FileStandardInfo]\n");
            content += kStandardOk ? standardInfoText : QStringLiteral("读取失败: %1\n").arg(standardStatusText);
            content += QStringLiteral("\n[FileObject / Section / ControlArea]\n");
            const QString kNtPathText = buildDriverNtPath(filePath_);
            const ksword::ark::FileInfoQueryResult kR0Info = queryR0FileInfo(kInfo, kNtPathText);
            content += formatR0FileInfoText(kR0Info);
            const ksword::ark::FileSectionMappingsQueryResult kSectionView =
                ksword::ark::DriverClient().queryFileSectionMappings(
                    kNtPathText.toStdWString(),
                    KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
                    KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            content += QStringLiteral("\n[ControlArea Cross-View]\n");
            if (kSectionView.io.ok)
            {
                content += QStringLiteral("查询状态: %1\n").arg(kSectionView.queryStatus);
                content += QStringLiteral("查询说明: %1\n").arg(friendlyFileIoMessage(kSectionView.io.message));
                content += QStringLiteral("FileObject: %1\n").arg(formatHex64(kSectionView.fileObjectAddress));
                content += QStringLiteral("SectionObjectPointers: %1\n").arg(formatHex64(kSectionView.sectionObjectPointersAddress));
                content += QStringLiteral("DataControlArea: %1\n").arg(formatHex64(kSectionView.dataControlAreaAddress));
                content += QStringLiteral("ImageControlArea: %1\n").arg(formatHex64(kSectionView.imageControlAreaAddress));
                content += QStringLiteral("映射数量: %1 / %2\n")
                    .arg(kSectionView.returnedCount)
                    .arg(kSectionView.totalCount);
                content += QStringLiteral("跨视图：R3 文件标准信息给出 DeletePending；R0 侧给出 FileObject / SectionObjectPointers / ControlArea。\n");
            }
            else
            {
                content += QStringLiteral("查询失败: %1\n").arg(friendlyFileIoMessage(kSectionView.io.message));
                content += QStringLiteral("跨视图：当前仅保留 R0 FileInfo 结果，ControlArea 查询降级。\n");
            }
            content += QStringLiteral("\n[Cross-View]\n");
            content += QStringLiteral("R0 FileObject: %1\n").arg(formatHex64(kR0Info.fileObjectAddress));
            content += QStringLiteral("R0 SectionObjectPointers: %1\n").arg(formatHex64(kR0Info.sectionObjectPointersAddress));
            content += QStringLiteral("R0 DataSectionObject: %1\n").arg(formatHex64(kR0Info.dataSectionObjectAddress));
            content += QStringLiteral("R0 ImageSectionObject: %1\n").arg(formatHex64(kR0Info.imageSectionObjectAddress));
            content += QStringLiteral("R3 DeletePending/Share: 通过 FileStandardInfo 和共享只读打开侧写。\n");
            content += QStringLiteral("R3 Shared flags: 采集句柄使用 READ|WRITE|DELETE 共享，仅用于只读探测。\n");
            ::CloseHandle(fileHandle);
            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* FileDetailDialog::buildStorageTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // Storage/BitLocker audit output also follows the 'group + name: value' format:
            // - Displayed using a property tree, with volume stack, mount points, and BitLocker status each on a separate line, allowing individual copying;
            // - The page remains read-only; no actions such as unloading, unlocking, or bypassing are provided.
            // The initial screen shows only a placeholder report: volume IOCTLs and 4 R0 audits are collected in the background, so switching tabs no longer waits.

            QString placeholderText;
            placeholderText += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(filePath_));
            placeholderText += QStringLiteral("正在加载...\n");
            QWidget* placeholderReportView = buildReportView(page, placeholderText);
            layout->addWidget(placeholderReportView, 1);
            startStorageAuditLoad(page, placeholderReportView);
            return page;
        }

        void FileDetailDialog::startStorageAuditLoad(QWidget* storagePage, QWidget* placeholderReportView)
        {
            // Purpose: Move the entire collection of Storage / MountMgr / FVE pages to a background thread.
            // Input: storagePage is the root control of the page; placeholderReportView is the placeholder report view for the first screen.
            // Return: None; after collection completes, replace the placeholder view with the real report view on the UI thread.
            // Reason: The sequence of volume IOCTLs (IOCTL_STORAGE_QUERY_PROPERTY may wake a spinning disk) and the 4 ArkDriverClient
            // audit IOCTLs (each requiring CreateFileW to open the device followed by synchronous dispatch) causes a single page
            // switch to take 0.3–3 seconds. Executing this within QTabWidget::currentChanged would freeze the entire window.
            if (storagePage == nullptr)
            {
                return;
            }

            const QString kFilePathSnapshot = filePath_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QWidget> pageGuard(storagePage);
            QPointer<QWidget> placeholderGuard(placeholderReportView);
            auto* task = QRunnable::create(
                [guardThis, pageGuard, placeholderGuard, kFilePathSnapshot]()
                {
                    // The background thread produces only a single value of type report text and does not interact with any QWidget.
                    const QString kReportText = buildStorageAuditReportText(kFilePathSnapshot);

                    FileDetailDialog* const kTargetDialog = guardThis.data();
                    if (kTargetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        kTargetDialog,
                        [guardThis, pageGuard, placeholderGuard, kReportText]()
                        {
                            if (guardThis.isNull() || pageGuard.isNull())
                            {
                                return;
                            }

                            QWidget* const kPage = pageGuard.data();
                            QVBoxLayout* const kPageLayout = qobject_cast<QVBoxLayout*>(kPage->layout());
                            if (kPageLayout == nullptr)
                            {
                                return;
                            }

                            if (!placeholderGuard.isNull())
                            {
                                kPageLayout->removeWidget(placeholderGuard.data());
                                placeholderGuard->hide();
                                placeholderGuard->deleteLater();
                            }
                            kPageLayout->addWidget(buildReportView(kPage, kReportText), 1);
                            // Views created after data collection must also receive the Surface palette; they cannot fall back to the system Base.
                            guardThis->applyThemeStyle();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QString FileDetailDialog::buildStorageAuditReportText(const QString& filePathText)
        {
            // Purpose: Generate a complete read-only report text for the Storage / MountMgr / FVE pages.
            // Input: filePathText is the target file path.
            // Returns: the raw report text that can be directly passed to buildReportView.
            // Constraint: This function performs only data collection and string concatenation; it must be called on a background thread.
            const FileVolumeAuditSnapshot kSnapshot = queryFileVolumeAuditSnapshot(filePathText);
            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(filePathText));
            content += QStringLiteral("卷根: %1\n").arg(kSnapshot.volumeRoot.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.volumeRoot);
            content += QStringLiteral("卷栈: %1\n").arg(kSnapshot.volumeStackText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.volumeStackText);
            content += QStringLiteral("挂载点: %1\n").arg(kSnapshot.mountPointsText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.mountPointsText);
            content += QStringLiteral("设备路径: %1\n").arg(kSnapshot.devicePathText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.devicePathText);
            content += QStringLiteral("文件系统: %1\n").arg(kSnapshot.fsNameText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.fsNameText);
            content += QStringLiteral("卷标: %1\n").arg(kSnapshot.labelText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.labelText);
            content += QStringLiteral("存储描述: %1\n").arg(kSnapshot.storageText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.storageText);
            content += QStringLiteral("BitLocker: %1\n").arg(kSnapshot.bitLockerText.isEmpty() ? QStringLiteral("<unknown>") : kSnapshot.bitLockerText);
            content += QStringLiteral("\n说明：本页只展示可见状态，不做解锁、卸载、绕过或密钥导出。\n");
            content += QStringLiteral("说明：DeviceObject 在此页以卷设备路径做只读侧写，不触碰内核对象本身。\n");

            // R0 audit supplement:
            // - Only call the read-only wrapper via ArkDriverClient.
            // - volumeAuditPath prioritizes the NT device path; falls back to the volume root if missing;
            // Each wrapper outputs IO, count, truncation, and message for cross-verification with R3-side results.
            const QString kVolumeAuditPath = kSnapshot.devicePathText.isEmpty()
                ? kSnapshot.volumeRoot
                : kSnapshot.devicePathText;
            const std::wstring kVolumeAuditPathWide = kVolumeAuditPath.toStdWString();
            const ksword::ark::DriverClient kDriverClient;

            const ksword::ark::StorageVolumeStackAuditResult kVolumeStackAudit =
                kDriverClient.queryVolumeStackAudit(kVolumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / VolumeStack"),
                kVolumeStackAudit,
                kVolumeStackAudit.responseFlags,
                false);
            content += formatVolumeStackAuditRows(kVolumeStackAudit);

            const ksword::ark::StorageMountMgrMappingAuditResult kMountMgrAudit =
                kDriverClient.queryMountMgrMappingAudit(kVolumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / MountMgr"),
                kMountMgrAudit,
                kMountMgrAudit.responseFlags,
                false);
            content += formatMountMgrMappingAuditRows(kMountMgrAudit);

            const ksword::ark::StorageFilesystemIntegrityAuditResult kFilesystemAudit =
                kDriverClient.queryFilesystemIntegrityAudit(kVolumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / FilesystemIntegrity"),
                kFilesystemAudit,
                kFilesystemAudit.responseFlags,
                false);
            content += formatFilesystemIntegrityAuditRows(kFilesystemAudit);

            const ksword::ark::StorageBitlockerFveAuditResult kBitlockerAudit =
                kDriverClient.queryBitlockerFveAudit(kVolumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / BitLocker FVE"),
                kBitlockerAudit,
                kBitlockerAudit.responseFlags,
                false);
            content += formatBitlockerFveAuditRows(kBitlockerAudit);
            return content;
        }
}
