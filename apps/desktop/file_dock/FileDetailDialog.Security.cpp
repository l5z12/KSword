#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        FileSecuritySnapshot FileDetailDialog::loadFileSecuritySnapshot(const QString& nativePath)
        {
            // Purpose: Read Owner, Group, DACL, and SACL to generate a permissions page snapshot.
            // Input: nativePath is a Windows native path; Caller ensures execution on a background thread.
            // Processing: Synchronously call the Windows Security API while preserving both the old text details and new table rows.
            // Return: FileSecuritySnapshot; if reading fails, detailText contains the error code, and aceRows may be empty.
            FileSecuritySnapshot snapshot;
            QString content;
            std::wstring nativePathBuffer = nativePath.toStdWString();

            PSID ownerSid = nullptr;
            PSID groupSid = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            const DWORD kQueryMask = OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION;
            const DWORD kQueryResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                kQueryMask,
                &ownerSid,
                &groupSid,
                &dacl,
                nullptr,
                &securityDescriptor);
            snapshot.descriptorError = kQueryResult;
            if (kQueryResult != ERROR_SUCCESS)
            {
                content += QStringLiteral("\n深层安全描述符读取失败, code=%1\n").arg(kQueryResult);
            }
            else
            {
                snapshot.descriptorOk = true;
                snapshot.ownerSidText = sidToStringText(ownerSid);
                snapshot.ownerAccountText = sidToAccountText(ownerSid);
                snapshot.groupSidText = sidToStringText(groupSid);
                snapshot.groupAccountText = sidToAccountText(groupSid);

                content += QStringLiteral("\n[Owner]\n");
                content += QStringLiteral("SID: %1\n").arg(snapshot.ownerSidText);
                content += QStringLiteral("账户: %1\n").arg(snapshot.ownerAccountText);

                content += QStringLiteral("\n[Primary Group]\n");
                content += QStringLiteral("SID: %1\n").arg(snapshot.groupSidText);
                content += QStringLiteral("账户: %1\n").arg(snapshot.groupAccountText);

                appendAclText(QStringLiteral("DACL"), dacl, content);
                appendAclRows(QStringLiteral("DACL"), dacl, snapshot.aceRows);
                ::LocalFree(securityDescriptor);
            }

            PSID saclOwnerSid = nullptr;
            PSID saclGroupSid = nullptr;
            PACL sacl = nullptr;
            PSECURITY_DESCRIPTOR saclDescriptor = nullptr;
            const DWORD kSaclResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION,
                &saclOwnerSid,
                &saclGroupSid,
                nullptr,
                &sacl,
                &saclDescriptor);
            snapshot.saclError = kSaclResult;
            if (kSaclResult == ERROR_SUCCESS)
            {
                snapshot.saclOk = true;
                appendAclText(QStringLiteral("SACL"), sacl, content);
                appendAclRows(QStringLiteral("SACL"), sacl, snapshot.aceRows);
                ::LocalFree(saclDescriptor);
            }
            else
            {
                content += QStringLiteral("\n[SACL]\n");
                content += QStringLiteral("读取失败（通常需要 SeSecurityPrivilege）, code=%1\n").arg(kSaclResult);
            }

            content += QStringLiteral("\n说明：Mask 显示为十六进制，权限列为常见位标志拆解。");
            snapshot.detailText = content;
            return snapshot;
        }

        QString FileDetailDialog::buildSecurityDeepText(const QString& nativePath)
        {
            // Purpose: Compatible with legacy call sites to generate a plain-text security descriptor detail.
            // Input: nativePath is a Windows native path.
            // Processing: Delegate to loadFileSecuritySnapshot to avoid maintaining two sets of ACL parsing logic.
            // Returns: Displayable text; includes an error code on failure.
            return loadFileSecuritySnapshot(nativePath).detailText;
        }

        void FileDetailDialog::populateSecurityWidgets(
            QTableWidget* aceTable,
            CodeEditorWidget* detailEditor,
            QLabel* statusLabel,
            const QString& baseContent,
            const FileSecuritySnapshot& snapshot)
        {
            // Purpose: Fill the permissions page UI with the permission snapshot read from the background.
            // Input: aceTable/detailEditor/statusLabel are the target controls; snapshot is the read result.
            // Processing: Display editable DACL ACEs in the table; the details dialog retains full text and error codes.
            // Returns: None; skips corresponding updates when the control is null.
            if (aceTable != nullptr &&
                ks::ui::isTableUiCommitBlockedByContextMenu({ aceTable }))
            {
                const auto kSnapshotGuard = std::make_shared<FileSecuritySnapshot>(snapshot);
                const QPointer<FileDetailDialog> kSafeThis(this);
                const QPointer<QTableWidget> kTableGuard(aceTable);
                const QPointer<CodeEditorWidget> kEditorGuard(detailEditor);
                const QPointer<QLabel> kStatusGuard(statusLabel);
                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    this,
                    QStringLiteral("file-detail-security-snapshot"),
                    { aceTable },
                    [kSafeThis, kTableGuard, kEditorGuard, kStatusGuard, baseContent, kSnapshotGuard]()
                    {
                        if (!kSafeThis.isNull())
                        {
                            kSafeThis->populateSecurityWidgets(
                                kTableGuard,
                                kEditorGuard,
                                kStatusGuard,
                                baseContent,
                                *kSnapshotGuard);
                        }
                    }))
                {
                    return;
                }
            }

            if (aceTable != nullptr)
            {
                aceTable->setSortingEnabled(false);
                aceTable->setRowCount(static_cast<int>(snapshot.aceRows.size()));
                for (int rowIndex = 0; rowIndex < static_cast<int>(snapshot.aceRows.size()); ++rowIndex)
                {
                    const FileSecurityAceRow& row = snapshot.aceRows[static_cast<std::size_t>(rowIndex)];
                    aceTable->setItem(rowIndex, 0, createReadonlyTableItem(row.scopeText));
                    aceTable->setItem(rowIndex, 1, createReadonlyTableItem(QString::number(row.aceIndex)));
                    aceTable->setItem(rowIndex, 2, createReadonlyTableItem(row.typeText));
                    aceTable->setItem(rowIndex, 3, createReadonlyTableItem(row.accountText));
                    aceTable->setItem(rowIndex, 4, createReadonlyTableItem(row.sidText));
                    aceTable->setItem(rowIndex, 5, createReadonlyTableItem(formatAccessMaskHex(row.mask)));
                    aceTable->setItem(rowIndex, 6, createReadonlyTableItem(row.rightsText));
                    aceTable->setItem(rowIndex, 7, createReadonlyTableItem(row.flagsText));
                    aceTable->setItem(rowIndex, 8, createReadonlyTableItem(row.canEdit ? QStringLiteral("可编辑") : QStringLiteral("只读展示")));
                    for (int columnIndex = 0; columnIndex < aceTable->columnCount(); ++columnIndex)
                    {
                        QTableWidgetItem* item = aceTable->item(rowIndex, columnIndex);
                        if (item == nullptr)
                        {
                            continue;
                        }
                        item->setData(Qt::UserRole + 1, row.scopeText);
                        item->setData(Qt::UserRole + 2, static_cast<qulonglong>(row.aceIndex));
                        item->setData(Qt::UserRole + 3, row.sidText);
                        item->setData(Qt::UserRole + 4, row.typeText);
                        item->setData(Qt::UserRole + 5, static_cast<qulonglong>(row.mask));
                        item->setData(Qt::UserRole + 6, row.canEdit);
                    }
                }
                aceTable->setSortingEnabled(true);
                aceTable->resizeColumnsToContents();
            }

            if (detailEditor != nullptr)
            {
                QString detailText = baseContent;
                if (snapshot.descriptorOk)
                {
                    detailText += QStringLiteral("\n[摘要]\nOwner: %1 | %2\nPrimary Group: %3 | %4\n")
                        .arg(snapshot.ownerAccountText)
                        .arg(snapshot.ownerSidText)
                        .arg(snapshot.groupAccountText)
                        .arg(snapshot.groupSidText);
                }
                detailText += snapshot.detailText;
                detailEditor->setLocalizedText(detailText);
            }

            if (statusLabel != nullptr)
            {
                const QString kDaclState = snapshot.descriptorOk
                    ? QStringLiteral("DACL 已读取")
                    : QStringLiteral("DACL 读取失败:%1").arg(snapshot.descriptorError);
                const QString kSaclState = snapshot.saclOk
                    ? QStringLiteral("SACL 已读取")
                    : QStringLiteral("SACL 只读失败:%1").arg(snapshot.saclError);
                statusLabel->setText(QStringLiteral("● %1；%2；ACE=%3")
                    .arg(kDaclState)
                    .arg(kSaclState)
                    .arg(snapshot.aceRows.size()));
            }
        }

        void FileDetailDialog::startSecurityDeepLoad(
            QTableWidget* aceTable,
            CodeEditorWidget* detailEditor,
            QLabel* statusLabel,
            const QString& baseContent,
            const QString& nativePath)
        {
            // Purpose: Perform deep ACL/SACL parsing in the background and refresh the permissions page UI.
            // Input: baseContent is the quick permission summary, nativePath is the target path.
            // Processing: The worker thread reads the security descriptor; the UI thread updates the table, status, and detail text.
            // Returns: None; discards result if controls are invalid.
            if (aceTable == nullptr || detailEditor == nullptr || statusLabel == nullptr)
            {
                return;
            }

            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTableWidget> tableGuard(aceTable);
            QPointer<CodeEditorWidget> editorGuard(detailEditor);
            QPointer<QLabel> statusGuard(statusLabel);
            auto* task = QRunnable::create([guardThis, tableGuard, editorGuard, statusGuard, baseContent, nativePath]()
                {
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    const FileSecuritySnapshot kSnapshot = FileDetailDialog::loadFileSecuritySnapshot(nativePath);
                    targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, tableGuard, editorGuard, statusGuard, baseContent, kSnapshot]()
                        {
                            if (guardThis != nullptr)
                            {
                                guardThis->populateSecurityWidgets(
                                    tableGuard,
                                    editorGuard,
                                    statusGuard,
                                    baseContent,
                                    kSnapshot);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        DWORD FileDetailDialog::maskFromSecurityPreset(const int presetIndex)
        {
            // Purpose: Map the permission preset dropdown to Windows file access masks.
            // Input: presetIndex is the current index of the QComboBox.
            // Handling: Prioritize overwriting common file security page semantics to reduce user manual bit-packing requirements.
            // Returns: FILE_* / standard permission combination mask.
            switch (presetIndex)
            {
            case 0:
                return FILE_GENERIC_READ;
            case 1:
                return FILE_GENERIC_WRITE;
            case 2:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE;
            case 3:
                return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            case 4:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
            case 5:
                return FILE_ALL_ACCESS;
            default:
                return FILE_GENERIC_READ;
            }
        }

        DWORD FileDetailDialog::maskFromSecurityChecks(
            QCheckBox* readCheck,
            QCheckBox* writeCheck,
            QCheckBox* executeCheck,
            QCheckBox* deleteCheck,
            QCheckBox* writeDacCheck,
            QCheckBox* writeOwnerCheck)
        {
            // Purpose: Synthesize access mask from advanced checkboxes.
            // Input: Permission check boxes, which may be null.
            // Processing: accept only checked permission bits; return 0 if none are checked.
            // Returns: access mask.
            DWORD mask = 0;
            if (readCheck != nullptr && readCheck->isChecked()) mask |= FILE_GENERIC_READ;
            if (writeCheck != nullptr && writeCheck->isChecked()) mask |= FILE_GENERIC_WRITE;
            if (executeCheck != nullptr && executeCheck->isChecked()) mask |= FILE_GENERIC_EXECUTE;
            if (deleteCheck != nullptr && deleteCheck->isChecked()) mask |= DELETE;
            if (writeDacCheck != nullptr && writeDacCheck->isChecked()) mask |= WRITE_DAC;
            if (writeOwnerCheck != nullptr && writeOwnerCheck->isChecked()) mask |= WRITE_OWNER;
            return mask;
        }

        DWORD FileDetailDialog::inheritanceFlagsFromCombo(const int inheritIndex)
        {
            // Purpose: Map the inheritance scope dropdown to EXPLICIT_ACCESS inheritance flags.
            // Input: inheritIndex is the current index of the QComboBox.
            // Processing: Files do not inherit by default; directories can optionally inherit to child objects.
            // Return: Flags such as NO_INHERITANCE / SUB_CONTAINERS_AND_OBJECTS_INHERIT.
            switch (inheritIndex)
            {
            case 1:
                return SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            case 2:
                return SUB_OBJECTS_ONLY_INHERIT;
            case 3:
                return SUB_CONTAINERS_ONLY_INHERIT;
            default:
                return NO_INHERITANCE;
            }
        }

        bool FileDetailDialog::extractAceSidAndType(LPVOID acePointer, BYTE* aceTypeOut, PSID* sidOut)
        {
            // Purpose: Extract AceType and SID pointer from common ACE structures.
            // Input: acePointer comes from GetAce.
            // Processing: Parse only the DACL ACE types that the current UI supports for deletion.
            // Returns: true on successful parsing; returns false for unknown types.
            if (acePointer == nullptr || aceTypeOut == nullptr || sidOut == nullptr)
            {
                return false;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            *aceTypeOut = aceHeader->AceType;
            *sidOut = nullptr;
            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer)->SidStart);
                return true;
            case ACCESS_DENIED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer)->SidStart);
                return true;
            default:
                return false;
            }
        }

        DWORD FileDetailDialog::applySecurityAceChange(
            const QString& accountText,
            const DWORD accessMask,
            const ACCESS_MODE accessMode,
            const DWORD inheritanceFlags,
            QString& detailTextOut)
        {
            // Purpose: Add or set a DACL ACE.
            // Input: accountText is an account name or SID string; accessMask is the permission mask; accessMode is the allow/deny mode.
            // Processing: Read the existing DACL, call SetEntriesInAclW to synthesize a new DACL, and write it back to the file object.
            // Returns: Win32 error code; ERROR_SUCCESS indicates successful write.
            const QString kNormalizedAccount = accountText.trimmed();
            if (kNormalizedAccount.isEmpty())
            {
                detailTextOut = QStringLiteral("账户不能为空。可填写 DOMAIN\\User、BUILTIN\\Administrators 或 S-1-...。");
                return ERROR_INVALID_PARAMETER;
            }
            if (accessMask == 0)
            {
                detailTextOut = QStringLiteral("权限掩码为 0，未执行写入。");
                return ERROR_INVALID_PARAMETER;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(filePath_).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }

            std::wstring accountBuffer = kNormalizedAccount.toStdWString();
            PSID trusteeSid = nullptr;
            const bool kAccountLooksLikeSid = kNormalizedAccount.startsWith(QStringLiteral("S-"), Qt::CaseInsensitive);
            if (kAccountLooksLikeSid)
            {
                if (::ConvertStringSidToSidW(accountBuffer.c_str(), &trusteeSid) == FALSE || trusteeSid == nullptr)
                {
                    result = ::GetLastError();
                    if (securityDescriptor != nullptr)
                    {
                        ::LocalFree(securityDescriptor);
                    }
                    detailTextOut = QStringLiteral("SID 字符串解析失败，code=%1，SID=%2。")
                        .arg(result)
                        .arg(kNormalizedAccount);
                    return result;
                }
            }

            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = accessMask;
            explicitAccess.grfAccessMode = accessMode;
            explicitAccess.grfInheritance = inheritanceFlags;
            explicitAccess.Trustee.TrusteeForm = kAccountLooksLikeSid ? TRUSTEE_IS_SID : TRUSTEE_IS_NAME;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            explicitAccess.Trustee.ptstrName = kAccountLooksLikeSid
                ? reinterpret_cast<LPWSTR>(trusteeSid)
                : accountBuffer.data();

            PACL newDacl = nullptr;
            result = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (result == ERROR_SUCCESS)
            {
                result = ::SetNamedSecurityInfoW(
                    pathBuffer.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }

            if (newDacl != nullptr)
            {
                ::LocalFree(newDacl);
            }
            if (trusteeSid != nullptr)
            {
                ::LocalFree(trusteeSid);
            }
            if (securityDescriptor != nullptr)
            {
                ::LocalFree(securityDescriptor);
            }

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已写入 DACL：账户=%1，模式=%2，Mask=%3，继承标志=0x%4。")
                    .arg(kNormalizedAccount)
                    .arg(accessMode == DENY_ACCESS ? QStringLiteral("拒绝") : QStringLiteral("允许/设置"))
                    .arg(formatAccessMaskHex(accessMask))
                    .arg(inheritanceFlags, 0, 16)
                : QStringLiteral("写入 DACL 失败，code=%1。账户=%2，Mask=%3。")
                    .arg(result)
                    .arg(kNormalizedAccount)
                    .arg(formatAccessMaskHex(accessMask));
            return result;
        }

        DWORD FileDetailDialog::deleteSelectedDaclAce(QTableWidget* aceTable, QString& detailTextOut)
        {
            // Purpose: Delete the currently selected non-inherited DACL ACE from the permission table.
            // Input: aceTable is the ACE table on the Permissions page; the current row stores SID/type/sequence metadata.
            // Action: Read the existing DACL, copy the original ACE bytes excluding the target ACE, then write back using SetNamedSecurityInfoW.
            // Returns: Win32 error code; ERROR_SUCCESS indicates successful deletion.
            if (aceTable == nullptr || aceTable->currentRow() < 0)
            {
                detailTextOut = QStringLiteral("请先在 DACL 表格中选择一条可编辑 ACE。");
                return ERROR_INVALID_PARAMETER;
            }

            const int kRowIndex = aceTable->currentRow();
            QTableWidgetItem* firstItem = aceTable->item(kRowIndex, 0);
            if (firstItem == nullptr)
            {
                detailTextOut = QStringLiteral("选中行无元数据，无法删除。");
                return ERROR_INVALID_PARAMETER;
            }

            const QString kScopeText = firstItem->data(Qt::UserRole + 1).toString();
            const DWORD kSelectedAceIndex = firstItem->data(Qt::UserRole + 2).toUInt();
            const QString kSelectedSidText = firstItem->data(Qt::UserRole + 3).toString();
            const QString kSelectedTypeText = firstItem->data(Qt::UserRole + 4).toString();
            const bool kCanEdit = firstItem->data(Qt::UserRole + 6).toBool();
            if (kScopeText != QStringLiteral("DACL") || !kCanEdit)
            {
                detailTextOut = QStringLiteral("当前 ACE 只能展示，不能由此按钮修改。继承 ACE、SACL 和对象 ACE 需要在来源对象或审计页处理。");
                return ERROR_ACCESS_DENIED;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(filePath_).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }
            if (oldDacl == nullptr)
            {
                if (securityDescriptor != nullptr)
                {
                    ::LocalFree(securityDescriptor);
                }
                detailTextOut = QStringLiteral("当前 DACL 为空，无法删除 ACE。");
                return ERROR_NOT_FOUND;
            }

            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("读取 ACL 信息失败，code=%1。").arg(result);
                return result;
            }

            DWORD newAclBytes = sizeof(ACL);
            bool targetFound = false;
            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("读取 ACE[%1] 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool kSidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool kIsTarget = kSidOk
                    && aceIndex == kSelectedAceIndex
                    && aceTypeToText(aceType) == kSelectedTypeText
                    && sidToStringText(aceSid) == kSelectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (kIsTarget)
                {
                    targetFound = true;
                    continue;
                }
                newAclBytes += aceHeader->AceSize;
            }

            if (!targetFound)
            {
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("未在当前 DACL 中找到匹配 ACE，可能权限已被其它进程修改。请刷新后重试。");
                return ERROR_NOT_FOUND;
            }

            PACL newDacl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, newAclBytes));
            if (newDacl == nullptr)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("分配新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            const DWORD kAclRevision = oldDacl->AclRevision;
            if (::InitializeAcl(newDacl, newAclBytes, kAclRevision) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(newDacl);
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("初始化新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 前读取失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool kSidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool kIsTarget = kSidOk
                    && aceIndex == kSelectedAceIndex
                    && aceTypeToText(aceType) == kSelectedTypeText
                    && sidToStringText(aceSid) == kSelectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (kIsTarget)
                {
                    continue;
                }
                if (::AddAce(newDacl, kAclRevision, MAXDWORD, acePointer, aceHeader->AceSize) == FALSE)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 到新 DACL 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }
            }

            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                newDacl,
                nullptr);
            ::LocalFree(newDacl);
            ::LocalFree(securityDescriptor);

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已删除 ACE[%1]：%2 | %3。").arg(kSelectedAceIndex).arg(kSelectedTypeText, kSelectedSidText)
                : QStringLiteral("删除 ACE 写回失败，code=%1。").arg(result);
            return result;
        }

        QWidget* FileDetailDialog::buildSecurityTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            const QString kNativePath = QDir::toNativeSeparators(filePath_);
            QString baseContent;
            baseContent += QStringLiteral("目标路径: %1\n").arg(kNativePath);

            // Provide a quick permission summary from the Qt perspective first, facilitating comparison with ACL details.
            QFileInfo info(filePath_);
            baseContent += QStringLiteral("快速权限摘要:\n");
            baseContent += QStringLiteral("Read: %1\n").arg(info.isReadable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));
            baseContent += QStringLiteral("Write: %1\n").arg(info.isWritable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));
            baseContent += QStringLiteral("Execute: %1\n").arg(info.isExecutable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));

            QGroupBox* operationGroup = new QGroupBox(QStringLiteral("权限编辑"), page);
            QGridLayout* operationLayout = new QGridLayout(operationGroup);

            QLineEdit* accountEdit = new QLineEdit(operationGroup);
            accountEdit->setPlaceholderText(QStringLiteral("账户或 SID，例如 BUILTIN\\Administrators / Everyone / S-1-5-32-544"));
            accountEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* accessModeCombo = new QComboBox(operationGroup);
            accessModeCombo->setStyleSheet(buildBlueInputStyle());
            accessModeCombo->addItem(QStringLiteral("允许：添加/合并"), static_cast<int>(GRANT_ACCESS));
            accessModeCombo->addItem(QStringLiteral("允许：替换该主体权限"), static_cast<int>(SET_ACCESS));
            accessModeCombo->addItem(QStringLiteral("拒绝：添加/合并"), static_cast<int>(DENY_ACCESS));

            QComboBox* presetCombo = new QComboBox(operationGroup);
            presetCombo->setStyleSheet(buildBlueInputStyle());
            presetCombo->addItems(QStringList{
                QStringLiteral("读取"),
                QStringLiteral("写入"),
                QStringLiteral("读取 + 写入"),
                QStringLiteral("读取 + 执行"),
                QStringLiteral("修改"),
                QStringLiteral("完全控制") });
            presetCombo->setCurrentIndex(4);

            QLineEdit* customMaskEdit = new QLineEdit(operationGroup);
            customMaskEdit->setPlaceholderText(QStringLiteral("可选自定义 Mask，如 0x001F01FF；留空使用预设/复选框"));
            customMaskEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* inheritanceCombo = new QComboBox(operationGroup);
            inheritanceCombo->setStyleSheet(buildBlueInputStyle());
            inheritanceCombo->addItems(QStringList{
                QStringLiteral("仅当前对象"),
                QStringLiteral("目录和文件继承"),
                QStringLiteral("仅文件继承"),
                QStringLiteral("仅目录继承") });

            QCheckBox* readCheck = new QCheckBox(QStringLiteral("读"), operationGroup);
            QCheckBox* writeCheck = new QCheckBox(QStringLiteral("写"), operationGroup);
            QCheckBox* executeCheck = new QCheckBox(QStringLiteral("执行"), operationGroup);
            QCheckBox* deleteCheck = new QCheckBox(QStringLiteral("删除"), operationGroup);
            QCheckBox* writeDacCheck = new QCheckBox(QStringLiteral("改 DACL"), operationGroup);
            QCheckBox* writeOwnerCheck = new QCheckBox(QStringLiteral("改所有者"), operationGroup);

            QPushButton* applyAceButton = new QPushButton(QStringLiteral("应用 ACE"), operationGroup);
            QPushButton* deleteAceButton = new QPushButton(QStringLiteral("删除选中 ACE"), operationGroup);
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新权限"), operationGroup);
            applyAceButton->setToolTip(
                QStringLiteral("按上面选择的账户和权限，给该文件新增一条访问控制规则（ACE）"));
            deleteAceButton->setToolTip(
                QStringLiteral("删除列表中选中的那条文件访问控制规则（ACE）"));
            applyAceButton->setStyleSheet(buildBlueButtonStyle());
            deleteAceButton->setStyleSheet(buildBlueButtonStyle());
            refreshButton->setStyleSheet(buildBlueButtonStyle());

            operationLayout->addWidget(new QLabel(QStringLiteral("主体"), operationGroup), 0, 0);
            operationLayout->addWidget(accountEdit, 0, 1, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("动作"), operationGroup), 1, 0);
            operationLayout->addWidget(accessModeCombo, 1, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("预设"), operationGroup), 1, 2);
            operationLayout->addWidget(presetCombo, 1, 3);
            operationLayout->addWidget(new QLabel(QStringLiteral("继承"), operationGroup), 1, 4);
            operationLayout->addWidget(inheritanceCombo, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("权限位"), operationGroup), 2, 0);
            operationLayout->addWidget(readCheck, 2, 1);
            operationLayout->addWidget(writeCheck, 2, 2);
            operationLayout->addWidget(executeCheck, 2, 3);
            operationLayout->addWidget(deleteCheck, 2, 4);
            operationLayout->addWidget(writeDacCheck, 2, 5);
            operationLayout->addWidget(writeOwnerCheck, 3, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("Mask"), operationGroup), 4, 0);
            operationLayout->addWidget(customMaskEdit, 4, 1, 1, 3);
            operationLayout->addWidget(applyAceButton, 4, 4);
            operationLayout->addWidget(deleteAceButton, 4, 5);
            operationLayout->addWidget(refreshButton, 5, 5);
            layout->addWidget(operationGroup, 0);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 正在读取安全描述符..."), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QSplitter* splitter = new QSplitter(Qt::Vertical, page);
            QTableWidget* aceTable = new ks::ui::VisibleTableWidget(splitter);
            aceTable->setColumnCount(9);
            aceTable->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("范围"),
                QStringLiteral("序号"),
                QStringLiteral("类型"),
                QStringLiteral("账户"),
                QStringLiteral("SID"),
                QStringLiteral("Mask"),
                QStringLiteral("权限"),
                QStringLiteral("标志"),
                QStringLiteral("编辑状态")
                });
            aceTable->setAlternatingRowColors(true);
            aceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
            aceTable->setSelectionMode(QAbstractItemView::SingleSelection);
            aceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            aceTable->setSortingEnabled(true);
            if (aceTable->horizontalHeader() != nullptr)
            {
                aceTable->horizontalHeader()->setStretchLastSection(true);
            }
            installFileTableCopyMenu(aceTable);

            CodeEditorWidget* detailEditor = new CodeEditorWidget(splitter);
            detailEditor->setReadOnly(true);
            detailEditor->setLocalizedText(baseContent + QStringLiteral(
                "\n深层 Owner/Group/DACL/SACL 正在后台加载...\n"
                "\n操作说明：\n"
                "- 上方表格用于结构化展示 ACE；继承 ACE、SACL、对象 ACE 默认只读展示。\n"
                "- 应用 ACE 使用 Windows 安全 API 写 DACL，失败会保留错误码。\n"
                "- 删除选中 ACE 只删除非继承 DACL 中精确匹配的当前 ACE。\n"));

            splitter->addWidget(aceTable);
            splitter->addWidget(detailEditor);
            splitter->setStretchFactor(0, 3);
            splitter->setStretchFactor(1, 2);
            layout->addWidget(splitter, 1);

            const auto kSyncChecksFromPreset = [this, presetCombo, readCheck, writeCheck, executeCheck, deleteCheck, writeDacCheck, writeOwnerCheck]()
                {
                    const DWORD kPresetMask = maskFromSecurityPreset(presetCombo->currentIndex());
                    readCheck->setChecked((kPresetMask & FILE_GENERIC_READ) == FILE_GENERIC_READ);
                    writeCheck->setChecked((kPresetMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE);
                    executeCheck->setChecked((kPresetMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE);
                    deleteCheck->setChecked((kPresetMask & DELETE) != 0);
                    writeDacCheck->setChecked((kPresetMask & WRITE_DAC) != 0);
                    writeOwnerCheck->setChecked((kPresetMask & WRITE_OWNER) != 0);
                };
            kSyncChecksFromPreset();
            connect(presetCombo, &QComboBox::currentIndexChanged, this, [kSyncChecksFromPreset](int)
                {
                    kSyncChecksFromPreset();
                });

            const auto kRefreshSecurityUi = [this, aceTable, detailEditor, statusLabel, baseContent, kNativePath]()
                {
                    if (aceTable != nullptr)
                    {
                        aceTable->setRowCount(0);
                    }
                    if (statusLabel != nullptr)
                    {
                        statusLabel->setText(QStringLiteral("● 正在读取安全描述符..."));
                    }
                    if (detailEditor != nullptr)
                    {
                        detailEditor->setLocalizedText(baseContent + QStringLiteral("\n深层 Owner/Group/DACL/SACL 正在后台加载...\n"));
                    }
                    startSecurityDeepLoad(aceTable, detailEditor, statusLabel, baseContent, kNativePath);
                };

            connect(refreshButton, &QPushButton::clicked, this, kRefreshSecurityUi);
            connect(applyAceButton, &QPushButton::clicked, this,
                [this,
                accountEdit,
                accessModeCombo,
                inheritanceCombo,
                customMaskEdit,
                readCheck,
                writeCheck,
                executeCheck,
                deleteCheck,
                writeDacCheck,
                writeOwnerCheck,
                statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    DWORD accessMask = maskFromSecurityChecks(
                        readCheck,
                        writeCheck,
                        executeCheck,
                        deleteCheck,
                        writeDacCheck,
                        writeOwnerCheck);
                    const QString kCustomMaskText = customMaskEdit->text().trimmed();
                    if (!kCustomMaskText.isEmpty())
                    {
                        bool parseOk = false;
                        const qulonglong kParsedMask = kCustomMaskText.toULongLong(&parseOk, 0);
                        if (!parseOk || kParsedMask > 0xFFFFFFFFULL)
                        {
                            QMessageBox::warning(this, QStringLiteral("权限编辑"), QStringLiteral("自定义 Mask 格式无效：%1").arg(kCustomMaskText));
                            return;
                        }
                        accessMask = static_cast<DWORD>(kParsedMask);
                    }

                    if (accountEdit->text().trimmed().isEmpty() || accessMask == 0U)
                    {
                        QMessageBox::warning(this, QStringLiteral("权限编辑"),
                            QStringLiteral("请填写主体，并选择至少一个权限位。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        ks::file::metadata::SecurityAcePatch ace;
                        ace.trustee = accountEdit->text().trimmed();
                        ace.accessMask = accessMask;
                        ace.accessMode = static_cast<DWORD>(accessModeCombo->currentData().toInt());
                        ace.inheritance = inheritanceFlagsFromCombo(inheritanceCombo->currentIndex());
                        patch.security.aceChanges.push_back(ace);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● ACE 修改已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            connect(deleteAceButton, &QPushButton::clicked, this, [this, aceTable, statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const int kRow = aceTable != nullptr ? aceTable->currentRow() : -1;
                    if (kRow < 0 || aceTable->item(kRow, 0) == nullptr)
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("请先选择一条可编辑的非继承 DACL ACE。"));
                        return;
                    }
                    QTableWidgetItem* const kItem = aceTable->item(kRow, 0);
                    if (!kItem->data(Qt::UserRole + 6).toBool())
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("继承 ACE、SACL 与对象 ACE保持只读，不能在此直接删除。"));
                        return;
                    }
                    const QString kTypeText = kItem->data(Qt::UserRole + 4).toString();
                    BYTE aceType = 0xFFU;
                    if (kTypeText == QStringLiteral("ACCESS_ALLOWED")) aceType = ACCESS_ALLOWED_ACE_TYPE;
                    if (kTypeText == QStringLiteral("ACCESS_DENIED")) aceType = ACCESS_DENIED_ACE_TYPE;
                    if (aceType == 0xFFU)
                    {
                        return;
                    }
                    BYTE aceFlags = 0U;
                    const QString kFlagsText = aceTable->item(kRow, 7) != nullptr
                        ? aceTable->item(kRow, 7)->text()
                        : QString();
                    if (kFlagsText.contains(QStringLiteral("OBJECT_INHERIT"))) aceFlags |= OBJECT_INHERIT_ACE;
                    if (kFlagsText.contains(QStringLiteral("CONTAINER_INHERIT"))) aceFlags |= CONTAINER_INHERIT_ACE;
                    if (kFlagsText.contains(QStringLiteral("NO_PROPAGATE"))) aceFlags |= NO_PROPAGATE_INHERIT_ACE;
                    if (kFlagsText.contains(QStringLiteral("INHERIT_ONLY"))) aceFlags |= INHERIT_ONLY_ACE;
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        ks::file::metadata::SecurityAceRemoval removal;
                        removal.aceType = aceType;
                        removal.aceFlags = aceFlags;
                        removal.accessMask = static_cast<DWORD>(
                            kItem->data(Qt::UserRole + 5).toULongLong());
                        removal.sid = kItem->data(Qt::UserRole + 3).toString();
                        patch.security.aceRemovals.push_back(removal);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● 删除 ACE 操作已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            QMetaObject::invokeMethod(page, kRefreshSecurityUi, Qt::QueuedConnection);
            return page;
        }
}
